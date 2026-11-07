"""Parent-side coordination for the protocol-only worker session.

This stage deliberately stops before diagnostic execution.  The coordinator owns
the parent resources and forwards only frames that the real WorkerSession has
successfully sent or received to the existing ScanSupervisor.
"""

import ntpath
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from dev_env_doctor.collectors.environment import _lexical_directory, _local_directory_state
from dev_env_doctor.collectors.executable_lookup import _candidate_is_regular_file
from dev_env_doctor.core.process_environment import build_worker_environment
from dev_env_doctor.core.scan_control import ScanDeadline, StopReason
from dev_env_doctor.core.scan_ipc import FramedTransport, IpcError, IpcState, PipePair
from dev_env_doctor.core.scan_protocol import ProtocolError
from dev_env_doctor.core.scan_supervisor import (
    EvidenceStatus,
    ResourceEvidence,
    ScanSupervisor,
    SupervisorDecision,
)
from dev_env_doctor.core.scan_worker import WorkerSession, WorkerState
from dev_env_doctor.core.windows_job import (
    CleanupObservation,
    JobSnapshot,
    WaitObservation,
    WindowsJob,
)
from dev_env_doctor.core.worker_task import WorkerTaskMode


class CoordinatorState(StrEnum):
    IDLE = "idle"
    STARTING = "starting"
    READY = "ready"
    RUNNING = "running"
    STOPPING = "stopping"
    FAILED = "failed"
    CLOSED = "closed"


class CoordinationError(RuntimeError):
    """Fixed coordinator error without paths, commands, or exception details."""

    def __init__(self, message: str = "The scan resources could not be coordinated safely."):
        super().__init__(message)


class DiagnosticStage(StrEnum):
    """Finite internal stages exposed only to an explicitly injected observer."""

    SERVICE_ENTERED = "SERVICE_ENTERED"
    COORDINATOR_CREATED = "COORDINATOR_CREATED"
    STARTING_RESOURCES = "STARTING_RESOURCES"
    STARTING_WORKER = "STARTING_WORKER"
    WAITING_READY = "WAITING_READY"
    SENDING_START = "SENDING_START"
    RECEIVING_WORKER_MESSAGE = "RECEIVING_WORKER_MESSAGE"
    VALIDATING_RESULT = "VALIDATING_RESULT"
    OBSERVING_PROCESS_EXIT = "OBSERVING_PROCESS_EXIT"
    OBSERVING_JOB = "OBSERVING_JOB"
    CLOSING_IPC = "CLOSING_IPC"
    FINALIZING = "FINALIZING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class DiagnosticWorkerExit(StrEnum):
    CONFIRMED_ZERO = "CONFIRMED_ZERO"
    CONFIRMED_NONZERO = "CONFIRMED_NONZERO"
    UNCONFIRMED = "UNCONFIRMED"
    NOT_OBSERVED = "NOT_OBSERVED"


class DiagnosticJobStatus(StrEnum):
    ZERO_CONFIRMED = "ZERO_CONFIRMED"
    NONZERO = "NONZERO"
    UNCONFIRMED = "UNCONFIRMED"
    NOT_OBSERVED = "NOT_OBSERVED"


class DiagnosticResourceStatus(StrEnum):
    CLOSED_CONFIRMED = "CLOSED_CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"
    NOT_STARTED = "NOT_STARTED"
    NOT_OBSERVED = "NOT_OBSERVED"


class DiagnosticFailureCategory(StrEnum):
    """Finite internal categories for a worker-message receive failure."""

    WORKER_MESSAGE_TRANSPORT_ERROR = "WORKER_MESSAGE_TRANSPORT_ERROR"
    WORKER_MESSAGE_PROTOCOL_ERROR = "WORKER_MESSAGE_PROTOCOL_ERROR"
    WORKER_MESSAGE_UNCLASSIFIED_ERROR = "WORKER_MESSAGE_UNCLASSIFIED_ERROR"
    WORKER_FAILED_MESSAGE = "WORKER_FAILED_MESSAGE"


class DiagnosticWorkerExitReason(StrEnum):
    CANDIDATE_SEND_RETURNED = "WORKER_CANDIDATE_SEND_RETURNED"
    CANDIDATE_BUILD_FAILED = "WORKER_CANDIDATE_BUILD_FAILED"
    CANDIDATE_SEND_FAILED = "WORKER_CANDIDATE_SEND_FAILED"
    SCAN_FAILED = "WORKER_SCAN_FAILED"
    FAILED_SEND_RETURNED = "WORKER_FAILED_SEND_RETURNED"
    FAILED_SEND_FAILED = "WORKER_FAILED_SEND_FAILED"
    STARTUP_FAILED = "WORKER_STARTUP_FAILED"
    UNKNOWN = "WORKER_EXIT_REASON_UNKNOWN"


@dataclass(frozen=True, slots=True)
class DiagnosticEvent:
    """Safe, finite diagnostic evidence for an explicitly injected observer."""

    stage: DiagnosticStage
    coordinator_state: str
    supervisor_state: str
    error_code: str | None = None
    worker_exit: DiagnosticWorkerExit = DiagnosticWorkerExit.NOT_OBSERVED
    job_status: DiagnosticJobStatus = DiagnosticJobStatus.NOT_OBSERVED
    ipc_status: DiagnosticResourceStatus = DiagnosticResourceStatus.NOT_STARTED
    helper_threads: DiagnosticResourceStatus = DiagnosticResourceStatus.NOT_OBSERVED
    parent_resources: DiagnosticResourceStatus = DiagnosticResourceStatus.NOT_STARTED
    failure_category: DiagnosticFailureCategory | None = None
    worker_exit_reason: DiagnosticWorkerExitReason | None = None


class _ObservingTransport:
    """Delegate transport I/O while retaining only successfully completed frames."""

    def __init__(self, transport: FramedTransport) -> None:
        self._transport = transport
        self._sent: list[bytes] = []
        self._received: list[bytes] = []

    @property
    def state(self) -> IpcState:
        return self._transport.state

    def send(self, frame: bytes) -> None:
        self._transport.send(frame)
        self._sent.append(frame)

    def receive(self, timeout_ms: int | None = None) -> bytes:
        frame = (
            self._transport.receive()
            if timeout_ms is None
            else self._transport.receive(timeout_ms=timeout_ms)
        )
        self._received.append(frame)
        return frame

    def close(self) -> IpcState:
        try:
            return self._transport.close()
        finally:
            self._sent.clear()
            self._received.clear()

    def take_sent(self) -> bytes:
        if not self._sent:
            raise CoordinationError()
        return self._sent.pop(0)

    def take_received(self) -> bytes:
        if not self._received:
            raise CoordinationError()
        return self._received.pop(0)


@dataclass(frozen=True, slots=True)
class _OwnedResources:
    pair: PipePair | None = None
    job: WindowsJob | None = None
    transport: FramedTransport | None = None
    observed_transport: _ObservingTransport | None = None
    worker: WorkerSession | None = None


class ScanCoordinator:
    """Own one parent resource set and coordinate its protocol observations.

    The fixed worker entry used in this stage performs only the protocol
    handshake.  Consequently this object never fabricates a candidate report or
    marks a session successful.
    """

    def __init__(
        self,
        session_id: str,
        deadline: ScanDeadline,
        *,
        pipe_factory: Callable[[], PipePair] = PipePair.create,
        job_factory: Callable[[], WindowsJob] = WindowsJob,
        transport_factory: Callable[[object], FramedTransport] = FramedTransport,
        worker_factory: Callable[..., WorkerSession] = WorkerSession,
    ) -> None:
        self._supervisor = ScanSupervisor(session_id, deadline)
        self._session_id = session_id
        self._pipe_factory = pipe_factory
        self._job_factory = job_factory
        self._transport_factory = transport_factory
        self._worker_factory = worker_factory
        self._owned = _OwnedResources()
        self._resources = ResourceEvidence()
        self._state = CoordinatorState.IDLE
        self._child_copies_attempted = False
        self._child_copies_confirmed = False
        self._resources_start_attempted = False
        self._transport_start_attempted = False
        self._diagnostic_observer: Callable[[DiagnosticEvent], None] | None = None
        self._diagnostic_failure_category: DiagnosticFailureCategory | None = None
        self._worker_exit_reason: DiagnosticWorkerExitReason | None = None
        self._require_path_snapshot = False

    @property
    def state(self) -> CoordinatorState:
        return self._state

    @property
    def decision(self) -> SupervisorDecision:
        return self._supervisor.decision

    @property
    def supervisor(self) -> ScanSupervisor:
        return self._supervisor

    @property
    def resources(self) -> ResourceEvidence:
        return self._resources

    @property
    def diagnostic_failure_category(self) -> DiagnosticFailureCategory | None:
        return self._diagnostic_failure_category

    @property
    def child_copies_confirmed(self) -> bool:
        return self._child_copies_confirmed

    @property
    def candidate_diagnostics(self) -> list[dict[str, object]] | None:
        return self._supervisor.candidate_diagnostics

    @property
    def candidate_report(self) -> dict[str, object] | None:
        return self._supervisor.candidate_report

    @property
    def result_report(self) -> dict[str, object] | None:
        return self._supervisor.result_report

    def set_diagnostic_observer(self, observer: Callable[[DiagnosticEvent], None] | None) -> None:
        """Install an optional in-process observer; observer failures are isolated."""
        self._diagnostic_observer = observer

    @staticmethod
    def _worker_exit_status(evidence: ResourceEvidence) -> DiagnosticWorkerExit:
        if evidence.worker_exited is EvidenceStatus.UNCONFIRMED:
            return DiagnosticWorkerExit.UNCONFIRMED
        if evidence.worker_exited is not EvidenceStatus.CONFIRMED:
            return DiagnosticWorkerExit.NOT_OBSERVED
        return (
            DiagnosticWorkerExit.CONFIRMED_ZERO
            if evidence.exit_code == 0
            else DiagnosticWorkerExit.CONFIRMED_NONZERO
        )

    @staticmethod
    def _job_status(evidence: ResourceEvidence) -> DiagnosticJobStatus:
        if evidence.job_observed is EvidenceStatus.UNCONFIRMED:
            return DiagnosticJobStatus.UNCONFIRMED
        if evidence.job_observed is not EvidenceStatus.CONFIRMED:
            return DiagnosticJobStatus.NOT_OBSERVED
        return (
            DiagnosticJobStatus.ZERO_CONFIRMED
            if evidence.job_active_processes == 0
            else DiagnosticJobStatus.NONZERO
        )

    @staticmethod
    def _resource_status(value: EvidenceStatus, *, not_started: bool = False):
        if value is EvidenceStatus.CONFIRMED:
            return DiagnosticResourceStatus.CLOSED_CONFIRMED
        if value is EvidenceStatus.UNCONFIRMED:
            return DiagnosticResourceStatus.UNCONFIRMED
        return (
            DiagnosticResourceStatus.NOT_STARTED
            if not_started
            else DiagnosticResourceStatus.NOT_OBSERVED
        )

    def _build_diagnostic_event(
        self, stage: DiagnosticStage, *, error_code: str | None = None
    ) -> DiagnosticEvent:
        decision = self._supervisor.decision
        evidence = decision.facts.resources
        return DiagnosticEvent(
            stage=stage,
            coordinator_state=self._state.value,
            supervisor_state=decision.lifecycle.state.value,
            error_code=error_code,
            worker_exit=self._worker_exit_status(evidence),
            job_status=self._job_status(evidence),
            ipc_status=self._resource_status(
                evidence.ipc_closed, not_started=not self._transport_start_attempted
            ),
            helper_threads=self._resource_status(evidence.threads_finished),
            parent_resources=self._resource_status(
                evidence.parent_resources_closed, not_started=not self._resources_start_attempted
            ),
            failure_category=self._diagnostic_failure_category,
            worker_exit_reason=self._worker_exit_reason,
        )

    def diagnostic_snapshot(
        self, *, stage: DiagnosticStage, error_code: str | None = None
    ) -> DiagnosticEvent:
        """Return a fresh safe snapshot using the latest resource evidence."""
        return self._build_diagnostic_event(stage, error_code=error_code)

    def _emit_diagnostic(self, stage: DiagnosticStage, *, error_code: str | None = None) -> None:
        observer = self._diagnostic_observer
        event = self._build_diagnostic_event(stage, error_code=error_code)
        if observer is None:
            return
        try:
            observer(event)
        except BaseException:
            pass

    def _record(self, **changes: object) -> SupervisorDecision:
        self._resources = replace(self._resources, **changes)
        return self._supervisor.observe_resources(self._session_id, self._resources)

    def _fail(self) -> SupervisorDecision:
        self._state = CoordinatorState.FAILED
        return self._supervisor.execution_failed(self._session_id)

    def _close_child_copies(self) -> None:
        self._child_copies_attempted = True
        pair = self._owned.pair
        if pair is None:
            raise CoordinationError()
        if pair.close_child_copies() is not True:
            raise CoordinationError()
        self._child_copies_confirmed = True

    def _default_worker_command(self, pair: PipePair, task_mode: WorkerTaskMode) -> tuple[str, ...]:
        worker_args = (
            "--session",
            self._session_id,
            "--read-handle",
            str(pair.child_handles[0]),
            "--write-handle",
            str(pair.child_handles[1]),
            "--mode",
            task_mode.value,
        )
        if self._require_path_snapshot:
            worker_args += ("--require-path-snapshot",)
        if getattr(sys, "frozen", False):
            executable = _lexical_directory(sys.executable)
            if executable is None:
                raise CoordinationError()
            directory = ntpath.dirname(executable)
            if _local_directory_state(directory) is not True:
                raise CoordinationError()
            worker_executable = ntpath.join(directory, "DevEnvDoctorWorker.exe")
            if not _candidate_is_regular_file(executable) or not _candidate_is_regular_file(
                worker_executable
            ):
                raise CoordinationError()
            return (worker_executable, *worker_args)
        return (
            sys.executable,
            "-m",
            "dev_env_doctor.core.scan_worker_entry",
            *worker_args,
        )

    def start(
        self,
        command_line: Sequence[str] | None = None,
        *,
        remaining_timeout_ms: int,
        task_mode: WorkerTaskMode = WorkerTaskMode.FULL_SCAN,
        require_path_snapshot: bool = False,
    ) -> SupervisorDecision:
        """Create, associate, resume and observe the fixed worker process."""
        if self._state is not CoordinatorState.IDLE:
            raise CoordinationError("The scan coordinator has already started.")
        if require_path_snapshot and (
            task_mode is not WorkerTaskMode.FULL_SCAN or command_line is not None
        ):
            raise CoordinationError()
        self._require_path_snapshot = require_path_snapshot
        self._state = CoordinatorState.STARTING
        decision = self._supervisor.begin(self._session_id)
        if decision.lifecycle.stop_reason is not None:
            self._state = CoordinatorState.FAILED
            return decision
        self._resources_start_attempted = True
        self._emit_diagnostic(DiagnosticStage.STARTING_RESOURCES)
        try:
            pair = self._pipe_factory()
            self._owned = replace(self._owned, pair=pair)
            job = self._job_factory()
            self._owned = replace(self._owned, job=job)
            self._transport_start_attempted = True
            transport = self._transport_factory(pair.parent)
            observed = _ObservingTransport(transport)
            self._owned = replace(self._owned, transport=transport, observed_transport=observed)
            worker = self._worker_factory(
                job=job,
                transport=observed,
                child_handles=pair.child_handles,
                close_child_copies=self._close_child_copies,
                session_id=self._session_id,
            )
            self._owned = replace(self._owned, worker=worker)
            self._emit_diagnostic(DiagnosticStage.STARTING_WORKER)
            if getattr(sys, "frozen", False) and command_line is not None:
                raise CoordinationError()
            if command_line is None:
                command_line = self._default_worker_command(pair, task_mode)
            if self._supervisor.tick(self._session_id).stop_required:
                self._cleanup_best_effort()
                return self.decision
            worker_environment = (
                build_worker_environment(include_probe_marker=True)
                if task_mode is WorkerTaskMode.ENVIRONMENT_PROBE
                else build_worker_environment()
            )
            worker.start(
                tuple(command_line),
                remaining_timeout_ms=remaining_timeout_ms,
                environment=worker_environment,
            )
            self._supervisor.process_started(self._session_id)
            decision = self._record(creation_finished=EvidenceStatus.CONFIRMED)
            if decision.lifecycle.stop_reason is not None:
                self._cleanup_best_effort()
                return decision
            return decision
        except ProtocolError:
            self._fail_safely(protocol=True)
            raise
        except BaseException:
            self._fail_safely()
            raise

    def wait_ready(self) -> SupervisorDecision:
        worker = self._owned.worker
        observed = self._owned.observed_transport
        if worker is None or observed is None:
            raise CoordinationError()
        self._emit_diagnostic(DiagnosticStage.WAITING_READY)
        try:
            worker.wait_ready()
            decision = self._supervisor.observe_message(
                self._session_id, observed.take_received(), sender="child"
            )
        except ProtocolError:
            self._fail_safely(protocol=True)
            raise
        except BaseException:
            self._fail_safely()
            raise
        self._state = CoordinatorState.READY if decision.facts.ready else CoordinatorState.FAILED
        return decision

    def send_start(self, *, path_snapshot: str | None = None) -> SupervisorDecision:
        worker = self._owned.worker
        observed = self._owned.observed_transport
        if worker is None or observed is None:
            raise CoordinationError()
        decision = self._supervisor.tick(self._session_id)
        if not decision.start_permitted:
            return self.decision
        self._emit_diagnostic(DiagnosticStage.SENDING_START)
        try:
            if self._require_path_snapshot != (path_snapshot is not None):
                raise ProtocolError()
            worker.send_start(self._supervisor.deadline.expires_at, path_snapshot=path_snapshot)
            decision = self._supervisor.observe_message(
                self._session_id, observed.take_sent(), sender="parent"
            )
        except ProtocolError:
            self._fail_safely(protocol=True)
            raise
        except BaseException:
            self._fail_safely()
            raise
        finally:
            path_snapshot = None
        self._state = (
            CoordinatorState.RUNNING if decision.facts.start_authorized else CoordinatorState.FAILED
        )
        return decision

    def request_stop(self, reason: StopReason) -> SupervisorDecision:
        return self._supervisor.request_stop(self._session_id, reason)

    def send_stop(self, reason: StopReason) -> SupervisorDecision:
        worker = self._owned.worker
        observed = self._owned.observed_transport
        if worker is None or observed is None:
            raise CoordinationError()
        decision = self._supervisor.decision
        if not decision.stop_required:
            return decision
        try:
            worker.send_stop(reason.value)
            decision = self._supervisor.observe_message(
                self._session_id, observed.take_sent(), sender="parent"
            )
        except ProtocolError:
            self._fail_safely(protocol=True)
            raise
        except BaseException:
            self._fail_safely()
            raise
        self._state = CoordinatorState.STOPPING
        return decision

    def receive_stop_observed(self) -> SupervisorDecision:
        worker = self._owned.worker
        observed = self._owned.observed_transport
        if worker is None or observed is None:
            raise CoordinationError()
        try:
            worker.receive_stop_observed()
            decision = self._supervisor.observe_message(
                self._session_id, observed.take_received(), sender="child"
            )
        except BaseException:
            self._fail_safely()
            raise
        return decision

    def receive_worker_message(
        self, *, remaining_timeout_ms: int | None = None
    ) -> SupervisorDecision:
        """Receive a candidate or fixed failure and apply parent validation."""
        worker = self._owned.worker
        observed = self._owned.observed_transport
        if worker is None or observed is None:
            raise CoordinationError()
        self._emit_diagnostic(DiagnosticStage.RECEIVING_WORKER_MESSAGE)
        try:
            message = (
                worker.receive_child_message()
                if remaining_timeout_ms is None
                else worker.receive_child_message(timeout_ms=remaining_timeout_ms)
            )
            decision = self._supervisor.observe_message(
                self._session_id, observed.take_received(), sender="child"
            )
            if message["type"] == "RESULT_CANDIDATE":
                self._emit_diagnostic(DiagnosticStage.VALIDATING_RESULT)
                decision = self._supervisor.observe_report_validation(
                    self._session_id, accepted=True
                )
        except ProtocolError:
            self._diagnostic_failure_category = (
                DiagnosticFailureCategory.WORKER_MESSAGE_PROTOCOL_ERROR
            )
            self._observe_process_after_receive_failure()
            self._fail_safely(protocol=True)
            raise
        except IpcError:
            self._diagnostic_failure_category = (
                DiagnosticFailureCategory.WORKER_MESSAGE_TRANSPORT_ERROR
            )
            self._observe_process_after_receive_failure()
            self._fail_safely()
            raise
        except BaseException:
            self._diagnostic_failure_category = (
                DiagnosticFailureCategory.WORKER_MESSAGE_UNCLASSIFIED_ERROR
            )
            self._observe_process_after_receive_failure()
            self._fail_safely()
            raise
        if message["type"] in {"FAILED", "CLEANUP_UNCONFIRMED"}:
            self._diagnostic_failure_category = DiagnosticFailureCategory.WORKER_FAILED_MESSAGE
        return decision

    def observe_process(self, timeout_ms: int) -> SupervisorDecision:
        job = self._owned.job
        if job is None:
            raise CoordinationError()
        self._emit_diagnostic(DiagnosticStage.OBSERVING_PROCESS_EXIT)
        try:
            observation = job.wait(timeout_ms)
        except BaseException:
            return self._record(worker_exited=EvidenceStatus.UNCONFIRMED, exit_code=None)
        if not isinstance(observation, WaitObservation):
            return self._record(worker_exited=EvidenceStatus.UNCONFIRMED, exit_code=None)
        if observation.state.value == "process_exited" and observation.exit_code is not None:
            self._worker_exit_reason = self._worker_exit_reason_for_code(observation.exit_code)
            return self._record(
                worker_exited=EvidenceStatus.CONFIRMED,
                exit_code=observation.exit_code,
            )
        if observation.failed:
            return self._record(worker_exited=EvidenceStatus.UNCONFIRMED, exit_code=None)
        return self.decision

    @staticmethod
    def _worker_exit_reason_for_code(code: int) -> DiagnosticWorkerExitReason:
        return {
            0: DiagnosticWorkerExitReason.CANDIDATE_SEND_RETURNED,
            1: DiagnosticWorkerExitReason.SCAN_FAILED,
            2: DiagnosticWorkerExitReason.CANDIDATE_BUILD_FAILED,
            3: DiagnosticWorkerExitReason.CANDIDATE_SEND_FAILED,
            4: DiagnosticWorkerExitReason.FAILED_SEND_FAILED,
            5: DiagnosticWorkerExitReason.STARTUP_FAILED,
            6: DiagnosticWorkerExitReason.FAILED_SEND_RETURNED,
        }.get(code, DiagnosticWorkerExitReason.UNKNOWN)

    def _observe_process_after_receive_failure(self) -> None:
        self._worker_exit_reason = DiagnosticWorkerExitReason.UNKNOWN
        try:
            self.observe_process(0)
        except BaseException:
            pass

    def observe_job(self) -> SupervisorDecision:
        job = self._owned.job
        if job is None:
            raise CoordinationError()
        self._emit_diagnostic(DiagnosticStage.OBSERVING_JOB)
        try:
            snapshot = job.observe_job_empty()
        except BaseException:
            return self._record(job_observed=EvidenceStatus.UNCONFIRMED)
        if not isinstance(snapshot, JobSnapshot) or snapshot.job_active_processes is None:
            return self._record(job_observed=EvidenceStatus.UNCONFIRMED)
        return self._record(
            job_observed=EvidenceStatus.CONFIRMED,
            job_active_processes=snapshot.job_active_processes,
        )

    def close_ipc(self) -> SupervisorDecision:
        transport = self._owned.observed_transport
        if transport is None:
            raise CoordinationError()
        self._emit_diagnostic(DiagnosticStage.CLOSING_IPC)
        try:
            state = transport.close()
        except BaseException:
            state = IpcState.UNCONFIRMED
        if state is IpcState.CLOSED:
            return self._record(
                ipc_closed=EvidenceStatus.CONFIRMED,
                threads_finished=EvidenceStatus.CONFIRMED,
            )
        return self._record(
            ipc_closed=EvidenceStatus.UNCONFIRMED,
            threads_finished=EvidenceStatus.UNCONFIRMED,
        )

    def close_resources(self) -> SupervisorDecision:
        """Attempt final owned-resource closure without claiming success."""
        self._emit_diagnostic(DiagnosticStage.FINALIZING)
        worker = self._owned.worker
        if worker is None:
            self._cleanup_best_effort()
            return self.decision
        try:
            worker.close()
        except BaseException:
            self._state = CoordinatorState.FAILED
        job = self._owned.job
        snapshot = job.snapshot if job is not None else None
        transport = self._owned.observed_transport
        transport_state = transport.state if transport is not None else IpcState.UNCONFIRMED
        ipc_confirmed = transport_state is IpcState.CLOSED
        job_confirmed = (
            isinstance(snapshot, JobSnapshot) and snapshot.cleanup is CleanupObservation.CONFIRMED
        )
        parent_confirmed = self._child_copies_confirmed and ipc_confirmed and job_confirmed
        decision = self._record(
            ipc_closed=EvidenceStatus.CONFIRMED if ipc_confirmed else EvidenceStatus.UNCONFIRMED,
            threads_finished=EvidenceStatus.CONFIRMED
            if ipc_confirmed
            else EvidenceStatus.UNCONFIRMED,
            parent_resources_closed=(
                EvidenceStatus.CONFIRMED if parent_confirmed else EvidenceStatus.UNCONFIRMED
            ),
        )
        if (
            worker.state is WorkerState.CLOSED
            and self._resources.parent_resources_closed is EvidenceStatus.CONFIRMED
        ):
            self._state = CoordinatorState.CLOSED
        else:
            self._state = CoordinatorState.FAILED
        return decision

    def _cleanup_best_effort(self) -> None:
        worker = self._owned.worker
        if worker is not None:
            try:
                worker.close()
            except BaseException:
                pass
            return
        transport = self._owned.observed_transport
        if transport is not None:
            try:
                transport.close()
            except BaseException:
                pass
        job = self._owned.job
        if job is not None:
            try:
                job.close()
            except BaseException:
                pass

    def _fail_safely(self, *, protocol: bool = False) -> None:
        try:
            if protocol:
                self._supervisor.protocol_failed(self._session_id)
                self._state = CoordinatorState.FAILED
            else:
                self._fail()
        except BaseException:
            self._state = CoordinatorState.FAILED
        self._cleanup_best_effort()
