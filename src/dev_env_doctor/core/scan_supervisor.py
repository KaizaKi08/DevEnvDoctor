"""Single-owner, pure supervision decisions; never perform resource operations.

Adapters record both sent and received messages with ``observe_message``. This
delegates validation, sequencing, phases and accounting to ProtocolSession; the
supervisor does not parse frames or implement another protocol state machine.
Resource observations and parent report approval are attestations supplied by
the future resource owner, not proof obtained by this module from the OS.
"""

from copy import deepcopy
from dataclasses import dataclass, field, replace
from enum import StrEnum

from dev_env_doctor.core.scan_control import (
    CleanupStatus,
    ScanDeadline,
    ScanLifecycle,
    ScanLifecycleState,
    StopReason,
    decide_stop,
)
from dev_env_doctor.core.scan_protocol import (
    MessageType,
    ProtocolError,
    ProtocolSession,
)


class EvidenceStatus(StrEnum):
    """Unknown, outstanding, positively confirmed, or explicitly unconfirmed."""

    UNKNOWN = "unknown"
    PENDING = "pending"
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"


@dataclass(frozen=True, slots=True)
class ResourceEvidence:
    """Latest owner observations, not termination requests or wait attempts.

    ``worker_absent`` is positive evidence that creation settled without a child;
    it permits failed startup cleanup without inventing a process exit. A Job
    count of zero is insufficient while creation remains outstanding. An IPC
    confirmation includes drained/validated input and completed cancellation,
    not just sending a close request. Thread confirmation covers all managed
    supervisor helpers, supplied after their termination by an external owner.
    """

    creation_finished: EvidenceStatus = EvidenceStatus.UNKNOWN
    worker_exited: EvidenceStatus = EvidenceStatus.UNKNOWN
    exit_code: int | None = None
    worker_absent: bool = False
    job_observed: EvidenceStatus = EvidenceStatus.UNKNOWN
    job_active_processes: int | None = None
    ipc_closed: EvidenceStatus = EvidenceStatus.UNKNOWN
    parent_resources_closed: EvidenceStatus = EvidenceStatus.UNKNOWN
    threads_finished: EvidenceStatus = EvidenceStatus.UNKNOWN

    def __post_init__(self) -> None:
        for value in (
            self.creation_finished,
            self.worker_exited,
            self.job_observed,
            self.ipc_closed,
            self.parent_resources_closed,
            self.threads_finished,
        ):
            if not isinstance(value, EvidenceStatus):
                raise TypeError("Resource observations require evidence statuses.")
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise TypeError("An exit code must be an integer or unknown.")
        if self.exit_code is not None and self.worker_exited is not EvidenceStatus.CONFIRMED:
            raise ValueError("An exit code requires observed process exit.")
        if type(self.worker_absent) is not bool:
            raise TypeError("Worker absence must be boolean evidence.")
        if self.worker_absent and (
            self.creation_finished is not EvidenceStatus.CONFIRMED
            or self.worker_exited is not EvidenceStatus.UNKNOWN
            or self.exit_code is not None
        ):
            raise ValueError("Worker absence requires settled creation and no claimed exit.")
        count = self.job_active_processes
        if count is not None and (type(count) is not int or count < 0):
            raise ValueError("A Job count must be a nonnegative integer or unknown.")

    @property
    def has_unconfirmed_observation(self) -> bool:
        """Whether an owner explicitly failed to confirm a managed resource."""
        return EvidenceStatus.UNCONFIRMED in (
            self.creation_finished,
            self.worker_exited,
            self.job_observed,
            self.ipc_closed,
            self.parent_resources_closed,
            self.threads_finished,
        )


@dataclass(frozen=True, slots=True)
class SupervisorFacts:
    """Independent facts; candidate arrival and cleanup are deliberately separate."""

    worker_started: EvidenceStatus = EvidenceStatus.UNKNOWN
    ready: bool = False
    start_authorized: bool = False
    candidate_count: int = 0
    stop_sent: bool = False
    stop_intent: StopReason | None = None
    stop_observed: bool = False
    report_validation: EvidenceStatus = EvidenceStatus.UNKNOWN
    protocol_error: bool = False
    execution_failed: bool = False
    resources: ResourceEvidence = field(default_factory=ResourceEvidence)


@dataclass(frozen=True, slots=True)
class SupervisorDecision:
    """Snapshot for an adapter; requests do not assert that work has stopped."""

    session_id: str
    lifecycle: ScanLifecycle
    facts: SupervisorFacts
    close_pending: bool
    start_permitted: bool
    stop_required: bool
    cleanup_required: bool
    result_available: bool


class ScanSupervisor:
    """Coordinate one session using a fixed deadline and existing state rules.

    Call serially from one owner. Wrong-session events are ignored before they
    can affect facts or read the current clock. No report is exposed as a result
    before final success. Returned candidate/result data are detached copies.
    """

    def __init__(self, session_id: str, deadline: ScanDeadline) -> None:
        self._protocol = ProtocolSession(session_id)
        if not isinstance(deadline, ScanDeadline):
            raise TypeError("Supervision requires a scan deadline.")
        self._session_id = session_id
        self._deadline = deadline
        self._lifecycle = ScanLifecycle()
        self._facts = SupervisorFacts()
        self._close_pending = False
        self._cleanup_uncertain = False
        self._candidate: list[dict[str, object]] | None = None
        self._candidate_report: dict[str, object] | None = None

    @property
    def deadline(self) -> ScanDeadline:
        """The original deadline object; this supervisor never replaces it."""
        return self._deadline

    @property
    def decision(self) -> SupervisorDecision:
        """Return the last adjudicated snapshot; use tick to observe new time."""
        active = not self._lifecycle.is_terminal and self._lifecycle.state is not (
            ScanLifecycleState.IDLE
        )
        stopping = (
            self._lifecycle.stop_reason is not None or self._facts.stop_intent is not None
        ) and active
        return SupervisorDecision(
            session_id=self._session_id,
            lifecycle=self._lifecycle,
            facts=self._facts,
            close_pending=self._close_pending,
            start_permitted=(
                self._lifecycle.state is ScanLifecycleState.STARTING
                and self._facts.ready
                and self._facts.worker_started is EvidenceStatus.CONFIRMED
                and self._facts.resources.creation_finished is EvidenceStatus.CONFIRMED
                and not self._facts.protocol_error
                and not self._facts.execution_failed
                and self._facts.stop_intent is None
                and not self._facts.stop_sent
            ),
            stop_required=(
                stopping
                and self._protocol.phase != "finished"
                and not self._facts.protocol_error
                and not self._facts.stop_sent
            ),
            cleanup_required=stopping,
            result_available=self._lifecycle.state is ScanLifecycleState.SUCCEEDED,
        )

    @property
    def candidate_diagnostics(self) -> list[dict[str, object]] | None:
        """Reviewed candidate for parent validation, never a completion signal."""
        return deepcopy(self._candidate)

    @property
    def candidate_report(self) -> dict[str, object] | None:
        """Return the validated, detached full candidate report."""
        return deepcopy(self._candidate_report)

    @property
    def result(self) -> list[dict[str, object]] | None:
        """Return only the minimized diagnostics after confirmed final success."""
        return deepcopy(self._candidate) if self.decision.result_available else None

    @property
    def result_report(self) -> dict[str, object] | None:
        """Return the full candidate report only after formal success."""
        return deepcopy(self._candidate_report) if self.decision.result_available else None

    def _current(self, session_id: str) -> bool:
        if type(session_id) is not str:
            raise TypeError("An event requires a session identifier.")
        return session_id == self._session_id

    def _active(self, session_id: str) -> bool:
        if not self._current(session_id) or self._lifecycle.is_terminal:
            return False
        if self._lifecycle.state is ScanLifecycleState.IDLE:
            raise ValueError("Begin the session before recording events.")
        return True

    def begin(self, session_id: str) -> SupervisorDecision:
        """Begin exactly once; an expired initial deadline cannot authorize work."""
        if not self._current(session_id):
            return self.decision
        self._lifecycle = self._lifecycle.transition(ScanLifecycleState.STARTING)
        return self._adjudicate()

    def process_started(self, session_id: str) -> SupervisorDecision:
        """Record positive process-start evidence, independent of READY."""
        if self._active(session_id):
            if self._facts.resources.worker_absent:
                return self.protocol_failed(session_id)
            self._facts = replace(self._facts, worker_started=EvidenceStatus.CONFIRMED)
            return self._adjudicate()
        return self.decision

    def observe_message(self, session_id: str, frame: bytes, *, sender: str) -> SupervisorDecision:
        """Delegate a complete routed frame to the existing protocol validator.

        Both directions are recorded exactly once. No frame is parsed here:
        only the sanitized message returned by ProtocolSession is interpreted.
        Original frame lengths, including whitespace, count toward its budget.
        Rejection permanently forbids success; raw frames and protocol exception
        details are never retained. There is no transport or I/O in this method.
        """
        if not self._active(session_id) or self._facts.protocol_error:
            return self.decision
        try:
            safe = self._protocol.accept_frame(frame, sender=sender)
        except ProtocolError:
            return self.protocol_failed(session_id)
        kind = MessageType(safe["type"])
        if kind is MessageType.READY:
            if self._facts.worker_started is not EvidenceStatus.CONFIRMED:
                return self.protocol_failed(session_id)
            self._facts = replace(self._facts, ready=True)
        elif kind is MessageType.START:
            if safe["payload"]["deadline"] != self._deadline.expires_at:
                return self.protocol_failed(session_id)
            self._adjudicate()
            if self._lifecycle.stop_reason is not None:
                return self.decision
            if not self.decision.start_permitted:
                return self.protocol_failed(session_id)
            self._facts = replace(self._facts, start_authorized=True)
            self._lifecycle = self._lifecycle.transition(ScanLifecycleState.RUNNING)
        elif kind is MessageType.STOP:
            self._facts = replace(self._facts, stop_sent=True)
            reason = StopReason(safe["payload"]["reason"])
            self._remember_stop_intent(reason)
            self._adjudicate(request=reason)
            if self._lifecycle.stop_reason is not reason:
                return self.protocol_failed(session_id)
        elif kind is MessageType.RESULT_CANDIDATE:
            if self._lifecycle.state is not ScanLifecycleState.RUNNING:
                return self.protocol_failed(session_id)
            report = safe["payload"]["report"]
            self._candidate_report = deepcopy(report)
            self._candidate = deepcopy(report["diagnostics"])
            self._facts = replace(self._facts, candidate_count=1)
            self._lifecycle = self._lifecycle.transition(ScanLifecycleState.FINALIZING)
        elif kind is MessageType.STOP_OBSERVED:
            self._facts = replace(self._facts, stop_observed=True)
        elif kind is MessageType.FAILED:
            return self.execution_failed(session_id)
        elif kind is MessageType.CLEANUP_UNCONFIRMED:
            return self.cleanup_unconfirmed(session_id)
        return self._adjudicate()

    def observe_resources(self, session_id: str, evidence: ResourceEvidence) -> SupervisorDecision:
        """Replace observations; only a complete fresh attestation resolves doubt."""
        if not self._active(session_id):
            return self.decision
        if type(evidence) is not ResourceEvidence:
            raise TypeError("Resource events require validated resource evidence.")
        if evidence.worker_absent and self._facts.worker_started is EvidenceStatus.CONFIRMED:
            return self.protocol_failed(session_id)
        self._facts = replace(self._facts, resources=evidence)
        if self._cleanup_complete():
            self._cleanup_uncertain = False
        if evidence.has_unconfirmed_observation:
            return self.cleanup_unconfirmed(session_id)
        if evidence.worker_absent or (
            evidence.worker_exited is EvidenceStatus.CONFIRMED
            and (
                evidence.exit_code is not None
                and evidence.exit_code != 0
                or evidence.ipc_closed is EvidenceStatus.CONFIRMED
                and self._facts.candidate_count == 0
            )
        ):
            return self.execution_failed(session_id)
        return self._adjudicate()

    def observe_report_validation(self, session_id: str, *, accepted: bool) -> SupervisorDecision:
        """Record parent safety validation of this session's detached candidate.

        The future adapter must actually run the existing report safety boundary
        before attesting success. Approval without a candidate is an error;
        failure is sticky even if a later event claims successful validation.
        """
        if not self._active(session_id):
            return self.decision
        if type(accepted) is not bool:
            raise TypeError("Report approval must be boolean evidence.")
        if self._candidate is None:
            return self.protocol_failed(session_id)
        status = (
            EvidenceStatus.CONFIRMED
            if accepted and self._facts.report_validation is not EvidenceStatus.UNCONFIRMED
            else EvidenceStatus.UNCONFIRMED
        )
        self._facts = replace(self._facts, report_validation=status)
        return self._adjudicate() if accepted else self.execution_failed(session_id)

    def request_stop(self, session_id: str, reason: StopReason) -> SupervisorDecision:
        """Arbitrate intent without claiming that a STOP was sent or observed."""
        if not self._current(session_id):
            return self.decision
        if self._lifecycle.is_terminal:
            return self._adjudicate(request=reason)
        self._active(session_id)
        return self._adjudicate(request=reason)

    def tick(self, session_id: str) -> SupervisorDecision:
        """Check actual monotonic time; notifications never establish expiry."""
        return self._adjudicate() if self._active(session_id) else self.decision

    def execution_failed(self, session_id: str) -> SupervisorDecision:
        """Record a fixed failure fact, never arbitrary exception text."""
        if self._active(session_id):
            self._facts = replace(self._facts, execution_failed=True)
            return self._adjudicate(request=StopReason.FAILURE)
        return self.decision

    def protocol_failed(self, session_id: str) -> SupervisorDecision:
        """Latch a protocol/adapter validation error; the session cannot recover."""
        if self._active(session_id):
            self._facts = replace(self._facts, protocol_error=True)
            return self._adjudicate(request=StopReason.FAILURE)
        return self.decision

    def cleanup_unconfirmed(self, session_id: str) -> SupervisorDecision:
        """Record missing cleanup proof, retaining any established stop cause."""
        if self._active(session_id):
            self._cleanup_uncertain = True
            self._facts = replace(self._facts, execution_failed=True)
            return self._adjudicate(request=StopReason.FAILURE)
        return self.decision

    def _cleanup_complete(self) -> bool:
        evidence = self._facts.resources
        return (
            evidence.creation_finished is EvidenceStatus.CONFIRMED
            and (evidence.worker_exited is EvidenceStatus.CONFIRMED or evidence.worker_absent)
            and evidence.job_observed is EvidenceStatus.CONFIRMED
            and evidence.job_active_processes == 0
            and evidence.ipc_closed is EvidenceStatus.CONFIRMED
            and evidence.parent_resources_closed is EvidenceStatus.CONFIRMED
            and evidence.threads_finished is EvidenceStatus.CONFIRMED
        )

    def _success_conditions_met(self) -> bool:
        """One centralized completion predicate; no individual fact is sufficient."""
        return (
            self._lifecycle.state is ScanLifecycleState.FINALIZING
            and self._facts.worker_started is EvidenceStatus.CONFIRMED
            and self._facts.ready
            and self._facts.start_authorized
            and self._facts.candidate_count == 1
            and self._candidate is not None
            and self._lifecycle.stop_reason is None
            and self._facts.stop_intent is None
            and not self._facts.stop_sent
            and not self._facts.protocol_error
            and not self._facts.execution_failed
            and not self._protocol.failed
            and self._protocol.phase == "candidate"
            and self._facts.resources.worker_exited is EvidenceStatus.CONFIRMED
            and self._facts.resources.exit_code == 0
            and not self._facts.resources.worker_absent
            and self._cleanup_complete()
            and not self._cleanup_uncertain
            and self._facts.report_validation is EvidenceStatus.CONFIRMED
            and not self._deadline.is_expired()
        )

    def _remember_stop_intent(self, reason: StopReason) -> None:
        """Persist intent before fallible arbitration, without asserting cleanup.

        This is the first request, not a replacement for the effective lifecycle
        cause: decide_stop still applies failure/expiry priority. Keep the intent
        even after successful arbitration so no later event can reopen success.
        """
        if reason is StopReason.WINDOW_CLOSE:
            self._close_pending = True
        if not self._lifecycle.is_terminal and self._facts.stop_intent is None:
            self._facts = replace(self._facts, stop_intent=reason)

    def _adjudicate(self, *, request: StopReason | None = None) -> SupervisorDecision:
        if request is not None and not isinstance(request, StopReason):
            raise TypeError("request must be a StopReason or None.")
        if request in {StopReason.USER_REQUEST, StopReason.WINDOW_CLOSE, StopReason.FAILURE}:
            self._remember_stop_intent(request)
        # Resume an interrupted request on ordinary events. An explicit observed
        # failure still has the priority defined by decide_stop; an early timeout
        # notification alone is not latched as a real stop intent.
        if request is not StopReason.FAILURE and self._facts.stop_intent is not None:
            request = self._facts.stop_intent
        arbitration = decide_stop(
            self._lifecycle, self._deadline, request=request, close_pending=self._close_pending
        )
        self._lifecycle = arbitration.lifecycle
        self._close_pending = arbitration.close_pending
        if self._lifecycle.stop_reason is not None:
            self._remember_stop_intent(self._lifecycle.stop_reason)
        if self._lifecycle.is_terminal:
            return self.decision
        if self._lifecycle.stop_reason is not None:
            if self._cleanup_complete() and not self._cleanup_uncertain:
                reason = self._lifecycle.stop_reason
                target = (
                    ScanLifecycleState.TIMED_OUT
                    if reason is StopReason.DEADLINE_EXCEEDED
                    else ScanLifecycleState.FAILED
                    if reason is StopReason.FAILURE
                    else ScanLifecycleState.STOPPED
                )
                self._lifecycle = self._lifecycle.transition(
                    target, cleanup_status=CleanupStatus.CONFIRMED
                )
            elif self._cleanup_uncertain and self._lifecycle.state is ScanLifecycleState.STOPPING:
                self._lifecycle = self._lifecycle.transition(
                    ScanLifecycleState.STOP_UNCONFIRMED, cleanup_status=CleanupStatus.UNCONFIRMED
                )
        elif self._success_conditions_met():
            self._lifecycle = self._lifecycle.transition(
                ScanLifecycleState.SUCCEEDED, cleanup_status=CleanupStatus.CONFIRMED
            )
        else:
            # A fresh final predicate may observe expiry after the initial
            # arbitration. Resolve it now instead of leaving a stale RUNNING or
            # FINALIZING decision until another external event happens to arrive.
            final_stop = decide_stop(
                self._lifecycle, self._deadline, close_pending=self._close_pending
            )
            if final_stop.lifecycle.stop_reason is not None:
                self._lifecycle = final_stop.lifecycle
                return self._adjudicate()
        return self.decision
