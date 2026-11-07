"""Protocol-only child-session coordination; no runner or diagnostic scan."""

from collections.abc import Callable, Mapping
from enum import StrEnum

from dev_env_doctor.core.scan_ipc import FramedTransport
from dev_env_doctor.core.scan_protocol import PATH_SNAPSHOT_KIND, ProtocolSession, encode_message
from dev_env_doctor.core.windows_job import CleanupObservation, JobSnapshot


class WorkerState(StrEnum):
    IDLE = "idle"
    WAITING_READY = "waiting_ready"
    READY = "ready"
    RUNNING = "running"
    STOPPING = "stopping"
    FAILED = "failed"
    CLOSED = "closed"


class WorkerSession:
    """Own one transport and Job adapter while performing protocol handshake.

    The session deliberately has no runner callback and cannot produce a
    diagnostic result in this phase. A future process entry point will call the
    same protocol operations after START is accepted.
    """

    def __init__(
        self,
        *,
        job: object,
        transport: FramedTransport,
        child_handle: int | None = None,
        child_handles: tuple[int, int] | None = None,
        close_child_copies: Callable[[], None] | None = None,
        session_id: str = "a" * 32,
    ) -> None:
        self._job = job
        self._transport = transport
        self._child_handle = child_handle
        self._child_handles = child_handles
        self._close_child_copies = close_child_copies
        self._session = ProtocolSession(session_id)
        self._session_id = session_id
        self._state = WorkerState.IDLE
        self._parent_sequence = 0
        self._result = None

    @property
    def state(self) -> WorkerState:
        return self._state

    @property
    def result(self):
        return self._result

    def start(
        self,
        command_line: tuple[str, ...],
        *,
        remaining_timeout_ms: int,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        if self._state is not WorkerState.IDLE:
            raise ValueError("Worker session has already started.")
        try:
            kwargs = {"environment": environment} if environment is not None else {}
            self._job.start(
                command_line,
                remaining_timeout_ms=remaining_timeout_ms,
                inherited_handles=(
                    self._child_handles
                    if self._child_handles is not None
                    else ()
                    if self._child_handle is None
                    else (self._child_handle,)
                ),
                **kwargs,
            )
            if self._close_child_copies is not None:
                self._close_child_copies()
            self._job.authorize_resume()
        except BaseException:
            self._state = WorkerState.FAILED
            self._cleanup_best_effort()
            raise
        self._state = WorkerState.WAITING_READY

    def wait_ready(self) -> None:
        if self._state is not WorkerState.WAITING_READY:
            raise ValueError("Worker is not waiting for READY.")
        try:
            frame = self._transport.receive()
            self._session.accept_frame(frame, sender="child")
        except Exception:
            self._state = WorkerState.FAILED
            raise
        except BaseException:
            self._state = WorkerState.FAILED
            self._cleanup_best_effort()
            raise
        self._state = WorkerState.READY

    def send_start(self, deadline: float, *, path_snapshot: str | None = None) -> None:
        if self._state is not WorkerState.READY:
            raise ValueError("READY must be accepted before START.")
        payload: dict[str, object] = {"deadline": deadline}
        if path_snapshot is not None:
            payload["diagnostic_input"] = {"kind": PATH_SNAPSHOT_KIND, "value": path_snapshot}
        frame = None
        try:
            frame = encode_message(
                {
                    "version": 1,
                    "session_id": self._session_id,
                    "sequence": self._parent_sequence,
                    "type": "START",
                    "payload": payload,
                }
            )
            self._session.accept_frame(frame, sender="parent")
            self._transport.send(frame)
        except Exception:
            self._state = WorkerState.FAILED
            raise
        except BaseException:
            self._state = WorkerState.FAILED
            self._cleanup_best_effort()
            raise
        finally:
            payload.clear()
            path_snapshot = None
            frame = None
        self._parent_sequence += 1
        self._state = WorkerState.RUNNING

    def send_stop(self, reason: str) -> None:
        if self._state not in {WorkerState.READY, WorkerState.RUNNING}:
            raise ValueError("Worker is not in a stoppable protocol state.")
        message = {
            "version": 1,
            "session_id": self._session_id,
            "sequence": self._parent_sequence,
            "type": "STOP",
            "payload": {"reason": reason},
        }
        frame = encode_message(message)
        self._session.accept_frame(frame, sender="parent")
        try:
            self._transport.send(frame)
        except Exception:
            self._state = WorkerState.FAILED
            raise
        except BaseException:
            self._state = WorkerState.FAILED
            self._cleanup_best_effort()
            raise
        self._parent_sequence += 1
        self._state = WorkerState.STOPPING

    def receive_stop_observed(self) -> None:
        if self._state is not WorkerState.STOPPING:
            raise ValueError("Worker is not stopping.")
        try:
            frame = self._transport.receive()
            self._session.accept_frame(frame, sender="child")
        except Exception:
            self._state = WorkerState.FAILED
            raise
        except BaseException:
            self._state = WorkerState.FAILED
            self._cleanup_best_effort()
            raise

    def receive_child_message(self, timeout_ms: int | None = None) -> dict[str, object]:
        """Receive one running-session child message through the validated protocol."""
        if self._state is not WorkerState.RUNNING:
            raise ValueError("Worker is not running.")
        try:
            frame = (
                self._transport.receive()
                if timeout_ms is None
                else self._transport.receive(timeout_ms=timeout_ms)
            )
            message = self._session.accept_frame(frame, sender="child")
        except Exception:
            self._state = WorkerState.FAILED
            raise
        except BaseException:
            self._state = WorkerState.FAILED
            self._cleanup_best_effort()
            raise
        if message["type"] in {"FAILED", "CLEANUP_UNCONFIRMED"}:
            self._state = WorkerState.FAILED
        return message

    def wait_process(self, timeout_ms: int):
        """Delegate direct-process observation to the owned Job adapter."""
        return self._job.wait(timeout_ms)

    def observe_job_empty(self):
        """Delegate Job active-process observation to the owned adapter."""
        return self._job.observe_job_empty()

    def close(self) -> None:
        first_base: BaseException | None = None
        first_error: Exception | None = None
        transport_state = None
        job_snapshot = None
        try:
            transport_state = self._transport.close()
        except BaseException as error:
            if isinstance(error, Exception):
                first_error = error
            else:
                first_base = error
        try:
            job_snapshot = self._job.close()
        except BaseException as error:
            if isinstance(error, Exception):
                if first_base is None and first_error is None:
                    first_error = error
            elif first_base is None:
                first_base = error
        if first_base is not None:
            self._state = WorkerState.FAILED
            raise first_base
        transport_confirmed = getattr(transport_state, "value", transport_state) == "closed"
        job_confirmed = (
            isinstance(job_snapshot, JobSnapshot)
            and job_snapshot.cleanup is CleanupObservation.CONFIRMED
        )
        if first_error is not None or not (transport_confirmed and job_confirmed):
            self._state = WorkerState.FAILED
            return
        self._state = WorkerState.CLOSED

    def _cleanup_best_effort(self) -> None:
        """Try both owned resources without replacing an active exception."""
        try:
            self._transport.close()
        except BaseException:
            pass
        try:
            self._job.close()
        except BaseException:
            pass
