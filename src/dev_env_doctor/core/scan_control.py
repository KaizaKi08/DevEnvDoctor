"""Pure lifecycle and monotonic deadline values; no scanning or process control."""

import math
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from time import monotonic


class ScanCleanupUnconfirmedError(RuntimeError):
    """Abort scanning without carrying process details or claiming cleanup."""

    def __init__(self) -> None:
        super().__init__("Scan cleanup could not be confirmed.")


class ScanLifecycleState(StrEnum):
    """Session states, separate from individual diagnostic result statuses."""

    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    FINALIZING = "finalizing"
    STOPPING = "stopping"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    STOPPED = "stopped"
    STOP_UNCONFIRMED = "stop_unconfirmed"


class StopReason(StrEnum):
    """Fixed causes of a stop request; a cause does not prove work has ended."""

    USER_REQUEST = "user_request"
    WINDOW_CLOSE = "window_close"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    FAILURE = "failure"


class CleanupStatus(StrEnum):
    """Declared cleanup knowledge, never inferred from a termination request."""

    PENDING = "pending"
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"


_TERMINAL_STATES = frozenset(
    {
        ScanLifecycleState.SUCCEEDED,
        ScanLifecycleState.FAILED,
        ScanLifecycleState.TIMED_OUT,
        ScanLifecycleState.STOPPED,
    }
)
_STOP_STATES = frozenset(
    {
        ScanLifecycleState.STOPPING,
        ScanLifecycleState.STOP_UNCONFIRMED,
        ScanLifecycleState.STOPPED,
        ScanLifecycleState.TIMED_OUT,
    }
)
_TRANSITIONS = {
    ScanLifecycleState.IDLE: frozenset({ScanLifecycleState.STARTING}),
    ScanLifecycleState.STARTING: frozenset(
        {ScanLifecycleState.RUNNING, ScanLifecycleState.STOPPING, ScanLifecycleState.FAILED}
    ),
    ScanLifecycleState.RUNNING: frozenset(
        {ScanLifecycleState.FINALIZING, ScanLifecycleState.STOPPING, ScanLifecycleState.FAILED}
    ),
    ScanLifecycleState.FINALIZING: frozenset(
        {ScanLifecycleState.SUCCEEDED, ScanLifecycleState.STOPPING, ScanLifecycleState.FAILED}
    ),
    ScanLifecycleState.STOPPING: frozenset(
        {
            ScanLifecycleState.STOPPED,
            ScanLifecycleState.TIMED_OUT,
            ScanLifecycleState.FAILED,
            ScanLifecycleState.STOP_UNCONFIRMED,
        }
    ),
    ScanLifecycleState.STOP_UNCONFIRMED: frozenset(
        {
            ScanLifecycleState.STOPPING,
            ScanLifecycleState.STOPPED,
            ScanLifecycleState.TIMED_OUT,
            ScanLifecycleState.FAILED,
        }
    ),
    **{state: frozenset() for state in _TERMINAL_STATES},
}


@dataclass(frozen=True, slots=True)
class ScanLifecycle:
    """Immutable lifecycle snapshot; defaults represent a new, idle session.

    ``transition`` checks both the graph and cleanup/reason consistency. Explicit
    snapshots are also validated, but this value cannot verify operating-system
    cleanup evidence. The future process owner must supply that evidence and
    validate its candidate report before requesting SUCCEEDED.
    """

    state: ScanLifecycleState = ScanLifecycleState.IDLE
    stop_reason: StopReason | None = None
    cleanup_status: CleanupStatus = CleanupStatus.PENDING

    def __post_init__(self) -> None:
        if not isinstance(self.state, ScanLifecycleState):
            raise TypeError("state must be a ScanLifecycleState.")
        if not isinstance(self.cleanup_status, CleanupStatus):
            raise TypeError("cleanup_status must be a CleanupStatus.")
        if self.stop_reason is not None and not isinstance(self.stop_reason, StopReason):
            raise TypeError("stop_reason must be a StopReason or None.")

        if self.state in _TERMINAL_STATES:
            if self.cleanup_status is not CleanupStatus.CONFIRMED:
                raise ValueError("A terminal state requires confirmed cleanup.")
        elif self.state is ScanLifecycleState.STOP_UNCONFIRMED:
            if self.cleanup_status is not CleanupStatus.UNCONFIRMED:
                raise ValueError("STOP_UNCONFIRMED requires unconfirmed cleanup.")
        elif self.state is ScanLifecycleState.FINALIZING:
            if self.cleanup_status is CleanupStatus.UNCONFIRMED:
                raise ValueError("Unconfirmed cleanup requires the stop handling path.")
        elif self.state is not ScanLifecycleState.STOPPING:
            if self.cleanup_status is not CleanupStatus.PENDING:
                raise ValueError("An active or idle session requires pending cleanup.")

        if self.state in _STOP_STATES:
            if self.stop_reason is None:
                raise ValueError("A stop reason is required for stop handling.")
            if self.state is ScanLifecycleState.TIMED_OUT:
                if self.stop_reason is not StopReason.DEADLINE_EXCEEDED:
                    raise ValueError("TIMED_OUT requires the deadline stop reason.")
            elif self.state is ScanLifecycleState.STOPPED:
                if self.stop_reason not in {StopReason.USER_REQUEST, StopReason.WINDOW_CLOSE}:
                    raise ValueError("STOPPED requires a user or window-close stop reason.")
        elif self.state is ScanLifecycleState.FAILED:
            if self.stop_reason not in {None, StopReason.FAILURE}:
                raise ValueError("FAILED cannot replace a user or deadline stop reason.")
        elif self.stop_reason is not None:
            raise ValueError("This lifecycle state cannot have a stop reason.")

    @property
    def is_terminal(self) -> bool:
        """Whether the session is ended; STOP_UNCONFIRMED is deliberately not ended."""
        return self.state in _TERMINAL_STATES

    def transition(
        self,
        target: ScanLifecycleState,
        *,
        stop_reason: StopReason | None = None,
        cleanup_status: CleanupStatus | None = None,
    ) -> "ScanLifecycle":
        """Return a checked new snapshot without altering this one.

        Omitted values preserve existing knowledge. The first stop reason is
        retained; unconfirmed or confirmed cleanup cannot be reset to pending.
        Self-transitions and transitions out of a terminal state are rejected.
        """
        if not isinstance(target, ScanLifecycleState):
            raise TypeError("target must be a ScanLifecycleState.")
        if target not in _TRANSITIONS[self.state]:
            raise ValueError("Illegal lifecycle transition.")
        if stop_reason is not None and not isinstance(stop_reason, StopReason):
            raise TypeError("stop_reason must be a StopReason or None.")
        if cleanup_status is not None and not isinstance(cleanup_status, CleanupStatus):
            raise TypeError("cleanup_status must be a CleanupStatus or None.")
        reason = self.stop_reason if stop_reason is None else stop_reason
        cleanup = self.cleanup_status if cleanup_status is None else cleanup_status
        if self.stop_reason is not None and reason is not self.stop_reason:
            raise ValueError("The established stop reason cannot be changed.")
        if self.cleanup_status is CleanupStatus.CONFIRMED:
            if cleanup is not CleanupStatus.CONFIRMED:
                raise ValueError("Confirmed cleanup cannot be reset.")
        elif self.cleanup_status is CleanupStatus.UNCONFIRMED:
            if cleanup is CleanupStatus.PENDING:
                raise ValueError("Unconfirmed cleanup cannot be reset to pending.")
        return ScanLifecycle(state=target, stop_reason=reason, cleanup_status=cleanup)


def _finite_seconds(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("Time values must be numeric seconds.")
    try:
        result = float(value)
    except OverflowError:
        raise ValueError("Time values must be finite.") from None
    if not math.isfinite(result):
        raise ValueError("Time values must be finite.")
    return result


def _exact_seconds(value: object) -> float:
    """Validate numeric seconds, rejecting lossy integer-to-float conversion."""
    result = _finite_seconds(value)
    if isinstance(value, int) and int(result) != value:
        raise ValueError("Integer time values must be represented exactly.")
    return result


class ScanDeadline:
    """A monotonic deadline, not a mechanism for interrupting blocked operations.

    Supply a monotonic ``clock`` for deterministic tests. Budgets must be finite,
    positive numbers with lossless integer conversion; expiry must remain
    representable. Clock errors propagate
    rather than being reported as a successful timeout or cleanup operation.
    """

    __slots__ = ("_clock", "_expires_at", "_started_at")

    def __init__(self, budget_seconds: float, *, clock: Callable[[], float] | None = None) -> None:
        budget = _exact_seconds(budget_seconds)
        if budget <= 0:
            raise ValueError("The deadline budget must be positive.")
        selected_clock = monotonic if clock is None else clock
        if not callable(selected_clock):
            raise TypeError("clock must be callable.")
        started_at = _finite_seconds(selected_clock())
        expires_at = started_at + budget
        if not math.isfinite(expires_at) or expires_at <= started_at:
            raise ValueError("The deadline budget cannot be represented by this clock.")
        self._clock = selected_clock
        self._started_at = started_at
        self._expires_at = expires_at

    @classmethod
    def from_expires_at(
        cls, expires_at: float, *, clock: Callable[[], float] | None = None
    ) -> "ScanDeadline":
        """View an existing monotonic cutoff, including one already reached.

        No new budget is allocated. The clock must share the cutoff's domain;
        this value neither requests stopping nor proves resource cleanup.
        """
        expiry = _exact_seconds(expires_at)
        selected_clock = monotonic if clock is None else clock
        if not callable(selected_clock):
            raise TypeError("clock must be callable.")
        now = _finite_seconds(selected_clock())
        if expiry > now and not math.isfinite(expiry - now):
            raise ValueError("Remaining time cannot be represented by this clock.")
        view = cls.__new__(cls)
        view._clock = selected_clock
        view._started_at = now
        view._expires_at = expiry
        return view

    @property
    def expires_at(self) -> float:
        """Expiry in the injected monotonic clock's domain, not wall-clock time."""
        return self._expires_at

    def remaining_seconds(self) -> float:
        """Return nonnegative remaining seconds using a fresh clock reading."""
        now = _finite_seconds(self._clock())
        if now < self._started_at:
            raise ValueError("The clock reading precedes deadline creation.")
        return max(0.0, self._expires_at - now)

    def is_expired(self) -> bool:
        """Whether the deadline is reached; does not request or confirm stopping."""
        return self.remaining_seconds() == 0.0


@dataclass(frozen=True, slots=True)
class StopDecision:
    """A lifecycle decision and independent intent to close the window."""

    lifecycle: ScanLifecycle
    close_pending: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.lifecycle, ScanLifecycle) or type(self.close_pending) is not bool:
            raise TypeError("A stop decision requires a lifecycle and boolean close intent.")


def decide_stop(
    lifecycle: ScanLifecycle,
    deadline: ScanDeadline,
    *,
    request: StopReason | None = None,
    close_pending: bool = False,
) -> StopDecision:
    """Arbitrate one current-session event without changing cleanup knowledge.

    Terminal sessions and established reasons are never rewritten. Otherwise
    an explicit FAILURE wins, then expiry wins over user/close requests; before
    expiry the first explicit request wins. An early deadline notification is
    only a hint, never evidence of expiry. Session identity belongs to the
    protocol caller. No resources
    are stopped here, and the original deadline is never replaced or extended.
    """
    if not isinstance(lifecycle, ScanLifecycle) or not isinstance(deadline, ScanDeadline):
        raise TypeError("Stop arbitration requires a lifecycle and deadline.")
    if request is not None and not isinstance(request, StopReason):
        raise TypeError("request must be a StopReason or None.")
    if type(close_pending) is not bool:
        raise TypeError("close_pending must be a boolean.")
    close_pending = close_pending or request is StopReason.WINDOW_CLOSE
    if lifecycle.is_terminal or lifecycle.stop_reason is not None:
        return StopDecision(lifecycle, close_pending)
    if lifecycle.state is ScanLifecycleState.IDLE:
        if request is not None:
            raise ValueError("An idle session has no work to stop.")
        return StopDecision(lifecycle, close_pending)
    if request is StopReason.FAILURE:
        reason = StopReason.FAILURE
    elif deadline.is_expired():
        reason = StopReason.DEADLINE_EXCEEDED
    else:
        reason = None if request is StopReason.DEADLINE_EXCEEDED else request
    if reason is None:
        return StopDecision(lifecycle, close_pending)
    return StopDecision(
        lifecycle.transition(ScanLifecycleState.STOPPING, stop_reason=reason), close_pending
    )
