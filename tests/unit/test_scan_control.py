from dataclasses import FrozenInstanceError
from typing import get_args
from unittest.mock import Mock

import pytest

from dev_env_doctor.core import scan_control
from dev_env_doctor.core.models import DiagnosticResult, ScanReport
from dev_env_doctor.core.scan_control import (
    CleanupStatus,
    ScanDeadline,
    ScanLifecycle,
    ScanLifecycleState,
    StopReason,
)

State = ScanLifecycleState
Reason = StopReason
Cleanup = CleanupStatus
TERMINAL_STATES = (State.SUCCEEDED, State.FAILED, State.TIMED_OUT, State.STOPPED)
STOP_STATES = (State.STOPPING, State.STOP_UNCONFIRMED, State.STOPPED, State.TIMED_OUT)


class ManualClock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        return self.value


def _snapshot(state: State, reason: Reason | None = None) -> ScanLifecycle:
    cleanup = (
        Cleanup.CONFIRMED
        if state in TERMINAL_STATES
        else Cleanup.UNCONFIRMED
        if state is State.STOP_UNCONFIRMED
        else Cleanup.PENDING
    )
    return ScanLifecycle(
        state=state,
        stop_reason=reason if state in STOP_STATES else None,
        cleanup_status=cleanup,
    )


def test_new_lifecycle_is_idle_pending_and_immutable() -> None:
    lifecycle = ScanLifecycle()

    assert lifecycle.state is State.IDLE
    assert lifecycle.stop_reason is None
    assert lifecycle.cleanup_status is Cleanup.PENDING
    assert not lifecycle.is_terminal
    with pytest.raises(FrozenInstanceError):
        lifecycle.state = State.RUNNING


@pytest.mark.parametrize(
    ("source", "target", "reason", "cleanup"),
    [
        (State.IDLE, State.STARTING, None, Cleanup.PENDING),
        (State.STARTING, State.RUNNING, None, Cleanup.PENDING),
        (State.STARTING, State.FAILED, None, Cleanup.CONFIRMED),
        (State.STARTING, State.STOPPING, Reason.USER_REQUEST, Cleanup.PENDING),
        (State.RUNNING, State.FINALIZING, None, Cleanup.PENDING),
        (State.RUNNING, State.FAILED, None, Cleanup.CONFIRMED),
        (State.RUNNING, State.STOPPING, Reason.USER_REQUEST, Cleanup.PENDING),
        (State.FINALIZING, State.SUCCEEDED, None, Cleanup.CONFIRMED),
        (State.FINALIZING, State.FAILED, None, Cleanup.CONFIRMED),
        (State.FINALIZING, State.STOPPING, Reason.WINDOW_CLOSE, Cleanup.PENDING),
        (State.STOPPING, State.STOPPED, Reason.USER_REQUEST, Cleanup.CONFIRMED),
        (State.STOPPING, State.TIMED_OUT, Reason.DEADLINE_EXCEEDED, Cleanup.CONFIRMED),
        (State.STOPPING, State.FAILED, Reason.FAILURE, Cleanup.CONFIRMED),
        (State.STOPPING, State.STOP_UNCONFIRMED, Reason.WINDOW_CLOSE, Cleanup.UNCONFIRMED),
        (State.STOP_UNCONFIRMED, State.STOPPING, Reason.USER_REQUEST, Cleanup.UNCONFIRMED),
        (State.STOP_UNCONFIRMED, State.STOPPED, Reason.WINDOW_CLOSE, Cleanup.CONFIRMED),
        (State.STOP_UNCONFIRMED, State.TIMED_OUT, Reason.DEADLINE_EXCEEDED, Cleanup.CONFIRMED),
        (State.STOP_UNCONFIRMED, State.FAILED, Reason.FAILURE, Cleanup.CONFIRMED),
    ],
)
def test_expected_transition_edges(
    source: State, target: State, reason: Reason | None, cleanup: Cleanup
) -> None:
    original = _snapshot(source, reason)

    updated = original.transition(target, stop_reason=reason, cleanup_status=cleanup)

    assert original.state is source
    assert updated is not original
    assert updated.state is target
    assert updated.stop_reason is reason
    assert updated.cleanup_status is cleanup
    assert updated.is_terminal == (target in TERMINAL_STATES)


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (State.IDLE, State.RUNNING),
        (State.IDLE, State.SUCCEEDED),
        (State.STARTING, State.FINALIZING),
        (State.STARTING, State.STOPPED),
        (State.RUNNING, State.SUCCEEDED),
        (State.RUNNING, State.TIMED_OUT),
        (State.FINALIZING, State.RUNNING),
        (State.STOPPING, State.RUNNING),
        (State.STOPPING, State.SUCCEEDED),
        (State.STOP_UNCONFIRMED, State.RUNNING),
        (State.STOP_UNCONFIRMED, State.SUCCEEDED),
    ],
)
def test_invalid_transition_is_explicitly_rejected(source: State, target: State) -> None:
    lifecycle = _snapshot(source, Reason.USER_REQUEST)

    with pytest.raises(ValueError, match="transition"):
        lifecycle.transition(target)
    assert lifecycle.state is source


@pytest.mark.parametrize("source", TERMINAL_STATES)
@pytest.mark.parametrize("target", list(State))
def test_terminal_session_cannot_transition_again(source: State, target: State) -> None:
    reason = Reason.DEADLINE_EXCEEDED if source is State.TIMED_OUT else Reason.USER_REQUEST
    lifecycle = _snapshot(source, reason)

    with pytest.raises(ValueError, match="transition"):
        lifecycle.transition(target)
    assert ScanLifecycle().state is State.IDLE


@pytest.mark.parametrize("reason", [Reason.USER_REQUEST, Reason.WINDOW_CLOSE])
def test_stop_reason_is_preserved_through_uncertainty_retry_and_confirmation(
    reason: Reason,
) -> None:
    lifecycle = _snapshot(State.RUNNING).transition(State.STOPPING, stop_reason=reason)
    unknown = lifecycle.transition(State.STOP_UNCONFIRMED, cleanup_status=Cleanup.UNCONFIRMED)
    retrying = unknown.transition(State.STOPPING)
    stopped = retrying.transition(State.STOPPED, cleanup_status=Cleanup.CONFIRMED)

    assert not unknown.is_terminal
    assert retrying.cleanup_status is Cleanup.UNCONFIRMED
    assert stopped.stop_reason is reason
    assert stopped.state is State.STOPPED


def test_established_stop_reason_cannot_be_overwritten() -> None:
    lifecycle = _snapshot(State.STOPPING, Reason.USER_REQUEST)

    with pytest.raises(ValueError, match="reason"):
        lifecycle.transition(
            State.TIMED_OUT, stop_reason=Reason.DEADLINE_EXCEEDED, cleanup_status=Cleanup.CONFIRMED
        )
    assert lifecycle.stop_reason is Reason.USER_REQUEST


@pytest.mark.parametrize("cleanup", [Cleanup.PENDING, Cleanup.UNCONFIRMED])
@pytest.mark.parametrize(
    ("source", "target", "reason"),
    [
        (State.FINALIZING, State.SUCCEEDED, None),
        (State.RUNNING, State.FAILED, None),
        (State.STOPPING, State.STOPPED, Reason.USER_REQUEST),
        (State.STOPPING, State.TIMED_OUT, Reason.DEADLINE_EXCEEDED),
        (State.STOPPING, State.FAILED, Reason.FAILURE),
    ],
)
def test_terminal_result_requires_explicit_cleanup_confirmation(
    source: State, target: State, reason: Reason | None, cleanup: Cleanup
) -> None:
    lifecycle = _snapshot(source, reason)

    with pytest.raises(ValueError, match="cleanup"):
        lifecycle.transition(target, cleanup_status=cleanup)


def test_timeout_reason_can_remain_unconfirmed_without_claiming_stopped() -> None:
    lifecycle = _snapshot(State.STOPPING, Reason.DEADLINE_EXCEEDED)
    unknown = lifecycle.transition(State.STOP_UNCONFIRMED, cleanup_status=Cleanup.UNCONFIRMED)

    assert unknown.state is State.STOP_UNCONFIRMED
    assert unknown.stop_reason is Reason.DEADLINE_EXCEEDED
    assert unknown.cleanup_status is Cleanup.UNCONFIRMED
    with pytest.raises(ValueError):
        unknown.transition(State.TIMED_OUT)
    assert unknown.transition(State.TIMED_OUT, cleanup_status=Cleanup.CONFIRMED).is_terminal


@pytest.mark.parametrize(
    ("reason", "wrong_target"),
    [
        (Reason.USER_REQUEST, State.TIMED_OUT),
        (Reason.WINDOW_CLOSE, State.FAILED),
        (Reason.DEADLINE_EXCEEDED, State.STOPPED),
        (Reason.FAILURE, State.STOPPED),
    ],
)
def test_terminal_state_must_agree_with_stop_reason(reason: Reason, wrong_target: State) -> None:
    with pytest.raises(ValueError):
        _snapshot(State.STOPPING, reason).transition(wrong_target, cleanup_status=Cleanup.CONFIRMED)


def test_cleanup_knowledge_cannot_be_reset() -> None:
    unknown = _snapshot(State.STOP_UNCONFIRMED, Reason.USER_REQUEST)
    with pytest.raises(ValueError, match="cleanup"):
        unknown.transition(State.STOPPING, cleanup_status=Cleanup.PENDING)
    finalized = ScanLifecycle(state=State.FINALIZING, cleanup_status=Cleanup.CONFIRMED)
    with pytest.raises(ValueError, match="cleanup"):
        finalized.transition(
            State.STOPPING, stop_reason=Reason.USER_REQUEST, cleanup_status=Cleanup.PENDING
        )


@pytest.mark.parametrize(
    "arguments",
    [
        {"state": State.STOPPING},
        {"state": State.STOP_UNCONFIRMED, "stop_reason": Reason.USER_REQUEST},
        {"state": State.SUCCEEDED},
        {"stop_reason": Reason.USER_REQUEST},
        {"cleanup_status": Cleanup.CONFIRMED},
    ],
)
def test_inconsistent_snapshots_are_rejected(arguments: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        ScanLifecycle(**arguments)


def test_raw_strings_are_not_accepted_as_control_enums() -> None:
    with pytest.raises(TypeError):
        ScanLifecycle(state="running")
    with pytest.raises(TypeError):
        _snapshot(State.RUNNING).transition("stopping")
    with pytest.raises(TypeError):
        _snapshot(State.RUNNING).transition(State.STOPPING, stop_reason="user_request")
    with pytest.raises(TypeError):
        _snapshot(State.RUNNING).transition(State.FAILED, cleanup_status="confirmed")


def test_deadline_remaining_time_and_exact_expiry_use_injected_clock() -> None:
    clock = ManualClock()
    deadline = ScanDeadline(5.0, clock=clock)

    assert clock.calls == 1
    assert deadline.expires_at == 105.0
    assert deadline.remaining_seconds() == 5.0
    assert not deadline.is_expired()
    clock.value = 102.25
    assert deadline.remaining_seconds() == 2.75
    clock.value = 105.0
    assert deadline.remaining_seconds() == 0.0
    assert deadline.is_expired()
    clock.value = 150.0
    assert deadline.remaining_seconds() == 0.0
    assert deadline.is_expired()


def test_default_clock_is_monotonic(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = ManualClock(20.0)
    monkeypatch.setattr(scan_control, "monotonic", clock)

    deadline = ScanDeadline(2)
    clock.value = 21.0

    assert deadline.remaining_seconds() == 1.0
    assert clock.calls == 2


def test_monotonic_origin_need_not_be_wall_clock_or_positive() -> None:
    clock = ManualClock(-100.0)
    deadline = ScanDeadline(4.0, clock=clock)
    clock.value = -98.0

    assert deadline.expires_at == -96.0
    assert deadline.remaining_seconds() == 2.0


@pytest.mark.parametrize("budget", [0, -1, -0.0, float("nan"), float("inf"), -float("inf")])
def test_non_positive_or_non_finite_budget_is_rejected_without_reading_clock(budget: float) -> None:
    clock = Mock()
    with pytest.raises(ValueError):
        ScanDeadline(budget, clock=clock)
    clock.assert_not_called()


@pytest.mark.parametrize("budget", [True, False, "5", None, object()])
def test_non_numeric_budget_is_rejected(budget: object) -> None:
    clock = Mock()
    with pytest.raises(TypeError):
        ScanDeadline(budget, clock=clock)
    clock.assert_not_called()


@pytest.mark.parametrize(("start", "budget"), [(1e308, 1e308), (1e20, 1.0)])
def test_unrepresentable_expiry_is_rejected(start: float, budget: float) -> None:
    with pytest.raises(ValueError):
        ScanDeadline(budget, clock=ManualClock(start))


def test_huge_integer_budget_and_non_callable_clock_are_rejected() -> None:
    with pytest.raises(ValueError):
        ScanDeadline(10**1000, clock=ManualClock())
    with pytest.raises(TypeError):
        ScanDeadline(1.0, clock=object())


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_non_finite_clock_reading_is_rejected_at_creation_and_query(value: float) -> None:
    with pytest.raises(ValueError):
        ScanDeadline(1, clock=ManualClock(value))
    clock = ManualClock()
    deadline = ScanDeadline(1, clock=clock)
    clock.value = value
    with pytest.raises(ValueError):
        deadline.remaining_seconds()


def test_clock_reading_before_creation_is_rejected() -> None:
    clock = ManualClock()
    deadline = ScanDeadline(1, clock=clock)
    clock.value = 99
    with pytest.raises(ValueError):
        deadline.remaining_seconds()


def test_expiry_does_not_automatically_request_stop_or_confirm_cleanup() -> None:
    clock = ManualClock()
    deadline = ScanDeadline(1, clock=clock)
    lifecycle = _snapshot(State.RUNNING)
    clock.value = 102

    assert deadline.is_expired()
    assert lifecycle.state is State.RUNNING
    assert lifecycle.stop_reason is None
    stopping = lifecycle.transition(State.STOPPING, stop_reason=Reason.USER_REQUEST)
    assert stopping.cleanup_status is Cleanup.PENDING
    assert stopping.stop_reason is Reason.USER_REQUEST


def test_existing_diagnostic_status_and_report_schema_are_unchanged() -> None:
    assert get_args(DiagnosticResult.model_fields["status"].annotation) == (
        "found",
        "passed",
        "skipped",
        "error",
    )
    assert set(ScanReport.model_fields) == {"schema_version", "metadata", "diagnostics"}
    assert ScanReport.model_fields["schema_version"].default == "1.0"


@pytest.mark.parametrize("reason", list(Reason))
def test_cleanup_control_exception_is_fixed_and_does_not_confirm_cleanup(reason: Reason) -> None:
    lifecycle = _snapshot(State.STOP_UNCONFIRMED, reason)
    error = scan_control.ScanCleanupUnconfirmedError()

    assert isinstance(error, RuntimeError)
    assert str(error) == "Scan cleanup could not be confirmed."
    assert error.args == ("Scan cleanup could not be confirmed.",)
    with pytest.raises(TypeError):
        scan_control.ScanCleanupUnconfirmedError("fictional secret C:/Users/Fictional/private")
    with pytest.raises(scan_control.ScanCleanupUnconfirmedError):
        raise error
    assert lifecycle.state is State.STOP_UNCONFIRMED
    assert not lifecycle.is_terminal
    assert lifecycle.cleanup_status is Cleanup.UNCONFIRMED
    assert lifecycle.stop_reason is reason
    for target in TERMINAL_STATES:
        with pytest.raises(ValueError):
            lifecycle.transition(target)

    retry = lifecycle.transition(State.STOPPING)
    assert retry.cleanup_status is Cleanup.UNCONFIRMED
    assert retry.stop_reason is reason
    assert not retry.is_terminal


@pytest.mark.parametrize("expiry,remaining", [(105.0, 5.0), (100.0, 0.0), (95.0, 0.0)])
def test_absolute_deadline_does_not_restart_budget(expiry: float, remaining: float) -> None:
    clock = ManualClock(100)
    deadline = ScanDeadline.from_expires_at(expiry, clock=clock)
    assert deadline.expires_at == expiry
    assert deadline.remaining_seconds() == remaining
    assert deadline.is_expired() is (remaining == 0)
    clock.value = 200
    assert deadline.remaining_seconds() == 0


@pytest.mark.parametrize("expiry", [True, False, None, "100", object()])
def test_absolute_deadline_rejects_wrong_types(expiry: object) -> None:
    with pytest.raises(TypeError):
        ScanDeadline.from_expires_at(expiry, clock=ManualClock())


@pytest.mark.parametrize("expiry", [float("nan"), float("inf"), -float("inf"), 10**1000])
def test_absolute_deadline_rejects_unrepresentable_values(expiry: object) -> None:
    with pytest.raises(ValueError):
        ScanDeadline.from_expires_at(expiry, clock=ManualClock())


def test_stop_decision_preserves_first_reason_and_separate_close_intent() -> None:
    clock = ManualClock()
    deadline = ScanDeadline(5, clock=clock)
    lifecycle = _snapshot(State.RUNNING)
    first = scan_control.decide_stop(lifecycle, deadline, request=Reason.USER_REQUEST)
    assert first.lifecycle.state is State.STOPPING
    assert first.lifecycle.stop_reason is Reason.USER_REQUEST
    assert first.lifecycle.cleanup_status is Cleanup.PENDING
    assert not first.close_pending
    clock.value = 105
    later = scan_control.decide_stop(
        first.lifecycle, deadline, request=Reason.WINDOW_CLOSE, close_pending=first.close_pending
    )
    assert later.lifecycle is first.lifecycle
    assert later.lifecycle.stop_reason is Reason.USER_REQUEST
    assert later.close_pending
    assert deadline.expires_at == 105


@pytest.mark.parametrize("stop_request", [None, Reason.USER_REQUEST, Reason.WINDOW_CLOSE])
def test_expiry_wins_when_no_stop_reason_exists(stop_request: Reason | None) -> None:
    deadline = ScanDeadline.from_expires_at(100, clock=ManualClock(100))
    result = scan_control.decide_stop(_snapshot(State.RUNNING), deadline, request=stop_request)
    assert result.lifecycle.state is State.STOPPING
    assert result.lifecycle.stop_reason is Reason.DEADLINE_EXCEEDED
    assert result.lifecycle.cleanup_status is Cleanup.PENDING
    assert result.close_pending is (stop_request is Reason.WINDOW_CLOSE)


@pytest.mark.parametrize("state", TERMINAL_STATES)
@pytest.mark.parametrize("stop_request", [Reason.WINDOW_CLOSE, Reason.FAILURE])
def test_late_stop_does_not_rewrite_terminal_lifecycle(state: State, stop_request: Reason) -> None:
    reason = Reason.DEADLINE_EXCEEDED if state is State.TIMED_OUT else Reason.USER_REQUEST
    lifecycle = _snapshot(state, reason)
    clock = Mock(side_effect=AssertionError("terminal events need no clock read"))
    deadline = ScanDeadline.from_expires_at(100, clock=ManualClock())
    deadline._clock = clock
    result = scan_control.decide_stop(lifecycle, deadline, request=stop_request, close_pending=True)
    assert result.lifecycle is lifecycle
    assert result.close_pending
    clock.assert_not_called()


def test_stop_decision_does_not_confirm_cleanup_or_restart_unknown_session() -> None:
    unknown = _snapshot(State.STOP_UNCONFIRMED, Reason.USER_REQUEST)
    deadline = ScanDeadline.from_expires_at(0, clock=ManualClock())
    result = scan_control.decide_stop(unknown, deadline, request=Reason.DEADLINE_EXCEEDED)
    assert result.lifecycle is unknown
    assert result.lifecycle.cleanup_status is Cleanup.UNCONFIRMED
    assert not result.lifecycle.is_terminal


def test_no_stop_before_expiry_and_invalid_requests_are_rejected() -> None:
    lifecycle = _snapshot(State.RUNNING)
    deadline = ScanDeadline(5, clock=ManualClock())
    assert scan_control.decide_stop(lifecycle, deadline).lifecycle is lifecycle
    for request in ("user_request", True, object()):
        with pytest.raises(TypeError):
            scan_control.decide_stop(lifecycle, deadline, request=request)
    with pytest.raises(ValueError):
        scan_control.decide_stop(ScanLifecycle(), deadline, request=Reason.USER_REQUEST)


def test_absolute_deadline_rejects_lossy_integer_and_overflowed_distance() -> None:
    expiry = 2**53 + 1
    clock = Mock(side_effect=AssertionError("invalid deadline must not read clock"))
    with pytest.raises(ValueError) as raised:
        ScanDeadline.from_expires_at(expiry, clock=clock)
    clock.assert_not_called()
    assert raised.value.args == ("Integer time values must be represented exactly.",)
    assert str(expiry) not in str(raised.value)
    with pytest.raises(ValueError):
        ScanDeadline.from_expires_at(1e308, clock=ManualClock(-1e308))


def test_exact_large_integer_absolute_deadline_preserves_remaining_time_and_expiry() -> None:
    expiry = 2**53
    clock = ManualClock(0)
    deadline = ScanDeadline.from_expires_at(expiry, clock=clock)
    assert clock.calls == 1
    assert deadline.expires_at == expiry
    assert deadline.remaining_seconds() == expiry
    assert not deadline.is_expired()
    clock.value = expiry - 1
    assert deadline.remaining_seconds() == 1
    assert not deadline.is_expired()
    clock.value = expiry
    assert deadline.remaining_seconds() == 0
    assert deadline.is_expired()
    clock.value = expiry + 2
    assert deadline.remaining_seconds() == 0
    assert deadline.is_expired()
    assert deadline.expires_at == expiry


def test_absolute_deadline_uses_injected_clock_and_rejects_invalid_clock() -> None:
    clock = ManualClock(-10)
    deadline = ScanDeadline.from_expires_at(-5, clock=clock)
    assert clock.calls == 1
    assert deadline.remaining_seconds() == 5
    clock.value = -11
    with pytest.raises(ValueError):
        deadline.remaining_seconds()
    with pytest.raises(TypeError):
        ScanDeadline.from_expires_at(100, clock=object())
    with pytest.raises(ValueError):
        ScanDeadline.from_expires_at(100, clock=ManualClock(float("nan")))


@pytest.mark.parametrize("state", [State.STARTING, State.RUNNING, State.FINALIZING])
@pytest.mark.parametrize("stop_reason", [Reason.USER_REQUEST, Reason.WINDOW_CLOSE, Reason.FAILURE])
def test_every_active_state_accepts_first_explicit_stop_without_cleanup_claim(
    state: State, stop_reason: Reason
) -> None:
    deadline = ScanDeadline(5, clock=ManualClock())
    result = scan_control.decide_stop(_snapshot(state), deadline, request=stop_reason)
    assert result.lifecycle.state is State.STOPPING
    assert result.lifecycle.stop_reason is stop_reason
    assert result.lifecycle.cleanup_status is Cleanup.PENDING
    assert result.close_pending is (stop_reason is Reason.WINDOW_CLOSE)


def test_stop_decision_validates_arguments_and_retains_close_intent() -> None:
    deadline = ScanDeadline(5, clock=ManualClock())
    lifecycle = _snapshot(State.RUNNING)
    assert scan_control.decide_stop(lifecycle, deadline, close_pending=True).close_pending
    assert scan_control.decide_stop(ScanLifecycle(), deadline).lifecycle.state is State.IDLE
    for arguments in ((None, deadline), (lifecycle, None)):
        with pytest.raises(TypeError):
            scan_control.decide_stop(*arguments)
    with pytest.raises(TypeError):
        scan_control.decide_stop(lifecycle, deadline, close_pending=1)
    with pytest.raises(TypeError):
        scan_control.StopDecision(lifecycle, "yes")


@pytest.mark.parametrize("state", [State.STARTING, State.RUNNING, State.FINALIZING])
def test_deadline_notification_cannot_claim_timeout_before_clock_expires(state: State) -> None:
    clock = ManualClock()
    deadline = ScanDeadline(5, clock=clock)
    lifecycle = _snapshot(state)
    early = scan_control.decide_stop(lifecycle, deadline, request=Reason.DEADLINE_EXCEEDED)
    assert early.lifecycle is lifecycle
    assert early.lifecycle.stop_reason is None
    clock.value = 105
    reached = scan_control.decide_stop(lifecycle, deadline, request=Reason.DEADLINE_EXCEEDED)
    assert reached.lifecycle.state is State.STOPPING
    assert reached.lifecycle.stop_reason is Reason.DEADLINE_EXCEEDED
    assert reached.lifecycle.cleanup_status is Cleanup.PENDING
    assert deadline.expires_at == 105


@pytest.mark.parametrize("budget", [1, 60, 2**53])
def test_integer_budget_is_accepted_when_float_conversion_is_exact(budget: int) -> None:
    clock = ManualClock(0)
    deadline = ScanDeadline(budget, clock=clock)
    assert int(deadline.expires_at) == budget
    assert int(deadline.remaining_seconds()) == budget
    assert not deadline.is_expired()
    assert clock.calls == 3


@pytest.mark.parametrize("budget", [2**53 + 1, 2**53 + 3, 2**60 + 1])
def test_lossy_integer_budget_is_rejected_before_reading_clock(budget: int) -> None:
    clock = Mock(side_effect=AssertionError("invalid budget must not read clock"))
    with pytest.raises(ValueError) as raised:
        ScanDeadline(budget, clock=clock)
    clock.assert_not_called()
    assert str(budget) not in str(raised.value)


@pytest.mark.parametrize("state", [State.STARTING, State.RUNNING, State.FINALIZING])
@pytest.mark.parametrize("now", [100, 105, 110])
def test_explicit_failure_wins_before_at_or_after_deadline_without_confirming_cleanup(
    state: State, now: float
) -> None:
    clock = ManualClock(now)
    deadline = ScanDeadline.from_expires_at(105, clock=clock)
    lifecycle = _snapshot(state)
    decision = scan_control.decide_stop(
        lifecycle, deadline, request=Reason.FAILURE, close_pending=True
    )
    assert decision.lifecycle.state is State.STOPPING
    assert decision.lifecycle.stop_reason is Reason.FAILURE
    assert decision.lifecycle.cleanup_status is Cleanup.PENDING
    assert not decision.lifecycle.is_terminal
    assert decision.close_pending
    assert lifecycle.state is state and lifecycle.stop_reason is None
    assert deadline.expires_at == 105
    assert clock.calls == 1  # The observed failure does not need a clock query.


@pytest.mark.parametrize("state", [State.STOPPING, State.STOP_UNCONFIRMED])
@pytest.mark.parametrize("reason", list(Reason))
def test_failure_does_not_override_established_reason_or_cleanup(
    state: State, reason: Reason
) -> None:
    lifecycle = _snapshot(state, reason)
    deadline = ScanDeadline.from_expires_at(100, clock=ManualClock(105))
    decision = scan_control.decide_stop(
        lifecycle, deadline, request=Reason.FAILURE, close_pending=True
    )
    assert decision.lifecycle is lifecycle
    assert decision.lifecycle.stop_reason is reason
    assert decision.lifecycle.cleanup_status is lifecycle.cleanup_status
    assert decision.close_pending
    assert not decision.lifecycle.is_terminal
