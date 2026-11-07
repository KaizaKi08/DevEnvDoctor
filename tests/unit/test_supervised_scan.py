from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from dev_env_doctor.core import supervised_scan as supervised_scan_module
from dev_env_doctor.core.models import DiagnosticResult, ScanMetadata, ScanReport, Severity
from dev_env_doctor.core.scan_control import CleanupStatus, ScanLifecycleState, StopReason
from dev_env_doctor.core.scan_coordinator import (
    DiagnosticEvent,
    DiagnosticResourceStatus,
    DiagnosticStage,
)
from dev_env_doctor.core.supervised_scan import SupervisedScanError, run_supervised_scan


def report_payload():
    return {
        "schema_version": "1.0",
        "metadata": {
            "scan_time": "2026-01-01T12:34:56.123456+00:00",
            "app_version": "0.1.0-test",
            "platform": "Windows-test",
            "python_version": "3.13.0-test",
        },
        "diagnostics": [
            {
                "rule_id": "COMMAND_VERSION",
                "title": "python version",
                "summary": "Version checked.",
                "severity": "info",
                "status": "passed",
                "suggestion": "",
                "evidence": ["Verified version: 3.13.9"],
            }
        ],
    }


def report_model():
    return ScanReport(
        metadata=ScanMetadata(
            scan_time=datetime(2026, 1, 1, 12, 34, 56, 123456, tzinfo=UTC),
            app_version="0.1.0-test",
            platform="Windows-test",
            python_version="3.13.0-test",
        ),
        diagnostics=[
            DiagnosticResult(
                rule_id="COMMAND_VERSION",
                title="python version",
                summary="Version checked.",
                severity=Severity.INFO,
                status="passed",
                suggestion="",
                evidence=["Verified version: 3.13.9"],
            )
        ],
    )


def decision(
    *,
    success=False,
    ready=True,
    started=True,
    candidate=1,
    validated=True,
    state=None,
    stop_reason=None,
    cleanup_status=CleanupStatus.PENDING,
    unconfirmed=False,
):
    return SimpleNamespace(
        lifecycle=SimpleNamespace(
            state=(
                state
                if state is not None
                else ScanLifecycleState.SUCCEEDED
                if success
                else ScanLifecycleState.RUNNING
            ),
            stop_reason=stop_reason,
            cleanup_status=cleanup_status,
        ),
        facts=SimpleNamespace(
            ready=ready,
            start_authorized=started,
            candidate_count=candidate,
            report_validation=SimpleNamespace(value="confirmed" if validated else "unknown"),
            resources=SimpleNamespace(has_unconfirmed_observation=unconfirmed),
        ),
        result_available=success,
    )


class FakeCoordinator:
    instances = []

    def __init__(
        self,
        session_id,
        deadline,
        *,
        final=True,
        payload=None,
        failure=None,
        failure_error=None,
        final_state=None,
        close_error=None,
        start_decision=None,
        close_decision=None,
    ):
        self.session_id = session_id
        self.deadline = deadline
        self.final = final
        self.payload = report_payload() if payload is None else payload
        self.failure = failure
        self.failure_error = failure_error
        self.final_state = final_state
        self.close_error = close_error
        self.start_decision = start_decision
        self.close_decision = close_decision
        self.calls = []
        self.result_report = self.payload if final else None
        self.close_calls = 0
        FakeCoordinator.instances.append(self)

    def _call(self, name):
        self.calls.append(name)
        if self.failure == name:
            raise self.failure_error or RuntimeError("fictional secret path")

    def start(self, *, remaining_timeout_ms, require_path_snapshot):
        assert require_path_snapshot is True
        self.calls.append(("start", remaining_timeout_ms))
        return decision() if self.start_decision is None else self.start_decision

    def wait_ready(self):
        self._call("wait_ready")
        return decision()

    def send_start(self, *, path_snapshot):
        self.path_snapshot = path_snapshot
        self._call("send_start")
        return decision()

    def receive_worker_message(self, *, remaining_timeout_ms=None):
        self.calls.append(("receive_worker_message", remaining_timeout_ms))
        self._call("receive_worker_message")
        return decision(candidate=1, validated=True)

    def observe_process(self, timeout_ms):
        self.calls.append(("observe_process", timeout_ms))
        return decision()

    def observe_job(self):
        self._call("observe_job")
        return decision()

    def close_ipc(self):
        self._call("close_ipc")
        return decision()

    def close_resources(self):
        self.close_calls += 1
        self.calls.append("close_resources")
        if self.close_error is not None:
            raise self.close_error
        if self.close_decision is not None:
            return self.close_decision
        return decision(success=self.final, state=self.final_state)


def make_factory(**kwargs):
    def factory(session_id, deadline):
        return FakeCoordinator(session_id, deadline, **kwargs)

    return factory


@pytest.fixture(autouse=True)
def clear_instances(monkeypatch):
    FakeCoordinator.instances.clear()
    monkeypatch.setattr(supervised_scan_module, "os", SimpleNamespace(environ={}))


@pytest.mark.parametrize("value", [None, "", r"C:\Synthetic-52F2\Tools"])
def test_parent_captures_path_once_before_creating_resources(monkeypatch, value):
    initial = {} if value is None else {"PATH": value}
    reads = Mock(side_effect=initial.get)
    monkeypatch.setattr(supervised_scan_module.os, "environ", SimpleNamespace(get=reads))
    factory = make_factory()

    def change_parent_path(session_id, deadline):
        initial["PATH"] = r"C:\Later-Path"
        return factory(session_id, deadline)

    events = []
    report = run_supervised_scan(
        10, coordinator_factory=change_parent_path, diagnostic_observer=events.append
    )

    reads.assert_called_once_with("PATH", "")
    assert FakeCoordinator.instances[0].path_snapshot == (value or "")
    assert "52F2" not in repr(events)
    assert "52F2" not in report.model_dump_json()


@pytest.mark.parametrize("value", ["X" * 4097, "PRIVATE-CANARY-594A\x00", r'"C:\broken'])
def test_bad_parent_snapshot_fails_before_coordinator_creation(monkeypatch, value):
    monkeypatch.setattr(supervised_scan_module.os, "environ", {"PATH": value})
    factory = Mock()
    with pytest.raises(SupervisedScanError) as raised:
        run_supervised_scan(10, coordinator_factory=factory)
    factory.assert_not_called()
    assert raised.value.code == "SCAN_FAILED"
    assert raised.value.__context__ is None
    assert "594A" not in str(raised.value)


def test_snapshot_transport_failure_has_no_raw_exception_chain(monkeypatch):
    monkeypatch.setattr(supervised_scan_module.os, "environ", {"PATH": r"C:\Private-52F2"})
    events = []
    with pytest.raises(SupervisedScanError) as raised:
        run_supervised_scan(
            10,
            coordinator_factory=make_factory(
                failure="send_start", failure_error=RuntimeError("Private-52F2")
            ),
            diagnostic_observer=events.append,
        )
    assert raised.value.code == "SCAN_FAILED"
    assert raised.value.__cause__ is None and raised.value.__context__ is None
    assert "52F2" not in repr(events)
    assert FakeCoordinator.instances[0].close_calls == 1


def test_success_uses_one_deadline_and_returns_full_report():
    result = run_supervised_scan(10, coordinator_factory=make_factory())
    coordinator = FakeCoordinator.instances[0]
    assert isinstance(result, ScanReport)
    assert result.metadata.app_version == "0.1.0-test"
    assert result.metadata.scan_time.isoformat() == "2026-01-01T12:34:56.123456+00:00"
    assert coordinator.calls[0][0] == "start"
    receive_calls = [
        call
        for call in coordinator.calls
        if isinstance(call, tuple) and call[0] == "receive_worker_message"
    ]
    assert len(receive_calls) == 1
    assert receive_calls[0][1] > 1000
    assert any(
        isinstance(call, tuple) and call[0] == "observe_process" for call in coordinator.calls
    )


def test_success_does_not_construct_report_from_diagnostics():
    payload = report_model()
    result = run_supervised_scan(
        10,
        coordinator_factory=make_factory(payload=payload.model_dump(mode="json")),
    )
    assert result.metadata.model_dump() == payload.metadata.model_dump()


class ExpiredDeadline:
    """Deterministic expired deadline used to exercise timeout mapping."""

    expires_at = 0.0

    def __init__(self, _budget_seconds):
        pass

    def remaining_seconds(self):
        return 0.0

    def is_expired(self):
        return True


class ActiveDeadline:
    """Deterministic active deadline used to exercise ordinary failures."""

    expires_at = 100.0

    def __init__(self, _budget_seconds):
        pass

    def remaining_seconds(self):
        return 10.0

    def is_expired(self):
        return False


def test_expired_deadline_returns_specific_timeout_code(monkeypatch):
    monkeypatch.setattr(supervised_scan_module, "ScanDeadline", ExpiredDeadline)
    expired = decision(
        state=ScanLifecycleState.STOPPING,
        stop_reason=StopReason.DEADLINE_EXCEEDED,
    )

    with pytest.raises(SupervisedScanError) as raised:
        run_supervised_scan(10, coordinator_factory=make_factory(start_decision=expired))

    assert raised.value.code == "SCAN_TIMED_OUT"
    assert str(raised.value) == "The supervised scan reached its deadline."


def test_expired_deadline_with_unconfirmed_cleanup_prefers_cleanup_code(monkeypatch):
    monkeypatch.setattr(supervised_scan_module, "ScanDeadline", ExpiredDeadline)
    unconfirmed = decision(
        state=ScanLifecycleState.STOP_UNCONFIRMED,
        stop_reason=StopReason.DEADLINE_EXCEEDED,
        cleanup_status=CleanupStatus.UNCONFIRMED,
        unconfirmed=True,
    )
    expired = decision(
        state=ScanLifecycleState.STOPPING,
        stop_reason=StopReason.DEADLINE_EXCEEDED,
    )

    with pytest.raises(SupervisedScanError) as raised:
        run_supervised_scan(
            10,
            coordinator_factory=make_factory(
                final=False,
                start_decision=expired,
                close_decision=unconfirmed,
            ),
        )

    coordinator = FakeCoordinator.instances[0]
    assert raised.value.code == "CLEANUP_UNCONFIRMED"
    assert not isinstance(coordinator.result_report, ScanReport)
    assert coordinator.close_calls == 1
    assert unconfirmed.lifecycle.state is ScanLifecycleState.STOP_UNCONFIRMED
    assert unconfirmed.lifecycle.cleanup_status is CleanupStatus.UNCONFIRMED


def test_unconfirmed_cleanup_returns_specific_code():
    unconfirmed = decision(
        state=ScanLifecycleState.STOP_UNCONFIRMED,
        stop_reason=StopReason.FAILURE,
        cleanup_status=CleanupStatus.UNCONFIRMED,
        unconfirmed=True,
    )

    with pytest.raises(SupervisedScanError) as raised:
        run_supervised_scan(
            10,
            coordinator_factory=make_factory(final=False, close_decision=unconfirmed),
        )

    assert raised.value.code == "CLEANUP_UNCONFIRMED"
    assert str(raised.value) == "The supervised scan cleanup could not be confirmed."


def test_confirmed_cleanup_failure_remains_generic_failure():
    confirmed = decision(
        state=ScanLifecycleState.FAILED,
        stop_reason=StopReason.FAILURE,
        cleanup_status=CleanupStatus.CONFIRMED,
    )

    with pytest.raises(SupervisedScanError) as raised:
        run_supervised_scan(
            10,
            coordinator_factory=make_factory(final=False, close_decision=confirmed),
        )

    assert raised.value.code == "SCAN_NOT_SUCCESSFUL"


def test_active_deadline_ordinary_failure_remains_generic(monkeypatch):
    monkeypatch.setattr(supervised_scan_module, "ScanDeadline", ActiveDeadline)
    confirmed = decision(
        state=ScanLifecycleState.FAILED,
        stop_reason=StopReason.FAILURE,
        cleanup_status=CleanupStatus.CONFIRMED,
    )

    with pytest.raises(SupervisedScanError) as raised:
        run_supervised_scan(
            10,
            coordinator_factory=make_factory(
                failure="receive_worker_message",
                failure_error=RuntimeError("ordinary scan failure"),
                final=False,
                close_decision=confirmed,
            ),
        )

    assert raised.value.code == "SCAN_FAILED"
    assert raised.value.code not in {"SCAN_TIMED_OUT", "CLEANUP_UNCONFIRMED"}
    assert FakeCoordinator.instances[0].close_calls == 1


def test_unknown_error_code_keeps_safe_fallback():
    error = SupervisedScanError("FICTIONAL_ERROR")

    assert error.code == "SCAN_FAILED"
    assert "FICTIONAL_ERROR" not in str(error)


@pytest.mark.parametrize("timeout", [0, -1, True, False, float("nan"), float("inf"), 2**53 + 1])
def test_invalid_timeout_is_rejected_without_coordinator(timeout):
    factory = Mock()
    with pytest.raises(SupervisedScanError) as raised:
        run_supervised_scan(timeout, coordinator_factory=factory)
    assert raised.value.code == "INVALID_TIMEOUT"
    factory.assert_not_called()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"final": False},
        {"payload": {"schema_version": "1.0", "metadata": {}, "diagnostics": []}},
    ],
)
def test_missing_success_evidence_cannot_return_report(kwargs):
    with pytest.raises(SupervisedScanError):
        run_supervised_scan(10, coordinator_factory=make_factory(**kwargs))
    assert FakeCoordinator.instances[0].close_calls == 1


def test_runner_or_coordinator_failure_uses_fixed_error_and_cleanup():
    with pytest.raises(SupervisedScanError) as raised:
        run_supervised_scan(10, coordinator_factory=make_factory(failure="receive_worker_message"))
    assert raised.value.code == "SCAN_FAILED"
    assert "fictional" not in str(raised.value)
    assert FakeCoordinator.instances[0].close_calls == 1


def test_coordinator_construction_failure_is_fixed_and_does_not_leak_details():
    def factory(_session_id, _deadline):
        raise RuntimeError("C:\\Users\\Secret\\traceback")

    with pytest.raises(SupervisedScanError) as raised:
        run_supervised_scan(10, coordinator_factory=factory)
    assert raised.value.code == "SCAN_FAILED"
    assert "Secret" not in str(raised.value)


def test_result_available_without_succeeded_lifecycle_is_rejected():
    with pytest.raises(SupervisedScanError) as raised:
        run_supervised_scan(
            10,
            coordinator_factory=make_factory(final=True, final_state=ScanLifecycleState.RUNNING),
        )
    assert raised.value.code == "SCAN_NOT_SUCCESSFUL"


def test_cleanup_error_does_not_replace_original_interrupt():
    error = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt) as raised:
        run_supervised_scan(
            10,
            coordinator_factory=make_factory(
                failure="wait_ready", failure_error=error, close_error=RuntimeError("secret")
            ),
        )
    assert raised.value is error


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(2)])
def test_base_exceptions_are_preserved(error):
    with pytest.raises(type(error)) as raised:
        run_supervised_scan(
            10,
            coordinator_factory=make_factory(failure="wait_ready", failure_error=error),
        )
    assert raised.value is error


def test_separate_calls_have_separate_sessions_and_deadlines():
    first = run_supervised_scan(10, coordinator_factory=make_factory())
    second = run_supervised_scan(10, coordinator_factory=make_factory())
    assert first.metadata == second.metadata
    assert len(FakeCoordinator.instances) == 2
    assert FakeCoordinator.instances[0] is not FakeCoordinator.instances[1]
    assert FakeCoordinator.instances[0].session_id != FakeCoordinator.instances[1].session_id
    assert FakeCoordinator.instances[0].deadline is not FakeCoordinator.instances[1].deadline


def test_diagnostic_observer_isolated_and_records_safe_failure_stage():
    events = []

    def observer(event):
        events.append(event)
        raise RuntimeError("observer secret path")

    with pytest.raises(SupervisedScanError) as raised:
        run_supervised_scan(
            10,
            coordinator_factory=make_factory(
                failure="wait_ready",
                failure_error=RuntimeError("private failure"),
                final=False,
            ),
            diagnostic_observer=observer,
        )

    assert raised.value.code == "SCAN_FAILED"
    assert [event.stage for event in events] == [
        DiagnosticStage.SERVICE_ENTERED,
        DiagnosticStage.COORDINATOR_CREATED,
        DiagnosticStage.FAILED,
    ]
    assert events[-1].error_code == "SCAN_FAILED"
    assert "private" not in repr(events)
    assert "secret" not in repr(events)


def test_failure_event_preserves_coordinator_resource_snapshot():
    snapshot = DiagnosticEvent(
        stage=DiagnosticStage.FINALIZING,
        coordinator_state="failed",
        supervisor_state="stopping",
        ipc_status=DiagnosticResourceStatus.UNCONFIRMED,
        helper_threads=DiagnosticResourceStatus.UNCONFIRMED,
        parent_resources=DiagnosticResourceStatus.NOT_OBSERVED,
    )

    class SnapshotCoordinator(FakeCoordinator):
        def diagnostic_snapshot(self, *, stage, error_code, failure_category=None):
            return replace(
                snapshot,
                stage=stage,
                error_code=error_code,
                failure_category=failure_category or "WORKER_MESSAGE_TRANSPORT_ERROR",
            )

    events = []

    def factory(session_id, deadline):
        return SnapshotCoordinator(
            session_id,
            deadline,
            failure="receive_worker_message",
            final=False,
            close_decision=decision(
                state=ScanLifecycleState.FAILED,
                cleanup_status=CleanupStatus.CONFIRMED,
            ),
        )

    with pytest.raises(SupervisedScanError) as raised:
        run_supervised_scan(10, coordinator_factory=factory, diagnostic_observer=events.append)

    assert raised.value.code == "SCAN_FAILED"
    failed = events[-1]
    assert failed.stage is DiagnosticStage.FAILED
    assert failed.ipc_status is DiagnosticResourceStatus.UNCONFIRMED
    assert failed.helper_threads is DiagnosticResourceStatus.UNCONFIRMED
    assert failed.parent_resources is DiagnosticResourceStatus.NOT_OBSERVED
    assert failed.failure_category == "WORKER_MESSAGE_TRANSPORT_ERROR"
    assert "fictional" not in repr(failed)
