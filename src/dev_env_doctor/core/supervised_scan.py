"""Application-level orchestration for one supervised diagnostic scan."""

import math
import os
import uuid
from collections.abc import Callable
from copy import deepcopy

from dev_env_doctor.core.models import ScanReport
from dev_env_doctor.core.scan_control import (
    CleanupStatus,
    ScanDeadline,
    ScanLifecycleState,
    StopReason,
)
from dev_env_doctor.core.scan_coordinator import (
    DiagnosticEvent,
    DiagnosticStage,
    ScanCoordinator,
)
from dev_env_doctor.core.scan_protocol import validate_path_snapshot
from dev_env_doctor.reports.json_report import JSON_SCHEMA_VERSION

_REPORT_FIELDS = frozenset({"schema_version", "metadata", "diagnostics"})
_METADATA_FIELDS = frozenset({"scan_time", "app_version", "platform", "python_version"})
_MAX_WAIT_MS = 0xFFFFFFFF


class SupervisedScanError(RuntimeError):
    """Fixed, safe application error for a scan that did not succeed."""

    _MESSAGES = {
        "INVALID_TIMEOUT": "The scan timeout is invalid.",
        "SCAN_FAILED": "The supervised scan failed.",
        "SCAN_NOT_SUCCESSFUL": "The supervised scan did not complete successfully.",
        "REPORT_INVALID": "The supervised scan returned an invalid report.",
        "SCAN_TIMED_OUT": "The supervised scan reached its deadline.",
        "CLEANUP_UNCONFIRMED": "The supervised scan cleanup could not be confirmed.",
    }

    def __init__(self, code: str) -> None:
        if code not in self._MESSAGES:
            code = "SCAN_FAILED"
        self.code = code
        super().__init__(self._MESSAGES[code])


def _remaining_timeout_ms(deadline: ScanDeadline) -> int:
    remaining = deadline.remaining_seconds()
    if remaining <= 0:
        return 0
    return min(_MAX_WAIT_MS, max(1, math.ceil(remaining * 1000)))


def _report_from_verified_payload(payload: object) -> ScanReport:
    if isinstance(payload, ScanReport):
        return payload.model_copy(deep=True)
    if type(payload) is not dict or set(payload) != _REPORT_FIELDS:
        raise SupervisedScanError("REPORT_INVALID")
    if payload["schema_version"] != JSON_SCHEMA_VERSION:
        raise SupervisedScanError("REPORT_INVALID")
    metadata = payload["metadata"]
    if type(metadata) is not dict or set(metadata) != _METADATA_FIELDS:
        raise SupervisedScanError("REPORT_INVALID")
    diagnostics = payload["diagnostics"]
    if type(diagnostics) is not list:
        raise SupervisedScanError("REPORT_INVALID")
    try:
        report = ScanReport.model_validate(deepcopy(payload))
    except Exception:
        raise SupervisedScanError("REPORT_INVALID") from None
    if not isinstance(report, ScanReport):
        raise SupervisedScanError("REPORT_INVALID")
    return report


def _decision_error_code(decision: object) -> str:
    """Map only explicit supervisor evidence to a stable failure code."""
    lifecycle = getattr(decision, "lifecycle", None)
    if (
        getattr(lifecycle, "state", None) is ScanLifecycleState.STOP_UNCONFIRMED
        or getattr(lifecycle, "cleanup_status", None) is CleanupStatus.UNCONFIRMED
    ):
        return "CLEANUP_UNCONFIRMED"
    facts = getattr(decision, "facts", None)
    resources = getattr(facts, "resources", None)
    if getattr(resources, "has_unconfirmed_observation", False):
        return "CLEANUP_UNCONFIRMED"
    if getattr(lifecycle, "stop_reason", None) is StopReason.DEADLINE_EXCEEDED:
        return "SCAN_TIMED_OUT"
    return "SCAN_NOT_SUCCESSFUL"


def _cleanup_after_failure(coordinator: object) -> object | None:
    close_resources = getattr(coordinator, "close_resources", None)
    if not callable(close_resources):
        return None
    try:
        return close_resources()
    except BaseException:
        return None


def _notify_diagnostic(
    observer: Callable[[DiagnosticEvent], None] | None,
    event: DiagnosticEvent,
) -> None:
    """Deliver internal diagnostics without affecting scan behavior."""
    if observer is None:
        return
    try:
        observer(event)
    except BaseException:
        pass


def _safe_state(value: object, fallback: str = "UNKNOWN") -> str:
    candidate = getattr(value, "value", None)
    return candidate if type(candidate) is str and len(candidate) <= 64 else fallback


def _coordinator_state(coordinator: object) -> str:
    return _safe_state(getattr(coordinator, "state", None))


def _supervisor_state(coordinator: object, decision: object | None = None) -> str:
    if decision is None:
        decision = getattr(coordinator, "decision", None)
    return _safe_state(getattr(getattr(decision, "lifecycle", None), "state", None))


def _diagnostic_event(
    coordinator: object,
    *,
    stage: DiagnosticStage,
    error_code: str | None = None,
) -> DiagnosticEvent:
    """Use the coordinator's current safe snapshot without exposing failures."""
    snapshot = getattr(coordinator, "diagnostic_snapshot", None)
    if callable(snapshot):
        try:
            event = snapshot(stage=stage, error_code=error_code)
        except BaseException:
            event = None
        if isinstance(event, DiagnosticEvent):
            return event
    return DiagnosticEvent(
        stage=stage,
        coordinator_state=_coordinator_state(coordinator),
        supervisor_state=_supervisor_state(coordinator),
        error_code=error_code,
    )


def run_supervised_scan(
    timeout_seconds: int | float,
    *,
    coordinator_factory: Callable[[str, ScanDeadline], ScanCoordinator] = ScanCoordinator,
    diagnostic_observer: Callable[[DiagnosticEvent], None] | None = None,
) -> ScanReport:
    """Run one scan through the coordinator and return only formal success."""
    try:
        deadline = ScanDeadline(timeout_seconds)
    except (TypeError, ValueError, OverflowError):
        raise SupervisedScanError("INVALID_TIMEOUT") from None

    session_id = uuid.uuid4().hex
    coordinator: ScanCoordinator | None = None
    cleanup_attempted = False
    path_snapshot = None
    try:
        _notify_diagnostic(
            diagnostic_observer,
            DiagnosticEvent(
                stage=DiagnosticStage.SERVICE_ENTERED,
                coordinator_state="NOT_CREATED",
                supervisor_state="NOT_CREATED",
            ),
        )
        try:
            path_snapshot = validate_path_snapshot(os.environ.get("PATH", ""))
        except Exception:
            pass
        if path_snapshot is None:
            raise SupervisedScanError("SCAN_FAILED")
        coordinator = coordinator_factory(session_id, deadline)
        set_observer = getattr(coordinator, "set_diagnostic_observer", None)
        if callable(set_observer):
            try:
                set_observer(diagnostic_observer)
            except BaseException:
                pass
        _notify_diagnostic(
            diagnostic_observer,
            DiagnosticEvent(
                stage=DiagnosticStage.COORDINATOR_CREATED,
                coordinator_state=_coordinator_state(coordinator),
                supervisor_state=_supervisor_state(coordinator),
            ),
        )
        decision = coordinator.start(
            remaining_timeout_ms=_remaining_timeout_ms(deadline), require_path_snapshot=True
        )
        if decision.lifecycle.stop_reason is not None:
            raise SupervisedScanError(_decision_error_code(decision))

        decision = coordinator.wait_ready()
        if not decision.facts.ready:
            raise SupervisedScanError(_decision_error_code(decision))

        try:
            decision = coordinator.send_start(path_snapshot=path_snapshot)
        finally:
            path_snapshot = None
        if not decision.facts.start_authorized:
            raise SupervisedScanError(_decision_error_code(decision))

        decision = coordinator.receive_worker_message(
            remaining_timeout_ms=_remaining_timeout_ms(deadline)
        )
        if decision.facts.candidate_count != 1:
            raise SupervisedScanError(_decision_error_code(decision))
        if decision.facts.report_validation.value != "confirmed":
            raise SupervisedScanError(_decision_error_code(decision))

        decision = coordinator.observe_process(_remaining_timeout_ms(deadline))
        if decision.lifecycle.stop_reason is not None:
            raise SupervisedScanError(_decision_error_code(decision))
        decision = coordinator.observe_job()
        if decision.lifecycle.stop_reason is not None:
            raise SupervisedScanError(_decision_error_code(decision))
        decision = coordinator.close_ipc()
        if decision.lifecycle.stop_reason is not None:
            raise SupervisedScanError(_decision_error_code(decision))
        cleanup_attempted = True
        decision = coordinator.close_resources()
        if (
            not decision.result_available
            or decision.lifecycle.state is not ScanLifecycleState.SUCCEEDED
        ):
            raise SupervisedScanError(_decision_error_code(decision))
        _notify_diagnostic(
            diagnostic_observer,
            _diagnostic_event(
                coordinator,
                stage=DiagnosticStage.SUCCEEDED,
                error_code=None,
            ),
        )
        return _report_from_verified_payload(coordinator.result_report)
    except SupervisedScanError as error:
        if coordinator is not None and not cleanup_attempted:
            cleanup_decision = _cleanup_after_failure(coordinator)
            if _decision_error_code(cleanup_decision) == "CLEANUP_UNCONFIRMED":
                raise SupervisedScanError("CLEANUP_UNCONFIRMED") from None
        if coordinator is not None:
            _notify_diagnostic(
                diagnostic_observer,
                _diagnostic_event(
                    coordinator,
                    stage=DiagnosticStage.FAILED,
                    error_code=error.code,
                ),
            )
        raise
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        if coordinator is not None and not cleanup_attempted:
            _cleanup_after_failure(coordinator)
        raise
    except Exception:
        cleanup_decision = None
        if coordinator is not None and not cleanup_attempted:
            cleanup_decision = _cleanup_after_failure(coordinator)
        if _decision_error_code(cleanup_decision) == "CLEANUP_UNCONFIRMED":
            failure_code = "CLEANUP_UNCONFIRMED"
        else:
            failure_code = "SCAN_FAILED"
            if coordinator is not None:
                _notify_diagnostic(
                    diagnostic_observer,
                    _diagnostic_event(
                        coordinator,
                        stage=DiagnosticStage.FAILED,
                        error_code=failure_code,
                    ),
                )
    finally:
        path_snapshot = None
    raise SupervisedScanError(failure_code) from None
