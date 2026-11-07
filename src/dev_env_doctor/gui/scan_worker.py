"""Qt worker that runs one supervised scan without touching UI objects."""

from PySide6.QtCore import QObject, Signal, Slot

from dev_env_doctor.core import supervised_scan
from dev_env_doctor.core.models import ScanReport
from dev_env_doctor.core.scan_control import ScanLifecycleState
from dev_env_doctor.core.scan_coordinator import (
    CoordinatorState,
    DiagnosticEvent,
    DiagnosticFailureCategory,
    DiagnosticJobStatus,
    DiagnosticResourceStatus,
    DiagnosticStage,
    DiagnosticWorkerExit,
    DiagnosticWorkerExitReason,
)

GUI_SCAN_TIMEOUT_SECONDS = 300
_SAFE_ERROR_CODES = frozenset(
    {
        "INVALID_TIMEOUT",
        "SCAN_FAILED",
        "SCAN_NOT_SUCCESSFUL",
        "REPORT_INVALID",
        "SCAN_TIMED_OUT",
        "CLEANUP_UNCONFIRMED",
    }
)
_SAFE_COORDINATOR_STATES = frozenset(state.value for state in CoordinatorState)
_SAFE_SUPERVISOR_STATES = frozenset(state.value for state in ScanLifecycleState)


def _safe_diagnostic_event(event: object) -> DiagnosticEvent | None:
    """Keep only finite, reviewed diagnostic values for GUI delivery."""
    if not isinstance(event, DiagnosticEvent):
        return None
    if not isinstance(event.stage, DiagnosticStage):
        return None
    if event.coordinator_state not in _SAFE_COORDINATOR_STATES:
        return None
    if event.supervisor_state not in _SAFE_SUPERVISOR_STATES:
        return None
    if event.error_code is not None and event.error_code not in _SAFE_ERROR_CODES:
        return None
    if not isinstance(event.worker_exit, DiagnosticWorkerExit):
        return None
    if not isinstance(event.job_status, DiagnosticJobStatus):
        return None
    if not isinstance(event.ipc_status, DiagnosticResourceStatus):
        return None
    if not isinstance(event.helper_threads, DiagnosticResourceStatus):
        return None
    if not isinstance(event.parent_resources, DiagnosticResourceStatus):
        return None
    if event.failure_category is not None and not isinstance(
        event.failure_category, DiagnosticFailureCategory
    ):
        return None
    if event.worker_exit_reason is not None and not isinstance(
        event.worker_exit_reason, DiagnosticWorkerExitReason
    ):
        return None
    return DiagnosticEvent(
        stage=event.stage,
        coordinator_state=event.coordinator_state,
        supervisor_state=event.supervisor_state,
        error_code=event.error_code,
        worker_exit=event.worker_exit,
        job_status=event.job_status,
        ipc_status=event.ipc_status,
        helper_threads=event.helper_threads,
        parent_resources=event.parent_resources,
        failure_category=event.failure_category,
        worker_exit_reason=event.worker_exit_reason,
    )


class ScanWorker(QObject):
    """Run the application-level supervised scan on a QThread."""

    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()
    diagnostic_event = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self._diagnostic_events: list[DiagnosticEvent] = []

    @property
    def diagnostic_events(self) -> list[DiagnosticEvent]:
        """Return the safe in-memory events observed during this run."""
        return list(self._diagnostic_events)

    @Slot()
    def run(self) -> None:
        """Execute one supervised scan and emit only a report or safe error code."""
        self._diagnostic_events.clear()

        def observe(event: object) -> None:
            safe_event = _safe_diagnostic_event(event)
            if safe_event is None:
                return
            self._diagnostic_events.append(safe_event)
            try:
                self.diagnostic_event.emit(safe_event)
            except BaseException:
                pass

        try:
            report: ScanReport = supervised_scan.run_supervised_scan(
                timeout_seconds=GUI_SCAN_TIMEOUT_SECONDS,
                diagnostic_observer=observe,
            )
        except supervised_scan.SupervisedScanError as error:
            self.failed.emit(error.code)
        except Exception:
            self.failed.emit("SCAN_FAILED")
        else:
            self.succeeded.emit(report)
        finally:
            self.finished.emit()
