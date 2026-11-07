import os
from unittest.mock import Mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtTest import QSignalSpy

from dev_env_doctor.core import runner
from dev_env_doctor.core.models import ScanReport
from dev_env_doctor.core.scan_coordinator import (
    DiagnosticEvent,
    DiagnosticResourceStatus,
    DiagnosticStage,
    DiagnosticWorkerExit,
)
from dev_env_doctor.core.supervised_scan import SupervisedScanError
from dev_env_doctor.gui import scan_worker as scan_worker_module
from dev_env_doctor.gui.scan_worker import ScanWorker


def test_worker_calls_supervised_service_once_with_approved_timeout(monkeypatch):
    report = ScanReport()
    service = Mock(return_value=report)
    monkeypatch.setattr(scan_worker_module.supervised_scan, "run_supervised_scan", service)
    runner_mock = Mock(side_effect=AssertionError("GUI worker must not call runner"))
    monkeypatch.setattr(runner, "run_scan", runner_mock)

    worker = ScanWorker()
    succeeded = QSignalSpy(worker.succeeded)
    failed = QSignalSpy(worker.failed)
    finished = QSignalSpy(worker.finished)
    worker.run()

    service.assert_called_once()
    assert service.call_args.kwargs["timeout_seconds"] == 300
    assert callable(service.call_args.kwargs["diagnostic_observer"])
    runner_mock.assert_not_called()
    assert succeeded.count() == 1
    assert succeeded.at(0)[0] is report
    assert failed.count() == 0
    assert finished.count() == 1


def test_worker_emits_fixed_error_code_for_supervised_failure(monkeypatch):
    service = Mock(side_effect=SupervisedScanError("SCAN_NOT_SUCCESSFUL"))
    monkeypatch.setattr(scan_worker_module.supervised_scan, "run_supervised_scan", service)

    worker = ScanWorker()
    succeeded = QSignalSpy(worker.succeeded)
    failed = QSignalSpy(worker.failed)
    finished = QSignalSpy(worker.finished)
    worker.run()

    assert succeeded.count() == 0
    assert failed.count() == 1
    assert failed.at(0)[0] == "SCAN_NOT_SUCCESSFUL"
    assert finished.count() == 1


@pytest.mark.parametrize("error_code", ["SCAN_TIMED_OUT", "CLEANUP_UNCONFIRMED"])
def test_worker_emits_specific_supervised_failure_codes(monkeypatch, error_code):
    service = Mock(side_effect=SupervisedScanError(error_code))
    monkeypatch.setattr(scan_worker_module.supervised_scan, "run_supervised_scan", service)

    worker = ScanWorker()
    succeeded = QSignalSpy(worker.succeeded)
    failed = QSignalSpy(worker.failed)
    finished = QSignalSpy(worker.finished)
    worker.run()

    service.assert_called_once()
    assert service.call_args.kwargs["timeout_seconds"] == 300
    assert callable(service.call_args.kwargs["diagnostic_observer"])
    assert succeeded.count() == 0
    assert failed.count() == 1
    assert failed.at(0)[0] == error_code
    assert finished.count() == 1


def test_worker_hides_unexpected_exception_text(monkeypatch):
    service = Mock(side_effect=RuntimeError("C:\\Users\\Secret\\token"))
    monkeypatch.setattr(scan_worker_module.supervised_scan, "run_supervised_scan", service)

    worker = ScanWorker()
    failed = QSignalSpy(worker.failed)
    worker.run()

    assert failed.count() == 1
    assert failed.at(0)[0] == "SCAN_FAILED"
    assert "Secret" not in failed.at(0)[0]


def test_worker_forwards_safe_diagnostic_events_in_order(monkeypatch):
    report = ScanReport()
    events = [
        DiagnosticEvent(
            stage=DiagnosticStage.STARTING_WORKER,
            coordinator_state="starting",
            supervisor_state="starting",
        ),
        DiagnosticEvent(
            stage=DiagnosticStage.FAILED,
            coordinator_state="failed",
            supervisor_state="failed",
            error_code="SCAN_FAILED",
            worker_exit=DiagnosticWorkerExit.NOT_OBSERVED,
            ipc_status=DiagnosticResourceStatus.UNCONFIRMED,
        ),
    ]

    def service(*, timeout_seconds, diagnostic_observer):
        assert timeout_seconds == 300
        for event in events:
            diagnostic_observer(event)
        return report

    monkeypatch.setattr(scan_worker_module.supervised_scan, "run_supervised_scan", service)
    worker = ScanWorker()
    observed = QSignalSpy(worker.diagnostic_event)
    succeeded = QSignalSpy(worker.succeeded)

    worker.run()

    assert succeeded.count() == 1
    assert observed.count() == len(events)
    assert [observed.at(index)[0].stage for index in range(observed.count())] == [
        event.stage for event in events
    ]
    assert worker.diagnostic_events == events


def test_worker_observer_failure_does_not_change_scan_result(monkeypatch):
    report = ScanReport()

    def service(*, timeout_seconds, diagnostic_observer):
        assert timeout_seconds == 300
        diagnostic_observer(
            DiagnosticEvent(
                stage=DiagnosticStage.SUCCEEDED,
                coordinator_state="closed",
                supervisor_state="succeeded",
            )
        )
        return report

    monkeypatch.setattr(scan_worker_module.supervised_scan, "run_supervised_scan", service)
    worker = ScanWorker()
    worker.diagnostic_event.connect(lambda _event: (_ for _ in ()).throw(RuntimeError("secret")))
    succeeded = QSignalSpy(worker.succeeded)
    failed = QSignalSpy(worker.failed)

    worker.run()

    assert succeeded.count() == 1
    assert failed.count() == 0
