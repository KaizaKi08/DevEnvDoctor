import json
import os
import socket
import threading
from unittest.mock import Mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop, QSize, Qt, QThread, QTimer
from PySide6.QtTest import QSignalSpy
from PySide6.QtWidgets import QApplication, QLabel, QListWidget, QPushButton

from dev_env_doctor.collectors.config_files import CodexConfigState
from dev_env_doctor.core.models import DiagnosticResult, ScanReport, Severity
from dev_env_doctor.core.rules.config_rules import codex_config_diagnostic
from dev_env_doctor.core.scan_coordinator import (
    DiagnosticEvent,
    DiagnosticJobStatus,
    DiagnosticResourceStatus,
    DiagnosticStage,
    DiagnosticWorkerExit,
)
from dev_env_doctor.core.scan_protocol import MessageType, decode_frame
from dev_env_doctor.core.scan_worker_entry import _candidate_payload, _message
from dev_env_doctor.core.supervised_scan import SupervisedScanError, _report_from_verified_payload
from dev_env_doctor.gui import main_window as main_window_module
from dev_env_doctor.gui import scan_worker as scan_worker_module
from dev_env_doctor.gui.main_window import MainWindow
from dev_env_doctor.reports import export_file


@pytest.fixture
def approved_report_export(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(export_file, "_REPORT_EXPORT_APPROVED", True)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    application = QApplication.instance()
    if application is None:
        application = QApplication(["dev-env-doctor-tests"])
    return application


def test_main_window_has_expected_title_size_and_scan_controls(qapp: QApplication) -> None:
    window = MainWindow()
    try:
        assert window.windowTitle() == "DevEnv Doctor"
        assert window.size() == QSize(1000, 680)
        assert window.findChild(QLabel, "productTitleLabel").text() == "DevEnv Doctor"
        assert window.findChild(QLabel, "statusLabel").text() == "尚未开始扫描"
        assert "环境诊断" in window.findChild(QLabel, "introLabel").text()
        assert window.findChild(QPushButton, "scanButton").isEnabled()
        assert not window.findChild(QPushButton, "exportJsonButton").isEnabled()
        assert not window.findChild(QPushButton, "exportHtmlButton").isEnabled()
        footer = window.findChild(QLabel, "privacyFooterLabel").text()
        assert "离线优先" in footer
        assert "隐私优先" in footer
    finally:
        window.close()


def _replace_scan_dependencies(monkeypatch: pytest.MonkeyPatch) -> Mock:
    scan = Mock()
    monkeypatch.setattr(scan_worker_module.supervised_scan, "run_supervised_scan", scan)
    return scan


def _report_with_diagnostics(count: int) -> ScanReport:
    return ScanReport(
        diagnostics=[
            DiagnosticResult(
                rule_id="COMMAND_TIMEOUT",
                title="Test diagnostic",
                severity=Severity.INFO,
                summary="Synthetic test result.",
            )
            for index in range(count)
        ]
    )


def _diagnostic(
    rule_id: str,
    title: str,
    severity: Severity,
    summary: str,
    *,
    status: str = "found",
    suggestion: str = "",
    evidence: list[str] | None = None,
) -> DiagnosticResult:
    return DiagnosticResult(
        rule_id=rule_id,
        title=title,
        severity=severity,
        summary=summary,
        status=status,
        suggestion=suggestion,
        evidence=evidence or [],
    )


def _show_report(window: MainWindow, diagnostics: list[DiagnosticResult]) -> ScanReport:
    report = ScanReport(diagnostics=diagnostics)
    window._on_scan_succeeded(report)
    return report


def test_success_displays_results_but_keeps_report_export_disabled(qapp: QApplication) -> None:
    window = MainWindow()
    try:
        report = _show_report(window, _report_with_diagnostics(1).diagnostics)
        assert window._current_report is report
        assert window.findChild(QListWidget, "diagnosticListWidget").count() == 1
        assert not window.export_json_button.isEnabled()
        assert not window.export_html_button.isEnabled()
    finally:
        window.close()


@pytest.mark.parametrize(
    ("state", "title", "summary_word"),
    [
        (CodexConfigState.PRESENT, "Codex 配置文件存在", "本地普通文件"),
        (CodexConfigState.MISSING, "Codex 配置文件缺失", "未找到"),
        (CodexConfigState.INACCESSIBLE, "Codex 配置不可访问", "访问被拒绝"),
        (CodexConfigState.UNSAFE, "Codex 配置路径未通过安全检查", "本地固定卷"),
        (CodexConfigState.UNVERIFIED, "Codex 配置无法验证", "存在性未知"),
    ],
)
def test_codex_config_diagnostic_survives_ipc_and_displays_reviewed_details(
    qapp: QApplication, state: CodexConfigState, title: str, summary_word: str
) -> None:
    original = _report_with_diagnostics(1)
    diagnostic = codex_config_diagnostic(state, cli_found=True)
    original.diagnostics.append(diagnostic)
    frame = _message(
        "a" * 32, 1, MessageType.RESULT_CANDIDATE, {"report": _candidate_payload(original)}
    )
    received = _report_from_verified_payload(decode_frame(frame)["payload"]["report"])
    window = MainWindow()
    try:
        window._on_scan_succeeded(received)
        results = window.findChild(QListWidget, "diagnosticListWidget")
        assert results.count() == 2
        assert title in results.item(1).text()
        results.setCurrentRow(1)
        assert summary_word in window.findChild(QLabel, "detailSummaryLabel").text()
        assert diagnostic.suggestion == window.findChild(QLabel, "detailSuggestionLabel").text()
        assert "已发现" in window.findChild(QLabel, "detailEvidenceLabel").text()
        assert not window.export_json_button.isEnabled()
        assert not window.export_html_button.isEnabled()
    finally:
        window.close()


@pytest.mark.parametrize("extension", ["json", "html"])
def test_direct_handler_denies_export_even_if_button_was_enabled(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch, tmp_path, extension: str
) -> None:
    destination = tmp_path / f"report.{extension}"
    destination.write_bytes(b"keep-existing-report")
    dialog = Mock(return_value=(str(destination), ""))
    monkeypatch.setattr(main_window_module.QFileDialog, "getSaveFileName", dialog)
    monkeypatch.setattr(main_window_module.QMessageBox, "information", Mock())
    window = MainWindow()
    try:
        _show_report(window, _report_with_diagnostics(1).diagnostics)
        getattr(window, f"export_{extension}_button").setEnabled(True)
        getattr(window, f"_export_{extension}_report")()
        dialog.assert_not_called()
        assert destination.read_bytes() == b"keep-existing-report"
        assert not window.export_json_button.isEnabled()
        assert not window.export_html_button.isEnabled()
    finally:
        window.close()


@pytest.mark.usefixtures("approved_report_export")
@pytest.mark.parametrize("extension", ["json", "html"])
def test_writer_denies_save_if_permission_is_lost_in_dialog(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch, tmp_path, extension: str
) -> None:
    destination = tmp_path / f"report.{extension}"
    destination.write_bytes(b"keep-existing-report")
    window = MainWindow()

    def choose_path(*args):
        export_file.revoke_report_export()
        return str(destination), ""

    dialog = Mock(side_effect=choose_path)
    saved = Mock()
    monkeypatch.setattr(main_window_module.QFileDialog, "getSaveFileName", dialog)
    monkeypatch.setattr(main_window_module.QMessageBox, "information", saved)
    try:
        _show_report(window, _report_with_diagnostics(1).diagnostics)
        assert getattr(window, f"export_{extension}_button").isEnabled()
        getattr(window, f"_export_{extension}_report")()
        assert dialog.call_args.args[2] == f"dev-env-doctor-report.{extension}"
        assert destination.read_bytes() == b"keep-existing-report"
        assert not window.export_json_button.isEnabled()
        assert not window.export_html_button.isEnabled()
        saved.assert_not_called()
    finally:
        window.close()


@pytest.mark.usefixtures("approved_report_export")
@pytest.mark.parametrize("extension", ["json", "html"])
def test_gui_export_redacts_local_hostname_after_candidate_round_trip(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch, extension: str
) -> None:
    hostname = "PHASE12-HOST-CANARY-62F8"
    monkeypatch.setattr(socket, "gethostname", Mock(return_value=hostname))
    writer = Mock()
    dialog = Mock(return_value=(f"unused.{extension}", ""))
    monkeypatch.setattr(export_file, "write_report_file", writer)
    monkeypatch.setattr(main_window_module.QFileDialog, "getSaveFileName", dialog)
    monkeypatch.setattr(main_window_module.QMessageBox, "information", Mock())
    report = _report_with_diagnostics(1)
    report.diagnostics[0].title = f"Local host {hostname}. Service name."
    frame = _message(
        "a" * 32, 2, MessageType.RESULT_CANDIDATE, {"report": _candidate_payload(report)}
    )
    received = _report_from_verified_payload(decode_frame(frame)["payload"]["report"])

    window = MainWindow()
    try:
        window._on_scan_succeeded(received)
        item = window.findChild(QListWidget, "diagnosticListWidget").item(0)
        assert hostname not in item.text()
        getattr(window, f"export_{extension}_button").click()
        writer.assert_called_once()
        assert hostname.encode() not in writer.call_args.args[1]
        assert dialog.call_args.args[2] == f"dev-env-doctor-report.{extension}"
    finally:
        window.close()


@pytest.mark.usefixtures("approved_report_export")
def test_unavailable_hostname_disables_export_without_hiding_results(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(socket, "gethostname", Mock(side_effect=OSError("synthetic lookup error")))
    dialog = Mock()
    monkeypatch.setattr(main_window_module.QFileDialog, "getSaveFileName", dialog)
    window = MainWindow()
    try:
        _show_report(window, _report_with_diagnostics(1).diagnostics)
        assert window.findChild(QListWidget, "diagnosticListWidget").count() == 1
        assert not window.export_json_button.isEnabled()
        assert not window.export_html_button.isEnabled()
        window.export_json_button.setEnabled(True)
        window._export_json_report()
        dialog.assert_not_called()
    finally:
        window.close()


def _thread_finished_spy(thread) -> QSignalSpy:
    return QSignalSpy(thread.finished)


def _wait_for_thread_finished(
    thread,
    spy: QSignalSpy,
    release: threading.Event,
) -> None:
    loop = QEventLoop()
    thread.finished.connect(loop.quit)
    QTimer.singleShot(0, release.set)
    QTimer.singleShot(5000, loop.quit)
    loop.exec()
    assert spy.count() == 1


def test_window_creation_does_not_start_scan(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_scan_mock = _replace_scan_dependencies(monkeypatch)

    window = MainWindow()
    try:
        scan_button = window.findChild(QPushButton, "scanButton")
        assert scan_button.text() == "开始扫描"
        assert scan_button.isEnabled()
        assert window.findChild(QLabel, "statusLabel").text() == "尚未开始扫描"

        run_scan_mock.assert_not_called()
    finally:
        window.close()


def test_click_runs_scan_in_background_and_restores_ui_after_success(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_scan_mock = _replace_scan_dependencies(monkeypatch)
    started = threading.Event()
    release = threading.Event()
    worker_thread_ids: list[int] = []
    report = _report_with_diagnostics(3)

    def blocked_scan(*, timeout_seconds: int, diagnostic_observer) -> ScanReport:
        assert timeout_seconds == 300
        assert callable(diagnostic_observer)
        worker_thread_ids.append(threading.get_ident())
        started.set()
        assert release.wait(timeout=5)
        return report

    run_scan_mock.side_effect = blocked_scan
    window = MainWindow()
    window.show()
    scan_button = window.findChild(QPushButton, "scanButton")
    try:
        _show_report(
            window,
            [
                _diagnostic(
                    "COMMAND_TIMEOUT",
                    "git version check timed out",
                    Severity.WARNING,
                    "Synthetic.",
                )
            ],
        )
        export_button = window.findChild(QPushButton, "exportJsonButton")
        export_html_button = window.findChild(QPushButton, "exportHtmlButton")
        assert not export_button.isEnabled()
        assert not export_html_button.isEnabled()

        scan_button.click()
        thread = window._scan_thread
        assert thread is not None
        finished = _thread_finished_spy(thread)
        assert started.wait(timeout=5)
        assert not scan_button.isEnabled()
        assert not export_button.isEnabled()
        assert not export_html_button.isEnabled()
        assert window._current_report is None
        assert window.findChild(QLabel, "statusLabel").text() == "正在扫描…"

        scan_button.click()
        window._start_scan()
        assert run_scan_mock.call_count == 1

        _wait_for_thread_finished(thread, finished, release)
        qapp.processEvents()

        assert len(worker_thread_ids) == 1
        assert worker_thread_ids[0] != threading.get_ident()
        assert window.findChild(QLabel, "statusLabel").text() == "扫描完成，共 3 条诊断结果。"
        assert window._current_report is report
        assert window.findChild(QListWidget, "diagnosticListWidget").count() == 3
        assert scan_button.isEnabled()
        assert not export_button.isEnabled()
        assert not export_html_button.isEnabled()
        assert run_scan_mock.call_count == 1
    finally:
        release.set()
        window.close()
        qapp.processEvents()


def test_scan_failure_shows_generic_message_and_restores_button(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_scan_mock = _replace_scan_dependencies(monkeypatch)
    started = threading.Event()
    release = threading.Event()

    def failing_scan(*, timeout_seconds: int, diagnostic_observer) -> ScanReport:
        assert timeout_seconds == 300
        assert callable(diagnostic_observer)
        started.set()
        assert release.wait(timeout=5)
        raise RuntimeError("fictional token=do-not-display")

    run_scan_mock.side_effect = failing_scan
    window = MainWindow()
    window.show()
    scan_button = window.findChild(QPushButton, "scanButton")
    try:
        _show_report(window, [_diagnostic("COMMAND_TIMEOUT", "old", Severity.WARNING, "old")])
        scan_button.click()
        thread = window._scan_thread
        assert thread is not None
        finished = _thread_finished_spy(thread)
        assert started.wait(timeout=5)
        assert not scan_button.isEnabled()

        _wait_for_thread_finished(thread, finished, release)
        qapp.processEvents()

        status = window.findChild(QLabel, "statusLabel").text()
        description = window.findChild(QLabel, "statusDescriptionLabel").text()
        assert status == "扫描失败"
        assert "do-not-display" not in status + description
        assert window._current_report is None
        assert window.findChild(QListWidget, "diagnosticListWidget").count() == 0
        assert scan_button.isEnabled()
        assert not window.findChild(QPushButton, "exportJsonButton").isEnabled()
        assert not window.findChild(QPushButton, "exportHtmlButton").isEnabled()
        run_scan_mock.assert_called_once()
        assert run_scan_mock.call_args.kwargs["timeout_seconds"] == 300
        assert callable(run_scan_mock.call_args.kwargs["diagnostic_observer"])
    finally:
        release.set()
        window.close()
        qapp.processEvents()


@pytest.mark.parametrize("error_code", ["SCAN_TIMED_OUT", "CLEANUP_UNCONFIRMED"])
def test_specific_supervised_failures_clear_report_and_keep_exports_disabled(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    error_code: str,
) -> None:
    run_scan_mock = _replace_scan_dependencies(monkeypatch)
    run_scan_mock.side_effect = SupervisedScanError(error_code)
    window = MainWindow()
    window.show()
    scan_button = window.findChild(QPushButton, "scanButton")
    try:
        _show_report(window, [_diagnostic("COMMAND_TIMEOUT", "old", Severity.WARNING, "old")])
        scan_button.click()
        thread = window._scan_thread
        assert thread is not None
        finished = _thread_finished_spy(thread)

        _wait_for_thread_finished(thread, finished, threading.Event())
        qapp.processEvents()

        assert window.findChild(QLabel, "statusLabel").text() == "扫描失败"
        assert window._current_report is None
        assert window.findChild(QListWidget, "diagnosticListWidget").count() == 0
        assert not window.findChild(QPushButton, "exportJsonButton").isEnabled()
        assert not window.findChild(QPushButton, "exportHtmlButton").isEnabled()
        assert scan_button.isEnabled()
        assert error_code in window.findChild(QLabel, "technicalDiagnosticsLabel").text()
        run_scan_mock.assert_called_once()
        assert run_scan_mock.call_args.kwargs["timeout_seconds"] == 300
        assert callable(run_scan_mock.call_args.kwargs["diagnostic_observer"])
    finally:
        window.close()
        qapp.processEvents()


def test_close_is_deferred_while_scan_is_running_without_terminating_thread(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_scan_mock = _replace_scan_dependencies(monkeypatch)
    started = threading.Event()
    release = threading.Event()

    def blocked_scan(*, timeout_seconds: int, diagnostic_observer) -> ScanReport:
        assert timeout_seconds == 300
        assert callable(diagnostic_observer)
        started.set()
        assert release.wait(timeout=5)
        return _report_with_diagnostics(0)

    run_scan_mock.side_effect = blocked_scan
    window = MainWindow()
    window.show()
    try:
        window.findChild(QPushButton, "scanButton").click()
        thread = window._scan_thread
        assert thread is not None
        finished = _thread_finished_spy(thread)
        assert started.wait(timeout=5)

        window.close()
        assert window.isVisible()
        assert "扫描仍在运行" in window.findChild(QLabel, "statusDescriptionLabel").text()
        assert thread.isRunning()

        _wait_for_thread_finished(thread, finished, release)
        qapp.processEvents()
        assert window._scan_thread is None
        assert window.findChild(QPushButton, "scanButton").isEnabled()
        window.close()
        assert not window.isVisible()
    finally:
        release.set()
        if window._scan_thread is not None:
            thread = window._scan_thread
            if thread.isRunning():
                finished = _thread_finished_spy(thread)
                release.set()
                _wait_for_thread_finished(thread, finished, release)
            qapp.processEvents()
        window.close()
        qapp.processEvents()


def test_success_slot_runs_on_qt_gui_thread(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _replace_scan_dependencies(monkeypatch)
    service.return_value = ScanReport()
    window = MainWindow()
    slot_threads: list[bool] = []
    original_populate_report = window._populate_report

    def recording_populate_report(report: ScanReport) -> bool:
        slot_threads.append(QThread.currentThread() == qapp.thread())
        return original_populate_report(report)

    monkeypatch.setattr(window, "_populate_report", recording_populate_report)
    window.show()
    try:
        window.findChild(QPushButton, "scanButton").click()
        thread = window._scan_thread
        assert thread is not None
        finished = _thread_finished_spy(thread)

        _wait_for_thread_finished(thread, finished, threading.Event())
        qapp.processEvents()

        assert slot_threads == [True]
    finally:
        if window._scan_thread is not None and window._scan_thread.isRunning():
            window._scan_thread.quit()
            window._scan_thread.wait(5000)
        window.close()
        qapp.processEvents()


def test_failure_slot_runs_on_qt_gui_thread(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _replace_scan_dependencies(monkeypatch)
    service.side_effect = SupervisedScanError("SCAN_NOT_SUCCESSFUL")
    window = MainWindow()
    slot_threads: list[bool] = []
    original_clear_report = window._clear_report

    def recording_clear_report(empty_state: str) -> None:
        slot_threads.append(QThread.currentThread() == qapp.thread())
        original_clear_report(empty_state)

    monkeypatch.setattr(window, "_clear_report", recording_clear_report)
    window.show()
    try:
        window.findChild(QPushButton, "scanButton").click()
        thread = window._scan_thread
        assert thread is not None
        slot_threads.clear()
        finished = _thread_finished_spy(thread)

        _wait_for_thread_finished(thread, finished, threading.Event())
        qapp.processEvents()

        assert slot_threads == [True]
    finally:
        if window._scan_thread is not None and window._scan_thread.isRunning():
            window._scan_thread.quit()
            window._scan_thread.wait(5000)
        window.close()
        qapp.processEvents()


def test_technical_diagnostics_render_safe_event_state_and_result(
    qapp: QApplication,
) -> None:
    window = MainWindow()
    event = DiagnosticEvent(
        stage=DiagnosticStage.FAILED,
        coordinator_state="failed",
        supervisor_state="stopping",
        error_code="CLEANUP_UNCONFIRMED",
        worker_exit=DiagnosticWorkerExit.NOT_OBSERVED,
        job_status=DiagnosticJobStatus.UNCONFIRMED,
        ipc_status=DiagnosticResourceStatus.CLOSED_CONFIRMED,
        helper_threads=DiagnosticResourceStatus.CLOSED_CONFIRMED,
        parent_resources=DiagnosticResourceStatus.UNCONFIRMED,
    )
    try:
        window._on_diagnostic_event(event)
        window._on_scan_failed("CLEANUP_UNCONFIRMED")
        text = window.findChild(QLabel, "technicalDiagnosticsLabel").text()
        assert "FAILED" in text
        assert "CLEANUP_UNCONFIRMED" in text
        assert "NOT_OBSERVED" in text
        assert "CLOSED_CONFIRMED" in text
        assert "UNCONFIRMED" in text
        assert "C:\\Users" not in text
        assert "traceback" not in text.lower()
    finally:
        window.close()


def test_main_window_can_be_shown_offscreen(qapp: QApplication) -> None:
    window = MainWindow()
    try:
        window.show()
        qapp.processEvents()
        assert window.isVisible()
    finally:
        window.close()
        qapp.processEvents()


def test_report_populates_list_and_calculates_severity_and_status_counts(
    qapp: QApplication,
) -> None:
    window = MainWindow()
    diagnostics = [
        _diagnostic(
            "COMMAND_VERSION",
            "python version",
            Severity.INFO,
            "The tool version was verified.",
            status="passed",
            evidence=["Verified version: 3.13.9"],
        ),
        _diagnostic(
            "PATH_MISSING_ENTRY",
            "PATH contains unavailable local directories",
            Severity.WARNING,
            "1 local absolute PATH item(s) were not found.",
            status="found",
            evidence=["Unavailable item positions: 4."],
        ),
        _diagnostic(
            "COMMAND_TIMEOUT",
            "git version check timed out",
            Severity.ERROR,
            "The tool could not be verified during this check.",
            status="error",
        ),
    ]
    try:
        report = _show_report(window, diagnostics)
        result_list = window.findChild(QListWidget, "diagnosticListWidget")
        assert result_list.count() == len(report.diagnostics)
        assert result_list.item(0).data(Qt.ItemDataRole.UserRole) is diagnostics[0]
        assert "信息" in result_list.item(0).text()
        assert "通过" in result_list.item(0).text()
        assert "警告" in result_list.item(1).text()
        assert "发现" in result_list.item(1).text()
        assert "错误" in result_list.item(2).text()
        assert "错误" in result_list.item(2).text()
        assert window.findChild(QLabel, "diagnosticCountLabel").text() == "诊断总数：3"
        assert window.findChild(QLabel, "diagnosticStatisticsLabel").text() == (
            "严重程度：错误 1 · 警告 1 · 信息 1 · 未知 0；"
            "状态：错误 1 · 通过 1 · 发现 1 · 已跳过 0 · 未知 0"
        )
        assert window.findChild(QLabel, "emptyStateLabel").isHidden()
    finally:
        window.close()


def test_empty_report_shows_explicit_empty_state_and_zero_summary(qapp: QApplication) -> None:
    window = MainWindow()
    try:
        _show_report(window, [])
        assert window.findChild(QListWidget, "diagnosticListWidget").count() == 0
        assert window.findChild(QLabel, "emptyStateLabel").text() == "扫描完成，没有诊断项。"
        assert window.findChild(QLabel, "diagnosticCountLabel").text() == "诊断总数：0"
    finally:
        window.close()


def test_selecting_result_updates_detail_and_clearing_selection_resets_it(
    qapp: QApplication,
) -> None:
    window = MainWindow()
    diagnostics = [
        _diagnostic(
            "PATH_EMPTY_ENTRY",
            "PATH contains empty entries",
            Severity.WARNING,
            "PATH contains 2 empty item(s).",
            status="found",
            suggestion="Review empty separators; this report does not change PATH.",
            evidence=["Empty item positions: 2, 5."],
        ),
        _diagnostic(
            "COMMAND_VERSION",
            "python version",
            Severity.INFO,
            "The tool version was verified.",
            status="passed",
            suggestion="Version confirmed.",
            evidence=["Verified version: 3.13.9"],
        ),
    ]
    try:
        _show_report(window, diagnostics)
        result_list = window.findChild(QListWidget, "diagnosticListWidget")
        result_list.setCurrentRow(0)
        assert window.findChild(QLabel, "detailTitleLabel").text() == diagnostics[0].title
        assert window.findChild(QLabel, "detailSummaryLabel").text() == diagnostics[0].summary
        assert window.findChild(QLabel, "detailSeverityValueLabel").text() == "警告"
        assert window.findChild(QLabel, "detailStatusValueLabel").text() == "发现"
        assert window.findChild(QLabel, "detailSuggestionLabel").text() == diagnostics[0].suggestion
        assert window.findChild(QLabel, "detailEvidenceLabel").text() == (
            "Empty item positions: 2, 5."
        )

        result_list.setCurrentRow(1)
        assert window.findChild(QLabel, "detailTitleLabel").text() == "python version"
        assert window.findChild(QLabel, "detailEvidenceLabel").text() == "Verified version: 3.13.9"

        result_list.setCurrentItem(None)
        assert window.findChild(QLabel, "detailTitleLabel").text() == "请选择一条诊断项"
        assert window.findChild(QLabel, "detailSummaryLabel").text() == ""
        assert window.findChild(QLabel, "detailEvidenceLabel").text() == "没有可安全展示的证据。"
    finally:
        window.close()


@pytest.mark.usefixtures("approved_report_export")
def test_unreviewed_evidence_is_not_shown_in_details(qapp: QApplication) -> None:
    window = MainWindow()
    secret_path = r"C:\Users\FictionalUser\Private Work\api-token.txt"
    secret_value = "fictional-evidence-secret"
    diagnostic = _diagnostic(
        "FUTURE_UNREVIEWED_RULE",
        "Future diagnostic",
        Severity.INFO,
        "Synthetic future result.",
        evidence=[f"Inspect {secret_path} token={secret_value}"],
    )
    try:
        _show_report(window, [diagnostic])
        assert not window.findChild(QPushButton, "exportJsonButton").isEnabled()
        assert not window.findChild(QPushButton, "exportHtmlButton").isEnabled()
        result_list = window.findChild(QListWidget, "diagnosticListWidget")
        result_list.setCurrentRow(0)
        detail_text = window.findChild(QLabel, "detailEvidenceLabel").text()
        assert detail_text == "没有可安全展示的证据。"
        assert "FictionalUser" not in detail_text
        assert "Private Work" not in detail_text
        assert "api-token.txt" not in detail_text
        assert secret_value not in detail_text
    finally:
        window.close()


def test_known_rule_rejects_unexpected_evidence_format(qapp: QApplication) -> None:
    window = MainWindow()
    secret_path = r"C:\Users\FictionalUser\Private Work\api-token.txt"
    secret_value = "fictional-known-rule-secret"
    diagnostic = _diagnostic(
        "PATH_ENTRY_UNKNOWN",
        "Some PATH entries were not checked",
        Severity.INFO,
        "1 ambiguous, remote, or unsupported item(s) were not checked.",
        status="skipped",
        evidence=[f"Unverified item positions: {secret_path} token={secret_value}"],
    )
    try:
        _show_report(window, [diagnostic])
        result_list = window.findChild(QListWidget, "diagnosticListWidget")
        result_list.setCurrentRow(0)
        detail_text = window.findChild(QLabel, "detailEvidenceLabel").text()
        assert detail_text == "没有可安全展示的证据。"
        assert "FictionalUser" not in detail_text
        assert "Private Work" not in detail_text
        assert "api-token.txt" not in detail_text
        assert secret_value not in detail_text
    finally:
        window.close()


def test_statistics_errors_are_reported_without_raising(qapp: QApplication) -> None:
    window = MainWindow()
    malformed_report = ScanReport()
    malformed_report.diagnostics = [object()]
    try:
        window._update_summary(malformed_report)
        assert window.findChild(QLabel, "diagnosticCountLabel").text() == "诊断总数：不可用"
        assert window.findChild(QLabel, "diagnosticStatisticsLabel").text() == "统计暂不可用。"
    finally:
        window.close()


def test_unknown_severity_is_rendered_as_unknown_without_crashing(qapp: QApplication) -> None:
    window = MainWindow()
    diagnostic = _diagnostic(
        "COMMAND_TIMEOUT",
        "Tool probe timed out",
        Severity.INFO,
        "Synthetic result.",
    )
    diagnostic.severity = "future-severity"

    try:
        _show_report(window, [diagnostic])

        result_list = window.findChild(QListWidget, "diagnosticListWidget")
        assert result_list.count() == 1
        assert "未知" in result_list.item(0).text()
        statistics = window.findChild(QLabel, "diagnosticStatisticsLabel").text()
        assert "严重程度：" in statistics
        assert "未知 1" in statistics
        result_list.setCurrentRow(0)
        assert window.findChild(QLabel, "detailSeverityValueLabel").text() == "未知"
    finally:
        window.close()


def test_unknown_status_is_included_in_list_and_unknown_statistics(qapp: QApplication) -> None:
    window = MainWindow()
    diagnostic = _diagnostic(
        "COMMAND_TIMEOUT",
        "Tool probe timed out",
        Severity.WARNING,
        "Synthetic result.",
    )
    diagnostic.status = "future-status"

    try:
        _show_report(window, [diagnostic])

        result_list = window.findChild(QListWidget, "diagnosticListWidget")
        assert result_list.count() == 1
        assert "未知" in result_list.item(0).text()
        statistics = window.findChild(QLabel, "diagnosticStatisticsLabel").text()
        assert "状态：" in statistics
        assert "未知 1" in statistics
        result_list.setCurrentRow(0)
        assert window.findChild(QLabel, "detailStatusValueLabel").text() == "未知"
    finally:
        window.close()


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "label_name", "safe_fallback"),
    [
        ("title", object(), "detailTitleLabel", "诊断标题不可用。"),
        ("title", "   ", "detailTitleLabel", "诊断标题不可用。"),
        ("summary", object(), "detailSummaryLabel", "摘要不可用。"),
        ("summary", "s" * 4097, "detailSummaryLabel", "摘要不可用。"),
        ("suggestion", object(), "detailSuggestionLabel", "建议不可用。"),
        ("evidence", object(), "detailEvidenceLabel", "没有可安全展示的证据。"),
        ("evidence", [object()], "detailEvidenceLabel", "没有可安全展示的证据。"),
    ],
)
def test_non_string_display_fields_are_replaced_with_safe_fallbacks(
    qapp: QApplication,
    field_name: str,
    invalid_value: object,
    label_name: str,
    safe_fallback: str,
) -> None:
    window = MainWindow()
    diagnostic = _diagnostic(
        "COMMAND_TIMEOUT",
        "Tool probe timed out",
        Severity.WARNING,
        "Synthetic result.",
        suggestion="Synthetic suggestion.",
        evidence=["unexpected evidence"],
    )
    setattr(diagnostic, field_name, invalid_value)

    try:
        _show_report(window, [diagnostic])
        window.findChild(QListWidget, "diagnosticListWidget").setCurrentRow(0)

        displayed = window.findChild(QLabel, label_name).text()
        assert displayed == safe_fallback
        assert "object at" not in displayed
        assert "unexpected evidence" not in displayed
    finally:
        window.close()


@pytest.mark.parametrize(
    "version",
    [
        "3.13.9\nfictional token=hidden",
        "٣.١٣.٩",
        f"1.{('1' * 158)}.2",
    ],
)
def test_version_evidence_rejects_newlines_unicode_digits_and_runner_overlength(
    qapp: QApplication,
    version: str,
) -> None:
    window = MainWindow()
    diagnostic = _diagnostic(
        "COMMAND_VERSION",
        "python version",
        Severity.INFO,
        "Synthetic version result.",
        status="passed",
        evidence=[f"Verified version: {version}"],
    )

    try:
        _show_report(window, [diagnostic])
        window.findChild(QListWidget, "diagnosticListWidget").setCurrentRow(0)
        evidence_text = window.findChild(QLabel, "detailEvidenceLabel").text()

        assert evidence_text == "没有可安全展示的证据。"
        assert "fictional" not in evidence_text
        assert "٣" not in evidence_text
    finally:
        window.close()


def test_success_slot_rejects_damaged_report_and_restores_consistent_ui(
    qapp: QApplication,
) -> None:
    window = MainWindow()
    damaged_report = ScanReport()
    damaged_report.diagnostics = [object()]
    window.scan_button.setEnabled(False)
    window._status_label.setText("正在扫描…")

    try:
        window._on_scan_succeeded(damaged_report)
        window._on_scan_thread_finished()

        assert window._current_report is None
        assert not window.findChild(QPushButton, "exportJsonButton").isEnabled()
        assert not window.findChild(QPushButton, "exportHtmlButton").isEnabled()
        assert window.findChild(QListWidget, "diagnosticListWidget").count() == 0
        assert window.findChild(QLabel, "statusLabel").text() == "扫描失败"
        assert window.findChild(QLabel, "diagnosticCountLabel").text() == "诊断总数：—"
        assert window.scan_button.isEnabled()
        assert window._scan_outcome_received
    finally:
        window.close()


def test_redaction_failure_uses_safe_text_fallback(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dev_env_doctor.gui import main_window as main_window_module

    window = MainWindow()
    diagnostic = _diagnostic(
        "COMMAND_TIMEOUT",
        "Original title",
        Severity.WARNING,
        "Original summary",
    )
    monkeypatch.setattr(
        main_window_module,
        "redact_text",
        Mock(side_effect=RuntimeError("fictional token=redactor-failure")),
    )

    try:
        _show_report(window, [diagnostic])
        window.findChild(QListWidget, "diagnosticListWidget").setCurrentRow(0)

        assert window.findChild(QLabel, "detailTitleLabel").text() == "诊断标题不可用。"
        assert window.findChild(QLabel, "detailSummaryLabel").text() == "摘要不可用。"
        assert "redactor-failure" not in window.findChild(QLabel, "detailSummaryLabel").text()
    finally:
        window.close()


@pytest.mark.usefixtures("approved_report_export")
def test_export_json_saves_utf8_report_and_uses_expected_dialog_options(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    window = MainWindow()
    destination = tmp_path / "dev-env-doctor-report.json"
    _show_report(
        window,
        [
            _diagnostic(
                "COMMAND_TIMEOUT",
                "git version check timed out",
                Severity.WARNING,
                "Synthetic.",
            )
        ],
    )
    dialog = Mock(return_value=(str(destination), "JSON 文件 (*.json)"))
    information = Mock()
    monkeypatch.setattr(main_window_module.QFileDialog, "getSaveFileName", dialog)
    monkeypatch.setattr(main_window_module.QMessageBox, "information", information)

    try:
        window.findChild(QPushButton, "exportJsonButton").click()

        assert destination.is_file()
        parsed = json.loads(destination.read_text(encoding="utf-8"))
        assert parsed["summary"]["total"] == len(parsed["diagnostics"]) == 1
        assert dialog.call_args.args[2] == "dev-env-doctor-report.json"
        assert "*.json" in dialog.call_args.args[3]
        information.assert_called_once()
        assert information.call_args.args[1:] == ("导出完成", "JSON 报告已保存。")
    finally:
        window.close()


@pytest.mark.usefixtures("approved_report_export")
def test_cancelled_json_save_does_not_write_or_change_report(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    window = MainWindow()
    report = _report_with_diagnostics(1)
    report = _show_report(window, report.diagnostics)
    warning = Mock()
    information = Mock()
    monkeypatch.setattr(
        main_window_module.QFileDialog,
        "getSaveFileName",
        Mock(return_value=("", "JSON 文件 (*.json)")),
    )
    monkeypatch.setattr(main_window_module.QMessageBox, "warning", warning)
    monkeypatch.setattr(main_window_module.QMessageBox, "information", information)

    try:
        window.findChild(QPushButton, "exportJsonButton").click()

        assert list(tmp_path.iterdir()) == []
        assert window._current_report is report
        assert window.findChild(QPushButton, "exportJsonButton").isEnabled()
        assert window.findChild(QPushButton, "exportHtmlButton").isEnabled()
        warning.assert_not_called()
        information.assert_not_called()
    finally:
        window.close()


@pytest.mark.usefixtures("approved_report_export")
def test_json_save_failure_shows_fixed_message_without_exception_text(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingSaveFile:
        def __init__(self, _path: str) -> None:
            raise OSError(r"C:\Users\FictionalUser\secret token=fictional-write-error")

    window = MainWindow()
    _show_report(window, _report_with_diagnostics(1).diagnostics)
    warning = Mock()
    monkeypatch.setattr(
        main_window_module.QFileDialog,
        "getSaveFileName",
        Mock(return_value=(r"C:\Users\FictionalUser\report.json", "JSON 文件 (*.json)")),
    )
    monkeypatch.setattr(export_file, "QSaveFile", FailingSaveFile)
    monkeypatch.setattr(main_window_module.QMessageBox, "warning", warning)

    try:
        window.findChild(QPushButton, "exportJsonButton").click()

        warning.assert_called_once()
        message = " ".join(str(part) for part in warning.call_args.args[1:])
        assert "无法保存 JSON 报告" in message
        assert "FictionalUser" not in message
        assert "fictional-write-error" not in message
        assert window._current_report is not None
        assert window.findChild(QPushButton, "exportJsonButton").isEnabled()
        assert window.findChild(QPushButton, "exportHtmlButton").isEnabled()
    finally:
        window.close()


@pytest.mark.parametrize("failure_branch", ["short_write", "write_exception", "commit"])
@pytest.mark.usefixtures("approved_report_export")
def test_json_save_write_or_commit_failure_is_safe_and_preserves_report(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    failure_branch: str,
) -> None:
    window = MainWindow()
    report = _show_report(window, _report_with_diagnostics(1).diagnostics)
    target_path = r"C:\Users\FictionalUser\private token=fake-save-target.json"
    failure_text = "fictional-save-error-detail"
    save_file = Mock(spec=export_file.QSaveFile)
    save_file.open.return_value = True
    if failure_branch == "short_write":
        save_file.write.side_effect = lambda data: len(data) - 1
        save_file.commit.return_value = True
    elif failure_branch == "write_exception":
        save_file.write.side_effect = OSError(target_path + " " + failure_text)
        save_file.commit.return_value = True
    else:
        save_file.write.side_effect = lambda data: len(data)
        save_file.commit.return_value = False
    warning = Mock()
    information = Mock()
    monkeypatch.setattr(
        main_window_module.QFileDialog,
        "getSaveFileName",
        Mock(return_value=(target_path, "JSON 文件 (*.json)")),
    )
    monkeypatch.setattr(export_file, "QSaveFile", Mock(return_value=save_file))
    monkeypatch.setattr(main_window_module.QMessageBox, "warning", warning)
    monkeypatch.setattr(main_window_module.QMessageBox, "information", information)

    try:
        window.findChild(QPushButton, "exportJsonButton").click()

        save_file.open.assert_called_once()
        save_file.write.assert_called_once()
        if failure_branch in {"short_write", "write_exception"}:
            save_file.commit.assert_not_called()
        else:
            save_file.commit.assert_called_once()
        save_file.cancelWriting.assert_called_once()
        warning.assert_called_once()
        information.assert_not_called()
        message = " ".join(str(part) for part in warning.call_args.args[1:])
        assert message == "导出失败 无法保存 JSON 报告。请检查所选位置。"
        assert target_path not in message
        assert "FictionalUser" not in message
        assert "fake-save-target" not in message
        assert failure_text not in message
        assert window._current_report is report
        assert window.findChild(QPushButton, "exportJsonButton").isEnabled()
    finally:
        window.close()


@pytest.mark.usefixtures("approved_report_export")
def test_export_html_saves_self_contained_utf8_report_and_uses_expected_dialog_options(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    window = MainWindow()
    destination = tmp_path / "dev-env-doctor-report.html"
    diagnostic = _diagnostic(
        "COMMAND_TIMEOUT",
        "Python probe",
        Severity.WARNING,
        "Synthetic diagnostic.",
        suggestion="Review locally.",
    )
    report = _show_report(window, [diagnostic])
    dialog = Mock(return_value=(str(destination), "HTML 文件 (*.html)"))
    information = Mock()
    monkeypatch.setattr(main_window_module.QFileDialog, "getSaveFileName", dialog)
    monkeypatch.setattr(main_window_module.QMessageBox, "information", information)

    try:
        button = window.findChild(QPushButton, "exportHtmlButton")
        assert button.isEnabled()
        button.click()

        rendered = destination.read_bytes().decode("utf-8", errors="strict")
        assert "<!doctype html>" in rendered.lower()
        assert "Synthetic diagnostic." in rendered
        assert dialog.call_args.args[2] == "dev-env-doctor-report.html"
        assert "*.html" in dialog.call_args.args[3]
        information.assert_called_once_with(window, "导出完成", "HTML 报告已保存。")
        assert window._current_report is report
        assert window.findChild(QPushButton, "exportHtmlButton").isEnabled()
    finally:
        window.close()


@pytest.mark.usefixtures("approved_report_export")
def test_cancelled_html_save_does_not_write_or_change_report(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    window = MainWindow()
    report = _show_report(window, _report_with_diagnostics(1).diagnostics)
    warning = Mock()
    information = Mock()
    monkeypatch.setattr(
        main_window_module.QFileDialog,
        "getSaveFileName",
        Mock(return_value=("", "HTML 文件 (*.html)")),
    )
    monkeypatch.setattr(main_window_module.QMessageBox, "warning", warning)
    monkeypatch.setattr(main_window_module.QMessageBox, "information", information)

    try:
        window.findChild(QPushButton, "exportHtmlButton").click()

        assert list(tmp_path.iterdir()) == []
        assert window._current_report is report
        assert window.findChild(QPushButton, "exportHtmlButton").isEnabled()
        warning.assert_not_called()
        information.assert_not_called()
    finally:
        window.close()


@pytest.mark.parametrize("failure_branch", ["short_write", "write_exception", "commit"])
@pytest.mark.usefixtures("approved_report_export")
def test_html_save_write_or_commit_failure_is_safe_and_preserves_report(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    failure_branch: str,
) -> None:
    window = MainWindow()
    report = _show_report(window, _report_with_diagnostics(1).diagnostics)
    target_path = r"C:\Users\FictionalUser\private token=fake-html-target.html"
    failure_text = "fictional-html-save-error-detail"
    save_file = Mock(spec=export_file.QSaveFile)
    save_file.open.return_value = True
    if failure_branch == "short_write":
        save_file.write.side_effect = lambda data: len(data) - 1
        save_file.commit.return_value = True
    elif failure_branch == "write_exception":
        save_file.write.side_effect = OSError(target_path + " " + failure_text)
        save_file.commit.return_value = True
    else:
        save_file.write.side_effect = lambda data: len(data)
        save_file.commit.return_value = False
    warning = Mock()
    information = Mock()
    monkeypatch.setattr(
        main_window_module.QFileDialog,
        "getSaveFileName",
        Mock(return_value=(target_path, "HTML 文件 (*.html)")),
    )
    monkeypatch.setattr(export_file, "QSaveFile", Mock(return_value=save_file))
    monkeypatch.setattr(main_window_module.QMessageBox, "warning", warning)
    monkeypatch.setattr(main_window_module.QMessageBox, "information", information)

    try:
        window.findChild(QPushButton, "exportHtmlButton").click()

        save_file.open.assert_called_once()
        save_file.write.assert_called_once()
        if failure_branch in {"short_write", "write_exception"}:
            save_file.commit.assert_not_called()
        else:
            save_file.commit.assert_called_once()
        save_file.cancelWriting.assert_called_once()
        warning.assert_called_once()
        information.assert_not_called()
        message = " ".join(str(part) for part in warning.call_args.args[1:])
        assert message == "导出失败 无法保存 HTML 报告。请检查所选位置。"
        assert target_path not in message
        assert "FictionalUser" not in message
        assert "fake-html-target" not in message
        assert failure_text not in message
        assert window._current_report is report
        assert window.findChild(QPushButton, "exportHtmlButton").isEnabled()
    finally:
        window.close()


@pytest.mark.usefixtures("approved_report_export")
def test_html_render_encoding_failure_precedes_dialog_and_preserves_report(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = MainWindow()
    report = _show_report(window, _report_with_diagnostics(1).diagnostics)
    dialog = Mock()
    warning = Mock()
    monkeypatch.setattr(main_window_module, "render_html_report", Mock(return_value="\ud800"))
    monkeypatch.setattr(main_window_module.QFileDialog, "getSaveFileName", dialog)
    monkeypatch.setattr(main_window_module.QMessageBox, "warning", warning)

    try:
        window.findChild(QPushButton, "exportHtmlButton").click()

        dialog.assert_not_called()
        warning.assert_called_once_with(window, "无法导出报告", "当前报告无法安全导出。")
        assert window._current_report is report
        assert not window.findChild(QPushButton, "exportJsonButton").isEnabled()
        assert not window.findChild(QPushButton, "exportHtmlButton").isEnabled()
    finally:
        window.close()
