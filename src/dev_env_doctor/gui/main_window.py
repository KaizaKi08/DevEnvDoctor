"""Main PySide6 window for read-only developer-environment diagnostics."""

import socket
from collections import Counter

from PySide6.QtCore import Qt, QThread, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from dev_env_doctor.core.models import DiagnosticResult, ScanReport, Severity
from dev_env_doctor.core.scan_coordinator import DiagnosticEvent
from dev_env_doctor.gui.scan_worker import ScanWorker, _safe_diagnostic_event
from dev_env_doctor.privacy.redaction import redact_text
from dev_env_doctor.reports import export_file
from dev_env_doctor.reports.html_report import render_html_report
from dev_env_doctor.reports.json_report import (
    REVIEWED_RULE_IDS,
    diagnostic_text,
    render_json_report,
    safe_evidence,
)

_SEVERITY_LABELS = {
    Severity.INFO.value: "信息",
    Severity.WARNING.value: "警告",
    Severity.ERROR.value: "错误",
}
_STATUS_LABELS = {
    "found": "发现",
    "passed": "通过",
    "skipped": "已跳过",
    "error": "错误",
}
_NO_SAFE_EVIDENCE = "没有可安全展示的证据。"
_MAX_DISPLAY_TEXT_LENGTH = 4096


class MainWindow(QMainWindow):
    """Display scan results and manage user-triggered background scans."""

    def __init__(self) -> None:
        super().__init__()
        try:
            hostname = socket.gethostname().strip()
        except OSError:
            hostname = ""
        self._machine_names = (
            tuple(dict.fromkeys((hostname, hostname.partition(".")[0]))) if hostname else ()
        )
        self.setWindowTitle("DevEnv Doctor")
        self.resize(1000, 680)
        self.setMinimumSize(760, 520)
        self._scan_thread: QThread | None = None
        self._scan_worker: ScanWorker | None = None
        self._scan_outcome_received = False
        self._current_report: ScanReport | None = None
        self._diagnostic_events: list[DiagnosticEvent] = []
        self._technical_report_available = False
        self._technical_error_code: str | None = None

        central_widget = QWidget(self)
        central_widget.setObjectName("centralWidget")
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(32, 28, 32, 24)
        layout.setSpacing(14)

        header = QVBoxLayout()
        header.setSpacing(6)
        title = QLabel("DevEnv Doctor", central_widget)
        title.setObjectName("productTitleLabel")
        title.setStyleSheet("font-size: 25px; font-weight: 600;")
        header.addWidget(title)
        subtitle = QLabel("只读检查开发环境中的常见配置问题", central_widget)
        subtitle.setObjectName("subtitleLabel")
        header.addWidget(subtitle)
        layout.addLayout(header)

        intro = QLabel(
            "环境诊断帮助你了解开发工具和 PATH 状态。扫描为只读操作，并在后台运行。",
            central_widget,
        )
        intro.setObjectName("introLabel")
        intro.setWordWrap(True)
        intro.setMinimumHeight(52)
        intro.setFrameShape(QFrame.Shape.StyledPanel)
        intro.setContentsMargins(16, 10, 16, 10)
        layout.addWidget(intro)

        status_group = QGroupBox("诊断状态", central_widget)
        status_layout = QVBoxLayout(status_group)
        status_layout.setContentsMargins(18, 12, 18, 12)
        status_layout.setSpacing(6)
        self._status_label = QLabel("尚未开始扫描", status_group)
        self._status_label.setObjectName("statusLabel")
        self._status_label.setStyleSheet("font-size: 17px; font-weight: 600;")
        status_layout.addWidget(self._status_label)
        self._status_description_label = QLabel(
            "点击“开始扫描”后才会检查当前进程中的开发工具和 PATH。",
            status_group,
        )
        self._status_description_label.setObjectName("statusDescriptionLabel")
        self._status_description_label.setWordWrap(True)
        status_layout.addWidget(self._status_description_label)
        layout.addWidget(status_group)

        technical_group = QGroupBox("技术诊断", central_widget)
        technical_layout = QVBoxLayout(technical_group)
        technical_layout.setContentsMargins(18, 10, 18, 10)
        self._technical_diagnostics_label = QLabel(technical_group)
        self._technical_diagnostics_label.setObjectName("technicalDiagnosticsLabel")
        self._technical_diagnostics_label.setWordWrap(True)
        self._technical_diagnostics_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.NoTextInteraction
        )
        technical_layout.addWidget(self._technical_diagnostics_label)
        layout.addWidget(technical_group)

        summary_group = QGroupBox("诊断摘要", central_widget)
        summary_layout = QVBoxLayout(summary_group)
        summary_layout.setContentsMargins(14, 8, 14, 8)
        summary_layout.setSpacing(3)
        self._diagnostic_count_label = QLabel("诊断总数：—", summary_group)
        self._diagnostic_count_label.setObjectName("diagnosticCountLabel")
        summary_layout.addWidget(self._diagnostic_count_label)
        self._diagnostic_statistics_label = QLabel(
            "完成扫描后显示严重程度和状态统计。", summary_group
        )
        self._diagnostic_statistics_label.setObjectName("diagnosticStatisticsLabel")
        self._diagnostic_statistics_label.setWordWrap(True)
        summary_layout.addWidget(self._diagnostic_statistics_label)
        layout.addWidget(summary_group)

        content_splitter = QSplitter(Qt.Orientation.Horizontal, central_widget)
        results_group = QGroupBox("诊断结果", content_splitter)
        results_layout = QVBoxLayout(results_group)
        self._empty_state_label = QLabel("尚未扫描。开始扫描后，结果会显示在这里。", results_group)
        self._empty_state_label.setObjectName("emptyStateLabel")
        self._empty_state_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_state_label.setWordWrap(True)
        results_layout.addWidget(self._empty_state_label)
        self._result_list = QListWidget(results_group)
        self._result_list.setObjectName("diagnosticListWidget")
        self._result_list.currentItemChanged.connect(self._on_current_item_changed)
        results_layout.addWidget(self._result_list)
        content_splitter.addWidget(results_group)

        details_group = QGroupBox("诊断详情", content_splitter)
        details_layout = QVBoxLayout(details_group)
        self._detail_title_label = self._detail_value_label(
            "detailTitleLabel", "请选择一条诊断项", details_group
        )
        details_layout.addWidget(self._detail_title_label)
        self._detail_summary_label = self._detail_value_label(
            "detailSummaryLabel", "", details_group
        )
        details_layout.addWidget(self._detail_caption("摘要", details_group))
        details_layout.addWidget(self._detail_summary_label)

        detail_state = QHBoxLayout()
        self._detail_severity_label = self._detail_value_label(
            "detailSeverityValueLabel", "", details_group
        )
        self._detail_status_label = self._detail_value_label(
            "detailStatusValueLabel", "", details_group
        )
        severity_column = QVBoxLayout()
        severity_column.addWidget(self._detail_caption("严重程度", details_group))
        severity_column.addWidget(self._detail_severity_label)
        status_column = QVBoxLayout()
        status_column.addWidget(self._detail_caption("状态", details_group))
        status_column.addWidget(self._detail_status_label)
        detail_state.addLayout(severity_column)
        detail_state.addLayout(status_column)
        details_layout.addLayout(detail_state)

        self._detail_suggestion_label = self._detail_value_label(
            "detailSuggestionLabel", "", details_group
        )
        details_layout.addWidget(self._detail_caption("建议", details_group))
        details_layout.addWidget(self._detail_suggestion_label)
        self._detail_evidence_label = self._detail_value_label(
            "detailEvidenceLabel", _NO_SAFE_EVIDENCE, details_group
        )
        details_layout.addWidget(self._detail_caption("证据", details_group))
        details_layout.addWidget(self._detail_evidence_label)
        details_layout.addStretch(1)
        content_splitter.addWidget(details_group)
        content_splitter.setStretchFactor(0, 1)
        content_splitter.setStretchFactor(1, 2)
        layout.addWidget(content_splitter, 1)

        actions = QHBoxLayout()
        self.scan_button = QPushButton("开始扫描", central_widget)
        self.scan_button.setObjectName("scanButton")
        self.scan_button.clicked.connect(self._start_scan)
        actions.addWidget(self.scan_button)
        self.export_json_button = QPushButton("导出 JSON", central_widget)
        self.export_json_button.setObjectName("exportJsonButton")
        self.export_json_button.setEnabled(False)
        self.export_json_button.clicked.connect(self._export_json_report)
        actions.addWidget(self.export_json_button)
        self.export_html_button = QPushButton("导出 HTML", central_widget)
        self.export_html_button.setObjectName("exportHtmlButton")
        self.export_html_button.setEnabled(False)
        self.export_html_button.clicked.connect(self._export_html_report)
        actions.addWidget(self.export_html_button)
        actions.addStretch(1)
        layout.addLayout(actions)

        footer = QLabel("离线优先 · 隐私优先。不会自动保存或上传诊断数据。", central_widget)
        footer.setObjectName("privacyFooterLabel")
        footer.setWordWrap(True)
        layout.addWidget(footer)
        self._clear_details()
        self._clear_technical_diagnostics()

    @staticmethod
    def _detail_caption(text: str, parent: QWidget) -> QLabel:
        label = QLabel(text, parent)
        label.setStyleSheet("font-weight: 600;")
        return label

    @staticmethod
    def _detail_value_label(object_name: str, text: str, parent: QWidget) -> QLabel:
        label = QLabel(text, parent)
        label.setObjectName(object_name)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setWordWrap(True)
        return label

    @staticmethod
    def _safe_evidence(diagnostic: DiagnosticResult) -> list[str]:
        """Use the same evidence allowlist for the UI and JSON export."""
        return safe_evidence(diagnostic)

    def _display_text(
        self,
        text: object,
        *,
        fallback: str = "",
        allow_empty: bool = False,
    ) -> str:
        if not isinstance(text, str) or len(text) > _MAX_DISPLAY_TEXT_LENGTH:
            return fallback
        if not allow_empty and not text.strip():
            return fallback
        try:
            redacted = redact_text(text, machine_names=self._machine_names)
        except Exception:
            return fallback
        return (
            redacted
            if isinstance(redacted, str) and len(redacted) <= _MAX_DISPLAY_TEXT_LENGTH
            else fallback
        )

    @staticmethod
    def _severity_value(diagnostic: DiagnosticResult) -> str | None:
        severity = diagnostic.severity
        if isinstance(severity, Severity):
            return severity.value
        if isinstance(severity, str) and severity in _SEVERITY_LABELS:
            return severity
        return None

    @staticmethod
    def _status_value(diagnostic: DiagnosticResult) -> str | None:
        status = diagnostic.status
        return status if isinstance(status, str) and status in _STATUS_LABELS else None

    def _clear_details(self) -> None:
        self._detail_title_label.setText("请选择一条诊断项")
        self._detail_summary_label.clear()
        self._detail_severity_label.clear()
        self._detail_status_label.clear()
        self._detail_suggestion_label.clear()
        self._detail_evidence_label.setText(_NO_SAFE_EVIDENCE)

    def _clear_technical_diagnostics(self) -> None:
        self._diagnostic_events.clear()
        self._technical_report_available = False
        self._technical_error_code = None
        self._technical_diagnostics_label.setText("尚未获取技术诊断。")

    @staticmethod
    def _diagnostic_value(value: object) -> str:
        candidate = getattr(value, "value", None)
        return candidate if isinstance(candidate, str) else "NOT_OBSERVED"

    def _render_technical_diagnostics(self) -> None:
        if not self._diagnostic_events:
            lines = ["尚未获取阶段事件。"]
            if self._technical_error_code is not None:
                lines.append(f"最终安全错误代码={self._technical_error_code}")
            lines.append("报告正式返回=" + ("是" if self._technical_report_available else "未确认"))
            self._technical_diagnostics_label.setText("\n".join(lines))
            return

        lines: list[str] = []
        for index, event in enumerate(self._diagnostic_events, start=1):
            parts = [
                f"{index}. 阶段={self._diagnostic_value(event.stage)}",
                f"Coordinator={event.coordinator_state}",
                f"Supervisor={event.supervisor_state}",
                f"Worker退出={self._diagnostic_value(event.worker_exit)}",
                f"Job={self._diagnostic_value(event.job_status)}",
                f"IPC={self._diagnostic_value(event.ipc_status)}",
                f"辅助线程={self._diagnostic_value(event.helper_threads)}",
                f"父端资源={self._diagnostic_value(event.parent_resources)}",
            ]
            if event.error_code is not None:
                parts.append(f"错误代码={event.error_code}")
            if event.failure_category is not None:
                parts.append(f"故障分类={self._diagnostic_value(event.failure_category)}")
            if event.worker_exit_reason is not None:
                parts.append(f"退出原因={self._diagnostic_value(event.worker_exit_reason)}")
            lines.append("；".join(parts))

        report_state = "是" if self._technical_report_available else "未确认"
        lines.append(f"报告正式返回={report_state}")
        if self._technical_error_code is not None:
            lines.append(f"最终安全错误代码={self._technical_error_code}")
        self._technical_diagnostics_label.setText("\n".join(lines))

    @Slot(object)
    def _on_diagnostic_event(self, event: object) -> None:
        safe_event = _safe_diagnostic_event(event)
        if safe_event is None:
            return
        self._diagnostic_events.append(safe_event)
        self._render_technical_diagnostics()

    def _set_empty_state(self, text: str) -> None:
        self._empty_state_label.setText(text)
        self._empty_state_label.setVisible(self._result_list.count() == 0)
        self._result_list.setVisible(self._result_list.count() > 0)

    def _clear_report(self, empty_state: str) -> None:
        self._current_report = None
        self._set_export_buttons_enabled(False)
        self._result_list.clear()
        self._set_empty_state(empty_state)
        self._clear_details()

    def _update_summary(self, report: ScanReport) -> None:
        try:
            diagnostics = report.diagnostics
            if not isinstance(diagnostics, list) or any(
                not isinstance(item, DiagnosticResult) for item in diagnostics
            ):
                raise TypeError("invalid diagnostics collection")
            severities = [self._severity_value(item) for item in diagnostics]
            statuses = [self._status_value(item) for item in diagnostics]
            severity_counts = Counter(value for value in severities if value is not None)
            status_counts = Counter(value for value in statuses if value is not None)
            total = len(diagnostics)
        except Exception:
            self._diagnostic_count_label.setText("诊断总数：不可用")
            self._diagnostic_statistics_label.setText("统计暂不可用。")
            return

        self._diagnostic_count_label.setText(f"诊断总数：{total}")
        self._diagnostic_statistics_label.setText(
            "严重程度："
            f"错误 {severity_counts[Severity.ERROR.value]} · "
            f"警告 {severity_counts[Severity.WARNING.value]} · "
            f"信息 {severity_counts[Severity.INFO.value]} · "
            f"未知 {severities.count(None)}；"
            "状态："
            f"错误 {status_counts['error']} · "
            f"通过 {status_counts['passed']} · "
            f"发现 {status_counts['found']} · "
            f"已跳过 {status_counts['skipped']} · "
            f"未知 {statuses.count(None)}"
        )

    def _display_title(self, diagnostic: DiagnosticResult) -> str:
        if not isinstance(diagnostic.rule_id, str) or diagnostic.rule_id not in REVIEWED_RULE_IDS:
            return "未审核的诊断项"
        title, _, _ = diagnostic_text(diagnostic)
        return self._display_text(title, fallback="诊断标题不可用。")

    def _populate_report(self, report: ScanReport) -> bool:
        self._set_export_buttons_enabled(False)
        if not isinstance(report, ScanReport) or not isinstance(report.diagnostics, list):
            return False
        if any(not isinstance(item, DiagnosticResult) for item in report.diagnostics):
            return False

        self._current_report = report
        self._result_list.clear()
        self._update_summary(report)
        for diagnostic in report.diagnostics:
            severity_value = self._severity_value(diagnostic)
            status_value = self._status_value(diagnostic)
            severity = _SEVERITY_LABELS.get(severity_value, "未知")
            status = _STATUS_LABELS.get(status_value, "未知")
            item = QListWidgetItem(f"{self._display_title(diagnostic)} · {severity} · {status}")
            item.setData(Qt.ItemDataRole.UserRole, diagnostic)
            self._result_list.addItem(item)

        if report.diagnostics:
            self._set_empty_state("")
        else:
            self._set_empty_state("扫描完成，没有诊断项。")
        self._clear_details()
        if not export_file.report_export_allowed() or not self._machine_names:
            return True
        try:
            render_json_report(report, machine_names=self._machine_names)
            render_html_report(report, machine_names=self._machine_names)
        except Exception:
            return True
        self._set_export_buttons_enabled(True)
        return True

    def _set_export_buttons_enabled(self, enabled: bool) -> None:
        enabled = enabled and export_file.report_export_allowed() and bool(self._machine_names)
        self.export_json_button.setEnabled(enabled)
        self.export_html_button.setEnabled(enabled)

    @Slot()
    def _export_json_report(self) -> None:
        """Save the current validated report only after explicit user action."""
        if not export_file.report_export_allowed() or not self._machine_names:
            self._set_export_buttons_enabled(False)
            return
        report = self._current_report
        if report is None or not self.export_json_button.isEnabled():
            return

        try:
            payload = render_json_report(report, machine_names=self._machine_names).encode("utf-8")
        except Exception:
            self._set_export_buttons_enabled(False)
            QMessageBox.warning(self, "无法导出报告", "当前报告无法安全导出。")
            return

        file_path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "导出 JSON 报告",
            "dev-env-doctor-report.json",
            "JSON 文件 (*.json)",
        )
        if not file_path:
            return

        try:
            export_file.write_report_file(file_path, payload)
        except PermissionError:
            self._set_export_buttons_enabled(False)
            return
        except OSError:
            QMessageBox.warning(self, "导出失败", "无法保存 JSON 报告。请检查所选位置。")
            return

        QMessageBox.information(self, "导出完成", "JSON 报告已保存。")

    @Slot()
    def _export_html_report(self) -> None:
        """Save a static HTML report after explicit user action."""
        if not export_file.report_export_allowed() or not self._machine_names:
            self._set_export_buttons_enabled(False)
            return
        report = self._current_report
        if report is None or not self.export_html_button.isEnabled():
            return

        try:
            payload = render_html_report(report, machine_names=self._machine_names).encode("utf-8")
        except Exception:
            self._set_export_buttons_enabled(False)
            QMessageBox.warning(self, "无法导出报告", "当前报告无法安全导出。")
            return

        file_path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "导出 HTML 报告",
            "dev-env-doctor-report.html",
            "HTML 文件 (*.html)",
        )
        if not file_path:
            return

        try:
            export_file.write_report_file(file_path, payload)
        except PermissionError:
            self._set_export_buttons_enabled(False)
            return
        except OSError:
            QMessageBox.warning(self, "导出失败", "无法保存 HTML 报告。请检查所选位置。")
            return

        QMessageBox.information(self, "导出完成", "HTML 报告已保存。")

    @Slot()
    def _start_scan(self) -> None:
        """Start one background scan in response to an explicit user action."""
        if self._scan_thread is not None:
            return

        thread = QThread(self)
        worker = ScanWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.diagnostic_event.connect(self._on_diagnostic_event)
        worker.succeeded.connect(self._on_scan_succeeded)
        worker.failed.connect(self._on_scan_failed)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(self._on_scan_thread_finished)
        thread.finished.connect(thread.deleteLater)

        self._scan_thread = thread
        self._scan_worker = worker
        self._scan_outcome_received = False
        self._clear_technical_diagnostics()
        self._clear_report("扫描进行中，结果将在完成后显示。")
        self._diagnostic_count_label.setText("诊断总数：扫描中")
        self._diagnostic_statistics_label.setText("扫描完成后显示统计。")
        self.scan_button.setEnabled(False)
        self._status_label.setText("正在扫描…")
        self._status_description_label.setText(
            "扫描在后台运行；此窗口不会显示原始命令输出或异常详情。"
        )
        self.statusBar().showMessage("正在扫描…")
        thread.start()

    @Slot(object)
    def _on_scan_succeeded(self, report: ScanReport) -> None:
        """Keep the report in memory and render its reviewed fields."""
        try:
            rendered = self._populate_report(report)
        except Exception:
            rendered = False
        if not rendered:
            self._on_scan_failed()
            return

        self._scan_outcome_received = True
        self._technical_report_available = True
        self._technical_error_code = None
        self._render_technical_diagnostics()
        self._status_label.setText(f"扫描完成，共 {len(report.diagnostics)} 条诊断结果。")
        self._status_description_label.setText("可选择一项查看摘要、建议和已审核证据。")
        self.statusBar().showMessage("扫描完成")

    @Slot()
    def _on_scan_failed(self, _error_code: str = "SCAN_FAILED") -> None:
        """Present a generic failure without exposing exception contents."""
        self._scan_outcome_received = True
        self._technical_report_available = False
        self._technical_error_code = _error_code
        self._render_technical_diagnostics()
        self._clear_report("扫描失败，未能生成结果。")
        self._diagnostic_count_label.setText("诊断总数：—")
        self._diagnostic_statistics_label.setText("扫描失败，暂无统计。")
        self._status_label.setText("扫描失败")
        self._status_description_label.setText("无法完成环境检查。原始异常详情不会显示在此窗口中。")
        self.statusBar().showMessage("扫描失败")

    @Slot()
    def _on_scan_thread_finished(self) -> None:
        """Release worker references and restore the scan action after exit."""
        if not self._scan_outcome_received:
            self._on_scan_failed()
        self._scan_worker = None
        self._scan_thread = None
        self.scan_button.setEnabled(True)

    def _on_current_item_changed(
        self,
        current: QListWidgetItem | None,
        _previous: QListWidgetItem | None,
    ) -> None:
        diagnostic = current.data(Qt.ItemDataRole.UserRole) if current is not None else None
        if not isinstance(diagnostic, DiagnosticResult):
            self._clear_details()
            return

        reviewed = isinstance(diagnostic.rule_id, str) and diagnostic.rule_id in REVIEWED_RULE_IDS
        if reviewed:
            raw_title, raw_summary, raw_suggestion = diagnostic_text(diagnostic)
            title = self._display_text(raw_title, fallback="诊断标题不可用。")
            summary = self._display_text(raw_summary, fallback="摘要不可用。")
            suggestion = self._display_text(
                raw_suggestion,
                fallback="建议不可用。",
                allow_empty=True,
            )
            evidence = self._safe_evidence(diagnostic)
        else:
            title = "未审核的诊断项"
            summary = "此诊断项的文本尚未审核，暂不显示。"
            suggestion = ""
            evidence = []

        self._detail_title_label.setText(title)
        self._detail_summary_label.setText(summary)
        self._detail_severity_label.setText(
            _SEVERITY_LABELS.get(self._severity_value(diagnostic), "未知")
        )
        self._detail_status_label.setText(
            _STATUS_LABELS.get(self._status_value(diagnostic), "未知")
        )
        self._detail_suggestion_label.setText(suggestion)
        self._detail_evidence_label.setText(
            "\n".join(self._display_text(item, fallback=_NO_SAFE_EVIDENCE) for item in evidence)
            if evidence
            else _NO_SAFE_EVIDENCE
        )

    def closeEvent(self, event: QCloseEvent) -> None:
        """Keep the window alive while a non-cancellable scan is still running."""
        if self._scan_thread is not None and self._scan_thread.isRunning():
            self._status_description_label.setText(
                "扫描仍在运行，窗口暂时保持打开；扫描完成后可再次关闭。"
            )
            self.statusBar().showMessage("扫描仍在运行")
            event.ignore()
            return
        super().closeEvent(event)
