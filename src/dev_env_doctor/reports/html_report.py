"""Render allowlisted diagnostic data as a static, offline HTML report."""

from datetime import datetime
from html import escape

from dev_env_doctor.core.models import ScanReport
from dev_env_doctor.reports.json_report import build_json_payload

_SEVERITY_LABELS = {
    "error": "错误",
    "info": "信息",
    "unknown": "未知",
    "warning": "警告",
}
_STATUS_LABELS = {
    "error": "错误",
    "found": "发现",
    "passed": "通过",
    "skipped": "已跳过",
    "unknown": "未知",
}

_DOCUMENT_START = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none';
      form-action 'none'; style-src 'unsafe-inline'">
  <title>DevEnv Doctor 诊断报告</title>
  <style>
    :root { color-scheme: light; font-family: "Segoe UI", "Microsoft YaHei", sans-serif; }
    body { color: #202124; line-height: 1.55; margin: 2rem auto;
      max-width: 72rem; padding: 0 1rem; }
    h1, h2, h3 { line-height: 1.25; }
    .summary, .diagnostic { border: 1px solid #c8ccd0; border-radius: 0.35rem;
      margin: 1rem 0; padding: 1rem; }
    .statistics { display: flex; flex-wrap: wrap; gap: 1.5rem; }
    .diagnostic h3 { margin-top: 0; }
    dt { font-weight: 600; margin-top: 0.7rem; }
    dd { margin-left: 0; overflow-wrap: anywhere; white-space: pre-wrap; }
    .evidence { border-left: 3px solid #607d8b; padding-left: 0.8rem; }
    @media print {
      body { margin: 0; max-width: none; }
      .summary, .diagnostic { break-inside: avoid; }
    }
  </style>
</head>
<body>
  <header>
    <h1>DevEnv Doctor 诊断报告</h1>
    <p>静态离线报告 · 生成时间："""
_SUMMARY_START = """</p>
  </header>
  <main>
    <section class="summary" aria-labelledby="summary-heading">
      <h2 id="summary-heading">总体摘要</h2>
      <p>诊断条目总数："""
_STATUS_START = """</ul>
        </section>
        <section aria-labelledby="status-heading">
          <h3 id="status-heading">状态</h3>
          <ul>"""
_DIAGNOSTICS_END = """</ul>
        </section>
      </div>
    </section>
    <section aria-labelledby="diagnostics-heading">
      <h2 id="diagnostics-heading">诊断详情</h2>
"""
_DOCUMENT_END = """    </section>
  </main>
</body>
</html>
"""


class HTMLReportError(ValueError):
    """Raised when a report cannot be safely rendered as HTML."""


def _escaped_text(value: object) -> str:
    if not isinstance(value, str):
        raise HTMLReportError("Report contains an invalid text value.")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        pass
    else:
        return escape(value, quote=True)
    raise HTMLReportError("Report contains text that is not valid UTF-8.") from None


def _count_markup(counts: object, labels: dict[str, str]) -> str:
    if not isinstance(counts, dict) or set(counts) != set(labels):
        raise HTMLReportError("Report summary is invalid.")
    rows: list[str] = []
    for key, label in labels.items():
        count = counts[key]
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise HTMLReportError("Report summary is invalid.")
        rows.append(f"<li>{_escaped_text(key)}（{_escaped_text(label)}）：{count}</li>")
    return "".join(rows)


def _diagnostic_markup(diagnostics: object) -> str:
    if not isinstance(diagnostics, list):
        raise HTMLReportError("Report diagnostics are invalid.")
    if not diagnostics:
        return '<p class="empty-state">本次报告没有诊断项。</p>\n'

    cards: list[str] = []
    expected_fields = {
        "evidence",
        "rule_id",
        "severity",
        "status",
        "suggestion",
        "summary",
        "title",
    }
    for diagnostic in diagnostics:
        if not isinstance(diagnostic, dict) or set(diagnostic) != expected_fields:
            raise HTMLReportError("Report diagnostic is invalid.")
        evidence = diagnostic["evidence"]
        if not isinstance(evidence, list) or any(not isinstance(item, str) for item in evidence):
            raise HTMLReportError("Report evidence is invalid.")
        evidence_markup = (
            "<ul>" + "".join(f"<li>{_escaped_text(item)}</li>" for item in evidence) + "</ul>"
            if evidence
            else "<p>没有可安全展示的证据。</p>"
        )
        cards.append(
            '<article class="diagnostic">'
            f"<h3>{_escaped_text(diagnostic['title'])}</h3>"
            "<dl>"
            f"<dt>规则</dt><dd>{_escaped_text(diagnostic['rule_id'])}</dd>"
            f"<dt>严重程度</dt><dd>{_escaped_text(diagnostic['severity'])}</dd>"
            f"<dt>状态</dt><dd>{_escaped_text(diagnostic['status'])}</dd>"
            f"<dt>摘要</dt><dd>{_escaped_text(diagnostic['summary'])}</dd>"
            f"<dt>建议</dt><dd>{_escaped_text(diagnostic['suggestion'])}</dd>"
            f'<dt>证据</dt><dd class="evidence">{evidence_markup}</dd>'
            "</dl></article>\n"
        )
    return "".join(cards)


def render_html_report(
    report: ScanReport,
    *,
    generated_at: datetime | None = None,
    machine_names: tuple[str, ...] = (),
) -> str:
    """Render reviewed JSON payload fields as escaped, static HTML.

    Field minimization and the shared JSON allowlists are the primary export
    boundary. Rule-based redaction only reduces risk; it cannot detect every
    possible secret.
    """
    try:
        payload = build_json_payload(
            report,
            generated_at=generated_at,
            machine_names=machine_names,
        )
        summary = payload["summary"]
        if not isinstance(summary, dict):
            raise HTMLReportError("Report summary is invalid.")
        total = summary.get("total")
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise HTMLReportError("Report summary is invalid.")
        diagnostics = payload["diagnostics"]
        rendered = (
            _DOCUMENT_START
            + _escaped_text(payload["generated_at"])
            + _SUMMARY_START
            + str(total)
            + '</p>\n      <div class="statistics">\n'
            + '        <section aria-labelledby="severity-heading">\n'
            + '          <h3 id="severity-heading">严重程度</h3>\n          <ul>'
            + _count_markup(summary["severity_counts"], _SEVERITY_LABELS)
            + _STATUS_START
            + _count_markup(summary["status_counts"], _STATUS_LABELS)
            + _DIAGNOSTICS_END
            + _diagnostic_markup(diagnostics)
            + _DOCUMENT_END
        )
        rendered.encode("utf-8", errors="strict")
        return rendered
    except Exception:
        pass
    raise HTMLReportError("Report could not be safely rendered.") from None
