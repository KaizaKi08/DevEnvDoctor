from datetime import UTC, datetime
from html.parser import HTMLParser

import pytest

from dev_env_doctor.core.models import DiagnosticResult, ScanReport, Severity
from dev_env_doctor.reports.html_report import HTMLReportError, render_html_report


class ReportParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attributes: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag.lower())
        self.attributes.extend(name.lower() for name, _value in attrs)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


class CSPMetaParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.policies: list[str | None] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "meta":
            return
        attributes = {name.lower(): value for name, value in attrs}
        http_equiv = attributes.get("http-equiv")
        if isinstance(http_equiv, str) and http_equiv.casefold() == "content-security-policy":
            self.policies.append(attributes.get("content"))


def _diagnostic(
    *,
    title: str = "Python version check",
    severity: Severity | str = Severity.WARNING,
    summary: str = "A synthetic diagnostic.",
    status: str = "found",
    suggestion: str = "Review this result locally.",
    evidence: list[str] | None = None,
) -> DiagnosticResult:
    return DiagnosticResult(
        rule_id="COMMAND_TIMEOUT",
        title=title,
        severity=severity,
        summary=summary,
        status=status,
        suggestion=suggestion,
        evidence=evidence or [],
    )


def test_html_report_renders_allowlisted_content_and_recomputed_summary() -> None:
    report = ScanReport(
        diagnostics=[
            _diagnostic(severity=Severity.WARNING, status="error"),
            _diagnostic(title="Git check", severity=Severity.INFO, status="passed"),
        ]
    )
    timestamp = datetime(2026, 10, 24, 4, 5, tzinfo=UTC)

    rendered = render_html_report(report, generated_at=timestamp)
    parser = ReportParser()
    parser.feed(rendered)

    assert '<meta charset="utf-8">' in rendered
    assert "2026-10-24T04:05:00+00:00" in "".join(parser.text)
    assert "诊断条目总数：2" in "".join(parser.text)
    assert "warning（警告）：1" in "".join(parser.text)
    assert "info（信息）：1" in "".join(parser.text)
    assert "error（错误）：1" in "".join(parser.text)
    assert "passed（通过）：1" in "".join(parser.text)
    assert parser.tags.count("article") == 2
    assert "raw_metadata" not in rendered
    assert "scan_time" not in rendered


def test_empty_report_has_explicit_empty_state_and_zero_counts() -> None:
    rendered = render_html_report(ScanReport())
    parser = ReportParser()
    parser.feed(rendered)

    assert "没有诊断项" in "".join(parser.text)
    assert "诊断条目总数：0" in "".join(parser.text)
    assert parser.tags.count("article") == 0


def test_unknown_enum_values_are_counted_as_unknown() -> None:
    diagnostic = _diagnostic()
    diagnostic.severity = "future-severity"
    diagnostic.status = "future-status"

    rendered = render_html_report(ScanReport(diagnostics=[diagnostic]))
    parser = ReportParser()
    parser.feed(rendered)

    assert "unknown（未知）：1" in "".join(parser.text)
    assert "future-severity" not in rendered
    assert "future-status" not in rendered


def test_unknown_rule_is_rejected_without_rendering_its_free_text() -> None:
    diagnostic = _diagnostic(summary="fictional unknown-rule payload")
    diagnostic.rule_id = "FUTURE_UNREVIEWED_RULE"

    with pytest.raises(HTMLReportError):
        render_html_report(ScanReport(diagnostics=[diagnostic]))


def test_structurally_invalid_report_is_rejected_and_mutated_fields_are_safely_reduced() -> None:
    invalid_report = ScanReport()
    invalid_report.diagnostics = [object()]
    with pytest.raises(HTMLReportError):
        render_html_report(invalid_report)

    diagnostic = _diagnostic()
    diagnostic.title = object()
    diagnostic.summary = object()
    diagnostic.suggestion = object()
    diagnostic.evidence = [object()]
    rendered = render_html_report(ScanReport(diagnostics=[diagnostic]))
    parser = ReportParser()
    parser.feed(rendered)

    visible = "".join(parser.text)
    assert "诊断标题不可用。" in visible
    assert "摘要不可用。" in visible
    assert "建议不可用。" in visible
    assert "没有可安全展示的证据。" in visible
    assert "object at" not in visible


def test_html_injection_is_only_text_and_no_dynamic_active_content_is_created() -> None:
    payload = (
        '<script>alert("fictional")</script> '
        '<img src=x onerror="fictional()"> '
        'quote=" & entity=&#x3C;svg onload=fictional&#x3E; javascript:alert(1)'
    )
    diagnostic = _diagnostic(title=payload, summary=payload, suggestion=payload)
    diagnostic.evidence = [payload]
    rendered = render_html_report(ScanReport(diagnostics=[diagnostic]))
    parser = ReportParser()
    parser.feed(rendered)

    assert "script" not in parser.tags
    assert "img" not in parser.tags
    assert "svg" not in parser.tags
    assert not any(name.startswith("on") for name in parser.attributes)
    assert "href" not in parser.attributes
    assert "src" not in parser.attributes
    assert payload in "".join(parser.text)
    assert "&lt;script&gt;" in rendered
    assert "&amp;#x3C;" in rendered
    assert "javascript:alert(1)" in "".join(parser.text)


def test_html_export_uses_shared_redaction_and_rejects_unreviewed_evidence() -> None:
    diagnostic = _diagnostic(
        summary=(
            r"C:\Users\TestUser\Private Project\tool.exe "
            "token=sk-test-fake-secret-123456 api_key=fictional_api_key"
        ),
        suggestion="password=fictional_password",
    )
    diagnostic.evidence = [
        r"C:\Users\TestUser\Private Project\evidence.txt token=fictional_evidence_token"
    ]
    report = ScanReport(diagnostics=[diagnostic])

    rendered = render_html_report(report)

    for marker in (
        "TestUser",
        "Private Project",
        "tool.exe",
        "evidence.txt",
        "sk-test-fake-secret-123456",
        "fictional_api_key",
        "fictional_password",
        "fictional_evidence_token",
    ):
        assert marker not in rendered


def test_utf8_safe_fallbacks_cover_isolated_high_and_low_surrogates() -> None:
    for invalid in (chr(0xD800), chr(0xDC00)):
        diagnostic = _diagnostic()
        diagnostic.title = f"Unsafe {invalid} title"
        diagnostic.summary = f"Unsafe {invalid}"
        diagnostic.suggestion = f"Unsafe {invalid}"
        report = ScanReport(diagnostics=[diagnostic])

        rendered = render_html_report(report)
        encoded = rendered.encode("utf-8", errors="strict")
        decoded = encoded.decode("utf-8", errors="strict")
        parser = ReportParser()
        parser.feed(decoded)

        assert "标题不可用" in "".join(parser.text)
        assert "摘要不可用" in "".join(parser.text)
        assert "建议不可用" in "".join(parser.text)


def test_standalone_html_has_no_remote_resources_or_script() -> None:
    rendered = render_html_report(ScanReport())
    lowered = rendered.lower()

    assert "<!doctype html>" in lowered
    assert '<meta charset="utf-8">' in lowered
    assert "<script" not in lowered
    assert "<link" not in lowered
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "@import" not in lowered
    assert "url(" not in lowered


def test_html_output_contains_one_restrictive_csp_policy() -> None:
    rendered = render_html_report(ScanReport())
    parser = CSPMetaParser()
    parser.feed(rendered)

    assert len(parser.policies) == 1
    content = parser.policies[0]
    assert isinstance(content, str) and content.strip()

    directives: dict[str, tuple[str, ...]] = {}
    for raw_directive in content.split(";"):
        parts = raw_directive.split()
        assert parts, "CSP contains an empty directive"
        name = parts[0].casefold()
        assert name not in directives, f"CSP directive repeated: {name}"
        assert all(char.isascii() and (char.isalnum() or char == "-") for char in name)
        assert len(parts) > 1, f"CSP directive has no source list: {name}"
        directives[name] = tuple(source.casefold() for source in parts[1:])

    assert directives == {
        "default-src": ("'none'",),
        "base-uri": ("'none'",),
        "form-action": ("'none'",),
        "style-src": ("'unsafe-inline'",),
    }
    assert "script-src" not in directives
    assert all("'unsafe-eval'" not in sources for sources in directives.values())
    assert all("*" not in sources for sources in directives.values())
    assert not {
        "img-src",
        "font-src",
        "frame-src",
        "child-src",
        "connect-src",
        "media-src",
        "object-src",
        "worker-src",
    }.intersection(directives)
