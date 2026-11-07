import json
from datetime import UTC, datetime, timedelta, timezone

import pytest

from dev_env_doctor.core.models import DiagnosticResult, ScanMetadata, ScanReport, Severity
from dev_env_doctor.reports.json_report import JSONReportError, render_json_report


def _diagnostic(
    *,
    rule_id: str = "COMMAND_TIMEOUT",
    title: str = "Tool probe timed out",
    severity: Severity = Severity.WARNING,
    summary: str = "The tool could not be verified.",
    evidence: list[str] | None = None,
    suggestion: str = "Review the tool locally.",
    status: str = "error",
) -> DiagnosticResult:
    return DiagnosticResult(
        rule_id=rule_id,
        title=title,
        severity=severity,
        summary=summary,
        evidence=evidence or [],
        suggestion=suggestion,
        status=status,
    )


def _report(*diagnostics: DiagnosticResult) -> ScanReport:
    return ScanReport(
        metadata=ScanMetadata(
            scan_time=datetime(2020, 1, 1, tzinfo=UTC),
            app_version="0.1.0",
            platform="Synthetic platform",
            python_version="3.13.9",
        ),
        diagnostics=list(diagnostics),
    )


def test_json_schema_is_parseable_uses_export_time_and_explicit_field_allowlist() -> None:
    report = _report(
        _diagnostic(
            title='诊断 "标题" \\ component\n第二行 <b>text</b>',
            summary='Summary with quote: " and newline\nUnicode: 中文',
            evidence=["unexpected arbitrary evidence"],
        )
    )
    generated_at = datetime(2026, 10, 24, 12, 30, tzinfo=timezone(timedelta(hours=8)))
    object.__setattr__(report, "future_secret", "fictional_future_secret")
    object.__setattr__(report.diagnostics[0], "future_field", "fictional_future_field")

    exported = render_json_report(report, generated_at=generated_at)
    parsed = json.loads(exported)

    assert set(parsed) == {"schema_version", "generated_at", "summary", "diagnostics"}
    assert parsed["schema_version"] == "1.0"
    assert parsed["generated_at"] == "2026-10-24T12:30:00+08:00"
    assert parsed["generated_at"] != report.metadata.scan_time.isoformat()
    assert set(parsed["summary"]) == {"total", "severity_counts", "status_counts"}
    assert set(parsed["diagnostics"][0]) == {
        "rule_id",
        "title",
        "severity",
        "summary",
        "evidence",
        "suggestion",
        "status",
    }
    assert parsed["diagnostics"][0]["title"] == '诊断 "标题" \\ component\n第二行 <b>text</b>'
    assert parsed["diagnostics"][0]["summary"] == 'Summary with quote: " and newline\nUnicode: 中文'
    assert "future_secret" not in exported
    assert "future_field" not in exported


def test_empty_report_has_zero_summary_and_timezone_aware_generated_time() -> None:
    parsed = json.loads(render_json_report(_report()))

    assert datetime.fromisoformat(parsed["generated_at"]).tzinfo is not None
    assert parsed["diagnostics"] == []
    assert parsed["summary"] == {
        "total": 0,
        "severity_counts": {"info": 0, "warning": 0, "error": 0, "unknown": 0},
        "status_counts": {
            "found": 0,
            "passed": 0,
            "skipped": 0,
            "error": 0,
            "unknown": 0,
        },
    }


def test_summary_counts_are_derived_from_the_exported_records() -> None:
    diagnostics = [
        _diagnostic(severity=Severity.INFO, status="passed"),
        _diagnostic(rule_id="PATH_EMPTY", severity=Severity.ERROR, status="found"),
        _diagnostic(severity=Severity.WARNING, status="skipped"),
    ]
    parsed = json.loads(render_json_report(_report(*diagnostics)))

    assert parsed["summary"]["total"] == len(parsed["diagnostics"]) == 3
    assert parsed["summary"]["severity_counts"] == {
        "info": 1,
        "warning": 1,
        "error": 1,
        "unknown": 0,
    }
    assert parsed["summary"]["status_counts"] == {
        "found": 1,
        "passed": 1,
        "skipped": 1,
        "error": 0,
        "unknown": 0,
    }


def test_mutated_unknown_enum_values_are_normalized_and_counted() -> None:
    diagnostic = _diagnostic()
    diagnostic.severity = "future-severity"
    diagnostic.status = "future-status"

    parsed = json.loads(render_json_report(_report(diagnostic)))

    assert parsed["diagnostics"][0]["severity"] == "unknown"
    assert parsed["diagnostics"][0]["status"] == "unknown"
    assert parsed["summary"]["total"] == 1
    assert parsed["summary"]["severity_counts"]["unknown"] == 1
    assert parsed["summary"]["status_counts"]["unknown"] == 1


def test_unreviewed_rule_id_rejects_the_entire_report() -> None:
    diagnostic = _diagnostic(rule_id="FUTURE_UNREVIEWED_RULE", title="fictional token=secret")

    with pytest.raises(JSONReportError):
        render_json_report(_report(diagnostic))


def test_damaged_report_structure_is_rejected_without_partial_output() -> None:
    report = _report()
    report.diagnostics = [object()]

    with pytest.raises(JSONReportError):
        render_json_report(report)


def test_invalid_text_fields_use_safe_placeholders_and_bad_evidence_is_omitted() -> None:
    diagnostic = _diagnostic(
        evidence=["Verified version: ٣.١٣.٩"],
        title="safe title",
        summary="safe summary",
        suggestion="safe suggestion",
    )
    diagnostic.title = object()
    diagnostic.summary = "x" * 4097
    diagnostic.suggestion = object()

    parsed = json.loads(render_json_report(_report(diagnostic)))
    item = parsed["diagnostics"][0]

    assert item["title"] == "诊断标题不可用。"
    assert item["summary"] == "摘要不可用。"
    assert item["suggestion"] == "建议不可用。"
    assert item["evidence"] == []
    assert "object at" not in json.dumps(item, ensure_ascii=False)


@pytest.mark.parametrize("surrogate", [chr(0xD800), chr(0xDC00)])
@pytest.mark.parametrize("field_name", ["title", "summary", "suggestion"])
def test_unpaired_surrogates_use_safe_fallback_and_remain_utf8_encodable(
    surrogate: str,
    field_name: str,
) -> None:
    diagnostic = _diagnostic()
    setattr(diagnostic, field_name, surrogate)

    rendered = render_json_report(_report(diagnostic))
    rendered.encode("utf-8")
    item = json.loads(rendered)["diagnostics"][0]

    assert (
        item[field_name]
        == {
            "title": "诊断标题不可用。",
            "summary": "摘要不可用。",
            "suggestion": "建议不可用。",
        }[field_name]
    )


@pytest.mark.parametrize(
    "evidence",
    [
        ["Verified version: 3.13.9\nfictional token=multiline-secret"],
        ["Verified version: ٣.١٣.٩"],
        [f"Verified version: 1.{('1' * 158)}.2"],
        ["Verified version: 3.13.9 extra=fictional_secret"],
    ],
)
def test_command_evidence_requires_exact_runner_version_format(evidence: list[str]) -> None:
    diagnostic = _diagnostic(
        rule_id="COMMAND_VERSION",
        title="python version",
        severity=Severity.INFO,
        status="passed",
        evidence=evidence,
    )

    parsed = json.loads(render_json_report(_report(diagnostic)))

    assert parsed["diagnostics"][0]["evidence"] == []
    assert "multiline-secret" not in json.dumps(parsed, ensure_ascii=False)
    assert "fictional_secret" not in json.dumps(parsed, ensure_ascii=False)


def test_safe_path_and_command_evidence_are_preserved() -> None:
    report = _report(
        _diagnostic(
            rule_id="PATH_MISSING_ENTRY",
            evidence=["Unavailable item positions: 2, 5."],
        ),
        _diagnostic(
            rule_id="COMMAND_VERSION",
            title="git version",
            severity=Severity.INFO,
            status="passed",
            evidence=["Verified version: 2.53.0.windows.3"],
        ),
    )

    parsed = json.loads(render_json_report(report))

    assert parsed["diagnostics"][0]["evidence"] == ["Unavailable item positions: 2, 5."]
    assert parsed["diagnostics"][1]["evidence"] == ["Verified version: 2.53.0.windows.3"]


def test_text_fields_are_redacted_and_html_remains_plain_json_text() -> None:
    private_key = (
        "-----BEGIN PRIVATE KEY-----\nFICTIONAL_PRIVATE_KEY_MATERIAL_64\n-----END PRIVATE KEY-----"
    )
    report = _report(
        _diagnostic(
            rule_id="COMMAND_TIMEOUT",
            title="Review C:\\Users\\TestUser\\Private Work\\tool.exe",
            summary=(
                "Normal <script>alert(1)</script>; "
                "Inspect \\\\FictionalMachine\\private-share\\token.txt; "
                "token=sk-test-fake-secret-123456; api_key=fictional-api-key; "
                "password=fictional password phrase; "
                f"{private_key}"
            ),
            suggestion="Review D:\\Private Apps\\tool.exe and cookie=fictional-cookie.",
        )
    )

    exported = render_json_report(report)
    parsed = json.loads(exported)
    serialized = json.dumps(parsed, ensure_ascii=False)

    for marker in (
        "TestUser",
        "Private Work",
        "tool.exe",
        "FictionalMachine",
        "private-share",
        "sk-test-fake-secret-123456",
        "fictional-api-key",
        "fictional password phrase",
        "FICTIONAL_PRIVATE_KEY_MATERIAL_64",
        "fictional-cookie",
    ):
        assert marker not in serialized
    assert "<script>alert(1)</script>" in parsed["diagnostics"][0]["summary"]


def test_redaction_failure_is_not_replaced_with_original_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dev_env_doctor.reports import json_report

    monkeypatch.setattr(
        json_report,
        "redact_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("redaction failed")),
    )
    parsed = json.loads(render_json_report(_report(_diagnostic(title="fictional token=secret"))))

    assert parsed["diagnostics"][0]["title"] == "诊断标题不可用。"
    assert "secret" not in json.dumps(parsed, ensure_ascii=False)
