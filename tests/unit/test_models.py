import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from dev_env_doctor.collectors.commands import CommandProbeResult, ProbeStatus
from dev_env_doctor.core import models
from dev_env_doctor.core.models import (
    DiagnosticResult,
    ProcessCleanupStatus,
    ScanMetadata,
    ScanReport,
    Severity,
)
from dev_env_doctor.core.scan_control import CleanupStatus
from dev_env_doctor.reports.html_report import render_html_report
from dev_env_doctor.reports.json_report import build_json_payload, render_json_report


def test_diagnostic_result_accepts_valid_data() -> None:
    result = DiagnosticResult(
        rule_id="PATH_EMPTY",
        title="PATH is empty",
        severity=Severity.WARNING,
        summary="No PATH entries were provided.",
    )

    assert result.rule_id == "PATH_EMPTY"
    assert result.status == "found"
    assert result.evidence == []
    assert result.suggestion == ""


def test_diagnostic_result_rejects_invalid_severity() -> None:
    with pytest.raises(ValidationError):
        DiagnosticResult(
            rule_id="TEST_RULE",
            title="Test",
            severity="critical",
            summary="A summary",
        )


@pytest.mark.parametrize("field", ["rule_id", "title", "summary"])
@pytest.mark.parametrize("value", ["", "   "])
def test_diagnostic_result_rejects_blank_required_strings(field: str, value: str) -> None:
    values = {
        "rule_id": "TEST_RULE",
        "title": "Test",
        "severity": Severity.INFO,
        "summary": "A summary",
    }
    values[field] = value

    with pytest.raises(ValidationError):
        DiagnosticResult(**values)


def test_scan_metadata_requires_timezone_aware_time() -> None:
    metadata = ScanMetadata(
        scan_time=datetime(2026, 10, 24, tzinfo=UTC),
    )

    assert metadata.scan_time.tzinfo is not None
    with pytest.raises(ValidationError):
        ScanMetadata(scan_time=datetime(2026, 10, 24))


def test_scan_metadata_uses_a_fresh_time_default() -> None:
    first = ScanMetadata()
    second = ScanMetadata()

    assert first.scan_time is not second.scan_time
    assert first.scan_time.tzinfo is not None
    assert second.scan_time.tzinfo is not None


def test_scan_report_serializes_to_json_with_iso_timestamp() -> None:
    report = ScanReport(
        diagnostics=[
            DiagnosticResult(
                rule_id="PATH_EMPTY",
                title="PATH is empty",
                severity=Severity.WARNING,
                summary="No entries were found.",
            )
        ]
    )

    json_text = report.model_dump_json()
    restored = ScanReport.model_validate_json(json_text)

    assert '"schema_version":"1.0"' in json_text
    assert "T" in json_text
    assert restored.diagnostics[0].severity is Severity.WARNING


def test_command_cleanup_status_is_explicit_strict_and_backwards_compatible() -> None:
    cleanup = models.ProcessCleanupStatus
    assert {item.value for item in cleanup} == {"not_started", "confirmed", "unconfirmed"}
    assert CommandProbeResult("git", ProbeStatus.MISSING).cleanup_status is cleanup.NOT_STARTED
    for status in cleanup:
        result = CommandProbeResult("git", ProbeStatus.ERROR, cleanup_status=status)
        assert result.cleanup_status is status
    for invalid in (
        "not_started",
        "confirmed",
        "unconfirmed",
        None,
        True,
        Severity.INFO,
        CleanupStatus.CONFIRMED,
        object(),
    ):
        with pytest.raises(TypeError, match="cleanup_status"):
            CommandProbeResult("git", ProbeStatus.ERROR, cleanup_status=invalid)


@pytest.mark.parametrize("probe_status", list(ProbeStatus))
@pytest.mark.parametrize("cleanup_status", list(ProcessCleanupStatus))
def test_probe_and_cleanup_status_combinations_are_consistent(
    probe_status: ProbeStatus, cleanup_status: ProcessCleanupStatus
) -> None:
    if probe_status is ProbeStatus.MISSING:
        allowed = cleanup_status is ProcessCleanupStatus.NOT_STARTED
    elif probe_status in (ProbeStatus.VERIFIED, ProbeStatus.NONZERO_EXIT, ProbeStatus.TIMEOUT):
        allowed = cleanup_status is not ProcessCleanupStatus.NOT_STARTED
    else:
        # FOUND_UNVERIFIED includes lookup-only and executed-but-rejected output.
        # ERROR can occur before or after child creation.
        allowed = True

    if not allowed:
        with pytest.raises(ValueError, match="inconsistent"):
            CommandProbeResult("git", probe_status, cleanup_status=cleanup_status)
    else:
        result = CommandProbeResult("git", probe_status, cleanup_status=cleanup_status)
        assert result.status is probe_status
        assert result.cleanup_status is cleanup_status


@pytest.mark.parametrize("status", ["verified", "missing", Severity.ERROR, None, object()])
def test_probe_status_requires_the_exact_enum_type(status: object) -> None:
    with pytest.raises(TypeError, match="status"):
        CommandProbeResult("git", status, cleanup_status=ProcessCleanupStatus.CONFIRMED)


@pytest.mark.parametrize(
    "status", [ProbeStatus.VERIFIED, ProbeStatus.NONZERO_EXIT, ProbeStatus.TIMEOUT]
)
def test_execution_status_cannot_use_default_not_started_cleanup(status: ProbeStatus) -> None:
    with pytest.raises(ValueError, match="inconsistent"):
        CommandProbeResult("git", status)


def test_process_cleanup_status_does_not_extend_public_model_fields_or_schema() -> None:
    assert set(DiagnosticResult.model_fields) == {
        "rule_id",
        "title",
        "severity",
        "summary",
        "evidence",
        "suggestion",
        "status",
    }
    assert set(ScanMetadata.model_fields) == {
        "scan_time",
        "app_version",
        "platform",
        "python_version",
    }
    assert set(ScanReport.model_fields) == {"schema_version", "metadata", "diagnostics"}
    assert ScanReport.model_fields["schema_version"].default == "1.0"
    for model in (DiagnosticResult, ScanMetadata, ScanReport):
        schema = json.dumps(model.model_json_schema())
        assert "cleanup_status" not in schema
        assert "ProcessCleanupStatus" not in schema

    with pytest.raises(ValidationError):
        DiagnosticResult(
            rule_id="PATH_EMPTY",
            title="PATH is empty",
            severity=Severity.WARNING,
            summary="No entries were provided.",
            cleanup_status=ProcessCleanupStatus.UNCONFIRMED,
        )


def test_real_json_and_html_exports_exclude_internal_cleanup_attributes() -> None:
    timestamp = datetime(2026, 10, 24, tzinfo=UTC)
    diagnostic = DiagnosticResult(
        rule_id="COMMAND_VERSION",
        title="python version",
        severity=Severity.INFO,
        summary="A version was verified.",
        evidence=["Verified version: 3.13.9"],
        suggestion="No action is required.",
        status="passed",
    )
    report = ScanReport(
        metadata=ScanMetadata(
            scan_time=timestamp,
            app_version="0.0.0-test",
            platform="fictional-platform",
            python_version="3.13.9",
        ),
        diagnostics=[diagnostic],
    )
    # An internal attribute must not become a public field, even after mutation.
    object.__setattr__(diagnostic, "cleanup_status", ProcessCleanupStatus.UNCONFIRMED)
    object.__setattr__(report, "cleanup_status", ProcessCleanupStatus.UNCONFIRMED)

    payload = build_json_payload(report, generated_at=timestamp)
    json_text = render_json_report(report, generated_at=timestamp)
    html_text = render_html_report(report, generated_at=timestamp)

    assert json.loads(json_text) == payload
    assert set(payload) == {"schema_version", "generated_at", "summary", "diagnostics"}
    assert payload["schema_version"] == "1.0"
    assert set(payload["summary"]) == {"total", "severity_counts", "status_counts"}
    assert payload["summary"]["total"] == 1
    assert len(payload["diagnostics"]) == 1
    assert set(payload["diagnostics"][0]) == {
        "rule_id",
        "title",
        "summary",
        "severity",
        "status",
        "suggestion",
        "evidence",
    }
    assert payload["diagnostics"][0]["evidence"] == ["Verified version: 3.13.9"]
    for output in (report.model_dump_json(), json_text, html_text):
        assert "cleanup_status" not in output
        assert "ProcessCleanupStatus" not in output
        assert ProcessCleanupStatus.UNCONFIRMED.value not in output
