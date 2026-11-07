"""Build the deliberately small, reviewed payload shared by report renderers."""

from datetime import datetime
from typing import TypedDict

from dev_env_doctor.core.models import ScanReport, Severity
from dev_env_doctor.privacy.redaction import redact_text

_ALLOWED_STATUSES = frozenset({"found", "passed", "skipped", "error"})
_UNKNOWN = "[omitted]"


class MetadataPayload(TypedDict):
    scan_time: str
    app_version: str
    platform: str
    python_version: str


class DiagnosticPayload(TypedDict):
    rule_id: str
    title: str
    severity: str
    summary: str
    evidence: list[str]
    suggestion: str
    status: str


class ReportPayload(TypedDict):
    schema_version: str
    metadata: MetadataPayload
    diagnostics: list[DiagnosticPayload]


def _safe_text(value: object) -> str:
    """Return only known text, applying rule-based redaction before export."""
    if not isinstance(value, str):
        return _UNKNOWN
    return redact_text(value)


def build_report_payload(report: ScanReport) -> ReportPayload:
    """Return a field-allowlisted JSON-compatible representation of a report.

    Do not replace this with model serialization: model fields can grow over
    time, while this boundary intentionally exports only reviewed fields.
    Rule-based redaction is defense in depth, not a substitute for this
    allowlist or for minimizing collected data.
    """
    metadata = report.metadata
    scan_time = metadata.scan_time
    safe_scan_time = (
        scan_time.isoformat()
        if isinstance(scan_time, datetime)
        and scan_time.tzinfo is not None
        and scan_time.utcoffset() is not None
        else _UNKNOWN
    )

    diagnostics: list[DiagnosticPayload] = []
    for diagnostic in report.diagnostics:
        severity = diagnostic.severity
        safe_severity = severity.value if isinstance(severity, Severity) else "unknown"
        status = diagnostic.status
        safe_status = (
            status if isinstance(status, str) and status in _ALLOWED_STATUSES else "unknown"
        )

        evidence = diagnostic.evidence
        safe_evidence = (
            [_safe_text(item) for item in evidence if isinstance(item, str)]
            if isinstance(evidence, list)
            else []
        )
        diagnostics.append(
            {
                "rule_id": _safe_text(diagnostic.rule_id),
                "title": _safe_text(diagnostic.title),
                "severity": safe_severity,
                "summary": _safe_text(diagnostic.summary),
                "evidence": safe_evidence,
                "suggestion": _safe_text(diagnostic.suggestion),
                "status": safe_status,
            }
        )

    return {
        "schema_version": _safe_text(report.schema_version),
        "metadata": {
            "scan_time": safe_scan_time,
            "app_version": _safe_text(metadata.app_version),
            "platform": _safe_text(metadata.platform),
            "python_version": _safe_text(metadata.python_version),
        },
        "diagnostics": diagnostics,
    }
