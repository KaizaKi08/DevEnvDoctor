"""Privacy-aware JSON rendering for diagnostic reports."""

import json
import re
from datetime import datetime

from dev_env_doctor.core.models import DiagnosticResult, ScanReport, Severity
from dev_env_doctor.core.rules.config_rules import CODEX_CLI_EVIDENCE, CODEX_CONFIG_FINDINGS
from dev_env_doctor.core.runner import _DISPLAY_NAMES, _MAX_PUBLIC_VERSION_LENGTH
from dev_env_doctor.privacy.redaction import redact_text

JSON_SCHEMA_VERSION = "1.0"
_MAX_TEXT_LENGTH = 4096
_MAX_EVIDENCE_LENGTH = 256
_UNKNOWN = "unknown"
_TEXT_FALLBACKS = {
    "title": "诊断标题不可用。",
    "summary": "摘要不可用。",
    "suggestion": "建议不可用。",
}
_PROBE_ERROR_TITLES = frozenset(f"{name} probe failed" for name in _DISPLAY_NAMES.values())
_PROBE_ERROR_RULES = frozenset({"COMMAND_PROBE_ERROR", "COMMAND_PROBE_EXCEPTION"})
_SEVERITIES = frozenset(item.value for item in Severity)
_STATUSES = frozenset({"found", "passed", "skipped", "error"})
REVIEWED_RULE_IDS = frozenset(
    {
        "COMMAND_VERSION",
        "COMMAND_VERSION_UNVERIFIED",
        "COMMAND_NOT_FOUND",
        "COMMAND_NONZERO_EXIT",
        "COMMAND_TIMEOUT",
        "COMMAND_PROBE_ERROR",
        "COMMAND_PROBE_EXCEPTION",
        "PATH_EMPTY",
        "PATH_EMPTY_ENTRY",
        "PATH_DUPLICATE_ENTRY",
        "PATH_MISSING_ENTRY",
        "PATH_RELATIVE_ENTRY",
        "PATH_ENTRY_UNKNOWN",
        "PATH_SCAN_ERROR",
        "REQUIRED_VARIABLES_PRESENT",
        "SYSTEMROOT_WINDIR_MATCH",
        "TEMP_TMP_VALID",
        "PATH_PRESENT",
        "UNICODE_VALUE_MATCH",
        "SENSITIVE_VARIABLES_ABSENT",
        "TOOL_CHILD_STARTED",
        "TOOL_CHILD_ENVIRONMENT_RECEIVED",
        "TOOL_CHILD_SENSITIVE_VARIABLES_ABSENT",
        "TOOL_CHILD_EXIT_SUCCESS",
        "TOOL_CHILD_OUTPUT_VALID",
    }
) | frozenset(CODEX_CONFIG_FINDINGS)
_COMMAND_VERSION_PATTERNS = {
    "python": re.compile(r"[0-9]+\.[0-9]+\.[0-9]+"),
    "git": re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:\.windows\.[0-9]+)?"),
    "node": re.compile(r"[0-9]+\.[0-9]+\.[0-9]+"),
    "npm": re.compile(r"[0-9]+\.[0-9]+\.[0-9]+"),
}
_PATH_POSITION_EVIDENCE = {
    "PATH_EMPTY_ENTRY": re.compile(r"Empty item positions: [0-9]+(?:, [0-9]+)*\."),
    "PATH_DUPLICATE_ENTRY": re.compile(
        r"Equivalent item positions: [0-9]+(?:, [0-9]+)*(?:; [0-9]+(?:, [0-9]+)*)*\."
    ),
    "PATH_MISSING_ENTRY": re.compile(r"Unavailable item positions: [0-9]+(?:, [0-9]+)*\."),
    "PATH_RELATIVE_ENTRY": re.compile(r"Relative item positions: [0-9]+(?:, [0-9]+)*\."),
    "PATH_ENTRY_UNKNOWN": re.compile(r"Unverified item positions: [0-9]+(?:, [0-9]+)*\."),
}
_FIXED_RECEIPT_RULES = frozenset(
    {
        "REQUIRED_VARIABLES_PRESENT",
        "SYSTEMROOT_WINDIR_MATCH",
        "TEMP_TMP_VALID",
        "PATH_PRESENT",
        "UNICODE_VALUE_MATCH",
        "SENSITIVE_VARIABLES_ABSENT",
        "TOOL_CHILD_STARTED",
        "TOOL_CHILD_ENVIRONMENT_RECEIVED",
        "TOOL_CHILD_SENSITIVE_VARIABLES_ABSENT",
        "TOOL_CHILD_EXIT_SUCCESS",
        "TOOL_CHILD_OUTPUT_VALID",
    }
)


class JSONReportError(ValueError):
    """Raised when a report cannot be safely represented by the JSON schema."""


def _safe_text(
    value: object,
    fallback: str,
    *,
    allow_empty: bool = False,
    machine_names: tuple[str, ...] = (),
) -> str:
    if not isinstance(value, str) or len(value) > _MAX_TEXT_LENGTH:
        return fallback
    if not allow_empty and not value.strip():
        return fallback
    try:
        value.encode("utf-8")
        redacted = redact_text(value, machine_names=machine_names)
        if not isinstance(redacted, str) or len(redacted) > _MAX_TEXT_LENGTH:
            return fallback
        redacted.encode("utf-8")
    except Exception:
        return fallback
    return redacted


def safe_evidence(diagnostic: DiagnosticResult) -> list[str]:
    """Return only evidence formats emitted by the current reviewed runner."""
    if not isinstance(diagnostic, DiagnosticResult):
        return []
    rule_id = diagnostic.rule_id
    evidence = diagnostic.evidence
    if not isinstance(rule_id, str) or not isinstance(evidence, list) or len(evidence) != 1:
        return []
    value = evidence[0]
    if not isinstance(value, str) or len(value) > _MAX_EVIDENCE_LENGTH:
        return []

    if rule_id == "PATH_EMPTY":
        return [value] if value == "No PATH entries were available." else []
    if rule_id in CODEX_CONFIG_FINDINGS:
        return [value] if value in CODEX_CLI_EVIDENCE else []
    path_pattern = _PATH_POSITION_EVIDENCE.get(rule_id)
    if path_pattern is not None:
        return [value] if path_pattern.fullmatch(value) else []

    if rule_id == "COMMAND_VERSION":
        title = diagnostic.title
        if not isinstance(title, str) or diagnostic.status != "passed":
            return []
        tool = title.removesuffix(" version")
        version_pattern = _COMMAND_VERSION_PATTERNS.get(tool)
        prefix = "Verified version: "
        if value.startswith(prefix) and version_pattern is not None:
            version = value[len(prefix) :]
            if len(version) <= _MAX_PUBLIC_VERSION_LENGTH and version_pattern.fullmatch(version):
                return [f"{prefix}{version}"]
    if rule_id in _FIXED_RECEIPT_RULES and value in {"PASS", "FAIL", "NOT_VERIFIED"}:
        return [value]
    return []


def diagnostic_text(diagnostic: DiagnosticResult) -> tuple[str, str, str]:
    """Use fixed text where diagnostics must not carry raw inputs."""
    config = CODEX_CONFIG_FINDINGS.get(diagnostic.rule_id)
    if config is not None:
        return config.title, config.summary, config.suggestion
    if diagnostic.rule_id in _PROBE_ERROR_RULES:
        title = diagnostic.title
        if not isinstance(title, str) or title not in _PROBE_ERROR_TITLES:
            title = "Tool probe failed"
        return title, "The tool probe could not be completed.", "Retry the check later."
    if diagnostic.rule_id == "PATH_SCAN_ERROR":
        return (
            "PATH check failed",
            "The current process PATH could not be checked.",
            "Review the process environment locally and retry the check.",
        )
    return diagnostic.title, diagnostic.summary, diagnostic.suggestion


def _diagnostic_payload(
    diagnostic: DiagnosticResult,
    *,
    machine_names: tuple[str, ...],
) -> dict[str, str | list[str]]:
    if not isinstance(diagnostic, DiagnosticResult):
        raise JSONReportError("Report contains an invalid diagnostic entry.")
    rule_id = diagnostic.rule_id
    if not isinstance(rule_id, str) or rule_id not in REVIEWED_RULE_IDS:
        raise JSONReportError("Report contains an unreviewed diagnostic rule.")

    severity = diagnostic.severity
    severity_value = (
        severity.value
        if isinstance(severity, Severity)
        else severity
        if isinstance(severity, str) and severity in _SEVERITIES
        else _UNKNOWN
    )
    status = diagnostic.status
    status_value = status if isinstance(status, str) and status in _STATUSES else _UNKNOWN
    config = CODEX_CONFIG_FINDINGS.get(rule_id)
    if config is not None:
        severity_value, status_value = config.severity.value, config.status

    title, summary, suggestion = diagnostic_text(diagnostic)
    return {
        "rule_id": rule_id,
        "title": _safe_text(
            title,
            _TEXT_FALLBACKS["title"],
            machine_names=machine_names,
        ),
        "summary": _safe_text(
            summary,
            _TEXT_FALLBACKS["summary"],
            machine_names=machine_names,
        ),
        "severity": severity_value,
        "status": status_value,
        "suggestion": _safe_text(
            suggestion,
            _TEXT_FALLBACKS["suggestion"],
            allow_empty=True,
            machine_names=machine_names,
        ),
        "evidence": safe_evidence(diagnostic),
    }


def build_json_payload(
    report: ScanReport,
    *,
    generated_at: datetime | None = None,
    machine_names: tuple[str, ...] = (),
) -> dict[str, object]:
    """Build the export schema from reviewed fields only.

    Text redaction is a risk reduction step, not a general secret detector.
    This explicit field/rule allowlist and minimal data selection define the
    export boundary; the complete Pydantic object is never serialized.
    """
    if not isinstance(report, ScanReport) or not isinstance(report.diagnostics, list):
        raise JSONReportError("Report structure is invalid.")
    if any(not isinstance(item, DiagnosticResult) for item in report.diagnostics):
        raise JSONReportError("Report structure is invalid.")

    timestamp = generated_at if generated_at is not None else datetime.now().astimezone()
    if (
        not isinstance(timestamp, datetime)
        or timestamp.tzinfo is None
        or timestamp.utcoffset() is None
    ):
        raise JSONReportError("Export time must include a timezone.")

    diagnostics = [
        _diagnostic_payload(item, machine_names=machine_names) for item in report.diagnostics
    ]
    severity_counts = {value: 0 for value in (*sorted(_SEVERITIES), _UNKNOWN)}
    status_counts = {value: 0 for value in (*sorted(_STATUSES), _UNKNOWN)}
    for item in diagnostics:
        severity_counts[item["severity"]] += 1
        status_counts[item["status"]] += 1

    return {
        "schema_version": JSON_SCHEMA_VERSION,
        "generated_at": timestamp.isoformat(),
        "summary": {
            "total": len(diagnostics),
            "severity_counts": severity_counts,
            "status_counts": status_counts,
        },
        "diagnostics": diagnostics,
    }


def render_json_report(
    report: ScanReport,
    *,
    generated_at: datetime | None = None,
    machine_names: tuple[str, ...] = (),
) -> str:
    """Render an allowlisted report as readable UTF-8-compatible JSON text."""
    try:
        payload = build_json_payload(
            report,
            generated_at=generated_at,
            machine_names=machine_names,
        )
        rendered = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        rendered.encode("utf-8")
        return rendered
    except Exception:
        pass
    raise JSONReportError("Report could not be safely serialized.") from None
