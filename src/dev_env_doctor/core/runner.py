"""Read-only orchestration for one developer-environment scan."""

import re

from dev_env_doctor.collectors.commands import (
    CommandProbeResult,
    ProbeStatus,
    probe_tool,
    validate_probe_result,
)
from dev_env_doctor.collectors.config_files import CodexConfigState, inspect_codex_config
from dev_env_doctor.collectors.environment import inspect_path_value, inspect_process_path
from dev_env_doctor.core.models import DiagnosticResult, ProcessCleanupStatus, ScanReport, Severity
from dev_env_doctor.core.rules.config_rules import codex_config_diagnostic
from dev_env_doctor.core.scan_control import ScanCleanupUnconfirmedError
from dev_env_doctor.privacy.redaction import redact_text

_TOOLS = ("python", "git", "node", "npm", "codex")
_DISPLAY_NAMES = {
    "python": "Python",
    "git": "Git",
    "node": "Node.js",
    "npm": "npm",
    "codex": "Codex CLI (local command-line tool)",
}
_PATH_RULE_IDS = frozenset(
    {
        "PATH_EMPTY",
        "PATH_EMPTY_ENTRY",
        "PATH_DUPLICATE_ENTRY",
        "PATH_MISSING_ENTRY",
        "PATH_RELATIVE_ENTRY",
        "PATH_ENTRY_UNKNOWN",
    }
)
_VERSION_PATTERNS = {
    "python": re.compile(r"[0-9]+\.[0-9]+\.[0-9]+"),
    "git": re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:\.windows\.[0-9]+)?"),
    "node": re.compile(r"[0-9]+\.[0-9]+\.[0-9]+"),
    "npm": re.compile(r"[0-9]+\.[0-9]+\.[0-9]+"),
}
_MAX_PUBLIC_VERSION_LENGTH = 160


def _diagnostic(
    rule_id: str,
    title: str,
    severity: Severity,
    summary: str,
    *,
    status: str,
    evidence: list[str] | None = None,
    suggestion: str = "",
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


def _unverified_command(tool: str) -> DiagnosticResult:
    display_name = _DISPLAY_NAMES.get(tool, tool)
    summary = "The executable was found, but its version was not verified."
    suggestion = "Review the tool locally if version verification is required."
    if tool == "codex":
        summary = "The local Codex CLI was found, but its version was not verified."
        suggestion = "This scan does not inspect ChatGPT web, accounts, or login status."
    return _diagnostic(
        "COMMAND_VERSION_UNVERIFIED",
        f"{display_name} version not verified",
        Severity.INFO,
        summary,
        status="skipped",
        suggestion=suggestion,
    )


def _map_probe_result(tool: str, result: CommandProbeResult) -> DiagnosticResult:
    status = result.status
    display_name = _DISPLAY_NAMES.get(tool, tool)
    if status is ProbeStatus.VERIFIED:
        version = result.version
        pattern = _VERSION_PATTERNS.get(tool)
        if (
            isinstance(version, str)
            and len(version) <= _MAX_PUBLIC_VERSION_LENGTH
            and pattern is not None
            and pattern.fullmatch(version)
        ):
            return _diagnostic(
                "COMMAND_VERSION",
                f"{display_name} version",
                Severity.INFO,
                "The tool version was verified.",
                status="passed",
                evidence=[f"Verified version: {version}"],
            )
        return _unverified_command(tool)

    if status is ProbeStatus.MISSING:
        if tool == "codex":
            return _diagnostic(
                "COMMAND_NOT_FOUND",
                f"{display_name} not found in permitted locations",
                Severity.WARNING,
                "The local Codex CLI was not found in the permitted locations. "
                "This result does not indicate whether Codex in ChatGPT web is available.",
                status="found",
                suggestion="This scan does not inspect ChatGPT web, accounts, or login status.",
            )
        return _diagnostic(
            "COMMAND_NOT_FOUND",
            f"{display_name} not found in permitted locations",
            Severity.WARNING,
            "The executable was not found in the permitted search locations.",
            status="found",
            suggestion="Review the local tool installation and permitted search locations.",
        )

    if status is ProbeStatus.FOUND_UNVERIFIED:
        return _unverified_command(tool)

    failures = {
        ProbeStatus.NONZERO_EXIT: (
            "COMMAND_NONZERO_EXIT",
            f"{display_name} version check failed",
            Severity.WARNING,
        ),
        ProbeStatus.TIMEOUT: (
            "COMMAND_TIMEOUT",
            f"{display_name} version check timed out",
            Severity.WARNING,
        ),
        ProbeStatus.ERROR: (
            "COMMAND_PROBE_ERROR",
            f"{display_name} probe failed",
            Severity.ERROR,
        ),
    }
    try:
        rule_id, title, severity = failures[status]
    except (KeyError, TypeError) as exc:
        raise ValueError("Command collector returned an unsupported probe status") from exc
    return _diagnostic(
        rule_id,
        title,
        severity,
        "The tool could not be verified during this check.",
        status="error",
        suggestion="Retry the check later or inspect the tool locally.",
    )


def _probe_exception(tool: str) -> DiagnosticResult:
    display_name = _DISPLAY_NAMES.get(tool, tool)
    return _diagnostic(
        "COMMAND_PROBE_EXCEPTION",
        f"{display_name} probe failed",
        Severity.ERROR,
        "The tool probe could not be completed.",
        status="error",
        suggestion="Retry the check later.",
    )


def _sanitize_path_diagnostic(item: DiagnosticResult) -> DiagnosticResult:
    if not isinstance(item, DiagnosticResult) or item.rule_id not in _PATH_RULE_IDS:
        raise ValueError("PATH collector returned an unsupported diagnostic")

    return DiagnosticResult(
        rule_id=item.rule_id,
        title=redact_text(item.title),
        severity=item.severity,
        summary=redact_text(item.summary),
        evidence=[redact_text(value) for value in item.evidence if isinstance(value, str)],
        suggestion=redact_text(item.suggestion),
        status=item.status,
    )


def _path_scan_error() -> DiagnosticResult:
    return _diagnostic(
        "PATH_SCAN_ERROR",
        "PATH check failed",
        Severity.ERROR,
        "The current process PATH could not be checked.",
        status="error",
        suggestion="Review the process environment locally and retry the check.",
    )


def run_scan(*, path_snapshot: str | None = None) -> ScanReport:
    """Probe the fixed tool list and inspect the supplied diagnostic PATH.

    Ordinary tool failures are recorded independently. Unconfirmed process
    cleanup aborts the scan before further probes, PATH checks or a report.
    A PATH collector failure becomes an explicit error diagnostic. Failures
    while validating or constructing the final report are allowed to propagate.
    """
    diagnostics: list[DiagnosticResult] = []
    codex_cli_found = None

    for tool in _TOOLS:
        try:
            result = (
                probe_tool(tool)
                if path_snapshot is None
                else probe_tool(tool, path_snapshot=path_snapshot)
            )
        except ScanCleanupUnconfirmedError:
            raise
        except Exception:
            diagnostics.append(_probe_exception(tool))
        else:
            try:
                validate_probe_result(result)
            except (TypeError, ValueError):
                invalid_result = True
            else:
                invalid_result = False
            # Raise outside the validation handler, without chaining its error.
            # A contradictory result is not an isolated ordinary tool failure.
            if invalid_result or result.cleanup_status is ProcessCleanupStatus.UNCONFIRMED:
                raise ScanCleanupUnconfirmedError()
            diagnostics.append(_map_probe_result(tool, result))
            if tool == "codex":
                if result.status is ProbeStatus.FOUND_UNVERIFIED:
                    codex_cli_found = True
                elif result.status is ProbeStatus.MISSING:
                    codex_cli_found = False

    # Legacy START peers accept only the older diagnostic rule set.
    if path_snapshot is not None:
        try:
            config_state = inspect_codex_config()
        except Exception:
            config_state = CodexConfigState.UNVERIFIED
        diagnostics.append(codex_config_diagnostic(config_state, cli_found=codex_cli_found))

    try:
        path_diagnostics = (
            inspect_process_path()
            if path_snapshot is None
            else inspect_path_value(path_snapshot, parent_snapshot=True)
        )
        safe_path_diagnostics = [_sanitize_path_diagnostic(item) for item in path_diagnostics]
    except ScanCleanupUnconfirmedError:
        raise
    except Exception:
        diagnostics.append(_path_scan_error())
    else:
        diagnostics.extend(safe_path_diagnostics)

    # ScanReport owns the authoritative schema version and ScanMetadata defaults.
    return ScanReport(diagnostics=diagnostics)


def run_probe() -> ScanReport:
    """Run fixed command probes without PATH collection or a full scan."""
    diagnostics: list[DiagnosticResult] = []
    for tool in _TOOLS:
        try:
            result = probe_tool(tool)
        except ScanCleanupUnconfirmedError:
            raise
        except Exception:
            diagnostics.append(_probe_exception(tool))
        else:
            validate_probe_result(result)
            if result.cleanup_status is ProcessCleanupStatus.UNCONFIRMED:
                raise ScanCleanupUnconfirmedError()
            diagnostics.append(_map_probe_result(tool, result))
    return ScanReport(diagnostics=diagnostics)
