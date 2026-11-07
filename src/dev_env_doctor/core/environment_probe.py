import ntpath
import os
import sys

from dev_env_doctor.collectors.commands import ToolReceipt, probe_python_environment
from dev_env_doctor.collectors.executable_lookup import find_local_executable, is_trusted_executable
from dev_env_doctor.core import runner
from dev_env_doctor.core.frozen_runtime_environment import validate_frozen_worker_environment
from dev_env_doctor.core.models import DiagnosticResult, ScanReport, Severity
from dev_env_doctor.core.process_environment import (
    PROBE_UNICODE_NAME,
    PROBE_UNICODE_VALUE,
    EnvironmentConstructionError,
    _safe_local_directory,
    build_worker_environment,
)
from dev_env_doctor.core.process_environment import _value as _environment_value
from dev_env_doctor.core.scan_control import ScanCleanupUnconfirmedError

_ALLOWED_ENVIRONMENT = frozenset(
    {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH", PROBE_UNICODE_NAME}
)
_SENSITIVE_NAMES = frozenset(
    {"PYTHONPATH", "NODE_OPTIONS", "GIT_CONFIG_GLOBAL", "CODEX_API_KEY", "HTTPS_PROXY", "TOKEN"}
)
_RECEIPT_RULES = (
    "REQUIRED_VARIABLES_PRESENT",
    "SYSTEMROOT_WINDIR_MATCH",
    "TEMP_TMP_VALID",
    "PATH_PRESENT",
    "UNICODE_VALUE_MATCH",
    "SENSITIVE_VARIABLES_ABSENT",
)


def _receipt(rule_id: str, status: str) -> DiagnosticResult:
    passed = status == "PASS"
    return DiagnosticResult(
        rule_id=rule_id,
        title=f"Environment receipt: {rule_id}",
        severity=Severity.INFO if passed else Severity.WARNING,
        summary="Fixed environment receipt predicate was evaluated.",
        evidence=[status],
        suggestion="Review the supervised environment boundary." if not passed else "",
        status="passed" if passed else "error" if status == "FAIL" else "skipped",
    )


def collect_worker_environment_receipt() -> tuple[DiagnosticResult, ...]:
    """Evaluate fixed predicates against the Worker process environment only."""
    environment = os.environ
    try:
        required = all(
            _environment_value(environment, name) is not None
            for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH")
        )
        roots = (
            _environment_value(environment, "SYSTEMROOT"),
            _environment_value(environment, "WINDIR"),
        )
        system_match = (
            all(isinstance(value, str) for value in roots)
            and ntpath.normcase(ntpath.normpath(roots[0]))
            == ntpath.normcase(ntpath.normpath(roots[1]))
            and _safe_local_directory(roots[0]) == _safe_local_directory(roots[1])
        )
        temp_valid = all(
            _safe_local_directory(_environment_value(environment, name)) for name in ("TEMP", "TMP")
        )
        path_present = isinstance(_environment_value(environment, "PATH"), str)
        unicode_value = _environment_value(environment, PROBE_UNICODE_NAME)
        unicode_match = (
            "NOT_VERIFIED"
            if unicode_value is None
            else "PASS"
            if unicode_value == PROBE_UNICODE_VALUE
            else "FAIL"
        )
        sensitive_absent = not any(key.upper() in _SENSITIVE_NAMES for key in environment)
    except Exception:
        return tuple(_receipt(rule_id, "NOT_VERIFIED") for rule_id in _RECEIPT_RULES)
    values = (
        required,
        system_match,
        temp_valid,
        path_present,
        unicode_match,
        sensitive_absent,
    )
    return tuple(
        _receipt(
            rule_id,
            value if isinstance(value, str) else "PASS" if value else "FAIL",
        )
        for rule_id, value in zip(_RECEIPT_RULES, values, strict=True)
    )


def validate_worker_environment() -> None:
    if not _ALLOWED_ENVIRONMENT.issuperset({key.upper() for key in os.environ}):
        raise EnvironmentConstructionError()
    build_worker_environment(os.environ)


def run_probe() -> ScanReport:
    if getattr(sys, "frozen", False) is not False or hasattr(sys, "_MEIPASS"):
        validate_frozen_worker_environment()
    else:
        validate_worker_environment()
    report = runner.run_probe()
    receipt = ToolReceipt()
    try:
        executable = find_local_executable("python")
        if executable is not None and is_trusted_executable(executable):
            receipt = probe_python_environment(executable)
    except ScanCleanupUnconfirmedError:
        raise
    except Exception:
        receipt = ToolReceipt()
    tool_receipt = (
        _receipt("TOOL_CHILD_STARTED", receipt.started),
        _receipt("TOOL_CHILD_ENVIRONMENT_RECEIVED", receipt.environment_received),
        _receipt("TOOL_CHILD_SENSITIVE_VARIABLES_ABSENT", receipt.sensitive_variables_absent),
        _receipt("TOOL_CHILD_EXIT_SUCCESS", receipt.exit_success),
        _receipt("TOOL_CHILD_OUTPUT_VALID", receipt.output_valid),
    )
    return report.model_copy(
        update={
            "diagnostics": [
                *collect_worker_environment_receipt(),
                *tool_receipt,
                *report.diagnostics,
            ]
        }
    )
