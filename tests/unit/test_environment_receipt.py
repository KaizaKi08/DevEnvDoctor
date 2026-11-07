import builtins
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from dev_env_doctor.collectors import commands
from dev_env_doctor.core import environment_probe, process_environment
from dev_env_doctor.core.models import DiagnosticResult, ScanReport, Severity
from dev_env_doctor.core.scan_control import ScanCleanupUnconfirmedError
from dev_env_doctor.reports.json_report import render_json_report


def _source() -> dict[str, str]:
    return {
        "SystemRoot": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "TEMP": r"C:\Temp",
        "TMP": r"C:\Temp",
        "PATH": r"C:\Windows\System32",
        process_environment.PROBE_UNICODE_NAME: process_environment.PROBE_UNICODE_VALUE,
    }


@pytest.fixture
def safe_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_environment, "_local_directory_state", lambda _path: True)


def test_worker_receipt_reads_actual_process_environment(monkeypatch, safe_paths) -> None:
    monkeypatch.setattr(environment_probe.os, "environ", _source())

    receipt = environment_probe.collect_worker_environment_receipt()

    assert {item.rule_id for item in receipt} == {
        "REQUIRED_VARIABLES_PRESENT",
        "SYSTEMROOT_WINDIR_MATCH",
        "TEMP_TMP_VALID",
        "PATH_PRESENT",
        "UNICODE_VALUE_MATCH",
        "SENSITIVE_VARIABLES_ABSENT",
    }
    assert all(item.evidence == ["PASS"] for item in receipt)


def test_worker_receipt_fails_closed_for_sensitive_canary(monkeypatch, safe_paths) -> None:
    source = _source()
    source["TOKEN"] = "synthetic"
    monkeypatch.setattr(environment_probe.os, "environ", source)

    receipt = environment_probe.collect_worker_environment_receipt()

    sensitive = next(item for item in receipt if item.rule_id == "SENSITIVE_VARIABLES_ABSENT")
    assert sensitive.evidence == ["FAIL"]


def test_worker_receipt_marks_missing_unicode_marker_unverified(monkeypatch, safe_paths) -> None:
    source = _source()
    source.pop(process_environment.PROBE_UNICODE_NAME)
    monkeypatch.setattr(environment_probe.os, "environ", source)

    receipt = environment_probe.collect_worker_environment_receipt()

    marker = next(item for item in receipt if item.rule_id == "UNICODE_VALUE_MATCH")
    assert marker.evidence == ["NOT_VERIFIED"]


def test_fixed_receipt_rules_use_existing_report_fields() -> None:
    report = ScanReport(
        diagnostics=[
            DiagnosticResult(
                rule_id="REQUIRED_VARIABLES_PRESENT",
                title="Environment receipt",
                severity=Severity.INFO,
                summary="Fixed predicate.",
                evidence=["PASS"],
                status="passed",
            )
        ]
    )

    exported = render_json_report(report)

    assert "REQUIRED_VARIABLES_PRESENT" in exported
    assert "PASS" in exported


def test_tool_receipt_rejects_untrusted_executable(monkeypatch) -> None:
    monkeypatch.setattr(commands, "is_trusted_executable", lambda _path: False)
    popen = Mock()
    monkeypatch.setattr(commands.subprocess, "Popen", popen)

    result = commands.probe_python_environment(r"C:\Users\Public\python.exe")

    assert result.started == "NOT_VERIFIED"
    popen.assert_not_called()


_PYTHON = r"C:\Program Files\Python\python.exe"
_OK = b"ENV_RECEIPT_V1 MARKER=PASS SENSITIVE=PASS\n"


@pytest.fixture
def receipt_process(monkeypatch):
    process = Mock()
    process.stdout = BytesIO(_OK)
    process.stderr = BytesIO()
    process.poll.return_value = 0
    process.wait.return_value = 0
    process.returncode = 0
    popen = Mock(return_value=process)
    monkeypatch.setattr(commands, "is_trusted_executable", lambda _path: True)
    monkeypatch.setattr(commands, "build_tool_environment", Mock(return_value=_source()))
    monkeypatch.setattr(commands.subprocess, "Popen", popen)
    return process, popen


def test_tool_receipt_uses_isolated_fixed_command_and_explicit_environment(receipt_process) -> None:
    _, popen = receipt_process
    result = commands.probe_python_environment(_PYTHON)
    assert result == commands.ToolReceipt("PASS", "PASS", "PASS", "PASS", "PASS")
    args, kwargs = popen.call_args
    assert args == ([_PYTHON, "-I", "-S", "-c", commands._ENVIRONMENT_RECEIPT_SCRIPT],)
    assert kwargs["shell"] is False
    assert kwargs["env"] == _source()
    commands.build_tool_environment.assert_called_once_with(_PYTHON, include_probe_marker=True)


@pytest.mark.parametrize(
    ("returncode", "wait_code", "expected"),
    [(7, 7, "FAIL"), (None, 0, "NOT_VERIFIED"), (0, 7, "NOT_VERIFIED"), (False, 0, "NOT_VERIFIED")],
)
def test_valid_output_cannot_replace_exit_evidence(
    receipt_process, returncode, wait_code, expected
) -> None:
    process, _ = receipt_process
    process.returncode = returncode
    process.wait.return_value = wait_code
    assert commands.probe_python_environment(_PYTHON) == commands.ToolReceipt(
        "PASS", "NOT_VERIFIED", "NOT_VERIFIED", expected, "PASS"
    )


@pytest.mark.parametrize(
    ("stdout", "stderr"),
    [
        (b"", b""),
        (_OK + b"x" * 100, b""),
        (b"ENV_RECEIPT_V1 MARKER=UNKNOWN SENSITIVE=PASS\n", b""),
        (_OK.rstrip() + b" EXTRA=PASS\n", b""),
        (_OK, b"unexpected diagnostic"),
    ],
)
def test_zero_exit_does_not_validate_invalid_output(receipt_process, stdout, stderr) -> None:
    process, _ = receipt_process
    process.stdout = BytesIO(stdout)
    process.stderr = BytesIO(stderr)
    assert commands.probe_python_environment(_PYTHON) == commands.ToolReceipt(
        "PASS", "NOT_VERIFIED", "NOT_VERIFIED", "PASS", "FAIL"
    )


@pytest.mark.parametrize(
    ("marker", "sensitive", "expected"),
    [("PASS", "FAIL", ("PASS", "FAIL")), ("FAIL", "PASS", ("FAIL", "PASS"))],
)
def test_independent_environment_predicates(receipt_process, marker, sensitive, expected) -> None:
    process, _ = receipt_process
    line = f"ENV_RECEIPT_V1 MARKER={marker} SENSITIVE={sensitive}\n"
    process.stdout = BytesIO(line.encode("ascii"))
    result = commands.probe_python_environment(_PYTHON)
    assert (result.environment_received, result.sensitive_variables_absent) == expected
    assert (result.started, result.exit_success, result.output_valid) == ("PASS", "PASS", "PASS")


@pytest.mark.parametrize(
    ("marker", "extras", "expected"),
    [
        (process_environment.PROBE_UNICODE_VALUE, {}, _OK),
        ("wrong", {}, b"ENV_RECEIPT_V1 MARKER=FAIL SENSITIVE=PASS\n"),
        (None, {}, b"ENV_RECEIPT_V1 MARKER=FAIL SENSITIVE=PASS\n"),
        (
            process_environment.PROBE_UNICODE_VALUE,
            {"tOkEn": "synthetic-secret"},
            b"ENV_RECEIPT_V1 MARKER=PASS SENSITIVE=FAIL\n",
        ),
    ],
)
def test_fixed_script_reads_child_environment_in_memory(marker, extras, expected) -> None:
    environment = dict(extras)
    if marker is not None:
        environment[process_environment.PROBE_UNICODE_NAME] = marker
    output = BytesIO()
    modules = {
        "os": SimpleNamespace(environ=environment),
        "sys": SimpleNamespace(stdout=SimpleNamespace(buffer=output)),
    }
    importer = Mock(side_effect=lambda name, *_args: modules[name])
    namespace = {"__builtins__": {**vars(builtins), "__import__": importer}}
    exec(commands._ENVIRONMENT_RECEIPT_SCRIPT, namespace)
    assert output.getvalue() == expected
    assert [call.args[0] for call in importer.call_args_list] == ["os", "sys"]


def test_creation_failure_has_no_child_evidence(receipt_process, monkeypatch) -> None:
    _, popen = receipt_process
    popen.side_effect = OSError("synthetic")
    cleanup = Mock()
    monkeypatch.setattr(commands, "_stop_process", cleanup)
    assert commands.probe_python_environment(_PYTHON) == commands.ToolReceipt(started="FAIL")
    cleanup.assert_not_called()


@pytest.mark.parametrize("path", ["python.exe", r"C:\Trusted\git.exe", r"C:\Trusted\python.cmd"])
def test_receipt_refuses_non_python_or_relative_paths(receipt_process, path) -> None:
    _, popen = receipt_process
    assert commands.probe_python_environment(path) == commands.ToolReceipt()
    popen.assert_not_called()


def test_receipt_rechecks_trust_before_launch(receipt_process, monkeypatch) -> None:
    _, popen = receipt_process
    trusted = Mock(side_effect=[True, False])
    monkeypatch.setattr(commands, "is_trusted_executable", trusted)
    assert commands.probe_python_environment(_PYTHON) == commands.ToolReceipt()
    commands.build_tool_environment.assert_called_once()
    assert trusted.call_count == 2
    popen.assert_not_called()


def test_wait_error_cannot_promote_exit_or_output_evidence(receipt_process) -> None:
    process, _ = receipt_process
    process.wait.side_effect = OSError("synthetic")
    assert commands.probe_python_environment(_PYTHON) == commands.ToolReceipt(started="PASS")


def test_timeout_stays_failed_after_cleanup(receipt_process) -> None:
    process, _ = receipt_process
    process.wait.side_effect = [commands.subprocess.TimeoutExpired(_PYTHON, 5), 0]
    process.poll.return_value = None
    result = commands.probe_python_environment(_PYTHON)
    process.kill.assert_called_once_with()
    assert process.wait.call_count == 2
    assert result == commands.ToolReceipt(started="PASS", exit_success="FAIL")


@pytest.mark.parametrize("cleanup_raises", [False, True])
def test_unconfirmed_cleanup_reaches_worker_failure_path(
    receipt_process, monkeypatch, cleanup_raises
) -> None:
    cleanup = Mock(return_value=commands.ProcessCleanupStatus.UNCONFIRMED)
    if cleanup_raises:
        cleanup.side_effect = OSError("synthetic")
    monkeypatch.setattr(commands, "_stop_process", cleanup)
    monkeypatch.setattr(environment_probe, "validate_worker_environment", Mock())
    monkeypatch.setattr(environment_probe.runner, "run_probe", Mock(return_value=ScanReport()))
    monkeypatch.setattr(environment_probe, "find_local_executable", Mock(return_value=_PYTHON))
    monkeypatch.setattr(environment_probe, "is_trusted_executable", Mock(return_value=True))
    with pytest.raises(ScanCleanupUnconfirmedError, match="cleanup could not be confirmed"):
        environment_probe.run_probe()
    cleanup.assert_called_once()


def test_probe_report_maps_each_rule_to_its_own_evidence(receipt_process, monkeypatch) -> None:
    process, _ = receipt_process
    process.stdout = BytesIO(b"ENV_RECEIPT_V1 MARKER=FAIL SENSITIVE=PASS\n")
    monkeypatch.setattr(environment_probe, "validate_worker_environment", Mock())
    monkeypatch.setattr(
        environment_probe, "collect_worker_environment_receipt", Mock(return_value=())
    )
    monkeypatch.setattr(environment_probe.runner, "run_probe", Mock(return_value=ScanReport()))
    monkeypatch.setattr(environment_probe, "find_local_executable", Mock(return_value=_PYTHON))
    monkeypatch.setattr(environment_probe, "is_trusted_executable", Mock(return_value=True))
    report = environment_probe.run_probe()
    assert {item.rule_id: item.evidence for item in report.diagnostics} == {
        "TOOL_CHILD_STARTED": ["PASS"],
        "TOOL_CHILD_ENVIRONMENT_RECEIVED": ["FAIL"],
        "TOOL_CHILD_SENSITIVE_VARIABLES_ABSENT": ["PASS"],
        "TOOL_CHILD_EXIT_SUCCESS": ["PASS"],
        "TOOL_CHILD_OUTPUT_VALID": ["PASS"],
    }
