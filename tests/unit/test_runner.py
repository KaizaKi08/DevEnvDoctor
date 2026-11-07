from unittest.mock import Mock, call

import pytest

from dev_env_doctor import __version__
from dev_env_doctor.collectors.commands import CommandProbeResult, ProbeStatus
from dev_env_doctor.core import models, runner
from dev_env_doctor.core.models import DiagnosticResult, ProcessCleanupStatus, Severity
from dev_env_doctor.core.scan_control import ScanCleanupUnconfirmedError

TOOLS = ("python", "git", "node", "npm", "codex")
DISPLAY_NAMES = {
    "python": "Python",
    "git": "Git",
    "node": "Node.js",
    "npm": "npm",
    "codex": "Codex CLI (local command-line tool)",
}
SAFE_VERSIONS = {
    "python": "3.13.9",
    "git": "2.53.0.windows.3",
    "node": "22.1.0",
    "npm": "10.8.0",
    "codex": None,
}


def _probe_result(
    tool: str,
    status: ProbeStatus,
    *,
    version: str | None = None,
    executable: str | None = None,
    message: str = "",
    cleanup_status: ProcessCleanupStatus = ProcessCleanupStatus.NOT_STARTED,
) -> CommandProbeResult:
    return CommandProbeResult(
        tool=tool,
        status=status,
        executable=executable,
        version=version,
        message=message,
        cleanup_status=cleanup_status,
    )


def _patch_empty_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "inspect_process_path", lambda: [])


def test_run_scan_probes_allowlisted_tools_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_probe(tool: str) -> CommandProbeResult:
        calls.append(tool)
        return _probe_result(tool, ProbeStatus.MISSING)

    monkeypatch.setattr(runner, "probe_tool", fake_probe)
    _patch_empty_path(monkeypatch)

    report = runner.run_scan()

    assert calls == list(TOOLS)
    assert [item.rule_id for item in report.diagnostics] == ["COMMAND_NOT_FOUND"] * 5
    for tool, item in zip(TOOLS, report.diagnostics, strict=True):
        assert item.title == f"{DISPLAY_NAMES[tool]} not found in permitted locations"
        assert item.status == "found"
        if tool == "codex":
            assert item.summary == (
                "The local Codex CLI was not found in the permitted locations. "
                "This result does not indicate whether Codex in ChatGPT web is available."
            )
        else:
            assert item.summary == "The executable was not found in the permitted search locations."


def test_run_scan_uses_local_cli_and_runtime_display_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_probe(tool: str) -> CommandProbeResult:
        if tool == "node":
            return _probe_result(tool, ProbeStatus.FOUND_UNVERIFIED)
        if tool == "npm":
            return _probe_result(
                tool,
                ProbeStatus.VERIFIED,
                version="10.8.0",
                cleanup_status=ProcessCleanupStatus.CONFIRMED,
            )
        return _probe_result(tool, ProbeStatus.MISSING)

    monkeypatch.setattr(runner, "probe_tool", fake_probe)
    _patch_empty_path(monkeypatch)

    report = runner.run_scan()
    by_tool = dict(zip(TOOLS, report.diagnostics, strict=True))

    assert by_tool["node"].title == "Node.js version not verified"
    assert by_tool["npm"].title == "npm version"
    assert by_tool["codex"].title == (
        "Codex CLI (local command-line tool) not found in permitted locations"
    )
    assert by_tool["codex"].summary == (
        "The local Codex CLI was not found in the permitted locations. "
        "This result does not indicate whether Codex in ChatGPT web is available."
    )
    assert by_tool["codex"].suggestion == (
        "This scan does not inspect ChatGPT web, accounts, or login status."
    )


def test_run_scan_describes_found_local_codex_cli_without_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_probe(tool: str) -> CommandProbeResult:
        if tool == "codex":
            return _probe_result(tool, ProbeStatus.FOUND_UNVERIFIED)
        return _probe_result(tool, ProbeStatus.MISSING)

    monkeypatch.setattr(runner, "probe_tool", fake_probe)
    _patch_empty_path(monkeypatch)

    report = runner.run_scan()
    codex = report.diagnostics[-1]

    assert codex.rule_id == "COMMAND_VERSION_UNVERIFIED"
    assert codex.status == "skipped"
    assert codex.severity is Severity.INFO
    assert codex.title == "Codex CLI (local command-line tool) version not verified"
    assert codex.summary == "The local Codex CLI was found, but its version was not verified."
    assert codex.suggestion == "This scan does not inspect ChatGPT web, accounts, or login status."


@pytest.mark.parametrize(
    ("probe_status", "rule_id", "diagnostic_status", "severity", "cleanup_status"),
    [
        (
            ProbeStatus.VERIFIED,
            "COMMAND_VERSION",
            "passed",
            Severity.INFO,
            ProcessCleanupStatus.CONFIRMED,
        ),
        (
            ProbeStatus.MISSING,
            "COMMAND_NOT_FOUND",
            "found",
            Severity.WARNING,
            ProcessCleanupStatus.NOT_STARTED,
        ),
        (
            ProbeStatus.FOUND_UNVERIFIED,
            "COMMAND_VERSION_UNVERIFIED",
            "skipped",
            Severity.INFO,
            ProcessCleanupStatus.NOT_STARTED,
        ),
        (
            ProbeStatus.FOUND_UNVERIFIED,
            "COMMAND_VERSION_UNVERIFIED",
            "skipped",
            Severity.INFO,
            ProcessCleanupStatus.CONFIRMED,
        ),
        (
            ProbeStatus.NONZERO_EXIT,
            "COMMAND_NONZERO_EXIT",
            "error",
            Severity.WARNING,
            ProcessCleanupStatus.CONFIRMED,
        ),
        (
            ProbeStatus.TIMEOUT,
            "COMMAND_TIMEOUT",
            "error",
            Severity.WARNING,
            ProcessCleanupStatus.CONFIRMED,
        ),
        (
            ProbeStatus.ERROR,
            "COMMAND_PROBE_ERROR",
            "error",
            Severity.ERROR,
            ProcessCleanupStatus.NOT_STARTED,
        ),
        (
            ProbeStatus.ERROR,
            "COMMAND_PROBE_ERROR",
            "error",
            Severity.ERROR,
            ProcessCleanupStatus.CONFIRMED,
        ),
    ],
)
def test_each_probe_status_maps_to_a_valid_diagnostic(
    probe_status: ProbeStatus,
    rule_id: str,
    diagnostic_status: str,
    severity: Severity,
    cleanup_status: ProcessCleanupStatus,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_probe(tool: str) -> CommandProbeResult:
        calls.append(tool)
        if tool != "python":
            return _probe_result(tool, ProbeStatus.MISSING)
        version = SAFE_VERSIONS[tool] if probe_status is ProbeStatus.VERIFIED else None
        return _probe_result(tool, probe_status, version=version, cleanup_status=cleanup_status)

    monkeypatch.setattr(runner, "probe_tool", fake_probe)
    _patch_empty_path(monkeypatch)

    report = runner.run_scan()

    assert calls == list(TOOLS)
    assert len(report.diagnostics) == len(TOOLS)
    first = report.diagnostics[0]
    assert first.rule_id == rule_id
    assert first.status == diagnostic_status
    assert first.severity is severity
    assert first.title
    assert first.summary
    assert first.evidence == (
        ["Verified version: 3.13.9"] if probe_status is ProbeStatus.VERIFIED else []
    )
    assert [item.rule_id for item in report.diagnostics[1:]] == ["COMMAND_NOT_FOUND"] * 4
    assert all(item.status == "found" for item in report.diagnostics[1:])


def test_untrusted_version_and_collector_message_are_not_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_probe(tool: str) -> CommandProbeResult:
        if tool == "python":
            return _probe_result(
                tool,
                ProbeStatus.VERIFIED,
                version=r"3.13.9 C:\Users\Alice\token=fictional-secret",
                executable=r"C:\Users\Alice\private\python.exe",
                message="fictional stdout and stderr secret",
                cleanup_status=ProcessCleanupStatus.CONFIRMED,
            )
        return _probe_result(
            tool,
            ProbeStatus.MISSING,
            executable=r"C:\Users\Alice\private\tool.exe",
            message="fictional raw output token=collector-secret",
        )

    monkeypatch.setattr(runner, "probe_tool", fake_probe)
    _patch_empty_path(monkeypatch)

    report = runner.run_scan()
    serialized = report.model_dump_json()

    assert report.diagnostics[0].rule_id == "COMMAND_VERSION_UNVERIFIED"
    for private_text in (
        "Alice",
        "private",
        "fictional-secret",
        "fictional stdout",
        "fictional raw output",
        "collector-secret",
    ):
        assert private_text not in serialized
    assert report.diagnostics[0].evidence == []


def test_safe_verified_version_is_the_only_command_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_probe(tool: str) -> CommandProbeResult:
        return _probe_result(
            tool,
            ProbeStatus.VERIFIED if tool == "git" else ProbeStatus.MISSING,
            version=SAFE_VERSIONS[tool] if tool == "git" else None,
            executable=r"C:\Users\Alice\private\git.exe",
            message="fictional raw stderr token=secret",
            cleanup_status=(
                ProcessCleanupStatus.CONFIRMED
                if tool == "git"
                else ProcessCleanupStatus.NOT_STARTED
            ),
        )

    monkeypatch.setattr(runner, "probe_tool", fake_probe)
    _patch_empty_path(monkeypatch)

    report = runner.run_scan()
    git_result = report.diagnostics[1]

    assert git_result.rule_id == "COMMAND_VERSION"
    assert git_result.status == "passed"
    assert git_result.evidence == ["Verified version: 2.53.0.windows.3"]
    assert "Alice" not in report.model_dump_json()
    assert "fictional raw stderr" not in report.model_dump_json()


def test_path_diagnostics_are_field_minimized_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fictional_path = r"C:\Users\FictionalUser\PrivateWorkspace\Nested Vault\credential-cache.exe"
    fictional_forward_path = (
        "D:/Users/FictionalUser/PrivateWorkspace/Nested Vault/credential-cache.exe"
    )
    path_result = DiagnosticResult(
        rule_id="PATH_ENTRY_UNKNOWN",
        title=f"Review {fictional_path}",
        severity=Severity.INFO,
        summary="token=fictional-path-secret",
        evidence=[fictional_path, fictional_forward_path, "password=fictional-password"],
        suggestion=f"Review {fictional_path} before retrying.",
        status="skipped",
    )
    monkeypatch.setattr(
        runner,
        "probe_tool",
        lambda tool: _probe_result(tool, ProbeStatus.MISSING),
    )
    monkeypatch.setattr(runner, "inspect_process_path", lambda: [path_result])

    report = runner.run_scan()
    path_diagnostic = report.diagnostics[-1]
    serialized = path_diagnostic.model_dump_json()

    assert path_diagnostic.rule_id == "PATH_ENTRY_UNKNOWN"
    assert path_diagnostic.status == "skipped"
    assert path_diagnostic.severity is Severity.INFO
    assert len(path_diagnostic.evidence) == 3
    for private_fragment in (
        "FictionalUser",
        "PrivateWorkspace",
        "Nested Vault",
        "credential-cache.exe",
        r"C:\Users\FictionalUser\PrivateWorkspace\Nested Vault\credential-cache.exe",
        "D:/Users/FictionalUser/PrivateWorkspace/Nested Vault/credential-cache.exe",
    ):
        assert private_fragment not in serialized
    assert "fictional-path-secret" not in serialized
    assert "fictional-password" not in serialized


def test_probe_exception_is_isolated_and_remaining_tools_are_probed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_probe(tool: str) -> CommandProbeResult:
        calls.append(tool)
        if tool == "python":
            raise RuntimeError("fictional exception token=private-detail")
        return _probe_result(tool, ProbeStatus.MISSING)

    monkeypatch.setattr(runner, "probe_tool", fake_probe)
    _patch_empty_path(monkeypatch)

    report = runner.run_scan()

    assert calls == list(TOOLS)
    assert len(report.diagnostics) == 5
    assert report.diagnostics[0].rule_id == "COMMAND_PROBE_EXCEPTION"
    assert report.diagnostics[0].status == "error"
    assert "private-detail" not in report.model_dump_json()
    assert "fictional exception" not in report.model_dump_json()


def test_path_inspection_exception_is_reported_as_error_not_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        runner,
        "probe_tool",
        lambda tool: calls.append(tool) or _probe_result(tool, ProbeStatus.MISSING),
    )

    def fail_path_check() -> list[DiagnosticResult]:
        raise OSError("fictional PATH failure token=do-not-disclose")

    monkeypatch.setattr(runner, "inspect_process_path", fail_path_check)

    report = runner.run_scan()

    assert calls == list(TOOLS)
    assert len(report.diagnostics) == 6
    path_error = report.diagnostics[-1]
    assert path_error.rule_id == "PATH_SCAN_ERROR"
    assert path_error.status == "error"
    assert path_error.severity is Severity.ERROR
    assert "do-not-disclose" not in report.model_dump_json()


def test_report_uses_model_defaults_for_version_schema_and_aware_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runner,
        "probe_tool",
        lambda tool: _probe_result(tool, ProbeStatus.MISSING),
    )
    _patch_empty_path(monkeypatch)

    report = runner.run_scan()

    assert report.schema_version == "1.0"
    assert report.metadata.app_version == __version__
    assert report.metadata.scan_time.tzinfo is not None
    assert report.metadata.scan_time.utcoffset() is not None


def test_platform_metadata_uses_standard_library_default_factories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform_field = models.ScanMetadata.model_fields["platform"]
    python_version_field = models.ScanMetadata.model_fields["python_version"]

    assert platform_field.default_factory is models.platform_info.platform
    assert python_version_field.default_factory is models.platform_info.python_version

    monkeypatch.setattr(
        runner,
        "probe_tool",
        lambda tool: _probe_result(tool, ProbeStatus.MISSING),
    )
    _patch_empty_path(monkeypatch)

    report = runner.run_scan()

    assert report.metadata.platform == models.platform_info.platform()
    assert report.metadata.python_version == models.platform_info.python_version()


def test_runner_does_not_create_report_files(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        runner,
        "probe_tool",
        lambda tool: _probe_result(tool, ProbeStatus.MISSING),
    )
    _patch_empty_path(monkeypatch)

    runner.run_scan()

    assert list(tmp_path.iterdir()) == []


def test_unrecoverable_report_construction_error_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runner,
        "probe_tool",
        lambda tool: _probe_result(tool, ProbeStatus.MISSING),
    )
    _patch_empty_path(monkeypatch)

    def fail_report(**_kwargs: object) -> None:
        raise RuntimeError("report construction failed")

    monkeypatch.setattr(runner, "ScanReport", fail_report)

    with pytest.raises(RuntimeError, match="report construction failed"):
        runner.run_scan()


def test_base_exception_is_not_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner,
        "probe_tool",
        lambda _tool: (_ for _ in ()).throw(KeyboardInterrupt),
    )
    _patch_empty_path(monkeypatch)

    with pytest.raises(KeyboardInterrupt):
        runner.run_scan()


@pytest.mark.parametrize("stopping_tool", TOOLS)
@pytest.mark.parametrize("probe_status", list(ProbeStatus))
def test_unconfirmed_cleanup_aborts_before_mapping_path_or_report(
    stopping_tool: str,
    probe_status: ProbeStatus,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    private_path = r"C:\Users\FictionalUser\PrivateFolder\tool.exe"
    private_message = "fictional stdout stderr token=cleanup-private-detail"

    def fake_probe(tool: str) -> CommandProbeResult:
        calls.append(tool)
        if tool != stopping_tool:
            return _probe_result(tool, ProbeStatus.MISSING)
        result = _probe_result(
            tool,
            ProbeStatus.ERROR,
            version=SAFE_VERSIONS[tool],
            executable=private_path,
            message=private_message,
            cleanup_status=ProcessCleanupStatus.UNCONFIRMED,
        )
        # Also retain the MISSING + UNCONFIRMED boundary case after mutation:
        # construction now correctly rejects this contradictory pair.
        object.__setattr__(result, "status", probe_status)
        return result

    path = Mock(side_effect=AssertionError("PATH must not run"))
    report = Mock(side_effect=AssertionError("partial report must not be constructed"))
    mapping = Mock(wraps=runner._map_probe_result)
    monkeypatch.setattr(runner, "probe_tool", fake_probe)
    monkeypatch.setattr(runner, "inspect_process_path", path)
    monkeypatch.setattr(runner, "ScanReport", report)
    monkeypatch.setattr(runner, "_map_probe_result", mapping)

    with pytest.raises(ScanCleanupUnconfirmedError) as raised:
        runner.run_scan()

    stopping_index = TOOLS.index(stopping_tool)
    assert calls == list(TOOLS[: stopping_index + 1])
    assert [args[0] for args, _kwargs in mapping.call_args_list] == list(TOOLS[:stopping_index])
    assert str(raised.value) == "Scan cleanup could not be confirmed."
    assert raised.value.args == ("Scan cleanup could not be confirmed.",)
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None
    for private_text in (private_path, "FictionalUser", "PrivateFolder", private_message):
        assert private_text not in str(raised.value)
        assert private_text not in repr(raised.value.args)
    path.assert_not_called()
    report.assert_not_called()
    if stopping_index == 0:
        mapping.assert_not_called()


@pytest.mark.parametrize("stopping_tool", TOOLS)
def test_dedicated_cleanup_exception_from_probe_is_not_isolated(
    stopping_tool: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = ScanCleanupUnconfirmedError()
    calls: list[str] = []

    def fake_probe(tool: str) -> CommandProbeResult:
        calls.append(tool)
        if tool == stopping_tool:
            raise error
        return _probe_result(tool, ProbeStatus.MISSING)

    path = Mock(side_effect=AssertionError("PATH must not run"))
    report = Mock(side_effect=AssertionError("partial report must not be constructed"))
    mapping = Mock(wraps=runner._map_probe_result)
    monkeypatch.setattr(runner, "probe_tool", fake_probe)
    monkeypatch.setattr(runner, "inspect_process_path", path)
    monkeypatch.setattr(runner, "ScanReport", report)
    monkeypatch.setattr(runner, "_map_probe_result", mapping)

    with pytest.raises(ScanCleanupUnconfirmedError) as raised:
        runner.run_scan()

    stopping_index = TOOLS.index(stopping_tool)
    assert raised.value is error
    assert calls == list(TOOLS[: stopping_index + 1])
    assert [args[0] for args, _kwargs in mapping.call_args_list] == list(TOOLS[:stopping_index])
    path.assert_not_called()
    report.assert_not_called()


def test_dedicated_cleanup_exception_from_path_is_not_converted_to_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = ScanCleanupUnconfirmedError()
    probe = Mock(side_effect=lambda tool: _probe_result(tool, ProbeStatus.MISSING))
    path = Mock(side_effect=error)
    report = Mock(side_effect=AssertionError("partial report must not be constructed"))
    mapping = Mock(wraps=runner._map_probe_result)
    monkeypatch.setattr(runner, "probe_tool", probe)
    monkeypatch.setattr(runner, "inspect_process_path", path)
    monkeypatch.setattr(runner, "ScanReport", report)
    monkeypatch.setattr(runner, "_map_probe_result", mapping)

    with pytest.raises(ScanCleanupUnconfirmedError) as raised:
        runner.run_scan()

    assert raised.value is error
    assert probe.call_args_list == [call(tool) for tool in TOOLS]
    assert [args[0] for args, _kwargs in mapping.call_args_list] == list(TOOLS)
    path.assert_called_once_with()
    report.assert_not_called()


@pytest.mark.parametrize("stopping_tool", TOOLS)
@pytest.mark.parametrize(
    ("status", "cleanup"),
    [
        (ProbeStatus.VERIFIED, ProcessCleanupStatus.NOT_STARTED),
        (ProbeStatus.NONZERO_EXIT, ProcessCleanupStatus.NOT_STARTED),
        (ProbeStatus.TIMEOUT, ProcessCleanupStatus.NOT_STARTED),
        (ProbeStatus.MISSING, ProcessCleanupStatus.CONFIRMED),
        ("verified", ProcessCleanupStatus.CONFIRMED),
        (Severity.ERROR, ProcessCleanupStatus.CONFIRMED),
        (ProbeStatus.ERROR, "confirmed"),
    ],
)
def test_mutated_probe_is_rejected_before_mapping_or_followup_work(
    stopping_tool: str,
    status: object,
    cleanup: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    private_path = r"C:\Users\FictionalMutationUser\PrivateFolder\tool.exe"
    private_output = "fictional stdout stderr token=mutation-secret"

    def fake_probe(tool: str) -> CommandProbeResult:
        calls.append(tool)
        if tool != stopping_tool:
            return _probe_result(tool, ProbeStatus.MISSING)
        result = CommandProbeResult(
            tool,
            ProbeStatus.VERIFIED,
            executable=private_path,
            version=SAFE_VERSIONS[tool],
            message=private_output,
            cleanup_status=ProcessCleanupStatus.CONFIRMED,
        )
        object.__setattr__(result, "status", status)
        object.__setattr__(result, "cleanup_status", cleanup)
        return result

    path = Mock(side_effect=AssertionError("PATH must not run"))
    report = Mock(side_effect=AssertionError("partial report must not be constructed"))
    mapping = Mock(wraps=runner._map_probe_result)
    monkeypatch.setattr(runner, "probe_tool", fake_probe)
    monkeypatch.setattr(runner, "inspect_process_path", path)
    monkeypatch.setattr(runner, "ScanReport", report)
    monkeypatch.setattr(runner, "_map_probe_result", mapping)

    with pytest.raises(ScanCleanupUnconfirmedError) as raised:
        runner.run_scan()

    index = TOOLS.index(stopping_tool)
    assert calls == list(TOOLS[: index + 1])
    assert [args[0] for args, _kwargs in mapping.call_args_list] == list(TOOLS[:index])
    assert str(raised.value) == "Scan cleanup could not be confirmed."
    assert raised.value.__context__ is None and raised.value.__cause__ is None
    assert all(
        text not in str(raised.value)
        for text in (private_path, "FictionalMutationUser", "PrivateFolder", private_output)
    )
    path.assert_not_called()
    report.assert_not_called()


@pytest.mark.parametrize("result", [None, {}, object(), Severity.ERROR])
def test_wrong_probe_result_type_is_a_safe_scan_abort(
    result: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    probe = Mock(return_value=result)
    path = Mock()
    report = Mock()
    mapping = Mock()
    monkeypatch.setattr(runner, "probe_tool", probe)
    monkeypatch.setattr(runner, "inspect_process_path", path)
    monkeypatch.setattr(runner, "ScanReport", report)
    monkeypatch.setattr(runner, "_map_probe_result", mapping)

    with pytest.raises(ScanCleanupUnconfirmedError) as raised:
        runner.run_scan()

    assert str(raised.value) == "Scan cleanup could not be confirmed."
    probe.assert_called_once_with("python")
    path.assert_not_called()
    report.assert_not_called()
    mapping.assert_not_called()
