import builtins
import io
import ntpath
import os
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from dev_env_doctor.collectors import commands, config_files, environment
from dev_env_doctor.core import runner
from dev_env_doctor.core.scan_protocol import MessageType, decode_frame
from dev_env_doctor.core.scan_worker_entry import _candidate_payload, _message
from dev_env_doctor.reports.html_report import render_html_report
from dev_env_doctor.reports.json_report import render_json_report

PROFILE = r"C:\Users\Synthetic-7F21"
CODEX_DIR = PROFILE + r"\.codex"
CONFIG = CODEX_DIR + r"\config.toml"
DIRECTORY = 0x10


@pytest.fixture
def audit(monkeypatch):
    query = Mock(return_value=r"\Device\HarddiskVolume7")
    drive_type = Mock(return_value=environment.DRIVE_FIXED)
    profile = Mock(return_value=PROFILE)
    files = {
        "C:\\": (DIRECTORY, 0),
        r"C:\Users": (DIRECTORY, 0),
        PROFILE: (DIRECTORY, 0),
        CODEX_DIR: (DIRECTORY, 0),
        CONFIG: (0x80, 34),
    }

    def metadata(path):
        if path not in files:
            raise FileNotFoundError()
        value = files[path]
        if isinstance(value, Exception):
            raise value
        return value

    read = Mock(side_effect=metadata)
    monkeypatch.setattr(environment, "_query_dos_device", query)
    monkeypatch.setattr(environment, "_drive_type", drive_type)
    monkeypatch.setattr(config_files, "user_profile_folder", profile)
    monkeypatch.setattr(config_files, "_metadata_reader", lambda: read)
    return profile, query, drive_type, files, read


def test_existing_config_only_queries_fixed_metadata(audit, monkeypatch, tmp_path):
    profile, query, drive_type, files, read = audit
    codex = tmp_path / ".codex"
    codex.mkdir()
    config = codex / "config.toml"
    auth = codex / "auth.json"
    config.write_text("config-body-canary-181F", encoding="utf-8")
    auth.write_text("auth-canary-65EE", encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", r"Z:\Ignored-Config-Override")
    before = {item.name: item.read_bytes() for item in codex.iterdir()}

    def metadata(path):
        if path == CONFIG:
            return 0x80, config.stat().st_size
        return files[path]

    read.side_effect = metadata
    deny_content = Mock(side_effect=AssertionError("configuration content must not be opened"))
    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", deny_content)
        patch.setattr(io, "open", deny_content)
        patch.setattr(os, "open", deny_content)
        assert config_files.inspect_codex_config().name == "PRESENT"

    deny_content.assert_not_called()
    profile.assert_called_once_with()
    query.assert_called_once_with("C:")
    drive_type.assert_called_once_with("C:")
    assert read.call_args_list == [
        call("C:\\"),
        call(r"C:\Users"),
        call(PROFILE),
        call(CODEX_DIR),
        call(CONFIG),
    ]
    assert {item.name: item.read_bytes() for item in codex.iterdir()} == before


@pytest.mark.parametrize("missing", [CODEX_DIR, CONFIG])
def test_missing_fixed_entry_is_distinguished_from_an_unverified_profile(audit, missing):
    _, _, _, files, read = audit
    del files[missing]
    assert config_files.inspect_codex_config().name == "MISSING"
    assert read.call_args == call(missing)


def test_missing_profile_cannot_prove_missing_configuration(audit):
    _, _, _, files, read = audit
    del files[PROFILE]
    assert config_files.inspect_codex_config().name == "UNVERIFIED"
    assert read.call_args == call(PROFILE)


@pytest.mark.parametrize("denied", [PROFILE, CODEX_DIR, CONFIG])
def test_permission_denial_stops_without_leaking_error(audit, denied):
    _, _, _, files, read = audit
    files[denied] = PermissionError("private-profile-canary")
    assert config_files.inspect_codex_config().name == "INACCESSIBLE"
    assert read.call_args == call(denied)


@pytest.mark.parametrize(
    ("path", "metadata", "expected"),
    [
        (PROFILE, (DIRECTORY | 0x400, 0), "UNSAFE"),
        (CODEX_DIR, (DIRECTORY | 0x400, 0), "UNSAFE"),
        (CODEX_DIR, (0x80, 0), "UNSAFE"),
        (CONFIG, (0x400, 0), "UNSAFE"),
        (CONFIG, (0x1000, 0), "UNSAFE"),
        (CONFIG, (DIRECTORY, 0), "INVALID_FILE"),
        (CONFIG, (0x40, 0), "INVALID_FILE"),
        (CONFIG, (0x80, 1_048_577), "TOO_LARGE"),
        (CONFIG, OSError("unknown-canary"), "UNVERIFIED"),
    ],
)
def test_reparse_unsafe_and_abnormal_file_results_stop_at_first_problem(
    audit, path, metadata, expected
):
    _, _, _, files, read = audit
    files[path] = metadata
    assert config_files.inspect_codex_config().name == expected
    assert read.call_args == call(path)


@pytest.mark.parametrize(
    ("candidate", "mapping", "kind", "namespace_calls", "drive_calls"),
    [
        (r"\\server\share\Profile", None, 0, 0, 0),
        (r"\\?\UNC\server\share\Profile", None, 0, 0, 0),
        (r"Z:\Profile", r"\Device\Mup\server\share", 4, 1, 0),
        (r"X:\Profile", r"\??\C:\Alias", 3, 1, 0),
        (r"X:\Profile", r"\Device\HarddiskVolume7", 2, 1, 1),
        (r"X:\Profile", None, 0, 1, 0),
        (r"C:\Users\..\Unsafe", None, 0, 0, 0),
    ],
)
def test_rejected_paths_never_reach_metadata(
    audit, candidate, mapping, kind, namespace_calls, drive_calls
):
    profile, query, drive_type, _, read = audit
    profile.return_value = candidate
    query.return_value = mapping
    drive_type.return_value = kind
    assert config_files.inspect_codex_config().name == "UNSAFE"
    assert query.call_count == namespace_calls
    assert drive_type.call_count == drive_calls
    read.assert_not_called()


def test_unresolved_profile_never_uses_environment_or_falls_back(audit, monkeypatch):
    profile, query, _, _, read = audit
    profile.return_value = None
    monkeypatch.setenv("USERPROFILE", ntpath.dirname(PROFILE))
    monkeypatch.setenv("CODEX_HOME", CODEX_DIR)
    assert config_files.inspect_codex_config().name == "UNVERIFIED"
    query.assert_not_called()
    read.assert_not_called()


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (2, FileNotFoundError),
        (3, OSError),
        (5, PermissionError),
        (32, PermissionError),
        (33, PermissionError),
    ],
)
def test_native_metadata_reports_safe_categories_without_content_handles(
    monkeypatch, error, expected
):
    query = Mock(return_value=0)
    loader = Mock(return_value=SimpleNamespace(GetFileAttributesExW=query))
    monkeypatch.setattr(config_files.ctypes, "WinDLL", loader, raising=False)
    monkeypatch.setattr(config_files.ctypes, "get_last_error", lambda: error, raising=False)

    with pytest.raises(expected) as captured:
        config_files._metadata_reader()(CONFIG)
    assert type(captured.value) is expected
    assert "7F21" not in str(captured.value)
    loader.assert_called_once_with("kernel32", use_last_error=True, winmode=0x800)
    assert query.call_args.args[:2] == (CONFIG, 0)


def test_native_metadata_uses_both_size_words(monkeypatch):
    def query(_path, _level, data):
        data._obj.attributes = 0x80
        data._obj.size_high = 1
        data._obj.size_low = 2
        return 1

    kernel = SimpleNamespace(GetFileAttributesExW=Mock(side_effect=query))
    monkeypatch.setattr(config_files.ctypes, "WinDLL", Mock(return_value=kernel), raising=False)
    assert config_files._metadata_reader()(CONFIG) == (0x80, 2**32 + 2)


@pytest.mark.parametrize(
    ("cli_status", "evidence"),
    [
        (commands.ProbeStatus.FOUND_UNVERIFIED, "Codex CLI：已发现，仅查找。"),
        (commands.ProbeStatus.MISSING, "Codex CLI：在允许的位置未发现。"),
        (commands.ProbeStatus.ERROR, "Codex CLI：查找结果无法确认。"),
    ],
)
def test_modern_scan_combines_config_and_cli_and_serializes_only_reviewed_text(
    audit, monkeypatch, cli_status, evidence
):
    probe = Mock(
        side_effect=lambda tool, **_kwargs: commands.CommandProbeResult(
            tool, cli_status if tool == "codex" else commands.ProbeStatus.MISSING
        )
    )
    monkeypatch.setattr(runner, "probe_tool", probe)
    monkeypatch.setattr(runner, "inspect_path_value", Mock(return_value=[]))
    report = runner.run_scan(path_snapshot="")
    result = report.diagnostics[-1]

    assert [request.args[0] for request in probe.call_args_list] == [
        "python",
        "git",
        "node",
        "npm",
        "codex",
    ]
    assert len(report.diagnostics) == 6
    assert result.rule_id == "CODEX_CONFIG_PRESENT"
    assert result.evidence == [evidence]

    result.title = PROFILE
    result.summary = "sensitive-unlabelled-canary-29BA"
    result.suggestion = CONFIG
    frame = _message(
        "a" * 32, 1, MessageType.RESULT_CANDIDATE, {"report": _candidate_payload(report)}
    )
    decoded = decode_frame(frame)["payload"]["report"]["diagnostics"][-1]
    assert decoded["title"] == "Codex 配置文件存在"
    assert decoded["evidence"] == [evidence]
    for output in (
        frame[4:].decode("utf-8"),
        render_json_report(report),
        render_html_report(report),
    ):
        assert all(marker not in output for marker in ("7F21", "29BA"))
    result.evidence = ["unapproved-evidence-canary-29BA"]
    assert "29BA" not in render_json_report(report)
    assert "29BA" not in render_html_report(report)


def test_legacy_full_scan_and_fixed_probe_keep_previous_candidate_rules(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("legacy peer cannot review new config rules"))
    monkeypatch.setattr(runner, "inspect_codex_config", forbidden)
    monkeypatch.setattr(runner, "inspect_process_path", Mock(return_value=[]))
    monkeypatch.setattr(
        runner,
        "probe_tool",
        lambda tool: commands.CommandProbeResult(tool, commands.ProbeStatus.MISSING),
    )
    assert len(runner.run_scan().diagnostics) == 5
    assert len(runner.run_probe().diagnostics) == 5
    forbidden.assert_not_called()
