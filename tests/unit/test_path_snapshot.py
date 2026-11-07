import io
import json
import ntpath
import stat
import struct
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from dev_env_doctor.collectors import commands, environment, executable_lookup
from dev_env_doctor.collectors.config_files import CodexConfigState
from dev_env_doctor.core import process_environment, runner, scan_protocol
from dev_env_doctor.reports import export_file
from dev_env_doctor.reports.html_report import render_html_report
from dev_env_doctor.reports.json_report import render_json_report

SESSION = "b" * 32
MAX_CHAR_PATH = ";".join(["A" * 1023] * 4) + "B"
MAX_UTF8_PATH = ";".join(["界" * 341] * 8) + "B"
MAX_POSITION_PATH = ";" * 127
PRIVATE = r"D:\Synthetic-Path-8EC4"
WORKER_ENV = {
    "SystemRoot": r"C:\Windows",
    "WINDIR": r"C:\Windows",
    "TEMP": r"C:\Temp",
    "TMP": r"C:\Temp",
    "PATH": r"C:\Windows\System32;C:\Windows",
}


def start(payload, *, version=1, sequence=0, session=SESSION):
    return {
        "version": version,
        "session_id": session,
        "sequence": sequence,
        "type": "START",
        "payload": payload,
    }


def diagnostic_input(value):
    return {"kind": "path_snapshot_v1", "value": value}


def raw_frame(message):
    body = json.dumps(message, ensure_ascii=True).encode("utf-8")
    return struct.pack("!I", len(body)) + body


@pytest.mark.parametrize(
    "value",
    ["", ' "C:\\合成 tools\\🚀";D:\\工具', MAX_CHAR_PATH, MAX_UTF8_PATH, MAX_POSITION_PATH],
    ids=["empty", "unicode", "4096-characters", "8192-bytes", "128-positions"],
)
def test_start_round_trip_at_each_snapshot_limit(value):
    message = start({"deadline": 10.0, "diagnostic_input": diagnostic_input(value)})
    assert scan_protocol.validate_path_snapshot(value) == value
    assert scan_protocol.decode_frame(scan_protocol.encode_message(message)) == message


@pytest.mark.parametrize(
    "value",
    [
        MAX_CHAR_PATH + ";",
        MAX_UTF8_PATH + ";",
        MAX_POSITION_PATH + ";",
        "A" * 1025,
        "CANARY-8EC4\x00",
        "CANARY-8EC4\n",
        "CANARY-8EC4\r",
        "CANARY-8EC4\t",
        "CANARY-8EC4\x85",
        "CANARY-8EC4\ud800",
        r'"C:\Incomplete;C:\Other"',
        r'C:\Malformed"Entry',
        None,
        {"PATH": PRIVATE},
    ],
    ids=[
        "4097-characters",
        "8193-bytes",
        "129-positions",
        "long-entry",
        "nul",
        "newline",
        "return",
        "tab",
        "c1",
        "surrogate",
        "split-quote",
        "embedded-quote",
        "null",
        "environment-map",
    ],
)
def test_sender_and_receiver_reject_entire_bad_snapshot_without_retaining_cause(value):
    message = start({"deadline": 10, "diagnostic_input": diagnostic_input(value)})
    for action in (
        lambda: scan_protocol.validate_path_snapshot(value),
        lambda: scan_protocol.encode_message(message),
        lambda: scan_protocol.decode_frame(raw_frame(message)),
    ):
        with pytest.raises(scan_protocol.ProtocolError) as raised:
            action()
        assert "8EC4" not in str(raised.value)
        assert raised.value.__cause__ is None and raised.value.__context__ is None


@pytest.mark.parametrize(
    ("payload", "version"),
    [
        ({"deadline": 10, "diagnostic_input": {"kind": "path_snapshot_v2", "value": ""}}, 1),
        ({"deadline": 10, "diagnostic_input": {"kind": "path_snapshot_v1"}}, 1),
        ({"deadline": 10, "diagnostic_input": diagnostic_input("") | {"env": {}}}, 1),
        ({"deadline": 10, "diagnostic_input": []}, 1),
        ({"deadline": 10, "PATH": PRIVATE}, 1),
        ({"deadline": 10, "diagnostic_input": diagnostic_input("")}, 2),
    ],
)
def test_extended_start_rejects_wrong_kind_schema_or_protocol_version(payload, version):
    with pytest.raises(scan_protocol.ProtocolError):
        scan_protocol.decode_frame(raw_frame(start(payload, version=version)))


@pytest.mark.parametrize(
    "payload", [{"deadline": 10}, {"deadline": 10, "diagnostic_input": diagnostic_input("")}]
)
def test_start_preserves_ready_order_session_sequence_and_budget(payload):
    encoded = scan_protocol.encode_message(start(payload))
    session = scan_protocol.ProtocolSession(SESSION)
    with pytest.raises(scan_protocol.ProtocolError):
        session.accept_frame(encoded, sender="parent")
    assert session.budget.message_count == 0 and session.failed

    session = scan_protocol.ProtocolSession(SESSION)
    ready = start({}) | {"type": "READY"}
    session.accept_frame(scan_protocol.encode_message(ready), sender="child")
    assert session.accept_frame(encoded, sender="parent")["payload"] == payload
    with pytest.raises(scan_protocol.ProtocolError):
        session.accept_frame(encoded, sender="parent")
    assert session.budget.message_count == 2 and session.failed


def test_decoder_rejects_duplicate_input_keys_and_invalid_utf8():
    body = (
        b'{"version":1,"session_id":"' + SESSION.encode() + b'","sequence":0,"type":"START",'
        b'"payload":{"deadline":10,"diagnostic_input":{"kind":"path_snapshot_v1",'
        b'"value":"","value":"duplicate"}}}'
    )
    for invalid in (body, body.replace(b'"duplicate"', b'"\xff"')):
        with pytest.raises(scan_protocol.ProtocolError):
            scan_protocol.decode_frame(struct.pack("!I", len(invalid)) + invalid)


@pytest.fixture
def local_tools(monkeypatch):
    files = set()

    def lstat(path):
        if path.lower().endswith((".exe", ".com", ".cmd", ".bat")):
            if ntpath.normcase(path) not in files:
                raise FileNotFoundError()
            mode = stat.S_IFREG
        else:
            mode = stat.S_IFDIR
        return SimpleNamespace(st_mode=mode, st_file_attributes=0)

    def query(drive):
        return {
            "Z:": r"\Device\Mup\server\share",
            "X:": r"\??\C:\Subst",
        }.get(drive, r"\Device\HarddiskVolume7")

    fs = Mock(side_effect=lstat)
    drives = Mock(return_value=environment.DRIVE_FIXED)
    roots = Mock(return_value=(r"C:\Program Files", r"\\bad\share", "D:\\"))
    worker_environment = WORKER_ENV | {"ProgramFiles": r"D:\FakeTrusted", "TOKEN": "canary"}
    monkeypatch.setattr(
        executable_lookup, "os", SimpleNamespace(name="nt", environ=worker_environment)
    )
    monkeypatch.setattr(process_environment, "os", SimpleNamespace(environ=worker_environment))
    monkeypatch.setattr(executable_lookup, "program_files_folders", roots)
    monkeypatch.setattr(executable_lookup, "_current_user_can_write", Mock(return_value=False))
    monkeypatch.setattr(environment, "_query_dos_device", Mock(side_effect=query))
    monkeypatch.setattr(environment, "_drive_type", drives)
    monkeypatch.setattr(environment, "_lstat", fs)
    monkeypatch.setattr(executable_lookup, "_lstat", fs)
    popen = Mock(side_effect=AssertionError("unexpected tool launch"))
    monkeypatch.setattr(commands.subprocess, "Popen", popen)
    monkeypatch.setattr(runner, "inspect_codex_config", lambda: CodexConfigState.UNVERIFIED)
    return SimpleNamespace(
        files=files, fs=fs, drives=drives, roots=roots, env=worker_environment, popen=popen
    )


def test_full_scan_discovers_fixed_tools_using_snapshot_with_separate_environments(local_tools):
    folder = r"C:\Program Files\合成 Tools"
    files = [ntpath.join(folder, name) for name in ("python.exe", "git.exe", "node.exe", "npm.cmd")]
    local_tools.files.update(map(ntpath.normcase, files))
    output = {
        "python.exe": b"Python 3.13.9\n",
        "git.exe": b"git version 2.53.0.windows.3\n",
        "node.exe": b"v22.1.0\n",
    }

    def launch(argv, **_options):
        return SimpleNamespace(
            stdout=io.BytesIO(output[ntpath.basename(argv[0])]),
            stderr=io.BytesIO(),
            wait=Mock(return_value=0),
            poll=Mock(return_value=0),
            kill=Mock(),
        )

    local_tools.popen.side_effect = launch
    before = local_tools.env.copy()
    snapshot = ";".join(
        [folder, folder.upper(), PRIVATE, r"\\server\share", r"Z:\Remote", r"X:\Alias"]
    )
    report = runner.run_scan(path_snapshot=snapshot)

    assert [item.title for item in report.diagnostics[:3]] == [
        "Python version",
        "Git version",
        "Node.js version",
    ]
    assert report.diagnostics[3].rule_id == "COMMAND_VERSION_UNVERIFIED"
    assert {item.rule_id for item in report.diagnostics} >= {
        "PATH_DUPLICATE_ENTRY",
        "PATH_ENTRY_UNKNOWN",
    }
    assert [call.args[0] for call in local_tools.popen.call_args_list] == [
        [path, "--version"] for path in files[:3]
    ]
    for launched in local_tools.popen.call_args_list:
        assert launched.kwargs["shell"] is False
        assert launched.kwargs["env"] == WORKER_ENV | {"PATH": folder + ";" + WORKER_ENV["PATH"]}
    assert local_tools.env == before
    assert all(
        not call.args[0].startswith(("X:", "Z:")) for call in local_tools.drives.call_args_list
    )
    assert all(
        not call.args[0].startswith(("X:", "Z:", "\\")) for call in local_tools.fs.call_args_list
    )
    assert "8EC4" not in render_json_report(report)
    assert "8EC4" not in render_html_report(report)
    assert not export_file.report_export_allowed()


@pytest.mark.parametrize(
    ("tool", "suffix"), [("npm", s) for s in (".exe", ".cmd", ".bat", ".com")] + [("codex", ".exe")]
)
def test_lookup_only_tools_never_execute_with_a_snapshot(local_tools, tool, suffix):
    local_tools.files.add(ntpath.normcase(ntpath.join(PRIVATE, tool + suffix)))
    result = commands.probe_tool(tool, path_snapshot=PRIVATE)
    assert result.status is commands.ProbeStatus.FOUND_UNVERIFIED
    local_tools.popen.assert_not_called()


def test_empty_path_never_uses_worker_path(local_tools):
    local_tools.files.add(ntpath.normcase(r"C:\Windows\System32\python.exe"))
    report = runner.run_scan(path_snapshot="")
    assert [item.rule_id for item in report.diagnostics] == ["COMMAND_NOT_FOUND"] * 5 + [
        "CODEX_CONFIG_UNVERIFIED",
        "PATH_EMPTY",
    ]
    assert "parent process PATH snapshot" in report.diagnostics[-1].summary
    local_tools.fs.assert_not_called()
    local_tools.popen.assert_not_called()


@pytest.mark.parametrize("folder", [r"D:\FakeTrusted", r"D:\Unapproved"])
def test_snapshot_cannot_create_a_trust_root_or_fall_through_first_match(local_tools, folder):
    trusted = r"C:\Program Files\Python"
    for directory in (folder, trusted):
        local_tools.files.add(ntpath.normcase(ntpath.join(directory, "python.exe")))
    result = commands.probe_tool("python", path_snapshot=f"{folder};{trusted}")
    assert result.status is commands.ProbeStatus.FOUND_UNVERIFIED
    local_tools.popen.assert_not_called()
