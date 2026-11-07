import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from dev_env_doctor.collectors import environment, executable_lookup
from dev_env_doctor.core import process_environment
from dev_env_doctor.core.scan_control import ScanDeadline
from dev_env_doctor.core.scan_coordinator import CoordinationError, ScanCoordinator
from dev_env_doctor.core.worker_task import WorkerTaskMode

_LOCAL_VOLUME = r"\Device\HarddiskVolume7"
_LOCAL_ENVIRONMENT = {
    "SystemRoot": r"C:\Windows",
    "WINDIR": r"C:\Windows",
    "TEMP": r"C:\Temp",
    "TMP": r"C:\Temp",
    "PATH": r"C:\SyntheticUserTools",
}


@pytest.fixture
def path_io(monkeypatch):
    def query(_drive, buffer, _capacity):
        if api.target is None:
            return 0
        result = api.target + "\0\0"
        for index, char in enumerate(result):
            buffer[index] = char
        return len(result)

    def metadata(path):
        return SimpleNamespace(
            st_mode=stat.S_IFREG if path.endswith(".exe") else stat.S_IFDIR,
            st_file_attributes=0,
        )

    api = SimpleNamespace(
        target=_LOCAL_VOLUME,
        QueryDosDeviceW=Mock(side_effect=query),
        GetDriveTypeW=Mock(return_value=environment.DRIVE_FIXED),
    )
    lstat = Mock(side_effect=metadata)
    write_access = Mock(return_value=False)
    observed = Mock()
    observed.attach_mock(api.QueryDosDeviceW, "namespace")
    observed.attach_mock(api.GetDriveTypeW, "volume")
    observed.attach_mock(lstat, "metadata")
    observed.attach_mock(write_access, "write_access")
    monkeypatch.setattr(environment.ctypes, "WinDLL", Mock(return_value=api), raising=False)
    monkeypatch.setattr(environment, "_lstat", lstat)
    monkeypatch.setattr(executable_lookup, "_lstat", lstat)
    monkeypatch.setattr(executable_lookup, "_current_user_can_write", write_access)
    monkeypatch.setattr(executable_lookup, "_is_windows", lambda: True)
    monkeypatch.setattr(executable_lookup, "_trusted_roots", lambda: (r"C:\Trusted",))
    return SimpleNamespace(api=api, lstat=lstat, access=write_access, observed=observed)


@pytest.mark.parametrize(
    ("directory", "mapping", "drive_type", "queries"),
    [
        pytest.param(r"\\server\share\Tools", None, 0, [], id="unc"),
        pytest.param(r"\\?\UNC\server\share\Tools", None, 0, [], id="extended-unc"),
        pytest.param(r"\\?\C:\Tools", None, 0, [], id="device-path"),
        pytest.param(r"Z:\Tools", r"\Device\Mup\server\share", 4, ["namespace"], id="mapped"),
        pytest.param(r"X:\Tools", r"\??\C:\Redirected", 3, ["namespace"], id="subst"),
        pytest.param(r"R:\Tools", _LOCAL_VOLUME, 2, ["namespace", "volume"], id="removable"),
        pytest.param(r"X:\Tools", None, 0, ["namespace"], id="unknown-mapping"),
        pytest.param(r"X:\Tools", _LOCAL_VOLUME, 0, ["namespace", "volume"], id="unknown-type"),
    ],
)
@pytest.mark.parametrize("entry", ["worker-environment", "path", "lookup", "trust"])
def test_rejected_volumes_have_no_metadata_access(
    path_io, entry, directory, mapping, drive_type, queries
):
    path_io.api.target = mapping
    path_io.api.GetDriveTypeW.return_value = drive_type

    if entry == "worker-environment":
        source = {name: directory for name in ("SystemRoot", "WINDIR", "TEMP", "TMP")}
        with pytest.raises(process_environment.EnvironmentConstructionError):
            process_environment.build_worker_environment(source)
    elif entry == "path":
        assert [result.rule_id for result in environment.inspect_path_value(directory)] == [
            "PATH_ENTRY_UNKNOWN"
        ]
    elif entry == "lookup":
        assert executable_lookup.find_local_executable("python", path_value=directory) is None
    else:
        assert executable_lookup.is_trusted_executable(directory + r"\python.exe") is False

    assert [operation[0] for operation in path_io.observed.mock_calls] == queries
    path_io.lstat.assert_not_called()
    path_io.access.assert_not_called()


def test_trusted_executable_checks_volume_and_ancestors_before_file_and_access(path_io):
    executable = r"C:\Trusted\Tools\python.exe"

    assert executable_lookup.is_trusted_executable(executable)
    assert [operation[0] for operation in path_io.observed.mock_calls] == [
        "namespace",
        "volume",
        "metadata",
        "metadata",
        "metadata",
        "metadata",
        "write_access",
        "write_access",
        "write_access",
    ]
    assert path_io.lstat.call_args_list == [
        call("C:\\"),
        call(r"C:\Trusted"),
        call(r"C:\Trusted\Tools"),
        call(executable),
    ]


def test_local_environment_construction_classifies_each_directory(path_io):
    worker = process_environment.build_worker_environment(_LOCAL_ENVIRONMENT)

    assert worker["PATH"] == r"C:\Windows\System32;C:\Windows"
    assert [operation[0] for operation in path_io.observed.mock_calls] == [
        "namespace",
        "volume",
        "metadata",
        "metadata",
    ] * 4


@pytest.mark.parametrize("target", [r"\Device\Mup\server\share", r"\??\C:\Redirected"])
def test_tool_environment_never_checks_metadata_on_denied_exe_drive(path_io, target):
    real_query = path_io.api.QueryDosDeviceW.side_effect

    def query(drive, buffer, capacity):
        path_io.api.target = _LOCAL_VOLUME if drive == "C:" else target
        return real_query(drive, buffer, capacity)

    path_io.api.QueryDosDeviceW.side_effect = query

    with pytest.raises(process_environment.EnvironmentConstructionError):
        process_environment.build_tool_environment(r"Z:\Tools\python.exe", _LOCAL_ENVIRONMENT)

    assert all(args.args[0].startswith("C:\\") for args in path_io.lstat.call_args_list)
    assert all(args.args == ("C:\\",) for args in path_io.api.GetDriveTypeW.call_args_list)
    assert path_io.api.QueryDosDeviceW.call_args.args[0] == "Z:"


@pytest.mark.parametrize("stage", ["QueryDosDeviceW", "GetDriveTypeW"])
def test_volume_query_exceptions_fail_closed(path_io, stage):
    getattr(path_io.api, stage).side_effect = OSError("synthetic Windows API failure")

    assert environment._local_directory_state(r"C:\Tools") is None

    path_io.lstat.assert_not_called()
    path_io.access.assert_not_called()


def test_trusted_executable_stops_at_reparse_ancestor(path_io):
    path_io.lstat.side_effect = [
        SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0),
        SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400),
    ]

    assert executable_lookup.is_trusted_executable(r"C:\Trusted\Tools\python.exe") is False
    assert path_io.lstat.call_args_list == [call("C:\\"), call(r"C:\Trusted")]
    path_io.access.assert_not_called()


def test_frozen_worker_lookup_checks_volume_before_any_path_resolution(path_io, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", r"Z:\Doctor\DevEnvDoctor.exe")
    path_io.api.target = r"\Device\Mup\server\share"
    resolve = Mock(side_effect=OSError("synthetic path resolution"))
    monkeypatch.setattr(Path, "resolve", resolve)
    coordinator = ScanCoordinator("a" * 32, ScanDeadline(1))
    pair = SimpleNamespace(child_handles=(41, 42))

    with pytest.raises(CoordinationError):
        coordinator._default_worker_command(pair, WorkerTaskMode.FULL_SCAN)

    resolve.assert_not_called()
    path_io.api.QueryDosDeviceW.assert_called_once()
    path_io.api.GetDriveTypeW.assert_not_called()
    path_io.lstat.assert_not_called()


def test_frozen_worker_lookup_checks_local_sibling_after_directory(path_io, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", r"C:\Doctor\DevEnvDoctor.exe")
    coordinator = ScanCoordinator("a" * 32, ScanDeadline(1))
    pair = SimpleNamespace(child_handles=(41, 42))

    command = coordinator._default_worker_command(pair, WorkerTaskMode.FULL_SCAN)

    assert command[0] == r"C:\Doctor\DevEnvDoctorWorker.exe"
    assert command[-2:] == ("--mode", "full_scan")
    assert [operation[0] for operation in path_io.observed.mock_calls] == [
        "namespace",
        "volume",
        "metadata",
        "metadata",
        "metadata",
        "metadata",
    ]
    assert path_io.lstat.call_args_list == [
        call("C:\\"),
        call(r"C:\Doctor"),
        call(r"C:\Doctor\DevEnvDoctor.exe"),
        call(r"C:\Doctor\DevEnvDoctorWorker.exe"),
    ]
