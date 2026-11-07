from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from dev_env_doctor.collectors import environment
from dev_env_doctor.core import environment_probe, process_environment
from dev_env_doctor.core import frozen_runtime_environment as frozen
from dev_env_doctor.core.models import ScanReport
from dev_env_doctor.core.process_environment import EnvironmentConstructionError

EXE = r"C:\Private\Doctor\DevEnvDoctorWorker.exe"
HOME = r"C:\Private\Doctor\_internal"
LEVEL = "_PYI_PARENT_PROCESS_LEVEL"
ARCHIVE = "_PYI_ARCHIVE_FILE"


@pytest.fixture
def runtime(monkeypatch):
    env = {
        "SYSTEMROOT": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "TEMP": r"C:\Private\Temp",
        "TMP": r"C:\Private\Temp",
        "PATH": r"C:\Windows\System32;C:\Windows",
        process_environment.PROBE_UNICODE_NAME: process_environment.PROBE_UNICODE_VALUE,
        LEVEL: "1",
        ARCHIVE: EXE,
    }
    state = SimpleNamespace(frozen=True, executable=EXE, _MEIPASS=HOME)
    system = SimpleNamespace(environ=env, name="nt")

    def module_filename(_module, buffer, _capacity):
        buffer.value = EXE
        return len(EXE)

    def file_information(_handle, info_class, pointer, _size):
        if info_class == 18:
            pointer._obj.volume = 42
            pointer._obj.file_id[:] = bytes(range(16))
        else:
            assert info_class == 9
        return True

    api = SimpleNamespace(
        GetModuleFileNameW=Mock(side_effect=module_filename),
        CreateFileW=Mock(side_effect=[100, 101, 102]),
        GetFileType=Mock(return_value=1),
        GetFileInformationByHandleEx=Mock(side_effect=file_information),
        CloseHandle=Mock(return_value=True),
    )
    monkeypatch.setattr(frozen.ctypes, "WinDLL", Mock(return_value=api))
    monkeypatch.setattr(frozen, "_local_directory_state", lambda _path: True)
    monkeypatch.setattr(process_environment, "_local_directory_state", lambda _path: True)
    monkeypatch.setattr(frozen, "sys", state)
    monkeypatch.setattr(frozen, "os", system)
    monkeypatch.setattr(environment_probe, "sys", state)
    monkeypatch.setattr(environment_probe, "os", system)
    return SimpleNamespace(env=env, state=state, api=api)


def test_exact_frozen_environment_checks_all_handles_and_keeps_environment(runtime):
    before = dict(runtime.env)
    frozen.validate_frozen_worker_environment()
    assert runtime.env == before
    assert [args.args[0] for args in runtime.api.CreateFileW.call_args_list] == [EXE] * 3
    assert all(args.args[5] == 0x00200000 for args in runtime.api.CreateFileW.call_args_list)
    assert runtime.api.CloseHandle.call_args_list == [call(102), call(101), call(100)]


@pytest.mark.parametrize(
    ("attr", "value"),
    [
        ("frozen", False),
        ("frozen", 1),
        ("executable", r"C:\Other\DevEnvDoctorWorker.exe"),
        ("executable", r"C:\Private\Doctor\python.exe"),
        ("_MEIPASS", r"C:\Other\_internal"),
    ],
)
def test_inconsistent_frozen_context_is_rejected(runtime, attr, value):
    setattr(runtime.state, attr, value)
    with pytest.raises(EnvironmentConstructionError):
        frozen.validate_frozen_worker_environment()
    runtime.api.CreateFileW.assert_not_called()


@pytest.mark.parametrize("attr", ["frozen", "_MEIPASS"])
def test_missing_frozen_context_is_rejected(runtime, attr):
    delattr(runtime.state, attr)
    with pytest.raises(EnvironmentConstructionError):
        frozen.validate_frozen_worker_environment()
    runtime.api.CreateFileW.assert_not_called()


def test_different_native_main_module_is_rejected(runtime):
    def mismatch(_module, buffer, _capacity):
        buffer.value = r"C:\Other\DevEnvDoctorWorker.exe"
        return len(buffer.value)

    runtime.api.GetModuleFileNameW.side_effect = mismatch
    with pytest.raises(EnvironmentConstructionError):
        frozen.validate_frozen_worker_environment()
    runtime.api.CreateFileW.assert_not_called()


def test_unsafe_layout_stops_before_opening_any_exe(runtime, monkeypatch):
    monkeypatch.setattr(frozen, "_local_directory_state", lambda _path: None)
    with pytest.raises(EnvironmentConstructionError):
        frozen.validate_frozen_worker_environment()
    runtime.api.CreateFileW.assert_not_called()


def test_frozen_identity_rejects_indirect_volume_before_metadata(runtime, monkeypatch):
    namespace = Mock(return_value=r"\??\D:\SyntheticSubst")
    volume = Mock()
    lstat = Mock()
    monkeypatch.setattr(environment, "_query_dos_device", namespace)
    monkeypatch.setattr(environment, "_drive_type", volume)
    monkeypatch.setattr(environment, "_lstat", lstat)
    monkeypatch.setattr(frozen, "_local_directory_state", environment._local_directory_state)

    with pytest.raises(EnvironmentConstructionError):
        frozen.validate_frozen_worker_environment()

    namespace.assert_called_once_with("C:")
    volume.assert_not_called()
    lstat.assert_not_called()
    runtime.api.CreateFileW.assert_not_called()


@pytest.mark.parametrize("key", [LEVEL, ARCHIVE])
def test_missing_required_internal_key_is_rejected(runtime, key):
    del runtime.env[key]
    with pytest.raises(EnvironmentConstructionError):
        frozen.validate_frozen_worker_environment()
    runtime.api.CreateFileW.assert_not_called()


@pytest.mark.parametrize("value", ["", "01", "+1", " 1", "2", "１", 1])
def test_parent_process_level_has_exact_ascii_format(runtime, value):
    runtime.env[LEVEL] = value
    with pytest.raises(EnvironmentConstructionError):
        frozen.validate_frozen_worker_environment()
    runtime.api.CreateFileW.assert_not_called()


@pytest.mark.parametrize(
    "path",
    [
        r"\\host\share\DevEnvDoctorWorker.exe",
        "DevEnvDoctorWorker.exe",
        r"\\?\C:\Private\Doctor\DevEnvDoctorWorker.exe",
        EXE + ":stream",
        r"C:\Private\Doctor\..\Doctor\DevEnvDoctorWorker.exe",
        r"C:\Other\DevEnvDoctorWorker.exe",
    ],
)
def test_archive_path_must_match_before_open(runtime, path):
    runtime.env[ARCHIVE] = path
    with pytest.raises(EnvironmentConstructionError):
        frozen.validate_frozen_worker_environment()
    runtime.api.CreateFileW.assert_not_called()


@pytest.mark.parametrize("key", ["_PYI_UNKNOWN", "TOKEN", "_pyi_archive_file"])
def test_unknown_or_duplicate_key_cannot_use_exception(runtime, key):
    runtime.env[key] = "synthetic-private"
    with pytest.raises(EnvironmentConstructionError) as error:
        frozen.validate_frozen_worker_environment()
    assert "synthetic-private" not in str(error.value)
    runtime.api.CreateFileW.assert_not_called()


@pytest.mark.parametrize("difference", ["file_id", "volume", "unavailable", "directory", "reparse"])
def test_file_identity_and_native_metadata_are_required(runtime, difference):
    original = runtime.api.GetFileInformationByHandleEx.side_effect

    def information(handle, info_class, pointer, size):
        original(handle, info_class, pointer, size)
        if handle == 102:
            if info_class == 18 and difference == "file_id":
                pointer._obj.file_id[0] = 99
            if info_class == 18 and difference == "volume":
                pointer._obj.volume += 1
            if info_class == 18 and difference == "unavailable":
                return False
            if info_class == 9 and difference == "directory":
                pointer._obj.attributes = 0x10
            if info_class == 9 and difference == "reparse":
                pointer._obj.attributes = 0x400
        return True

    runtime.api.GetFileInformationByHandleEx.side_effect = information
    with pytest.raises(EnvironmentConstructionError):
        frozen.validate_frozen_worker_environment()
    assert runtime.api.CloseHandle.call_args_list == [call(102), call(101), call(100)]


@pytest.mark.parametrize("failure", ["not_found", "invalid_handle"])
def test_open_failure_closes_previously_acquired_handles(runtime, failure):
    last = FileNotFoundError("synthetic-private") if failure == "not_found" else -1
    runtime.api.CreateFileW.side_effect = [100, 101, last]
    with pytest.raises(EnvironmentConstructionError) as error:
        frozen.validate_frozen_worker_environment()
    assert "synthetic-private" not in str(error.value)
    assert runtime.api.CloseHandle.call_args_list == [call(101), call(100)]


@pytest.mark.parametrize("failure", [False, OSError("synthetic-private")])
def test_failed_handle_close_cannot_report_success(runtime, failure):
    runtime.api.CloseHandle.side_effect = [failure, True, True]
    with pytest.raises(EnvironmentConstructionError) as error:
        frozen.validate_frozen_worker_environment()
    assert "synthetic-private" not in str(error.value)
    assert runtime.api.CloseHandle.call_args_list == [call(102), call(101), call(100)]


@pytest.mark.parametrize("extra", [(LEVEL,), (ARCHIVE,), (LEVEL, ARCHIVE)])
def test_unfrozen_probe_stays_strict(runtime, monkeypatch, extra):
    monkeypatch.setattr(environment_probe, "sys", SimpleNamespace())
    for key in {LEVEL, ARCHIVE} - set(extra):
        del runtime.env[key]
    runner = Mock()
    monkeypatch.setattr(environment_probe.runner, "run_probe", runner)
    with pytest.raises(EnvironmentConstructionError):
        environment_probe.run_probe()
    runner.assert_not_called()
    runtime.api.GetModuleFileNameW.assert_not_called()


def test_frozen_probe_uses_validator_before_producing_fixed_receipts(runtime, monkeypatch):
    runner = Mock(return_value=ScanReport())
    monkeypatch.setattr(environment_probe.runner, "run_probe", runner)
    monkeypatch.setattr(environment_probe, "find_local_executable", Mock(return_value=None))
    report = environment_probe.run_probe()
    assert len(report.diagnostics) == 11
    assert {tuple(item.evidence) for item in report.diagnostics} == {("PASS",), ("NOT_VERIFIED",)}
    assert EXE not in str(report)
    runner.assert_called_once_with()
    assert runtime.api.CloseHandle.call_count == 3


def test_invalid_frozen_environment_does_not_generate_report(runtime, monkeypatch):
    runtime.env["TOKEN"] = "synthetic-secret"
    runner = Mock()
    monkeypatch.setattr(environment_probe.runner, "run_probe", runner)
    with pytest.raises(EnvironmentConstructionError) as error:
        environment_probe.run_probe()
    assert "synthetic-secret" not in str(error.value)
    assert EXE not in str(error.value)
    runner.assert_not_called()
