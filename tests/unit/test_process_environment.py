import pytest

from dev_env_doctor.core import process_environment


@pytest.fixture
def safe_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_environment, "_local_directory_state", lambda _path: True)


def _source() -> dict[str, str]:
    return {
        "SystemRoot": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "TEMP": r"C:\Temp",
        "TMP": r"C:\Temp",
        "PATH": r"C:\Windows\System32;C:\Users\Alice\bin",
        "PYTHONPATH": r"C:\Users\Alice\secret",
        "NODE_OPTIONS": "--require=secret",
        "GIT_CONFIG_GLOBAL": r"C:\Users\Alice\config",
        "CODEX_TOKEN": "secret",
        "HTTPS_PROXY": "http://secret",
    }


def test_worker_environment_is_explicit_and_does_not_mutate_parent(safe_paths) -> None:
    source = _source()
    result = process_environment.build_worker_environment(source)

    assert set(result) == {"SystemRoot", "WINDIR", "TEMP", "TMP", "PATH"}
    assert "Users" not in result["PATH"]
    assert source["PYTHONPATH"] == r"C:\Users\Alice\secret"


def test_tool_environment_adds_only_the_trusted_executable_directory(safe_paths) -> None:
    result = process_environment.build_tool_environment(
        r"C:\Program Files\Git\cmd\git.exe", _source()
    )

    assert result["PATH"].startswith(r"C:\Program Files\Git\cmd;")
    assert "PYTHONPATH" not in result
    assert "HTTPS_PROXY" not in result


def test_worker_and_tool_blocks_drop_frozen_keys_and_leave_source_intact(safe_paths) -> None:
    source = _source() | {
        "_PYI_PARENT_PROCESS_LEVEL": "1",
        "_PYI_ARCHIVE_FILE": r"C:\Private\DevEnvDoctorWorker.exe",
        "_PYI_UNKNOWN": "synthetic",
        "CODEX_API_KEY": "synthetic",
        "TOKEN": "synthetic",
    }
    original = dict(source)
    base_names = {"SystemRoot", "WINDIR", "TEMP", "TMP", "PATH"}
    assert set(process_environment.build_worker_environment(source)) == base_names
    expected = base_names | {process_environment.PROBE_UNICODE_NAME}
    assert set(process_environment.build_worker_environment(source, include_probe_marker=True)) == (
        expected
    )
    tool = process_environment.build_tool_environment(
        r"C:\Program Files\Python\python.exe", source, include_probe_marker=True
    )
    assert set(tool) == expected
    assert tool[process_environment.PROBE_UNICODE_NAME] == process_environment.PROBE_UNICODE_VALUE
    assert source == original


@pytest.mark.parametrize("name", ["SystemRoot", "WINDIR", "TEMP", "TMP"])
def test_required_environment_values_missing_fail_closed(name: str, safe_paths) -> None:
    source = _source()
    source.pop(name)
    with pytest.raises(process_environment.EnvironmentConstructionError):
        process_environment.build_worker_environment(source)


def test_both_system_values_are_required_and_consistent(safe_paths) -> None:
    source = _source()
    source.pop("SystemRoot")
    with pytest.raises(process_environment.EnvironmentConstructionError):
        process_environment.build_worker_environment(source)

    source = _source()
    source.pop("WINDIR")
    with pytest.raises(process_environment.EnvironmentConstructionError):
        process_environment.build_worker_environment(source)

    source = _source()
    source["WINDIR"] = r"C:\Windows\..\Windows"
    assert process_environment.build_worker_environment(source)["SystemRoot"] == r"C:\Windows"


@pytest.mark.parametrize("value", [r"Windows", r"\\server\share\Windows", r"C:\Missing"])
def test_invalid_system_root_paths_fail_closed(value: str, safe_paths) -> None:
    source = _source()
    source["SystemRoot"] = value
    source["WINDIR"] = value
    if value == r"C:\Missing":
        import dev_env_doctor.core.process_environment as environment_module

        environment_module._local_directory_state = lambda _path: False
    with pytest.raises(process_environment.EnvironmentConstructionError):
        process_environment.build_worker_environment(source)


def test_case_variants_and_duplicate_keys_fail_closed(safe_paths) -> None:
    source = _source()
    source["systemroot"] = r"C:\Windows"
    with pytest.raises(process_environment.EnvironmentConstructionError):
        process_environment.build_worker_environment(source)


def test_conflicting_windows_root_values_fail_closed(safe_paths) -> None:
    source = _source()
    source["WINDIR"] = r"D:\Windows"

    with pytest.raises(process_environment.EnvironmentConstructionError):
        process_environment.build_worker_environment(source)
