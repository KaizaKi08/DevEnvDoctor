import shutil
import stat
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from dev_env_doctor.collectors import commands, environment
from dev_env_doctor.collectors import executable_lookup as lookup

LOCAL_TARGET = r"\Device\HarddiskVolume7"


@pytest.fixture
def local_windows(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    state = SimpleNamespace(
        query=Mock(return_value=LOCAL_TARGET),
        drive_type=Mock(return_value=3),
        directory=Mock(return_value=True),
        directory_walk=environment._directory_state_on_local_volume,
        candidate=Mock(return_value=False),
    )
    monkeypatch.setattr(lookup, "_is_windows", lambda: True)
    monkeypatch.setattr(environment, "_query_dos_device", state.query)
    monkeypatch.setattr(environment, "_drive_type", state.drive_type)
    monkeypatch.setattr(environment, "_directory_state_on_local_volume", state.directory)
    monkeypatch.setattr(lookup, "_candidate_is_regular_file", state.candidate)
    return state


@pytest.mark.parametrize(
    ("directory", "expected"),
    [
        (r"C:\Tools", r"C:\Tools"),
        ("d:/Apps and Tools", r"D:\Apps and Tools"),
        ('  "D:\\Tools"  ', r"D:\Tools"),
        ("D:\\KAI'\\bin", "D:\\KAI'\\bin"),
    ],
)
def test_local_absolute_directory_is_searched_only_after_classification(
    directory: str, expected: str, local_windows: SimpleNamespace
) -> None:
    local_windows.candidate.return_value = True

    assert lookup.find_local_executable("git", path_value=directory) == expected + r"\git.exe"

    local_windows.query.assert_called_once_with(expected[:2])
    local_windows.drive_type.assert_called_once_with(expected[:2])
    local_windows.directory.assert_called_once_with(expected)
    local_windows.candidate.assert_called_once_with(expected + r"\git.exe")


@pytest.mark.parametrize("suffix", [".exe", ".com", ".cmd", ".bat"])
def test_npm_discovery_returns_only_existing_absolute_file(local_windows, suffix) -> None:
    directory = r"C:\Tools"
    target = directory + "\\npm" + suffix
    local_windows.candidate.side_effect = lambda path: path == target

    assert lookup.find_local_executable("npm", path_value=directory) == target
    assert local_windows.candidate.call_args == call(target)


def test_com_does_not_expand_discovery_for_other_tools(local_windows) -> None:
    local_windows.candidate.side_effect = lambda path: path.endswith(".com")

    assert lookup.find_local_executable("git", path_value=r"C:\Tools") is None
    assert not any(args.args[0].endswith(".com") for args in local_windows.candidate.call_args_list)


@pytest.mark.parametrize(
    "directory",
    [
        "",
        " ",
        ".",
        "tools",
        r"tools\bin",
        "C:",
        r"C:Tools",
        r"\Tools",
        r"\\server\share\tools",
        "//server/share/tools",
        r"\\?\C:\Tools",
        r"\\.\C:\Tools",
        r"\??\C:\Tools",
        r"C:\Tools\..\Other",
        r"C:\Tools\.\Other",
        r"C:\Tools\name:stream",
        r"C:\NUL\Tools",
        r"C:\COM1\Tools",
        "C:\\Tools.\\bin",
        "C:\\Tools \\bin",
        '"C:\\Tools',
        'C:\\Too"ls',
        "C:\\Tools\nOther",
        r"C:\%UNRESOLVED%\Tools",
    ],
)
def test_lexically_rejected_directory_never_reaches_system_or_filesystem_probes(
    directory: str, local_windows: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy_which = Mock(side_effect=AssertionError("unfiltered lookup must not run"))
    monkeypatch.setattr(shutil, "which", legacy_which)

    assert lookup.find_local_executable("git", path_value=directory) is None

    local_windows.query.assert_not_called()
    local_windows.drive_type.assert_not_called()
    local_windows.directory.assert_not_called()
    local_windows.candidate.assert_not_called()
    legacy_which.assert_not_called()


@pytest.mark.parametrize(
    "target",
    [
        r"\Device\Mup\server\share",
        r"\Device\LanmanRedirector\server\share",
        r"\Device\WebDavRedirector\server\share",
        r"\??\UNC\server\share",
        r"\??\C:\Subst",
        r"\Device\UnknownVolume7",
        r"\Device\HarddiskVolume7\redirected",
        None,
    ],
)
def test_remote_alias_or_unknown_drive_mapping_is_rejected_before_drive_or_file_probe(
    target: str | None, local_windows: SimpleNamespace
) -> None:
    local_windows.query.return_value = target

    assert lookup.find_local_executable("git", path_value=r"Z:\Tools") is None

    local_windows.query.assert_called_once_with("Z:")
    local_windows.drive_type.assert_not_called()
    local_windows.directory.assert_not_called()
    local_windows.candidate.assert_not_called()


@pytest.mark.parametrize("drive_type", [0, 1, 2, 4, 5, 6])
def test_non_fixed_drive_is_not_searched(drive_type: int, local_windows: SimpleNamespace) -> None:
    local_windows.drive_type.return_value = drive_type

    assert lookup.find_local_executable("git", path_value=r"D:\Tools") is None

    local_windows.directory.assert_not_called()
    local_windows.candidate.assert_not_called()


def test_raw_process_path_is_filtered_in_order_without_which_or_cwd_fallback(
    local_windows: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    path_value = r";.;C:relative;\\server\share;Z:\Remote;D:\First;d:/First;C:\Second"
    monkeypatch.setattr(lookup, "_process_path_value", lambda: path_value)
    local_windows.query.side_effect = lambda drive: (
        r"\Device\Mup\server\share" if drive == "Z:" else LOCAL_TARGET
    )
    local_windows.candidate.side_effect = lambda path: path == r"C:\Second\git.exe"
    legacy_which = Mock(side_effect=AssertionError("which must never be called"))
    monkeypatch.setattr(shutil, "which", legacy_which)

    assert lookup.find_local_executable("git") == r"C:\Second\git.exe"

    assert local_windows.directory.call_args_list == [call(r"D:\First"), call(r"C:\Second")]
    assert local_windows.candidate.call_args_list == [
        call(r"D:\First\git.exe"),
        call(r"D:\First\git.cmd"),
        call(r"D:\First\git.bat"),
        call(r"C:\Second\git.exe"),
    ]
    legacy_which.assert_not_called()


@pytest.mark.parametrize("stage", ["query", "drive_type", "directory", "candidate"])
def test_lookup_exceptions_skip_uncertain_locations_without_exposing_details(
    stage: str, local_windows: SimpleNamespace
) -> None:
    getattr(local_windows, stage).side_effect = OSError("fictional private path token=hidden")

    assert lookup.find_local_executable("git", path_value=r"D:\Private") is None
    if stage in {"query", "drive_type"}:
        local_windows.directory.assert_not_called()
        local_windows.candidate.assert_not_called()
    elif stage == "directory":
        local_windows.candidate.assert_not_called()


def test_uncertain_or_reparse_directory_is_not_searched(local_windows: SimpleNamespace) -> None:
    local_windows.directory.return_value = None

    assert lookup.find_local_executable("git", path_value=r"D:\Link\Child") is None

    local_windows.candidate.assert_not_called()


def test_local_classification_precedes_directory_and_candidate_checks(
    local_windows: SimpleNamespace,
) -> None:
    events: list[str] = []
    local_windows.query.side_effect = lambda _drive: events.append("namespace") or LOCAL_TARGET
    local_windows.drive_type.side_effect = lambda _drive: events.append("drive-type") or 3
    local_windows.directory.side_effect = lambda _path: events.append("directory") or True
    local_windows.candidate.side_effect = lambda _path: events.append("candidate") or True

    assert lookup.find_local_executable("git", path_value=r"D:\Tools") == r"D:\Tools\git.exe"
    assert events == ["namespace", "drive-type", "directory", "candidate"]


def test_reparse_component_stops_lookup_before_its_descendants(
    local_windows: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    checked: list[str] = []

    def lstat(path: str) -> SimpleNamespace:
        checked.append(path)
        return SimpleNamespace(
            st_file_attributes=0x400 if path == r"D:\Link" else 0,
            st_mode=stat.S_IFDIR,
        )

    monkeypatch.setattr(
        environment, "_directory_state_on_local_volume", local_windows.directory_walk
    )
    monkeypatch.setattr(environment, "_lstat", lstat)

    assert lookup.find_local_executable("git", path_value=r"D:\Link\Child") is None
    assert checked == ["D:\\", r"D:\Link"]
    local_windows.candidate.assert_not_called()


def test_codex_uses_safe_lookup_without_launching_a_process(
    local_windows: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lookup, "_process_path_value", lambda: r"D:\Tools")
    local_windows.candidate.return_value = True
    launch = Mock(side_effect=AssertionError("Codex must not execute"))
    monkeypatch.setattr(commands.subprocess, "Popen", launch)

    result = commands.probe_tool("codex")

    assert result.status is commands.ProbeStatus.FOUND_UNVERIFIED
    assert result.executable == "<PATH>"
    assert result.version is None
    launch.assert_not_called()


def test_non_windows_does_not_use_posix_search_or_windows_apis(
    local_windows: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lookup, "_is_windows", lambda: False)

    assert lookup.find_local_executable("git", path_value=r"D:\Tools") is None

    local_windows.query.assert_not_called()
    local_windows.directory.assert_not_called()
    local_windows.candidate.assert_not_called()


@pytest.mark.parametrize("name", [r"..\git", "git.exe", "git --version", "git/path", ""])
def test_lookup_rejects_non_basename_inputs(name: str, local_windows: SimpleNamespace) -> None:
    assert lookup.find_local_executable(name, path_value=r"D:\Tools") is None
    local_windows.query.assert_not_called()


@pytest.mark.parametrize(
    ("attributes", "mode", "expected"),
    [
        (0, stat.S_IFREG, True),
        (0x400, stat.S_IFREG, False),
        (None, stat.S_IFREG, False),
        (0, stat.S_IFDIR, False),
    ],
)
def test_candidate_metadata_requires_regular_non_reparse_file(
    attributes: int | None, mode: int, expected: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    details = SimpleNamespace(st_file_attributes=attributes, st_mode=mode)
    lstat = Mock(return_value=details)
    monkeypatch.setattr(lookup, "_lstat", lstat)

    assert lookup._candidate_is_regular_file(r"D:\Tools\git.exe") is expected
    lstat.assert_called_once_with(r"D:\Tools\git.exe")


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Program Files\Python313\python.exe",
        r"C:\Program Files\Git\cmd\git.exe",
        r"C:\Program Files\nodejs\node.exe",
    ],
)
def test_trusted_executable_requires_approved_non_writable_root(
    path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lookup, "_is_windows", lambda: True)
    monkeypatch.setattr(lookup, "_trusted_roots", lambda: (r"C:\Program Files",))
    monkeypatch.setattr(lookup, "_local_directory_state", Mock(return_value=True))
    monkeypatch.setattr(lookup, "_candidate_is_regular_file", Mock(return_value=True))
    monkeypatch.setattr(lookup.os, "access", Mock(return_value=False))

    assert lookup.is_trusted_executable(path) is True


def test_trusted_executable_rejects_user_writable_or_unapproved_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lookup, "_is_windows", lambda: True)
    monkeypatch.setattr(lookup, "_trusted_roots", lambda: (r"C:\Program Files",))
    monkeypatch.setattr(lookup, "_local_directory_state", Mock(return_value=True))
    monkeypatch.setattr(lookup, "_candidate_is_regular_file", Mock(return_value=True))
    access = Mock(side_effect=lambda path, _mode: path.endswith(r"\Git\cmd"))
    monkeypatch.setattr(lookup.os, "access", access)

    assert lookup.is_trusted_executable(r"C:\Program Files\Git\cmd\git.exe") is False
    assert lookup.is_trusted_executable(r"D:\Tools\git.exe") is False


def test_trusted_executable_rejects_acl_or_metadata_uncertainty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lookup, "_is_windows", lambda: True)
    monkeypatch.setattr(lookup, "_trusted_roots", lambda: (r"C:\Program Files",))
    monkeypatch.setattr(lookup, "_local_directory_state", Mock(return_value=True))
    monkeypatch.setattr(lookup, "_candidate_is_regular_file", Mock(return_value=True))
    monkeypatch.setattr(lookup.os, "access", Mock(side_effect=OSError("ACL detail")))

    assert lookup.is_trusted_executable(r"C:\Program Files\Git\cmd\git.exe") is False

    monkeypatch.setattr(lookup, "_candidate_is_regular_file", Mock(return_value=False))
    monkeypatch.setattr(lookup.os, "access", Mock(return_value=False))
    assert lookup.is_trusted_executable(r"C:\Program Files\Git\cmd\git.exe") is False

    monkeypatch.setattr(lookup, "_candidate_is_regular_file", Mock(return_value=True))
    monkeypatch.setattr(lookup, "_local_directory_state", Mock(return_value=None))
    assert lookup.is_trusted_executable(r"C:\Program Files\Git\cmd\git.exe") is False


@pytest.mark.parametrize(
    "path",
    [
        "git.exe",
        r"..\git.exe",
        r"\\server\share\git.exe",
        r"C:\Program Files\Git\cmd\git.cmd",
        r"C:\Program Files\Git\cmd\git.bat",
    ],
)
def test_trusted_executable_rejects_non_absolute_or_non_exe_paths(
    path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lookup, "_is_windows", lambda: True)

    assert lookup.is_trusted_executable(path) is False


def test_query_dos_device_uses_only_drive_name_and_rejects_multiple_mappings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    targets = [LOCAL_TARGET]

    def query(name: str, buffer, capacity: int) -> int:
        assert name == "D:"
        assert capacity == len(buffer)
        value = "\0".join(targets) + "\0\0"
        for index, char in enumerate(value):
            buffer[index] = char
        return len(value)

    kernel32 = SimpleNamespace(QueryDosDeviceW=Mock(side_effect=query))
    monkeypatch.setattr(environment.ctypes, "WinDLL", Mock(return_value=kernel32), raising=False)

    assert environment._query_dos_device("D:") == LOCAL_TARGET
    targets.append(r"\Device\Mup\old-mapping")
    assert environment._query_dos_device("D:") is None
    kernel32.QueryDosDeviceW.return_value = 0
    kernel32.QueryDosDeviceW.side_effect = None
    assert environment._query_dos_device("D:") is None


def test_drive_type_api_receives_only_explicit_drive_root(monkeypatch: pytest.MonkeyPatch) -> None:
    get_drive_type = Mock(return_value=3)
    kernel32 = SimpleNamespace(GetDriveTypeW=get_drive_type)
    monkeypatch.setattr(environment.ctypes, "WinDLL", Mock(return_value=kernel32), raising=False)

    assert environment._drive_type("D:") == 3
    get_drive_type.assert_called_once_with("D:\\")
