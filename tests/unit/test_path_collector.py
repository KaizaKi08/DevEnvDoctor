import pytest

from dev_env_doctor.collectors import environment
from dev_env_doctor.collectors.environment import inspect_path_value


class FakeStat:
    def __init__(self, *, reparse: bool = False, directory: bool = True) -> None:
        self.st_file_attributes = environment.FILE_ATTRIBUTE_REPARSE_POINT if reparse else 0
        self.st_mode = 0o040755 if directory else 0o100644


@pytest.fixture(autouse=True)
def mock_local_volume(monkeypatch):
    monkeypatch.setattr(environment, "_query_dos_device", lambda _drive: r"\Device\HarddiskVolume7")
    monkeypatch.setattr(environment, "_drive_type", lambda _drive: environment.DRIVE_FIXED)
    monkeypatch.setattr(environment, "_lstat", lambda _path: FakeStat())


def _rule_ids(path: str | None) -> list[str]:
    return [item.rule_id for item in inspect_path_value(path)]


def test_empty_path_is_reported() -> None:
    assert "PATH_EMPTY" in _rule_ids(None)
    assert "PATH_EMPTY" in _rule_ids("")


def test_empty_path_entries_are_reported() -> None:
    assert "PATH_EMPTY_ENTRY" in _rule_ids(r"C:\Tools;;D:\Apps;")


def test_duplicate_windows_paths_ignore_case_and_slash_style(
    monkeypatch,
) -> None:
    monkeypatch.setattr(environment, "_lstat", lambda _path: FakeStat())
    monkeypatch.setattr(environment, "_drive_type", lambda _drive: environment.DRIVE_FIXED)

    results = inspect_path_value(r"C:\Program Files\Tool; c:/program files/tool\\")

    duplicate = [item for item in results if item.rule_id == "PATH_DUPLICATE_ENTRY"]
    assert len(duplicate) == 1


def test_disappearing_absolute_directory_is_unknown_without_path_leak(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        environment,
        "_lstat",
        lambda _path: (_ for _ in ()).throw(FileNotFoundError),
    )
    monkeypatch.setattr(environment, "_drive_type", lambda _drive: environment.DRIVE_FIXED)

    results = inspect_path_value(r"C:\Users\Alice\Missing Folder")

    unknown = [item for item in results if item.rule_id == "PATH_ENTRY_UNKNOWN"]
    assert len(unknown) == 1
    assert unknown[0].status == "skipped"
    assert "Alice" not in unknown[0].summary
    assert "Alice" not in str(unknown[0].evidence)


def test_relative_path_is_reported_as_unverified(monkeypatch) -> None:
    monkeypatch.setattr(
        environment,
        "_lstat",
        lambda _path: (_ for _ in ()).throw(AssertionError("relative path must not be checked")),
    )

    results = inspect_path_value(r"tools\bin")

    relative = [item for item in results if item.rule_id == "PATH_RELATIVE_ENTRY"]
    assert len(relative) == 1
    assert relative[0].status == "skipped"


def test_balanced_quotes_and_whitespace_are_used_for_check_without_rewriting(
    monkeypatch,
) -> None:
    checked: list[str] = []
    monkeypatch.setattr(
        environment,
        "_lstat",
        lambda path: checked.append(path) or FakeStat(),
    )
    monkeypatch.setattr(environment, "_drive_type", lambda _drive: environment.DRIVE_FIXED)

    results = inspect_path_value('  "C:\\Program Files\\Tool"  ')

    assert checked == ["C:\\", "C:\\Program Files", "C:\\Program Files\\Tool"]
    assert results == []


def test_unmatched_quote_is_reported_as_unknown_without_filesystem_check(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        environment,
        "_lstat",
        lambda _path: (_ for _ in ()).throw(AssertionError("ambiguous path must not be checked")),
    )

    results = inspect_path_value('"C:\\Program Files\\Tool')

    assert _rule_ids_from(results) == ["PATH_ENTRY_UNKNOWN"]


def test_local_path_missing_does_not_leak_personal_path_in_summary(monkeypatch) -> None:
    monkeypatch.setattr(
        environment,
        "_lstat",
        lambda _path: (_ for _ in ()).throw(FileNotFoundError),
    )
    monkeypatch.setattr(environment, "_drive_type", lambda _drive: environment.DRIVE_FIXED)

    results = inspect_path_value(r"C:\Users\Alice\private")

    assert all("Alice" not in item.summary for item in results)


def test_remote_drive_and_unc_entries_are_not_accessed(monkeypatch) -> None:
    monkeypatch.setattr(environment, "_drive_type", lambda _drive: environment.DRIVE_REMOTE)
    monkeypatch.setattr(
        environment,
        "_lstat",
        lambda _path: (_ for _ in ()).throw(AssertionError("remote paths must not be accessed")),
    )

    remote_drive_results = inspect_path_value(r"Z:\Shared\Tools")
    unc_results = inspect_path_value(r"\\server\share\Tools")

    assert "PATH_ENTRY_UNKNOWN" in _rule_ids_from(remote_drive_results)
    assert "PATH_ENTRY_UNKNOWN" in _rule_ids_from(unc_results)


def test_unknown_drive_type_is_skipped_without_lstat(monkeypatch) -> None:
    monkeypatch.setattr(environment, "_drive_type", lambda _drive: environment.DRIVE_UNKNOWN)
    monkeypatch.setattr(
        environment,
        "_lstat",
        lambda _path: (_ for _ in ()).throw(AssertionError("unknown drive must not be accessed")),
    )

    results = inspect_path_value(r"X:\Tools")

    assert _rule_ids_from(results) == ["PATH_ENTRY_UNKNOWN"]


def test_safe_local_directory_is_checked_component_by_component(monkeypatch) -> None:
    checked: list[str] = []

    def fake_lstat(path: str) -> FakeStat:
        checked.append(path)
        return FakeStat()

    monkeypatch.setattr(environment, "_drive_type", lambda _drive: environment.DRIVE_FIXED)
    monkeypatch.setattr(environment, "_lstat", fake_lstat)

    results = inspect_path_value(r"C:\Tools\Python")

    assert results == []
    assert checked == ["C:\\", r"C:\Tools", r"C:\Tools\Python"]


def test_reparse_point_stops_before_descendants_and_existence_probe(monkeypatch) -> None:
    checked: list[str] = []

    def fake_lstat(path: str) -> FakeStat:
        checked.append(path)
        return FakeStat(reparse=path == r"C:\Tools")

    monkeypatch.setattr(environment, "_drive_type", lambda _drive: environment.DRIVE_FIXED)
    monkeypatch.setattr(environment, "_lstat", fake_lstat)

    results = inspect_path_value(r"C:\Tools\Link\Python")

    assert checked == ["C:\\", r"C:\Tools"]
    assert _rule_ids_from(results) == ["PATH_ENTRY_UNKNOWN"]
    assert results[0].status == "skipped"


def test_component_inspection_error_marks_path_unknown(monkeypatch) -> None:
    checked: list[str] = []

    def fake_lstat(path: str) -> FakeStat:
        checked.append(path)
        if path == r"C:\Tools":
            raise PermissionError("fictional access failure")
        return FakeStat()

    monkeypatch.setattr(environment, "_drive_type", lambda _drive: environment.DRIVE_FIXED)
    monkeypatch.setattr(environment, "_lstat", fake_lstat)

    results = inspect_path_value(r"C:\Tools\Python")

    assert checked == ["C:\\", r"C:\Tools"]
    assert _rule_ids_from(results) == ["PATH_ENTRY_UNKNOWN"]


def test_missing_file_attributes_marks_path_unknown_without_descending(monkeypatch) -> None:
    checked: list[str] = []

    class MissingAttributes:
        st_mode = 0o040755

    def fake_lstat(path: str) -> MissingAttributes:
        checked.append(path)
        return MissingAttributes()

    monkeypatch.setattr(environment, "_drive_type", lambda _drive: environment.DRIVE_FIXED)
    monkeypatch.setattr(environment, "_lstat", fake_lstat)

    results = inspect_path_value(r"C:\Tools\Python")

    assert checked == ["C:\\"]
    assert _rule_ids_from(results) == ["PATH_ENTRY_UNKNOWN"]


def test_path_disappearing_during_component_walk_is_unknown(monkeypatch) -> None:
    checked: list[str] = []

    def fake_lstat(path: str) -> FakeStat:
        checked.append(path)
        if path == r"C:\Tools":
            raise FileNotFoundError("fictional disappearance")
        return FakeStat()

    monkeypatch.setattr(environment, "_drive_type", lambda _drive: environment.DRIVE_FIXED)
    monkeypatch.setattr(environment, "_lstat", fake_lstat)

    results = inspect_path_value(r"C:\Tools\Python")

    assert checked == ["C:\\", r"C:\Tools"]
    assert _rule_ids_from(results) == ["PATH_ENTRY_UNKNOWN"]


def _rule_ids_from(results) -> list[str]:
    return [item.rule_id for item in results]
