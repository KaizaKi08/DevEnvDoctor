"""Conservative Windows executable lookup with no implicit search locations.

Lexical rejection precedes all system queries. QueryDosDeviceW reads the local
DOS-device namespace, not a candidate directory. Only a single, direct local
volume mapping can proceed to GetDriveTypeW and local filesystem inspection.
Neither system queries nor local filesystem calls have a wall-clock deadline.
Stable mappings and lstat checks reduce risk; they cannot eliminate TOCTOU races
or prove that a storage driver never uses a network internally.
"""

import ntpath
import os
import re
import stat

from dev_env_doctor.collectors.environment import (
    FILE_ATTRIBUTE_REPARSE_POINT,
    _lexical_directory,
    _local_directory_state,
    _lstat,
)
from dev_env_doctor.collectors.known_folders import program_files_folders

_BASENAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
_EXECUTABLE_SUFFIXES = (".exe", ".cmd", ".bat")
_NPM_DISCOVERY_SUFFIXES = (*_EXECUTABLE_SUFFIXES, ".com")


def _is_windows() -> bool:
    return os.name == "nt"


def _process_path_value() -> str | None:
    return os.environ.get("PATH")


def _search_directories(path_value: str | None) -> list[str]:
    if not isinstance(path_value, str):
        return []
    directories: list[str] = []
    seen: set[str] = set()
    for entry in path_value.split(";"):
        directory = _lexical_directory(entry)
        if directory is None:
            continue
        identity = ntpath.normcase(directory)
        if identity not in seen:
            seen.add(identity)
            directories.append(directory)
    return directories


def _candidate_is_regular_file(path: str) -> bool:
    """Inspect a file only after its directory passed the local volume walk."""
    try:
        details = _lstat(path)
        attributes = getattr(details, "st_file_attributes", None)
        return (
            isinstance(attributes, int)
            and not attributes & FILE_ATTRIBUTE_REPARSE_POINT
            and stat.S_ISREG(details.st_mode)
        )
    except Exception:
        return False


def _trusted_roots() -> tuple[str, ...]:
    """Resolve approved Windows roots independently of the diagnostic PATH."""
    roots: list[str] = []
    for name in ("SystemRoot", "WINDIR"):
        raw = os.environ.get(name)
        normalized = _lexical_directory(raw) if isinstance(raw, str) else None
        if normalized is not None and normalized not in roots:
            roots.append(normalized)
    for folder in program_files_folders():
        normalized = _lexical_directory(folder)
        if (
            normalized is not None
            and ntpath.dirname(normalized) != normalized
            and normalized not in roots
        ):
            roots.append(normalized)
    return tuple(roots)


def _path_is_within(path: str, root: str) -> bool:
    try:
        return ntpath.normcase(ntpath.commonpath((path, root))) == ntpath.normcase(root)
    except (TypeError, ValueError):
        return False


def _current_user_can_write(path: str) -> bool | None:
    """Return effective write access; uncertainty is never treated as safe."""
    try:
        return bool(os.access(path, os.W_OK))
    except (OSError, TypeError, ValueError):
        return None


def _directories_are_not_user_writable(path: str, root: str) -> bool:
    """Check the file and every directory from an approved root to the file."""
    file_access = _current_user_can_write(path)
    if file_access is not False:
        return False

    current = ntpath.dirname(path)
    while True:
        if not _path_is_within(current, root):
            return False
        directory_access = _current_user_can_write(current)
        if directory_access is not False:
            return False
        if ntpath.normcase(current) == ntpath.normcase(root):
            return True
        parent = ntpath.dirname(current)
        if parent == current:
            return False
        current = parent


def is_trusted_executable(path: str) -> bool:
    """Return whether a discovered executable may run a fixed version probe.

    Trust is deliberately narrower than discovery. Only absolute ``.exe`` files
    below approved Windows roots, with confirmed local non-reparse metadata and
    no effective write access for the current user, are executable. Any failed
    or uncertain check returns ``False``.
    """
    if not _is_windows() or not isinstance(path, str) or path != path.strip(" ") or '"' in path:
        return False
    normalized = _lexical_directory(path)
    if normalized is None or not normalized.lower().endswith(".exe"):
        return False
    directory = ntpath.dirname(normalized)
    try:
        if _local_directory_state(directory) is not True:
            return False
        if _candidate_is_regular_file(normalized) is not True:
            return False
        for root in _trusted_roots():
            if _path_is_within(directory, root) and _directories_are_not_user_writable(
                normalized, root
            ):
                return True
    except Exception:
        return False
    return False


def find_local_executable(executable: str, *, path_value: str | None = None) -> str | None:
    """Find a fixed basename only in approved Windows directories.

    Do not use which/PATHEXT: they can add implicit search locations or launchers.
    Non-Windows hosts intentionally perform no lookup. Batch launchers may be
    located, but the command collector must keep them lookup-only. The extra
    npm.com candidate is specific to npm's lookup-only policy.
    """
    if not isinstance(executable, str) or _BASENAME.fullmatch(executable) is None:
        return None
    if not _is_windows():
        return None
    if path_value is None:
        path_value = _process_path_value()
    suffixes = _NPM_DISCOVERY_SUFFIXES if executable.lower() == "npm" else _EXECUTABLE_SUFFIXES
    for directory in _search_directories(path_value):
        # Stop at reparse/uncertain components without descending beneath them.
        try:
            if _local_directory_state(directory) is not True:
                continue
        except Exception:
            continue
        for suffix in suffixes:
            candidate = ntpath.join(directory, executable + suffix)
            try:
                if _candidate_is_regular_file(candidate):
                    return candidate
            except Exception:
                continue
    return None
