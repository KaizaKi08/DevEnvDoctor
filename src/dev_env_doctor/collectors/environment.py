"""Read-only inspection of PATH values using Windows path semantics."""

import ctypes
import ntpath
import os
import re
import stat
from collections import defaultdict
from ctypes import wintypes

from dev_env_doctor.core.models import DiagnosticResult, Severity

DRIVE_UNKNOWN = 0
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_DRIVE = re.compile(r"[A-Z]:")
_LOCAL_VOLUME = re.compile(r"\\Device\\HarddiskVolume[0-9]+", re.IGNORECASE)
_RESERVED_NAMES = frozenset({"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"})
_RESERVED_PORT = re.compile(r"(?:COM|LPT)[1-9¹²³]")


def _lexical_directory(raw_entry: str) -> str | None:
    """Recognize an unambiguous drive-absolute path without filesystem I/O."""
    if any(ord(char) < 32 for char in raw_entry):
        return None
    entry = raw_entry.strip(" ")
    if len(entry) >= 2 and entry.startswith('"') and entry.endswith('"'):
        entry = entry[1:-1]
    if '"' in entry or re.match(r"[A-Za-z]:[\\/]", entry) is None:
        return None
    tail = entry[3:].replace("/", "\\")
    if any(char in '<>:"|?*%' for char in tail):
        return None
    for component in filter(None, tail.split("\\")):
        if component in {".", ".."} or component.endswith((" ", ".")):
            return None
        stem = component.split(".", 1)[0].rstrip(" .").upper()
        if stem in _RESERVED_NAMES or _RESERVED_PORT.fullmatch(stem):
            return None
    normalized = ntpath.normpath(entry.replace("/", "\\"))
    return normalized[0].upper() + normalized[1:]


def _query_dos_device(drive: str) -> str | None:
    """Read only the named drive's object-namespace mapping; reject ambiguity."""
    if _DRIVE.fullmatch(drive) is None:
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel32.QueryDosDeviceW
    query.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
    query.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(4096)
    count = query(drive, buffer, len(buffer))
    if not 0 < count <= len(buffer):
        return None
    targets = [target for target in buffer[:count].split("\0") if target]
    return targets[0] if len(targets) == 1 else None


def _drive_type(drive: str) -> int:
    """Query a root only after its DOS mapping has been classified as local.

    This is synchronous and may still block on a local driver. It is not a
    substitute for the namespace gate and does not provide a scan deadline.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_drive_type = kernel32.GetDriveTypeW
    get_drive_type.argtypes = (wintypes.LPCWSTR,)
    get_drive_type.restype = wintypes.UINT
    return int(get_drive_type(f"{drive}\\"))


def _is_local_fixed_drive(drive: str) -> bool:
    """Reject remote and indirect aliases before querying a volume root."""
    try:
        target = _query_dos_device(drive)
        return (
            isinstance(target, str)
            and _LOCAL_VOLUME.fullmatch(target) is not None
            and _drive_type(drive) == DRIVE_FIXED
        )
    except Exception:
        return False


def _lstat(path: str) -> os.stat_result:
    """Inspect one path component without following a final link/reparse point."""
    return os.lstat(path)


def _local_directory_state(path: str) -> bool | None:
    """Return exists-directory, missing/not-directory, or unsafe/unknown.

    Components are lstat'ed from the drive root downward. An unsafe or uncertain
    component stops the walk, so no child below a reparse point is inspected.
    """
    directory = _lexical_directory(path)
    if directory is None or not _is_local_fixed_drive(directory[:2]):
        return None
    return _directory_state_on_local_volume(directory)


def _directory_state_on_local_volume(directory: str) -> bool | None:
    """Walk a normalized directory whose volume has already been classified."""
    drive, tail = ntpath.splitdrive(directory)
    components = [part for part in tail.split("\\") if part]
    current = f"{drive}\\"
    for component in [None, *components]:
        if component is not None:
            current = ntpath.join(current, component)
        try:
            details = _lstat(current)
            attributes = getattr(details, "st_file_attributes", None)
            mode = details.st_mode
        except Exception:
            return None

        if not isinstance(attributes, int):
            return None
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            return None
        if not stat.S_ISDIR(mode):
            return False
    return True


def _diagnostic(
    rule_id: str,
    title: str,
    severity: Severity,
    summary: str,
    evidence: list[str],
    suggestion: str,
    *,
    status: str = "found",
) -> DiagnosticResult:
    return DiagnosticResult(
        rule_id=rule_id,
        title=title,
        severity=severity,
        summary=summary,
        evidence=evidence,
        suggestion=suggestion,
        status=status,
    )


def inspect_process_path() -> list[DiagnosticResult]:
    """Inspect only the current process PATH without changing it."""
    return inspect_path_value(os.environ.get("PATH"))


def inspect_path_value(
    path_value: str | None, *, parent_snapshot: bool = False
) -> list[DiagnosticResult]:
    """Return privacy-safe diagnostics for a supplied Windows PATH string.

    UNC, non-fixed-drive, ambiguous and reparse-point paths are not traversed.
    Components on a fixed local drive are inspected with lstat from the root
    down; any uncertainty, including a disappearing component, is reported as
    unverified. Path-based checks cannot eliminate component replacement races.
    No input value is rewritten or included in diagnostic output.
    """
    if path_value is None or not path_value.strip():
        return [
            _diagnostic(
                "PATH_EMPTY",
                "PATH is empty",
                Severity.WARNING,
                (
                    "The parent process PATH snapshot is unset or empty."
                    if parent_snapshot
                    else "The current process PATH is unset or empty."
                ),
                ["No PATH entries were available."],
                "Review the process environment and its parent configuration.",
            )
        ]

    results: list[DiagnosticResult] = []
    empty_indices: list[int] = []
    relative_indices: list[int] = []
    unknown_indices: list[int] = []
    missing_indices: list[int] = []
    duplicate_groups: dict[str, list[int]] = defaultdict(list)

    for index, raw_entry in enumerate(path_value.split(";"), start=1):
        entry = raw_entry.strip()
        if not entry:
            empty_indices.append(index)
            continue

        if entry.startswith('"') or entry.endswith('"'):
            if len(entry) >= 2 and entry.startswith('"') and entry.endswith('"'):
                entry = entry[1:-1].strip()
            else:
                unknown_indices.append(index)
                continue
        if not entry or '"' in entry:
            unknown_indices.append(index)
            continue

        normalized = ntpath.normcase(ntpath.normpath(entry))
        if ntpath.isabs(entry):
            duplicate_groups[normalized].append(index)
            directory_state = _local_directory_state(entry)
            if directory_state is None:
                unknown_indices.append(index)
            elif not directory_state:
                missing_indices.append(index)
        else:
            relative_indices.append(index)

    if empty_indices:
        results.append(
            _diagnostic(
                "PATH_EMPTY_ENTRY",
                "PATH contains empty entries",
                Severity.WARNING,
                f"PATH contains {len(empty_indices)} empty item(s).",
                [f"Empty item positions: {', '.join(map(str, empty_indices))}."],
                "Review empty separators; this report does not change PATH.",
            )
        )

    duplicates = [indices for indices in duplicate_groups.values() if len(indices) > 1]
    if duplicates:
        positions = [", ".join(map(str, group)) for group in duplicates]
        results.append(
            _diagnostic(
                "PATH_DUPLICATE_ENTRY",
                "PATH contains duplicate directories",
                Severity.INFO,
                f"Found {len(duplicates)} group(s) of equivalent PATH entries.",
                [f"Equivalent item positions: {'; '.join(positions)}."],
                "Review whether the repeated directories are intentional.",
            )
        )

    if missing_indices:
        results.append(
            _diagnostic(
                "PATH_MISSING_ENTRY",
                "PATH contains unavailable local directories",
                Severity.WARNING,
                f"{len(missing_indices)} local absolute PATH item(s) were not found.",
                [f"Unavailable item positions: {', '.join(map(str, missing_indices))}."],
                "Check whether these local directories were moved or removed.",
            )
        )

    if relative_indices:
        results.append(
            _diagnostic(
                "PATH_RELATIVE_ENTRY",
                "PATH contains relative entries",
                Severity.WARNING,
                f"{len(relative_indices)} relative PATH item(s) could not be validated safely.",
                [f"Relative item positions: {', '.join(map(str, relative_indices))}."],
                "Review relative entries in the context of the process working directory.",
                status="skipped",
            )
        )

    if unknown_indices:
        results.append(
            _diagnostic(
                "PATH_ENTRY_UNKNOWN",
                "Some PATH entries were not checked",
                Severity.INFO,
                (
                    f"{len(unknown_indices)} ambiguous, remote, or unsupported item(s) "
                    "were not checked."
                ),
                [f"Unverified item positions: {', '.join(map(str, unknown_indices))}."],
                "Review these entries locally; remote paths are intentionally not accessed.",
                status="skipped",
            )
        )

    return results
