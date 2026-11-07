"""Metadata-only audit of the current user's fixed Codex configuration path."""

import ctypes
import ntpath
from collections.abc import Callable
from ctypes import wintypes
from enum import StrEnum

from dev_env_doctor.collectors.environment import (
    FILE_ATTRIBUTE_REPARSE_POINT,
    _is_local_fixed_drive,
    _lexical_directory,
)
from dev_env_doctor.collectors.known_folders import user_profile_folder

_DIRECTORY = 0x10
_DEVICE = 0x40
_OFFLINE = 0x1000
_RECALL_ON_OPEN = 0x40000
_RECALL_ON_DATA_ACCESS = 0x400000
_UNSAFE_ATTRIBUTES = (
    FILE_ATTRIBUTE_REPARSE_POINT | _OFFLINE | _RECALL_ON_OPEN | _RECALL_ON_DATA_ACCESS
)
_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_PATH_UNITS = 259
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
_GET_FILEEX_INFO_STANDARD = 0
_ERROR_FILE_NOT_FOUND = 2
_INACCESSIBLE_ERRORS = frozenset({5, 32, 33})  # Access denied, sharing or lock violation.


class CodexConfigState(StrEnum):
    PRESENT = "CODEX_CONFIG_PRESENT"
    MISSING = "CODEX_CONFIG_MISSING"
    INACCESSIBLE = "CODEX_CONFIG_INACCESSIBLE"
    UNSAFE = "CODEX_CONFIG_UNSAFE"
    INVALID_FILE = "CODEX_CONFIG_INVALID_FILE"
    TOO_LARGE = "CODEX_CONFIG_TOO_LARGE"
    UNVERIFIED = "CODEX_CONFIG_UNVERIFIED"


class _FileAttributes(ctypes.Structure):
    _fields_ = [
        ("attributes", wintypes.DWORD),
        ("creation_time", wintypes.FILETIME),
        ("access_time", wintypes.FILETIME),
        ("write_time", wintypes.FILETIME),
        ("size_high", wintypes.DWORD),
        ("size_low", wintypes.DWORD),
    ]


def _metadata_reader() -> Callable[[str], tuple[int, int]]:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32)
    get_attributes = kernel.GetFileAttributesExW
    get_attributes.argtypes = (wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(_FileAttributes))
    get_attributes.restype = wintypes.BOOL

    def read(path: str) -> tuple[int, int]:
        data = _FileAttributes()
        if not get_attributes(path, _GET_FILEEX_INFO_STANDARD, ctypes.byref(data)):
            error = ctypes.get_last_error()
            if error == _ERROR_FILE_NOT_FOUND:
                raise FileNotFoundError()
            if error in _INACCESSIBLE_ERRORS:
                raise PermissionError()
            raise OSError()
        return data.attributes, (data.size_high << 32) | data.size_low

    return read


def _safe_directory(attributes: int) -> bool:
    return bool(attributes & _DIRECTORY) and not attributes & (_DEVICE | _UNSAFE_ATTRIBUTES)


def inspect_codex_config() -> CodexConfigState:
    """Return only a fixed outcome. Never open file data or enumerate directories."""
    try:
        raw_profile = user_profile_folder()
        if raw_profile is None:
            return CodexConfigState.UNVERIFIED
        profile = _lexical_directory(raw_profile)
        if profile is None or raw_profile != raw_profile.strip(" ") or '"' in raw_profile:
            return CodexConfigState.UNSAFE
        drive, tail = ntpath.splitdrive(profile)
        components = [part for part in tail.split("\\") if part]
        codex_dir = ntpath.join(profile, ".codex")
        config = ntpath.join(codex_dir, "config.toml")
        if not components or len(config.encode("utf-16-le")) // 2 > _MAX_PATH_UNITS:
            return CodexConfigState.UNVERIFIED
        if not _is_local_fixed_drive(drive):
            return CodexConfigState.UNSAFE

        metadata = _metadata_reader()
        current = f"{drive}\\"
        for component in ("", *components):
            current = ntpath.join(current, component) if component else current
            attributes, _ = metadata(current)
            if not _safe_directory(attributes):
                return CodexConfigState.UNSAFE

        try:
            attributes, _ = metadata(codex_dir)
            if not _safe_directory(attributes):
                return CodexConfigState.UNSAFE
            attributes, size = metadata(config)
        except FileNotFoundError:
            return CodexConfigState.MISSING
    except PermissionError:
        return CodexConfigState.INACCESSIBLE
    except (AttributeError, OSError, TypeError, ValueError):
        return CodexConfigState.UNVERIFIED

    if attributes & _UNSAFE_ATTRIBUTES:
        return CodexConfigState.UNSAFE
    if attributes & (_DIRECTORY | _DEVICE):
        return CodexConfigState.INVALID_FILE
    if size > _MAX_CONFIG_BYTES:
        return CodexConfigState.TOO_LARGE
    return CodexConfigState.PRESENT
