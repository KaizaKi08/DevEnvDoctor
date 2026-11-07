"""Resolve the reviewed Windows profile and Program Files locations."""

import ctypes
import os
from ctypes import wintypes
from uuid import UUID

_PROGRAM_FILES = UUID("905e63b6-c1bf-494e-b29c-65b732d3d21a")
_PROGRAM_FILES_X86 = UUID("7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e")
_PROGRAM_FILES_X64 = UUID("6d809377-6af0-444b-8957-a3773f02200e")
_PROFILE = UUID("5e6c858f-0e22-4760-9afe-ea3317b67173")
_KF_FLAG_DEFAULT_PATH = 0x00000400
_KF_FLAG_DONT_VERIFY = 0x00004000
_COINIT_MULTITHREADED = 0
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800


class _GUID(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]


def program_files_folders() -> tuple[str, ...]:
    """Resolve Windows defaults without creating or probing the directories."""
    ids = (_PROGRAM_FILES, _PROGRAM_FILES_X86)
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        ids += (_PROGRAM_FILES_X64,)
    return _resolve_folders(ids, flags=_KF_FLAG_DEFAULT_PATH | _KF_FLAG_DONT_VERIFY)


def user_profile_folder() -> str | None:
    """Resolve the current user's profile without probing its filesystem."""
    folders = _resolve_folders((_PROFILE,), flags=_KF_FLAG_DONT_VERIFY)
    return folders[0] if folders else None


def _resolve_folders(ids: tuple[UUID, ...], *, flags: int) -> tuple[str, ...]:
    if os.name != "nt":
        return ()
    try:
        ole32 = ctypes.WinDLL("ole32", winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32)
        shell32 = ctypes.WinDLL("shell32", winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32)
        initialize = ole32.CoInitializeEx
        initialize.argtypes = (ctypes.c_void_p, wintypes.DWORD)
        initialize.restype = ctypes.c_int32
        uninitialize = ole32.CoUninitialize
        uninitialize.argtypes = ()
        uninitialize.restype = None
        free = ole32.CoTaskMemFree
        free.argtypes = (ctypes.c_void_p,)
        free.restype = None
        get_folder = shell32.SHGetKnownFolderPath
        get_folder.argtypes = (
            ctypes.POINTER(_GUID),
            wintypes.DWORD,
            wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_void_p),
        )
        get_folder.restype = ctypes.c_int32
        if initialize(None, _COINIT_MULTITHREADED) not in (0, 1):
            return ()
    except (AttributeError, OSError):
        return ()

    folders = []
    try:
        for folder_id in ids:
            guid = _GUID.from_buffer_copy(folder_id.bytes_le)
            result = ctypes.c_void_p()
            try:
                status = get_folder(
                    ctypes.byref(guid),
                    flags,
                    None,
                    ctypes.byref(result),
                )
                if status == 0 and result.value is not None:
                    folders.append(ctypes.wstring_at(result.value))
            except (OSError, ValueError):
                continue
            finally:
                if result.value is not None:
                    free(result)
    finally:
        uninitialize()
    return tuple(folders)
