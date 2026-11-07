"""Runtime-only PyInstaller checks for the supervised environment probe."""

import ctypes
import ntpath
import os
import sys
from contextlib import ExitStack
from ctypes import wintypes

from dev_env_doctor.collectors.environment import (
    FILE_ATTRIBUTE_REPARSE_POINT,
    _lexical_directory,
    _local_directory_state,
)
from dev_env_doctor.core.process_environment import (
    _ALLOWED_NAMES,
    PROBE_UNICODE_NAME,
    EnvironmentConstructionError,
    build_worker_environment,
)

_LEVEL = "_PYI_PARENT_PROCESS_LEVEL"
_ARCHIVE = "_PYI_ARCHIVE_FILE"
# The exact PyInstaller 6.22.3 onedir MAIN encoding verified in D6C.10D.9A.
_MAIN_LEVEL = "1"
_FROZEN_NAMES = _ALLOWED_NAMES | {PROBE_UNICODE_NAME, _LEVEL, _ARCHIVE}
_WORKER_EXE = "devenvdoctorworker.exe"
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_FILE_READ_ATTRIBUTES = 0x80
_FILE_SHARE_ALL = 7
_OPEN_EXISTING = 3
_OPEN_REPARSE_POINT = 0x00200000
_FILE_TYPE_DISK = 1
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_TAG_INFO = 9
_FILE_ID_INFO = 18


class _FileIdInfo(ctypes.Structure):
    _fields_ = [("volume", ctypes.c_uint64), ("file_id", ctypes.c_ubyte * 16)]


class _AttributeTagInfo(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]


def _bind(kernel, name, argtypes, restype):
    function = getattr(kernel, name)
    function.argtypes = argtypes
    function.restype = restype
    return function


def _absolute_local_syntax(value: object) -> str:
    """Reject aliases and ambiguous syntax before any candidate filesystem I/O."""
    if (
        type(value) is not str
        or value[1:3] not in (":\\", ":/")
        or not all(value[3:].replace("/", "\\").split("\\"))
        or value != value.strip(" ")
    ):
        raise EnvironmentConstructionError()
    path = _lexical_directory(value)
    if path is None:
        raise EnvironmentConstructionError()
    return path


def _main_module_path(kernel) -> str:
    get_filename = _bind(
        kernel,
        "GetModuleFileNameW",
        (wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD),
        wintypes.DWORD,
    )
    buffer = ctypes.create_unicode_buffer(32768)
    if not 0 < get_filename(None, buffer, len(buffer)) < len(buffer):
        raise EnvironmentConstructionError()
    return _absolute_local_syntax(buffer.value)


def _close_checked(close, handle: int) -> None:
    if not close(handle):
        raise EnvironmentConstructionError()


def _verify_exe_identity(kernel, paths: tuple[str, str, str]) -> None:
    open_file = _bind(
        kernel,
        "CreateFileW",
        (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ),
        wintypes.HANDLE,
    )
    close = _bind(kernel, "CloseHandle", (wintypes.HANDLE,), wintypes.BOOL)
    file_type = _bind(kernel, "GetFileType", (wintypes.HANDLE,), wintypes.DWORD)
    info = _bind(
        kernel,
        "GetFileInformationByHandleEx",
        (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD),
        wintypes.BOOL,
    )
    identities = []
    with ExitStack() as cleanup:
        for path in paths:
            handle = open_file(
                path,
                _FILE_READ_ATTRIBUTES,
                _FILE_SHARE_ALL,
                None,
                _OPEN_EXISTING,
                _OPEN_REPARSE_POINT,
                None,
            )
            if handle in (None, 0, -1, _INVALID_HANDLE):
                raise EnvironmentConstructionError()
            cleanup.callback(_close_checked, close, handle)

            tag = _AttributeTagInfo()
            identity = _FileIdInfo()
            if (
                file_type(handle) != _FILE_TYPE_DISK
                or not info(handle, _FILE_ATTRIBUTE_TAG_INFO, ctypes.byref(tag), ctypes.sizeof(tag))
                or tag.attributes & (_FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                or not info(handle, _FILE_ID_INFO, ctypes.byref(identity), ctypes.sizeof(identity))
            ):
                raise EnvironmentConstructionError()
            file_id = bytes(identity.file_id)
            if not any(file_id):
                raise EnvironmentConstructionError()
            identities.append((identity.volume, file_id))
        if identities[0] != identities[1] or identities[0] != identities[2]:
            raise EnvironmentConstructionError()


def validate_frozen_worker_environment() -> None:
    """Validate onedir consistency for Probe-only, not general process authentication."""
    try:
        if os.name != "nt" or getattr(sys, "frozen", False) is not True:
            raise EnvironmentConstructionError()
        executable = _absolute_local_syntax(sys.executable)
        home = _absolute_local_syntax(getattr(sys, "_MEIPASS", None))
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        module = _main_module_path(kernel)
        if (
            ntpath.normcase(ntpath.basename(module)) != _WORKER_EXE
            or ntpath.normcase(module) != ntpath.normcase(executable)
            or home != ntpath.join(ntpath.dirname(executable), "_internal")
        ):
            raise EnvironmentConstructionError()

        env = {}
        for name, value in os.environ.items():
            key = name.upper()
            if key not in _FROZEN_NAMES or key in env:
                raise EnvironmentConstructionError()
            env[key] = value
        expected = build_worker_environment(env, include_probe_marker=True)
        if (
            env.get("PATH") != expected["PATH"]
            or env.get(PROBE_UNICODE_NAME) != expected[PROBE_UNICODE_NAME]
        ):
            raise EnvironmentConstructionError()
        level = env.get(_LEVEL)
        if type(level) is not str or not level.isascii() or len(level) != 1 or level != _MAIN_LEVEL:
            raise EnvironmentConstructionError()
        archive = _absolute_local_syntax(env.get(_ARCHIVE))
        if ntpath.normcase(archive) != ntpath.normcase(module):
            raise EnvironmentConstructionError()

        paths = (module, executable, archive)
        directories = {home, *(ntpath.dirname(path) for path in paths)}
        if any(_local_directory_state(path) is not True for path in directories):
            raise EnvironmentConstructionError()
        _verify_exe_identity(kernel, paths)
    except Exception:
        # The Worker returns a fixed error. Never carry environment values,
        # candidate paths, native error details or file identity into that path.
        raise EnvironmentConstructionError() from None
