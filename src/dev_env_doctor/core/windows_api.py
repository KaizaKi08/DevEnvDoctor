"""Small, explicit Win32 bindings used by the future scan resource owner.

The module is importable on every platform, but constructing ``NativeWindowsApi``
on a non-Windows host is rejected. It does not provide fallbacks that pretend a
Job or process was created successfully.
"""

import ctypes
import os
import subprocess
from collections.abc import Mapping, Sequence
from ctypes import wintypes
from dataclasses import dataclass

WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF
INFINITE = 0xFFFFFFFF
CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
ERROR_INSUFFICIENT_BUFFER = 122


class WindowsApiError(RuntimeError):
    """A fixed, non-sensitive native API failure."""

    def __init__(self, message: str = "A Windows resource operation failed.") -> None:
        super().__init__(message)


class UnsupportedPlatformError(WindowsApiError):
    """Raised when a native Windows resource adapter is requested elsewhere."""

    def __init__(self) -> None:
        super().__init__("Windows resource operations are unavailable on this platform.")


class _StartupInfoW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _StartupInfoExW(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", _StartupInfoW),
        ("lpAttributeList", ctypes.c_void_p),
    ]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _BasicAccountingInformation(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong),
        ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


@dataclass(frozen=True, slots=True)
class ProcessHandles:
    """Owned process and primary-thread handles returned by CreateProcessW."""

    process: int
    thread: int


class NativeWindowsApi:
    """Explicit ctypes adapter; no implicit shell, PATH, or handle inheritance."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise UnsupportedPlatformError()
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._bind()

    def _bind(self) -> None:
        k = self._kernel32
        self._CreateJobObjectW = k.CreateJobObjectW
        self._CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        self._CreateJobObjectW.restype = wintypes.HANDLE
        self._SetInformationJobObject = k.SetInformationJobObject
        self._SetInformationJobObject.argtypes = (
            wintypes.HANDLE,
            wintypes.INT,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        self._SetInformationJobObject.restype = wintypes.BOOL
        self._QueryInformationJobObject = k.QueryInformationJobObject
        self._QueryInformationJobObject.argtypes = (
            wintypes.HANDLE,
            wintypes.INT,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        self._QueryInformationJobObject.restype = wintypes.BOOL
        self._CreateProcessW = k.CreateProcessW
        self._CreateProcessW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.BOOL,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.POINTER(_StartupInfoExW),
            ctypes.POINTER(_ProcessInformation),
        )
        self._CreateProcessW.restype = wintypes.BOOL
        self._InitializeProcThreadAttributeList = k.InitializeProcThreadAttributeList
        self._InitializeProcThreadAttributeList.argtypes = (
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_size_t),
        )
        self._InitializeProcThreadAttributeList.restype = wintypes.BOOL
        self._UpdateProcThreadAttribute = k.UpdateProcThreadAttribute
        self._UpdateProcThreadAttribute.argtypes = (
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
        )
        self._UpdateProcThreadAttribute.restype = wintypes.BOOL
        self._DeleteProcThreadAttributeList = k.DeleteProcThreadAttributeList
        self._DeleteProcThreadAttributeList.argtypes = (ctypes.c_void_p,)
        self._DeleteProcThreadAttributeList.restype = None
        self._ResumeThread = k.ResumeThread
        self._ResumeThread.argtypes = (wintypes.HANDLE,)
        self._ResumeThread.restype = wintypes.DWORD
        self._WaitForSingleObject = k.WaitForSingleObject
        self._WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        self._WaitForSingleObject.restype = wintypes.DWORD
        self._GetExitCodeProcess = k.GetExitCodeProcess
        self._GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        self._GetExitCodeProcess.restype = wintypes.BOOL
        self._TerminateJobObject = k.TerminateJobObject
        self._TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        self._TerminateJobObject.restype = wintypes.BOOL
        self._IsProcessInJob = k.IsProcessInJob
        self._IsProcessInJob.argtypes = (
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.BOOL),
        )
        self._IsProcessInJob.restype = wintypes.BOOL
        self._CloseHandle = k.CloseHandle
        self._CloseHandle.argtypes = (wintypes.HANDLE,)
        self._CloseHandle.restype = wintypes.BOOL

    @staticmethod
    def _check(value: bool, message: str = "A Windows resource operation failed.") -> None:
        if not value:
            raise WindowsApiError(message)

    def create_job(self) -> int:
        handle = self._CreateJobObjectW(None, None)
        if not handle:
            raise WindowsApiError()
        return int(handle)

    def configure_job(self, job: int) -> None:
        info = _ExtendedLimitInformation()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        self._check(
            self._SetInformationJobObject(
                job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info)
            )
        )

    def create_suspended_process(
        self,
        command_line: Sequence[str],
        job: int,
        inherited_handles: Sequence[int] = (),
        environment: Mapping[str, str] | None = None,
    ) -> ProcessHandles:
        if not command_line or any(type(item) is not str or not item for item in command_line):
            raise WindowsApiError("A fixed process command is required.")
        if any(type(handle) is not int or handle <= 0 for handle in inherited_handles):
            raise WindowsApiError("Inherited handles are invalid.")
        attribute_count = 1 + (1 if inherited_handles else 0)
        size = ctypes.c_size_t(0)
        self._InitializeProcThreadAttributeList(None, attribute_count, 0, ctypes.byref(size))
        if not size.value:
            raise WindowsApiError()
        attributes = ctypes.create_string_buffer(size.value)
        self._check(
            self._InitializeProcThreadAttributeList(
                attributes, attribute_count, 0, ctypes.byref(size)
            )
        )
        job_array = (wintypes.HANDLE * 1)(job)
        startup = _StartupInfoExW()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.lpAttributeList = ctypes.cast(attributes, ctypes.c_void_p)
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline(list(command_line)))
        if environment is None:
            from dev_env_doctor.core.process_environment import build_worker_environment

            environment = build_worker_environment()
        environment_items = sorted(environment.items(), key=lambda item: item[0].upper())
        environment_block = "\0".join(f"{key}={value}" for key, value in environment_items) + "\0\0"
        environment_buffer = ctypes.create_unicode_buffer(environment_block)
        info = _ProcessInformation()
        try:
            self._check(
                self._UpdateProcThreadAttribute(
                    startup.lpAttributeList,
                    0,
                    PROC_THREAD_ATTRIBUTE_JOB_LIST,
                    ctypes.byref(job_array),
                    ctypes.sizeof(job_array),
                    None,
                    None,
                )
            )
            inherit = False
            if inherited_handles:
                handle_array = (wintypes.HANDLE * len(inherited_handles))(*inherited_handles)
                self._check(
                    self._UpdateProcThreadAttribute(
                        startup.lpAttributeList,
                        0,
                        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                        ctypes.byref(handle_array),
                        ctypes.sizeof(handle_array),
                        None,
                        None,
                    )
                )
                inherit = True
            flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT
            self._check(
                self._CreateProcessW(
                    command_line[0],
                    command,
                    None,
                    None,
                    inherit,
                    flags,
                    ctypes.cast(environment_buffer, ctypes.c_void_p),
                    None,
                    ctypes.byref(startup),
                    ctypes.byref(info),
                )
            )
            return ProcessHandles(int(info.hProcess), int(info.hThread))
        finally:
            self._DeleteProcThreadAttributeList(startup.lpAttributeList)

    def is_process_in_job(self, process: int, job: int) -> bool:
        result = wintypes.BOOL()
        self._check(self._IsProcessInJob(process, job, ctypes.byref(result)))
        return bool(result.value)

    def resume_thread(self, thread: int) -> bool:
        result = self._ResumeThread(thread)
        return type(result) is int and result == 1

    def wait_process(self, process: int, timeout_ms: int) -> int:
        return int(self._WaitForSingleObject(process, timeout_ms))

    def get_exit_code(self, process: int) -> int:
        code = wintypes.DWORD()
        self._check(self._GetExitCodeProcess(process, ctypes.byref(code)))
        return int(code.value)

    def terminate_job(self, job: int) -> bool:
        return bool(self._TerminateJobObject(job, 1))

    def query_active_processes(self, job: int) -> int:
        info = _BasicAccountingInformation()
        returned = wintypes.DWORD()
        self._check(
            self._QueryInformationJobObject(
                job,
                JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                ctypes.byref(info),
                ctypes.sizeof(info),
                ctypes.byref(returned),
            )
        )
        return int(info.ActiveProcesses)

    def close_handle(self, handle: int) -> bool:
        return bool(self._CloseHandle(handle))
