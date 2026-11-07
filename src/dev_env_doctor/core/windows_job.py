"""Explicit Job Object ownership and suspended-process lifecycle."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from dev_env_doctor.core.windows_api import (
    WAIT_FAILED,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
    NativeWindowsApi,
    ProcessHandles,
)


class WindowsResourceError(RuntimeError):
    """Fixed, non-sensitive resource lifecycle error."""

    def __init__(
        self, message: str = "Windows scan resources could not be managed safely."
    ) -> None:
        super().__init__(message)


class JobState(StrEnum):
    IDLE = "idle"
    CREATING = "creating"
    ASSOCIATED = "associated"
    RUNNING = "running"
    FAILED = "failed"
    CLOSED = "closed"
    UNCONFIRMED = "unconfirmed"


class CreationState(StrEnum):
    NOT_STARTED = "not_started"
    CREATING = "creating"
    JOB_CREATED = "job_created"
    PROCESS_SUSPENDED = "process_suspended"
    ASSOCIATED = "associated"
    PROCESS_EXITED = "process_exited"
    JOB_EMPTY = "job_empty"


class CleanupObservation(StrEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"


@dataclass(frozen=True, slots=True)
class WaitObservation:
    state: CreationState
    exit_code: int | None = None
    timed_out: bool = False
    failed: bool = False


@dataclass(frozen=True, slots=True)
class JobSnapshot:
    state: JobState
    creation: CreationState
    cleanup: CleanupObservation
    resume_authorized: bool
    association_verified: bool
    process_exit_confirmed: bool
    exit_code: int | None
    job_active_processes: int | None
    process_handle: int | None
    thread_handle: int | None
    job_handle: int | None


class WindowsJob:
    """Own one Job, one suspended process and its primary thread handles.

    The injected API is intentionally small and testable. This class never
    starts arbitrary work: callers supply a fixed internal command only after
    a later stage defines the worker entry point.
    """

    def __init__(self, api: object | None = None) -> None:
        self._api = NativeWindowsApi() if api is None else api
        self._state = JobState.IDLE
        self._creation = CreationState.NOT_STARTED
        self._cleanup = CleanupObservation.PENDING
        self._resume_authorized = False
        self._association_verified = False
        self._process_exit_confirmed = False
        self._exit_code: int | None = None
        self._job_active: int | None = None
        self._job: int | None = None
        self._process: int | None = None
        self._thread: int | None = None

    @property
    def snapshot(self) -> JobSnapshot:
        return JobSnapshot(
            state=self._state,
            creation=self._creation,
            cleanup=self._cleanup,
            resume_authorized=self._resume_authorized,
            association_verified=self._association_verified,
            process_exit_confirmed=self._process_exit_confirmed,
            exit_code=self._exit_code,
            job_active_processes=self._job_active,
            process_handle=self._process,
            thread_handle=self._thread,
            job_handle=self._job,
        )

    def _validate_timeout(self, value: object) -> int:
        if type(value) is not int:
            raise TypeError("remaining_timeout_ms must be a nonnegative integer.")
        if value < 0:
            raise ValueError("remaining_timeout_ms must be nonnegative.")
        return value

    def start(
        self,
        command_line: Sequence[str],
        *,
        remaining_timeout_ms: int,
        inherited_handles: Sequence[int] = (),
        environment: Mapping[str, str] | None = None,
    ) -> JobSnapshot:
        """Create/configure/associate a suspended process, never resume it."""
        self._validate_timeout(remaining_timeout_ms)
        if self._state is not JobState.IDLE:
            raise WindowsResourceError()
        self._state = JobState.CREATING
        self._creation = CreationState.CREATING
        try:
            self._job = self._api.create_job()
            self._creation = CreationState.JOB_CREATED
            self._api.configure_job(self._job)
            kwargs = {"environment": environment} if environment is not None else {}
            handles: ProcessHandles | tuple[int, int] = self._api.create_suspended_process(
                tuple(command_line), self._job, tuple(inherited_handles), **kwargs
            )
            if isinstance(handles, ProcessHandles):
                self._process, self._thread = int(handles.process), int(handles.thread)
            elif type(handles) is tuple and len(handles) == 2:
                self._process, self._thread = int(handles[0]), int(handles[1])
            else:
                raise WindowsResourceError()
            self._creation = CreationState.PROCESS_SUSPENDED
            if not self._api.is_process_in_job(self._process, self._job):
                raise WindowsResourceError()
            self._association_verified = True
            self._state = JobState.ASSOCIATED
            return self.snapshot
        except BaseException as original:
            cleanup_ok = self._close_owned_handles()
            self._state = JobState.FAILED if cleanup_ok else JobState.UNCONFIRMED
            if not cleanup_ok:
                self._cleanup = CleanupObservation.UNCONFIRMED
            if isinstance(original, WindowsResourceError):
                raise
            if isinstance(original, Exception):
                raise WindowsResourceError() from None
            raise

    def authorize_resume(self) -> JobSnapshot:
        """Resume only after association has been positively verified."""
        if self._state is JobState.RUNNING and self._resume_authorized:
            return self.snapshot
        if self._state is not JobState.ASSOCIATED or self._thread is None:
            raise WindowsResourceError()
        if self._resume_authorized:
            return self.snapshot
        try:
            resumed = self._api.resume_thread(self._thread)
        except BaseException:
            self._state = JobState.UNCONFIRMED
            self._cleanup = CleanupObservation.UNCONFIRMED
            raise
        if type(resumed) is not bool or resumed is not True:
            self._state = JobState.FAILED
            self._cleanup = CleanupObservation.UNCONFIRMED
            raise WindowsResourceError()
        self._resume_authorized = True
        self._state = JobState.RUNNING
        return self.snapshot

    def wait(self, timeout_ms: int) -> WaitObservation:
        """Observe direct process exit, timeout, or wait failure separately."""
        timeout = self._validate_timeout(timeout_ms)
        if self._process is None:
            raise WindowsResourceError()
        result = self._api.wait_process(self._process, timeout)
        if result == WAIT_OBJECT_0:
            try:
                code = self._api.get_exit_code(self._process)
            except BaseException:
                self._state = JobState.UNCONFIRMED
                self._cleanup = CleanupObservation.UNCONFIRMED
                raise WindowsResourceError() from None
            self._process_exit_confirmed = True
            self._exit_code = code
            self._creation = CreationState.PROCESS_EXITED
            return WaitObservation(self._creation, code)
        if result == WAIT_TIMEOUT:
            return WaitObservation(self._creation, timed_out=True)
        if result == WAIT_FAILED:
            return WaitObservation(self._creation, failed=True)
        return WaitObservation(self._creation, failed=True)

    def observe_job_empty(self) -> JobSnapshot:
        """Observe Job count; zero alone never confirms process cleanup."""
        if self._job is None:
            raise WindowsResourceError()
        try:
            active = self._api.query_active_processes(self._job)
        except BaseException:
            self._state = JobState.UNCONFIRMED
            self._cleanup = CleanupObservation.UNCONFIRMED
            raise WindowsResourceError() from None
        if type(active) is not int or active < 0:
            self._state = JobState.UNCONFIRMED
            self._cleanup = CleanupObservation.UNCONFIRMED
            raise WindowsResourceError()
        self._job_active = active
        if active == 0 and self._process_exit_confirmed:
            self._creation = CreationState.JOB_EMPTY
        return self.snapshot

    def terminate(self) -> bool:
        """Request Job termination without converting the request to exit proof."""
        if self._job is None:
            raise WindowsResourceError()
        try:
            result = bool(self._api.terminate_job(self._job))
        except BaseException:
            self._state = JobState.UNCONFIRMED
            self._cleanup = CleanupObservation.UNCONFIRMED
            raise WindowsResourceError() from None
        if not result:
            self._state = JobState.UNCONFIRMED
            self._cleanup = CleanupObservation.UNCONFIRMED
        return result

    def close(self) -> JobSnapshot:
        """Close owned handles only after exit and Job-empty evidence."""
        if self._cleanup is CleanupObservation.CONFIRMED:
            return self.snapshot
        if self._process is not None and not self._process_exit_confirmed:
            self._cleanup = CleanupObservation.UNCONFIRMED
            raise WindowsResourceError()
        if self._job is not None and self._job_active != 0:
            self._cleanup = CleanupObservation.UNCONFIRMED
            raise WindowsResourceError()
        if self._job is not None and self._job_active is None:
            self._cleanup = CleanupObservation.UNCONFIRMED
            raise WindowsResourceError()
        if not self._close_owned_handles():
            self._cleanup = CleanupObservation.UNCONFIRMED
            self._state = JobState.UNCONFIRMED
            raise WindowsResourceError()
        self._cleanup = CleanupObservation.CONFIRMED
        self._state = JobState.CLOSED
        return self.snapshot

    def _close_owned_handles(self) -> bool:
        success = True
        for attribute in ("_thread", "_process", "_job"):
            handle = getattr(self, attribute)
            if handle is None:
                continue
            try:
                closed = bool(self._api.close_handle(handle))
            except BaseException:
                closed = False
            if closed:
                setattr(self, attribute, None)
            else:
                success = False
        return success
