import ctypes
import os
import sys
from unittest.mock import Mock

import pytest

from dev_env_doctor.core import windows_api
from dev_env_doctor.core.windows_api import (
    WAIT_FAILED,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
    WindowsApiError,
)
from dev_env_doctor.core.windows_job import (
    CleanupObservation,
    CreationState,
    JobState,
    WindowsJob,
    WindowsResourceError,
)


class FakeApi:
    def __init__(self):
        self.calls = []
        self.close_results = {}
        self.active = 1
        self.wait_result = WAIT_TIMEOUT
        self.exit_code = 0
        self.in_job = True
        self.resume_result = True
        self.terminate_result = True
        self.create_job_result = 11
        self.process_result = (21, 22)

    def create_job(self):
        self.calls.append(("create_job",))
        return self.create_job_result

    def configure_job(self, job):
        self.calls.append(("configure_job", job))

    def create_suspended_process(self, command_line, job, inherited_handles=()):
        self.calls.append(("create_process", tuple(command_line), job, tuple(inherited_handles)))
        return self.process_result

    def is_process_in_job(self, process, job):
        self.calls.append(("is_in_job", process, job))
        return self.in_job

    def resume_thread(self, thread):
        self.calls.append(("resume", thread))
        return self.resume_result

    def wait_process(self, process, timeout_ms):
        self.calls.append(("wait", process, timeout_ms))
        return self.wait_result

    def get_exit_code(self, process):
        self.calls.append(("exit_code", process))
        return self.exit_code

    def query_active_processes(self, job):
        self.calls.append(("query_active", job))
        return self.active

    def terminate_job(self, job):
        self.calls.append(("terminate", job))
        return self.terminate_result

    def close_handle(self, handle):
        self.calls.append(("close", handle))
        return self.close_results.get(handle, True)


def started(api=None):
    api = FakeApi() if api is None else api
    owner = WindowsJob(api)
    snapshot = owner.start(("worker.exe", "--fixed"), remaining_timeout_ms=500)
    return owner, api, snapshot


def test_initial_snapshot_is_explicit_and_not_cleaned():
    owner = WindowsJob(FakeApi())
    snapshot = owner.snapshot
    assert snapshot.state is JobState.IDLE
    assert snapshot.creation is CreationState.NOT_STARTED
    assert snapshot.cleanup is CleanupObservation.PENDING
    assert snapshot.process_handle is None
    assert snapshot.job_handle is None


def test_start_creates_configures_associates_before_resume():
    owner, api, snapshot = started()
    assert snapshot.creation is CreationState.PROCESS_SUSPENDED
    assert snapshot.association_verified
    assert not snapshot.resume_authorized
    assert snapshot.process_handle == 21 and snapshot.thread_handle == 22
    assert [call[0] for call in api.calls] == [
        "create_job",
        "configure_job",
        "create_process",
        "is_in_job",
    ]
    assert not any(call[0] == "resume" for call in api.calls)
    owner.authorize_resume()
    assert owner.snapshot.resume_authorized
    assert [call[0] for call in api.calls][-1] == "resume"


def test_resume_requires_association_and_explicit_authorization():
    api = FakeApi()
    owner = WindowsJob(api)
    with pytest.raises(WindowsResourceError):
        owner.authorize_resume()
    owner.start(("worker.exe",), remaining_timeout_ms=10)
    assert owner.snapshot.creation is CreationState.PROCESS_SUSPENDED
    assert owner.snapshot.association_verified
    owner.authorize_resume()
    owner.authorize_resume()
    assert [call[0] for call in api.calls].count("resume") == 1


@pytest.mark.parametrize("return_value", [0, 2, 3, 0xFFFFFFFF, "one"])
def test_resume_rejects_every_return_value_other_than_one(return_value):
    api = FakeApi()
    api.resume_result = return_value
    owner = WindowsJob(api)
    owner.start(("worker.exe",), remaining_timeout_ms=10)
    with pytest.raises(WindowsResourceError):
        owner.authorize_resume()
    assert not owner.snapshot.resume_authorized
    assert owner.snapshot.cleanup is CleanupObservation.UNCONFIRMED


def test_accounting_structure_matches_windows_sdk_64_bit_layout():
    fields = windows_api._BasicAccountingInformation._fields_
    assert [name for name, _ in fields] == [
        "TotalUserTime",
        "TotalKernelTime",
        "ThisPeriodTotalUserTime",
        "ThisPeriodTotalKernelTime",
        "TotalPageFaultCount",
        "TotalProcesses",
        "ActiveProcesses",
        "TotalTerminatedProcesses",
    ]
    assert [field_type for _, field_type in fields[:4]] == [ctypes.c_longlong] * 4
    assert [field_type for _, field_type in fields[4:]] == [ctypes.c_ulong] * 4
    expected_offsets = {
        "TotalUserTime": 0,
        "TotalKernelTime": 8,
        "ThisPeriodTotalUserTime": 16,
        "ThisPeriodTotalKernelTime": 24,
        "TotalPageFaultCount": 32,
        "TotalProcesses": 36,
        "ActiveProcesses": 40,
        "TotalTerminatedProcesses": 44,
    }
    assert ctypes.sizeof(windows_api._BasicAccountingInformation) == 48
    assert {
        name: getattr(windows_api._BasicAccountingInformation, name).offset
        for name in expected_offsets
    } == expected_offsets


def test_query_active_processes_returns_count_and_rejects_query_failure():
    owner, api, _ = started()
    api.active = 3
    assert owner.observe_job_empty().job_active_processes == 3
    api.query_active_processes = Mock(side_effect=WindowsApiError())
    with pytest.raises(WindowsResourceError):
        owner.observe_job_empty()
    assert owner.snapshot.cleanup is CleanupObservation.UNCONFIRMED


def test_nonzero_exit_is_distinct_from_confirmed_cleanup():
    owner, api, _ = started()
    owner.authorize_resume()
    api.wait_result = WAIT_OBJECT_0
    api.exit_code = 7
    observation = owner.wait(100)
    assert observation.exit_code == 7
    api.active = 0
    owner.observe_job_empty()
    owner.close()
    assert owner.snapshot.cleanup is CleanupObservation.CONFIRMED
    assert owner.snapshot.exit_code == 7


def test_attribute_update_failure_is_not_downgraded_to_unmanaged_start():
    api = FakeApi()
    api.create_suspended_process = Mock(side_effect=WindowsApiError())
    owner = WindowsJob(api)
    with pytest.raises(WindowsResourceError):
        owner.start(("worker.exe",), remaining_timeout_ms=10)
    assert not any(call[0] == "resume" for call in api.calls)
    assert owner.snapshot.state is JobState.FAILED
    assert owner.snapshot.cleanup is not CleanupObservation.CONFIRMED


@pytest.mark.parametrize("step", ["create_job", "configure_job", "create_process", "is_in_job"])
def test_start_failure_never_resumes_and_closes_partial_resources(step):
    api = FakeApi()
    if step == "create_job":
        api.create_job = Mock(side_effect=WindowsResourceError("create failed"))
    elif step == "configure_job":
        api.configure_job = Mock(side_effect=WindowsResourceError("configure failed"))
    elif step == "create_process":
        api.create_suspended_process = Mock(side_effect=WindowsResourceError("process failed"))
    else:
        api.is_process_in_job = Mock(return_value=False)
    owner = WindowsJob(api)
    with pytest.raises(WindowsResourceError):
        owner.start(("worker.exe",), remaining_timeout_ms=50)
    assert not any(call[0] == "resume" for call in api.calls)
    if step != "create_job":
        assert any(call[0] == "close" for call in api.calls)
    assert owner.snapshot.cleanup is not CleanupObservation.CONFIRMED


def test_in_job_verification_failure_is_not_downgraded_to_unmanaged_process():
    api = FakeApi()
    api.in_job = False
    owner = WindowsJob(api)
    with pytest.raises(WindowsResourceError):
        owner.start(("worker.exe",), remaining_timeout_ms=50)
    assert not any(call[0] == "resume" for call in api.calls)
    assert owner.snapshot.state is JobState.FAILED


@pytest.mark.parametrize(
    "result,expected",
    [
        (WAIT_OBJECT_0, CreationState.PROCESS_EXITED),
        (WAIT_TIMEOUT, CreationState.PROCESS_SUSPENDED),
        (WAIT_FAILED, CreationState.PROCESS_SUSPENDED),
    ],
)
def test_wait_distinguishes_exit_timeout_and_failure(result, expected):
    owner, api, _ = started()
    owner.authorize_resume()
    api.wait_result = result
    observation = owner.wait(125)
    assert observation.state is expected
    if result == WAIT_OBJECT_0:
        assert observation.exit_code == 0


def test_wait_requires_finite_nonnegative_integer_timeout():
    owner, _, _ = started()
    for value in (-1, True, 1.5, None):
        with pytest.raises((TypeError, ValueError)):
            owner.wait(value)


def test_job_zero_does_not_confirm_cleanup_without_process_exit():
    owner, api, _ = started()
    api.active = 0
    owner.observe_job_empty()
    assert owner.snapshot.creation is not CreationState.JOB_EMPTY
    assert owner.snapshot.cleanup is CleanupObservation.PENDING
    assert owner.snapshot.state is JobState.ASSOCIATED


def test_job_zero_after_exit_is_observed_but_close_is_separate():
    owner, api, _ = started()
    owner.authorize_resume()
    api.wait_result = WAIT_OBJECT_0
    owner.wait(500)
    api.active = 0
    owner.observe_job_empty()
    assert owner.snapshot.creation is CreationState.JOB_EMPTY
    assert owner.snapshot.cleanup is CleanupObservation.PENDING
    owner.close()
    assert owner.snapshot.cleanup is CleanupObservation.CONFIRMED
    assert owner.snapshot.state is JobState.CLOSED


def test_terminate_request_does_not_claim_exit_or_cleanup():
    owner, api, _ = started()
    assert owner.terminate()
    assert owner.snapshot.creation is CreationState.PROCESS_SUSPENDED
    assert owner.snapshot.cleanup is CleanupObservation.PENDING
    assert ("terminate", 11) in api.calls


def test_terminate_failure_is_explicit():
    owner, api, _ = started()
    api.terminate_result = False
    assert not owner.terminate()
    assert owner.snapshot.cleanup is CleanupObservation.UNCONFIRMED


def test_close_failure_is_unconfirmed_and_retry_does_not_reclose_successful_handles():
    owner, api, _ = started()
    owner.authorize_resume()
    api.wait_result = WAIT_OBJECT_0
    owner.wait(100)
    api.active = 0
    owner.observe_job_empty()
    api.close_results[22] = False
    with pytest.raises(WindowsResourceError):
        owner.close()
    first_close_count = [call[1] for call in api.calls if call[0] == "close"].count(21)
    assert owner.snapshot.cleanup is CleanupObservation.UNCONFIRMED
    api.close_results[22] = True
    owner.close()
    second_close_count = [call[1] for call in api.calls if call[0] == "close"].count(21)
    assert first_close_count == second_close_count == 1
    assert owner.snapshot.cleanup is CleanupObservation.CONFIRMED


def test_close_does_not_confirm_when_exit_or_job_observation_is_missing():
    owner, _, _ = started()
    with pytest.raises(WindowsResourceError):
        owner.close()
    assert owner.snapshot.cleanup is CleanupObservation.UNCONFIRMED


def test_original_base_exception_is_not_replaced_by_cleanup_failure():
    api = FakeApi()
    api.create_suspended_process = Mock(side_effect=KeyboardInterrupt("original"))
    api.close_handle = Mock(side_effect=RuntimeError("cleanup detail"))
    owner = WindowsJob(api)
    with pytest.raises(KeyboardInterrupt, match="original"):
        owner.start(("worker.exe",), remaining_timeout_ms=1)
    assert owner.snapshot.cleanup is CleanupObservation.UNCONFIRMED


def test_snapshot_is_detached_and_read_only():
    owner, _, snapshot = started()
    assert snapshot is not owner.snapshot
    with pytest.raises(AttributeError):
        snapshot.process_handle = 99


def test_repeated_close_after_confirmation_is_idempotent():
    owner, api, _ = started()
    owner.authorize_resume()
    api.wait_result = WAIT_OBJECT_0
    owner.wait(1)
    api.active = 0
    owner.observe_job_empty()
    owner.close()
    owner.close()
    handles = [call[1] for call in api.calls if call[0] == "close"]
    assert handles.count(21) == handles.count(22) == handles.count(11) == 1


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("DEVENV_DOCTOR_RUN_WINDOWS_JOB_INTEGRATION") != "1",
    reason="Explicit Windows Job integration opt-in is not enabled",
)
def test_explicit_windows_job_smoke():
    owner = WindowsJob()
    try:
        owner.start(
            (sys.executable, "-c", "import time; time.sleep(0.1)"), remaining_timeout_ms=1000
        )
        assert owner.snapshot.association_verified
        owner.authorize_resume()
        assert owner.wait(2000).state is CreationState.PROCESS_EXITED
        owner.observe_job_empty()
        owner.close()
        assert owner.snapshot.cleanup is CleanupObservation.CONFIRMED
    finally:
        if owner.snapshot.cleanup is not CleanupObservation.CONFIRMED and owner.snapshot.job_handle:
            owner.terminate()
