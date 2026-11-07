import os
import sys
from datetime import datetime
from unittest.mock import Mock

import pytest

from dev_env_doctor.core import scan_worker_entry
from dev_env_doctor.core.models import DiagnosticResult, ScanMetadata, ScanReport, Severity
from dev_env_doctor.core.scan_ipc import FramedTransport, IpcState, PipePair
from dev_env_doctor.core.scan_protocol import decode_frame, encode_message
from dev_env_doctor.core.scan_worker import WorkerSession, WorkerState
from dev_env_doctor.core.windows_job import (
    CleanupObservation,
    CreationState,
    JobSnapshot,
    JobState,
    WindowsJob,
)
from dev_env_doctor.core.worker_task import WorkerTaskMode


class FakeJob:
    def __init__(self):
        self.calls = []
        self.snapshot = JobSnapshot(
            state=JobState.CLOSED,
            creation=CreationState.JOB_EMPTY,
            cleanup=CleanupObservation.CONFIRMED,
            resume_authorized=True,
            association_verified=True,
            process_exit_confirmed=True,
            exit_code=0,
            job_active_processes=0,
            process_handle=None,
            thread_handle=None,
            job_handle=None,
        )

    def start(self, command, *, remaining_timeout_ms, inherited_handles=()):
        self.calls.append(("start", tuple(command), remaining_timeout_ms, tuple(inherited_handles)))
        return self.snapshot

    def authorize_resume(self):
        self.calls.append(("resume",))
        return self.snapshot

    def wait(self, timeout_ms):
        self.calls.append(("wait", timeout_ms))
        return Mock()

    def observe_job_empty(self):
        self.calls.append(("job_empty",))
        return self.snapshot

    def terminate(self):
        self.calls.append(("terminate",))
        return True

    def close(self):
        self.calls.append(("close",))
        return self.snapshot


class FakeTransport:
    def __init__(self, incoming=(), send_error=None):
        self.incoming = list(incoming)
        self.sent = []
        self.closed = False
        self.send_error = send_error
        self.receive_timeouts = []

    def send(self, frame):
        if self.send_error is not None:
            raise self.send_error
        self.sent.append(frame)

    def receive(self, timeout_ms=None):
        self.receive_timeouts.append(timeout_ms)
        if not self.incoming:
            raise RuntimeError("no frame")
        return self.incoming.pop(0)

    def close(self):
        self.closed = True
        return None


def test_worker_requires_supervised_start_and_does_not_run_scan():
    job = FakeJob()
    transport = FakeTransport()
    worker = WorkerSession(job=job, transport=transport)
    assert worker.state is WorkerState.IDLE
    with pytest.raises(ValueError):
        worker.send_start(1)
    assert not any(call[0] == "resume" for call in job.calls)


def test_worker_start_uses_inherited_endpoint_and_explicit_resume():
    job = FakeJob()
    transport = FakeTransport()
    worker = WorkerSession(job=job, transport=transport, child_handle=99)
    worker.start(("fixed-worker",), remaining_timeout_ms=500)
    assert job.calls[0] == ("start", ("fixed-worker",), 500, (99,))
    assert job.calls[1][0] == "resume"
    assert worker.state is WorkerState.WAITING_READY


def test_worker_transport_failure_is_terminal_and_cleanup_is_attempted():
    job = FakeJob()
    transport = FakeTransport()
    transport.receive = Mock(side_effect=RuntimeError("secret path"))
    worker = WorkerSession(job=job, transport=transport)
    worker.start(("fixed-worker",), remaining_timeout_ms=500)
    with pytest.raises(RuntimeError):
        worker.wait_ready()
    assert worker.state is WorkerState.FAILED
    worker.close()
    assert ("close",) in job.calls


def test_worker_never_reports_success_from_ready_or_start_alone():
    worker = WorkerSession(job=FakeJob(), transport=FakeTransport())
    worker.start(("fixed-worker",), remaining_timeout_ms=500)
    assert worker.result is None
    assert worker.state is WorkerState.WAITING_READY


def _entry_frame(session_id, sequence, kind, payload):
    return encode_message(
        {
            "version": 1,
            "session_id": session_id,
            "sequence": sequence,
            "type": kind,
            "payload": payload,
        }
    )


def _entry_report():
    return ScanReport(
        metadata=ScanMetadata(
            scan_time=datetime.fromisoformat("2026-01-01T00:00:00+00:00"),
            app_version="0.1.0-test",
            platform="Windows-test",
            python_version="3.13.0-test",
        ),
        diagnostics=[
            DiagnosticResult(
                rule_id="COMMAND_VERSION",
                title="python version",
                severity=Severity.INFO,
                summary="Version checked.",
                evidence=["Verified version: 3.13.9"],
                status="passed",
            )
        ],
    )


def _run_entry_with_fake_transport(monkeypatch, incoming, runner_result=None, runner_error=None):
    session_id = "d" * 32
    transport = FakeTransport(incoming)
    monkeypatch.setattr(
        scan_worker_entry.PipeEndpoint,
        "from_inherited_handles",
        classmethod(lambda cls, read_handle, write_handle: object()),
    )
    monkeypatch.setattr(scan_worker_entry, "FramedTransport", lambda endpoint: transport)
    if runner_error is not None:
        monkeypatch.setattr(scan_worker_entry.runner, "run_scan", Mock(side_effect=runner_error))
    else:
        monkeypatch.setattr(scan_worker_entry.runner, "run_scan", Mock(return_value=runner_result))
    return session_id, transport


def test_worker_entry_does_not_scan_before_valid_start(monkeypatch):
    session_id, transport = _run_entry_with_fake_transport(
        monkeypatch,
        [_entry_frame(session_id := "d" * 32, 0, "STOP", {"reason": "user_request"})],
        runner_result=_entry_report(),
    )
    assert scan_worker_entry.run_worker(session_id, 1, 2) == 5
    scan_worker_entry.runner.run_scan.assert_not_called()
    assert len(transport.sent) == 1


def test_worker_entry_runs_once_and_naturally_exits_after_candidate(monkeypatch):
    session_id = "d" * 32
    start = _entry_frame(session_id, 0, "START", {"deadline": 110.0})
    session_id, transport = _run_entry_with_fake_transport(
        monkeypatch, [start], runner_result=_entry_report()
    )
    probe = Mock(side_effect=AssertionError("FULL_SCAN must not call the environment probe"))
    monkeypatch.setattr(scan_worker_entry, "run_probe", probe)
    result = scan_worker_entry.run_worker(session_id, 1, 2)
    assert result == 0
    messages = [decode_frame(frame) for frame in transport.sent]
    assert [item["type"] for item in messages] == ["READY", "RESULT_CANDIDATE"]
    report = messages[1]["payload"]["report"]
    assert report["schema_version"] == "1.0"
    assert report["metadata"] == {
        "scan_time": "2026-01-01T00:00:00+00:00",
        "app_version": "0.1.0-test",
        "platform": "Windows-test",
        "python_version": "3.13.0-test",
    }
    assert report["diagnostics"][0]["rule_id"] == "COMMAND_VERSION"
    scan_worker_entry.runner.run_scan.assert_called_once_with()
    probe.assert_not_called()


def test_probe_mode_does_not_call_full_scan(monkeypatch):
    session_id = "d" * 32
    start = _entry_frame(session_id, 0, "START", {"deadline": 1.0})
    session_id, transport = _run_entry_with_fake_transport(
        monkeypatch, [start], runner_result=_entry_report()
    )
    monkeypatch.setattr(scan_worker_entry, "run_probe", Mock(return_value=_entry_report()))
    result = scan_worker_entry.run_worker(session_id, 1, 2, mode=WorkerTaskMode.ENVIRONMENT_PROBE)

    assert result == scan_worker_entry.WorkerExitCode.SUCCESS
    scan_worker_entry.run_probe.assert_called_once_with()
    scan_worker_entry.runner.run_scan.assert_not_called()


@pytest.mark.parametrize("value", ["", "C:\\合成\\工具;D:\\Example"])
def test_worker_dispatches_explicit_snapshot_and_never_echoes_it(monkeypatch, value):
    session = "d" * 32
    payload = {"deadline": 100.5, "diagnostic_input": {"kind": "path_snapshot_v1", "value": value}}
    _, transport = _run_entry_with_fake_transport(
        monkeypatch, [_entry_frame(session, 0, "START", payload)], runner_result=_entry_report()
    )
    result = scan_worker_entry.run_worker(session, 1, 2, require_path_snapshot=True)

    assert result == scan_worker_entry.WorkerExitCode.SUCCESS
    scan_worker_entry.runner.run_scan.assert_called_once_with(path_snapshot=value)
    assert decode_frame(transport.sent[1])["type"] == "RESULT_CANDIDATE"
    assert "工具" not in transport.sent[1].decode("utf-8", errors="ignore")
    assert transport.closed


@pytest.mark.parametrize(
    ("mode", "required", "extension"),
    [
        (WorkerTaskMode.FULL_SCAN, True, False),
        (WorkerTaskMode.FULL_SCAN, False, True),
        (WorkerTaskMode.ENVIRONMENT_PROBE, False, True),
        (WorkerTaskMode.ENVIRONMENT_PROBE, True, True),
    ],
)
def test_worker_refuses_mismatched_start_without_fallback(monkeypatch, mode, required, extension):
    session = "d" * 32
    payload = {"deadline": 100.5}
    if extension:
        payload["diagnostic_input"] = {"kind": "path_snapshot_v1", "value": ""}
    _, transport = _run_entry_with_fake_transport(
        monkeypatch, [_entry_frame(session, 0, "START", payload)]
    )
    probe = Mock()
    monkeypatch.setattr(scan_worker_entry, "run_probe", probe)

    result = scan_worker_entry.run_worker(session, 1, 2, mode, require_path_snapshot=required)

    assert result == scan_worker_entry.WorkerExitCode.STARTUP_FAILED
    scan_worker_entry.runner.run_scan.assert_not_called()
    probe.assert_not_called()
    assert [decode_frame(item)["type"] for item in transport.sent] == ["READY"]
    assert transport.closed


@pytest.mark.parametrize(
    ("old", "new"),
    [(b'"version":1', b'"version":2'), (b"path_snapshot_v1", b"path_snapshot_v2")],
)
def test_worker_rejects_incompatible_wire_versions_before_running(monkeypatch, old, new):
    session = "d" * 32
    payload = {"deadline": 10, "diagnostic_input": {"kind": "path_snapshot_v1", "value": ""}}
    start = _entry_frame(session, 0, "START", payload).replace(old, new)
    _, transport = _run_entry_with_fake_transport(monkeypatch, [start])
    assert (
        scan_worker_entry.run_worker(session, 1, 2, require_path_snapshot=True)
        == scan_worker_entry.WorkerExitCode.STARTUP_FAILED
    )
    scan_worker_entry.runner.run_scan.assert_not_called()
    assert transport.closed


def test_worker_entry_scan_failure_sends_fixed_failed_code_without_exception_text(monkeypatch):
    session_id = "d" * 32
    start = _entry_frame(session_id, 0, "START", {"deadline": 110.0})
    session_id, transport = _run_entry_with_fake_transport(
        monkeypatch,
        [start],
        runner_error=RuntimeError("C:\\Users\\Secret\\traceback"),
    )
    assert scan_worker_entry.run_worker(session_id, 1, 2) == 1
    messages = [decode_frame(frame) for frame in transport.sent]
    assert [item["type"] for item in messages] == ["READY", "FAILED"]
    assert messages[1]["payload"] == {"code": "SCAN_FAILED"}
    assert b"Secret" not in transport.sent[-1]


def test_worker_entry_report_conversion_failure_sends_failed(monkeypatch):
    session_id = "d" * 32
    start = _entry_frame(session_id, 0, "START", {"deadline": 110.0})
    session_id, transport = _run_entry_with_fake_transport(
        monkeypatch, [start], runner_result=_entry_report()
    )
    monkeypatch.setattr(
        scan_worker_entry, "_candidate_payload", Mock(side_effect=ValueError("secret"))
    )
    assert scan_worker_entry.run_worker(session_id, 1, 2) == 2
    messages = [decode_frame(frame) for frame in transport.sent]
    assert messages[-1]["type"] == "FAILED"
    assert messages[-1]["payload"] == {"code": "SCAN_FAILED"}


def test_worker_entry_candidate_send_failure_has_distinct_exit_reason(monkeypatch):
    session_id = "d" * 32
    start = _entry_frame(session_id, 0, "START", {"deadline": 110.0})
    send_error = RuntimeError("private send failure")
    session_id, transport = _run_entry_with_fake_transport(
        monkeypatch, [start], runner_result=_entry_report()
    )
    transport.send_error = None
    original_send = transport.send
    send_count = 0

    def send(frame):
        nonlocal send_count
        send_count += 1
        if send_count == 1:
            return original_send(frame)
        raise send_error

    transport.send = send
    assert scan_worker_entry.run_worker(session_id, 1, 2) == 3
    messages = [decode_frame(frame) for frame in transport.sent]
    assert [item["type"] for item in messages] == ["READY"]
    assert "private" not in repr(messages)


def test_worker_entry_failed_message_send_has_distinct_exit_reason(monkeypatch):
    session_id = "d" * 32
    start = _entry_frame(session_id, 0, "START", {"deadline": 110.0})
    session_id, transport = _run_entry_with_fake_transport(
        monkeypatch,
        [start],
        runner_error=RuntimeError("private scan failure"),
    )
    transport.send_error = None
    original_send = transport.send
    send_count = 0

    def send(frame):
        nonlocal send_count
        send_count += 1
        if send_count == 1:
            return original_send(frame)
        raise RuntimeError("private failed send")

    transport.send = send
    assert scan_worker_entry.run_worker(session_id, 1, 2) == 4
    assert len(transport.sent) == 1


def test_worker_entry_repeated_start_does_not_run_second_scan(monkeypatch):
    session_id = "d" * 32
    start = _entry_frame(session_id, 0, "START", {"deadline": 110.0})
    repeated = _entry_frame(session_id, 1, "START", {"deadline": 110.0})
    session_id, transport = _run_entry_with_fake_transport(
        monkeypatch, [start, repeated], runner_result=_entry_report()
    )
    assert scan_worker_entry.run_worker(session_id, 1, 2) == 0
    scan_worker_entry.runner.run_scan.assert_called_once_with()
    assert len(transport.sent) == 2


class _StartInterruptJob(FakeJob):
    def __init__(self, error):
        super().__init__()
        self.error = error

    def start(self, command, *, remaining_timeout_ms, inherited_handles=()):
        self.calls.append(("start", tuple(command), remaining_timeout_ms, tuple(inherited_handles)))
        raise self.error


class _ResumeInterruptJob(FakeJob):
    def authorize_resume(self):
        self.calls.append(("resume",))
        raise SystemExit("resume interruption")


class _CloseResultJob(FakeJob):
    def __init__(self, result):
        super().__init__()
        self.snapshot = result


class _ClosedTransport(FakeTransport):
    def close(self):
        self.closed = True
        return IpcState.CLOSED


class _InterruptingTransport(FakeTransport):
    def __init__(self, error):
        super().__init__()
        self.error = error

    def close(self):
        self.closed = True
        raise self.error


class _ErrorTransport(FakeTransport):
    def __init__(self, error):
        super().__init__()
        self.error = error

    def close(self):
        self.closed = True
        raise self.error


class _ErrorCloseJob(FakeJob):
    def __init__(self, error):
        super().__init__()
        self.error = error

    def close(self):
        self.calls.append(("close",))
        raise self.error


def test_worker_start_base_exception_attempts_job_cleanup_and_preserves_identity():
    error = KeyboardInterrupt()
    job = _StartInterruptJob(error)
    worker = WorkerSession(job=job, transport=FakeTransport())
    with pytest.raises(KeyboardInterrupt) as raised:
        worker.start(("fixed-worker",), remaining_timeout_ms=500)

    assert raised.value is error
    assert worker.state is WorkerState.FAILED
    assert ("close",) in job.calls


def test_worker_authorize_base_exception_attempts_cleanup():
    job = _ResumeInterruptJob()
    worker = WorkerSession(job=job, transport=FakeTransport())
    with pytest.raises(SystemExit):
        worker.start(("fixed-worker",), remaining_timeout_ms=500)

    assert worker.state is WorkerState.FAILED
    assert ("close",) in job.calls


def test_worker_transport_base_exception_still_closes_job_and_preserves_identity():
    error = KeyboardInterrupt()
    job = FakeJob()
    worker = WorkerSession(job=job, transport=_InterruptingTransport(error))
    with pytest.raises(KeyboardInterrupt) as raised:
        worker.close()

    assert raised.value is error
    assert ("close",) in job.calls
    assert worker.state is WorkerState.FAILED


@pytest.mark.parametrize(
    "snapshot",
    [
        JobSnapshot(
            state=JobState.UNCONFIRMED,
            creation=CreationState.JOB_EMPTY,
            cleanup=CleanupObservation.UNCONFIRMED,
            resume_authorized=True,
            association_verified=True,
            process_exit_confirmed=True,
            exit_code=0,
            job_active_processes=0,
            process_handle=None,
            thread_handle=None,
            job_handle=None,
        ),
        object(),
    ],
)
def test_worker_close_requires_confirmed_job_snapshot(snapshot):
    job = _CloseResultJob(snapshot)
    worker = WorkerSession(job=job, transport=_ClosedTransport())
    worker.close()
    assert worker.state is WorkerState.FAILED


def test_worker_close_requires_confirmed_transport_and_job():
    worker = WorkerSession(job=FakeJob(), transport=FakeTransport())
    worker.close()
    assert worker.state is WorkerState.FAILED


def test_worker_close_continues_after_transport_exception_and_preserves_job_base_exception():
    transport_error = RuntimeError("transport")
    job_error = KeyboardInterrupt()
    job = _ErrorCloseJob(job_error)
    worker = WorkerSession(job=job, transport=_ErrorTransport(transport_error))
    with pytest.raises(KeyboardInterrupt) as raised:
        worker.close()

    assert raised.value is job_error
    assert ("close",) in job.calls
    assert worker.state is WorkerState.FAILED


def test_worker_close_preserves_first_base_exception_and_attempts_job_cleanup():
    transport_error = KeyboardInterrupt()
    job_error = SystemExit()
    job = _ErrorCloseJob(job_error)
    worker = WorkerSession(job=job, transport=_ErrorTransport(transport_error))
    with pytest.raises(KeyboardInterrupt) as raised:
        worker.close()

    assert raised.value is transport_error
    assert ("close",) in job.calls
    assert worker.state is WorkerState.FAILED


def test_worker_close_attempts_both_resources_when_both_raise_regular_errors():
    transport_error = OSError("transport close")
    job_error = ValueError("job close")
    job = _ErrorCloseJob(job_error)
    worker = WorkerSession(job=job, transport=_ErrorTransport(transport_error))
    worker.close()
    assert worker.state is WorkerState.FAILED
    assert ("close",) in job.calls


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("DEVENV_DOCTOR_RUN_WINDOWS_JOB_INTEGRATION") != "1",
    reason="Explicit Windows IPC integration opt-in is not enabled",
)
def test_windows_ipc_end_to_end():
    session_id = "c" * 32
    pair = PipePair.create()
    worker = WorkerSession(
        job=WindowsJob(),
        transport=FramedTransport(pair.parent),
        child_handles=pair.child_handles,
        close_child_copies=pair.close_child_copies,
        session_id=session_id,
    )
    try:
        worker.start(
            (
                sys.executable,
                "-m",
                "dev_env_doctor.core.scan_worker_entry",
                "--session",
                session_id,
                "--read-handle",
                str(pair.child_handles[0]),
                "--write-handle",
                str(pair.child_handles[1]),
            ),
            remaining_timeout_ms=2000,
        )
        worker.wait_ready()
        worker.send_start(10**6)
        worker.send_stop("window_close")
        worker.receive_stop_observed()
        assert worker._job.wait(3000).exit_code == 0
        worker._job.observe_job_empty()
        worker.close()
        assert worker.state is WorkerState.CLOSED
    finally:
        pair.parent.close()
