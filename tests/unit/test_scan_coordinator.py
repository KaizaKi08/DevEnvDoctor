import json
import struct
import sys
from dataclasses import replace
from datetime import datetime
from unittest.mock import Mock

import pytest

from dev_env_doctor.core import scan_coordinator as coordinator_module
from dev_env_doctor.core.models import DiagnosticResult, ScanMetadata, ScanReport
from dev_env_doctor.core.scan_control import ScanDeadline, StopReason
from dev_env_doctor.core.scan_coordinator import (
    CoordinatorState,
    DiagnosticResourceStatus,
    DiagnosticStage,
    ScanCoordinator,
)
from dev_env_doctor.core.scan_ipc import IpcError, IpcState
from dev_env_doctor.core.scan_protocol import ProtocolError, decode_frame, encode_message
from dev_env_doctor.core.scan_supervisor import EvidenceStatus
from dev_env_doctor.core.windows_job import (
    CleanupObservation,
    CreationState,
    JobSnapshot,
    JobState,
    WaitObservation,
)
from dev_env_doctor.core.worker_task import WorkerTaskMode

SESSION = "a" * 32


class Clock:
    def __init__(self, value=100.0):
        self.value = value

    def __call__(self):
        return self.value


def frame(kind, sequence, *, sender, payload=None):
    payload = {} if payload is None else payload
    if kind == "RESULT_CANDIDATE" and "diagnostics" in payload:
        payload = {
            "report": {
                "schema_version": "1.0",
                "metadata": {
                    "scan_time": "2026-01-01T00:00:00+00:00",
                    "app_version": "0.1.0",
                    "platform": "Windows",
                    "python_version": "3.13.0",
                },
                "diagnostics": payload["diagnostics"],
            }
        }
    return encode_message(
        {
            "version": 1,
            "session_id": SESSION,
            "sequence": sequence,
            "type": kind,
            "payload": payload,
        }
    )


def confirmed_snapshot(*, cleanup=CleanupObservation.CONFIRMED, active=0, exit_code=0):
    return JobSnapshot(
        state=JobState.CLOSED if cleanup is CleanupObservation.CONFIRMED else JobState.UNCONFIRMED,
        creation=CreationState.JOB_EMPTY,
        cleanup=cleanup,
        resume_authorized=True,
        association_verified=True,
        process_exit_confirmed=True,
        exit_code=exit_code,
        job_active_processes=active,
        process_handle=None,
        thread_handle=None,
        job_handle=None,
    )


class FakePipe:
    def __init__(self, *, close_result=True, close_error=None):
        self.parent = object()
        self.child_handles = (41, 42)
        self.child_copies_closed = 0
        self.close_result = close_result
        self.close_error = close_error

    def close_child_copies(self):
        self.child_copies_closed += 1
        if self.close_error is not None:
            raise self.close_error
        return self.close_result


class FakeTransport:
    def __init__(self, incoming=(), *, close_state=IpcState.CLOSED, send_error=None):
        self.incoming = list(incoming)
        self.sent = []
        self.close_state = close_state
        self.send_error = send_error
        self.closed = False
        self.state = IpcState.OPEN
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
        self.state = self.close_state
        return self.close_state


class FakeJob:
    def __init__(
        self, *, start_error=None, resume_error=None, wait_observation=None, snapshot=None
    ):
        self.calls = []
        self.start_error = start_error
        self.resume_error = resume_error
        self.wait_observation = wait_observation or WaitObservation(CreationState.PROCESS_EXITED, 0)
        self._snapshot = snapshot or confirmed_snapshot()

    @property
    def snapshot(self):
        return self._snapshot

    def start(self, command, *, remaining_timeout_ms, inherited_handles=(), environment=None):
        self.calls.append(
            ("start", tuple(command), remaining_timeout_ms, tuple(inherited_handles), environment)
        )
        if self.start_error is not None:
            raise self.start_error
        return self._snapshot

    def authorize_resume(self):
        self.calls.append(("resume",))
        if self.resume_error is not None:
            raise self.resume_error
        return self._snapshot

    def wait(self, timeout_ms):
        self.calls.append(("wait", timeout_ms))
        return self.wait_observation

    def observe_job_empty(self):
        self.calls.append(("job_empty",))
        return self._snapshot

    def close(self):
        self.calls.append(("close",))
        return self._snapshot


def make_coordinator(*, clock=None, transport=None, job=None, pipe=None):
    clock = clock or Clock()
    pipe = pipe or FakePipe()
    transport = transport or FakeTransport(
        [
            frame("READY", 0, sender="child"),
            frame("STOP_OBSERVED", 1, sender="child", payload={"reason": "user_request"}),
        ]
    )
    job = job or FakeJob()
    coordinator = ScanCoordinator(
        SESSION,
        ScanDeadline(10, clock=clock),
        pipe_factory=lambda: pipe,
        job_factory=lambda: job,
        transport_factory=lambda _endpoint: transport,
    )
    return coordinator, clock, pipe, transport, job


def start_ready():
    coordinator, clock, pipe, transport, job = make_coordinator()
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    decision = coordinator.wait_ready()
    return coordinator, clock, pipe, transport, job, decision


def test_start_order_and_resource_ownership(monkeypatch):
    environment = {"SystemRoot": r"C:\Windows", "PATH": r"C:\Windows\System32"}
    monkeypatch.setattr(coordinator_module, "build_worker_environment", lambda: environment)
    coordinator, _, pipe, _, job = make_coordinator()
    decision = coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    assert decision.facts.worker_started is EvidenceStatus.CONFIRMED
    assert decision.facts.resources.creation_finished is EvidenceStatus.CONFIRMED
    assert [call[0] for call in job.calls] == ["start", "resume"]
    assert job.calls[0][4] is environment
    assert pipe.child_copies_closed == 1
    assert coordinator.child_copies_confirmed
    assert coordinator.state is CoordinatorState.STARTING


def test_diagnostic_resource_status_distinguishes_unstarted_from_unobserved():
    coordinator, _clock, _pipe, _transport, _job = make_coordinator()

    before_start = coordinator.diagnostic_snapshot(stage=DiagnosticStage.COORDINATOR_CREATED)
    assert before_start.ipc_status is DiagnosticResourceStatus.NOT_STARTED
    assert before_start.parent_resources is DiagnosticResourceStatus.NOT_STARTED

    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    after_start = coordinator.diagnostic_snapshot(stage=DiagnosticStage.STARTING_WORKER)
    assert after_start.ipc_status is DiagnosticResourceStatus.NOT_OBSERVED
    assert after_start.parent_resources is DiagnosticResourceStatus.NOT_OBSERVED


def test_default_worker_command_uses_python_module_in_source_mode(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    coordinator, _, _, _, job = make_coordinator()

    coordinator.start(remaining_timeout_ms=500)

    command = next(call[1] for call in job.calls if call[0] == "start")
    assert command[:3] == (
        sys.executable,
        "-m",
        "dev_env_doctor.core.scan_worker_entry",
    )
    assert command[3:] == (
        "--session",
        SESSION,
        "--read-handle",
        "41",
        "--write-handle",
        "42",
        "--mode",
        "full_scan",
    )


@pytest.mark.parametrize("snapshot", ["", r"C:\Synthetic-3AB1\bin"])
def test_modern_start_keeps_snapshot_out_of_command_environment_and_observer(snapshot):
    coordinator, _, _, transport, job = make_coordinator()
    events = []
    coordinator.set_diagnostic_observer(events.append)

    coordinator.start(remaining_timeout_ms=500, require_path_snapshot=True)
    assert coordinator.wait_ready().facts.ready
    decision = coordinator.send_start(path_snapshot=snapshot)

    assert decision.facts.start_authorized and not decision.result_available
    start = next(item for item in job.calls if item[0] == "start")
    assert start[1][-1] == "--require-path-snapshot"
    assert start[1][-3:-1] == ("--mode", "full_scan")
    assert "3AB1" not in repr(start)
    assert start[4] == coordinator_module.build_worker_environment()
    assert decode_frame(transport.sent[0])["payload"] == {
        "deadline": coordinator.supervisor.deadline.expires_at,
        "diagnostic_input": {"kind": "path_snapshot_v1", "value": snapshot},
    }
    assert "3AB1" not in repr(events)
    assert coordinator._owned.observed_transport._sent == []


def test_modern_coordinator_missing_snapshot_rejects_start():
    coordinator, _, _, transport, job = make_coordinator()
    coordinator.start(remaining_timeout_ms=500, require_path_snapshot=True)
    assert coordinator.wait_ready().facts.ready

    with pytest.raises(ProtocolError):
        coordinator.send_start()

    assert coordinator.decision.facts.protocol_error
    assert not coordinator.decision.facts.start_authorized
    assert transport.sent == []
    assert transport.closed and ("close",) in job.calls


def test_observing_transport_releases_frames_even_if_close_fails():
    raw_transport = FakeTransport([b"synthetic-received"])
    observer = coordinator_module._ObservingTransport(raw_transport)
    observer.send(b"synthetic-start-canary")
    observer.receive()
    raw_transport.close = Mock(side_effect=OSError("synthetic close failure"))

    with pytest.raises(OSError):
        observer.close()
    assert observer._sent == [] and observer._received == []


def test_default_worker_command_uses_sibling_exe_when_frozen(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        coordinator_module.sys,
        "executable",
        r"C:\Program Files\DevEnv Doctor\DevEnvDoctor.exe",
    )
    monkeypatch.setattr(coordinator_module, "_local_directory_state", lambda _path: True)
    monkeypatch.setattr(coordinator_module, "_candidate_is_regular_file", lambda _path: True)
    coordinator, _, _, _, job = make_coordinator()

    coordinator.start(remaining_timeout_ms=500)

    command = next(call[1] for call in job.calls if call[0] == "start")
    assert command[0] == r"C:\Program Files\DevEnv Doctor\DevEnvDoctorWorker.exe"
    assert "-m" not in command
    assert command[1:] == (
        "--session",
        SESSION,
        "--read-handle",
        "41",
        "--write-handle",
        "42",
        "--mode",
        "full_scan",
    )


def test_frozen_worker_missing_does_not_fallback_to_python_module(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        coordinator_module.sys,
        "executable",
        r"C:\Program Files\DevEnv Doctor\DevEnvDoctor.exe",
    )
    monkeypatch.setattr(coordinator_module, "_local_directory_state", lambda _path: True)
    monkeypatch.setattr(
        coordinator_module,
        "_candidate_is_regular_file",
        lambda path: not path.endswith("DevEnvDoctorWorker.exe"),
    )
    coordinator, _, _, _, job = make_coordinator()

    with pytest.raises(RuntimeError):
        coordinator.start(remaining_timeout_ms=500)

    start_calls = [call for call in job.calls if call[0] == "start"]
    assert start_calls == []
    assert ("close",) in job.calls
    assert coordinator.state is CoordinatorState.FAILED


def test_frozen_mode_rejects_custom_worker_command(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        coordinator_module.sys,
        "executable",
        r"C:\Program Files\DevEnv Doctor\DevEnvDoctor.exe",
    )
    coordinator, _, _, _, job = make_coordinator()

    with pytest.raises(RuntimeError):
        coordinator.start(("untrusted-worker.exe",), remaining_timeout_ms=500)

    assert [call for call in job.calls if call[0] == "start"] == []
    assert ("close",) in job.calls


@pytest.mark.parametrize("close_result", [False, None, object()])
def test_child_copy_close_nonconfirmed_blocks_resume(close_result):
    pipe = FakePipe(close_result=close_result)
    coordinator, _, _, _, job = make_coordinator(pipe=pipe)
    with pytest.raises(RuntimeError):
        coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    assert pipe.child_copies_closed == 1
    assert not coordinator.child_copies_confirmed
    assert not any(call[0] == "resume" for call in job.calls)


def test_child_copy_close_exception_propagates_and_triggers_cleanup():
    error = KeyboardInterrupt()
    pipe = FakePipe(close_error=error)
    coordinator, _, _, _, job = make_coordinator(pipe=pipe)
    with pytest.raises(KeyboardInterrupt) as raised:
        coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    assert raised.value is error
    assert ("close",) in job.calls
    assert coordinator.state is CoordinatorState.FAILED


def test_ready_enables_start_only_after_supervisor_observation():
    coordinator, _, _, _, _, decision = start_ready()
    assert decision.facts.ready
    assert decision.start_permitted
    decision = coordinator.send_start()
    assert decision.facts.start_authorized
    assert coordinator.state is CoordinatorState.RUNNING


def test_environment_probe_remains_subject_to_supervisor_ready_start(monkeypatch):
    marker = "DEVENV_DOCTOR_PROBE_UNICODE"
    env = {marker: "synthetic"}
    monkeypatch.setattr(
        coordinator_module,
        "build_worker_environment",
        lambda *, include_probe_marker: env if include_probe_marker else {},
    )
    coordinator, _, _, transport, job = make_coordinator()
    coordinator.start(
        ("fixed-worker",), remaining_timeout_ms=500, task_mode=WorkerTaskMode.ENVIRONMENT_PROBE
    )
    assert job.calls[0][4] == env
    assert not transport.sent
    assert coordinator.wait_ready().start_permitted
    assert coordinator.send_start().facts.start_authorized
    assert coordinator.state is CoordinatorState.RUNNING


def candidate_frame(sequence=1):
    return frame(
        "RESULT_CANDIDATE",
        sequence,
        sender="child",
        payload={
            "diagnostics": [
                {
                    "rule_id": "COMMAND_VERSION",
                    "title": "python version",
                    "summary": "Version checked.",
                    "severity": "info",
                    "status": "passed",
                    "suggestion": "",
                    "evidence": ["Verified version: 3.13.9"],
                }
            ]
        },
    )


def test_parent_validates_and_stages_candidate_without_success():
    transport = FakeTransport([frame("READY", 0, sender="child"), candidate_frame()])
    coordinator, _, _, _, _ = make_coordinator(transport=transport)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.wait_ready()
    coordinator.send_start()
    decision = coordinator.receive_worker_message()
    assert decision.facts.candidate_count == 1
    assert decision.facts.report_validation is EvidenceStatus.CONFIRMED
    assert decision.lifecycle.state.value == "finalizing"
    assert not decision.result_available
    assert coordinator.candidate_diagnostics is not None
    assert coordinator.candidate_report is not None
    assert coordinator.candidate_report["schema_version"] == "1.0"
    assert set(coordinator.candidate_report["metadata"]) == {
        "scan_time",
        "app_version",
        "platform",
        "python_version",
    }


def test_verified_candidate_report_reconstructs_without_metadata_defaults():
    transport = FakeTransport([frame("READY", 0, sender="child"), candidate_frame()])
    coordinator, _, _, _, _ = make_coordinator(transport=transport)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.wait_ready()
    coordinator.send_start()
    coordinator.receive_worker_message()
    candidate = coordinator.candidate_report
    assert candidate is not None
    metadata = candidate["metadata"]
    restored = ScanReport(
        schema_version=candidate["schema_version"],
        metadata=ScanMetadata(
            scan_time=datetime.fromisoformat(metadata["scan_time"]),
            app_version=metadata["app_version"],
            platform=metadata["platform"],
            python_version=metadata["python_version"],
        ),
        diagnostics=[DiagnosticResult(**item) for item in candidate["diagnostics"]],
    )
    assert restored.schema_version == candidate["schema_version"]
    assert restored.metadata.model_dump() == {
        **metadata,
        "scan_time": datetime.fromisoformat(metadata["scan_time"]),
    }
    assert [item.model_dump() for item in restored.diagnostics] == candidate["diagnostics"]


def test_complete_candidate_and_resource_evidence_enters_supervisor_success():
    transport = FakeTransport([frame("READY", 0, sender="child"), candidate_frame()])
    coordinator, _, _, _, _ = make_coordinator(transport=transport)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.wait_ready()
    coordinator.send_start()
    coordinator.receive_worker_message()
    coordinator.observe_process(100)
    coordinator.observe_job()
    coordinator.close_ipc()
    decision = coordinator.close_resources()
    assert decision.result_available
    assert decision.lifecycle.state.value == "succeeded"
    assert coordinator.supervisor.result == coordinator.candidate_diagnostics
    assert coordinator.result_report == coordinator.candidate_report


def test_parent_rejects_invalid_candidate_and_does_not_stage_it():
    body = json.dumps(
        {
            "version": 1,
            "session_id": SESSION,
            "sequence": 1,
            "type": "RESULT_CANDIDATE",
            "payload": {"diagnostics": [{"rule_id": "UNKNOWN", "bad": "value"}]},
        }
    ).encode()
    invalid = struct.pack("!I", len(body)) + body
    transport = FakeTransport([frame("READY", 0, sender="child"), invalid])
    coordinator, _, _, _, _ = make_coordinator(transport=transport)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.wait_ready()
    coordinator.send_start()
    with pytest.raises(Exception) as raised:
        coordinator.receive_worker_message()
    assert isinstance(raised.value, ValueError)
    assert coordinator.decision.facts.protocol_error
    assert coordinator.candidate_diagnostics is None


def test_parent_failed_message_cannot_become_candidate():
    failed = frame("FAILED", 1, sender="child", payload={"code": "SCAN_FAILED"})
    transport = FakeTransport([frame("READY", 0, sender="child"), failed])
    coordinator, _, _, _, _ = make_coordinator(transport=transport)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.wait_ready()
    coordinator.send_start()
    decision = coordinator.receive_worker_message()
    assert decision.facts.execution_failed
    assert coordinator.candidate_diagnostics is None
    assert not decision.result_available
    assert coordinator.diagnostic_failure_category == "WORKER_FAILED_MESSAGE"


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (
            IpcError("endpoint closed before a complete frame arrived."),
            "WORKER_MESSAGE_TRANSPORT_ERROR",
        ),
        (RuntimeError("private path and traceback"), "WORKER_MESSAGE_UNCLASSIFIED_ERROR"),
    ],
)
def test_receive_failure_uses_fixed_safe_category(error, expected):
    transport = FakeTransport([frame("READY", 0, sender="child")])
    original_receive = transport.receive
    receive_count = 0

    def receive():
        nonlocal receive_count
        receive_count += 1
        if receive_count == 1:
            return original_receive()
        raise error

    transport.receive = receive
    coordinator, _, _, _, _ = make_coordinator(transport=transport)
    events = []
    coordinator.set_diagnostic_observer(events.append)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.wait_ready()
    coordinator.send_start()
    with pytest.raises(type(error)):
        coordinator.receive_worker_message()
    assert coordinator.diagnostic_failure_category == expected
    assert all("private" not in repr(event) for event in events)


def test_receive_protocol_failure_has_distinct_category():
    body = b'{"invalid": true}'
    invalid = struct.pack("!I", len(body)) + body
    transport = FakeTransport([frame("READY", 0, sender="child"), invalid])
    coordinator, _, _, _, _ = make_coordinator(transport=transport)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.wait_ready()
    coordinator.send_start()
    with pytest.raises(ProtocolError):
        coordinator.receive_worker_message()
    assert coordinator.diagnostic_failure_category == "WORKER_MESSAGE_PROTOCOL_ERROR"


def test_receive_failure_keeps_nonblocking_worker_exit_evidence():
    transport = FakeTransport([frame("READY", 0, sender="child")])
    original_receive = transport.receive
    receive_count = 0

    def receive():
        nonlocal receive_count
        receive_count += 1
        if receive_count == 1:
            return original_receive()
        raise IpcError()

    transport.receive = receive
    job = FakeJob(wait_observation=WaitObservation(CreationState.PROCESS_EXITED, 3))
    coordinator, _, _, _, job = make_coordinator(transport=transport, job=job)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.wait_ready()
    coordinator.send_start()
    with pytest.raises(IpcError):
        coordinator.receive_worker_message()
    assert coordinator.decision.facts.resources.worker_exited is EvidenceStatus.CONFIRMED
    assert coordinator.decision.facts.resources.exit_code == 3
    assert (
        coordinator.diagnostic_snapshot(stage=DiagnosticStage.FAILED).worker_exit_reason
        == "WORKER_CANDIDATE_SEND_FAILED"
    )
    assert ("wait", 0) in job.calls


def test_diagnostic_observer_failure_does_not_replace_receive_error():
    transport = FakeTransport([frame("READY", 0, sender="child")])
    original_receive = transport.receive
    receive_count = 0

    def receive():
        nonlocal receive_count
        receive_count += 1
        if receive_count == 1:
            return original_receive()
        raise RuntimeError("private receive failure")

    transport.receive = receive
    coordinator, _, _, _, _ = make_coordinator(transport=transport)

    def observer(_event):
        raise ValueError("observer secret")

    coordinator.set_diagnostic_observer(observer)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.wait_ready()
    coordinator.send_start()
    with pytest.raises(RuntimeError, match="private receive failure"):
        coordinator.receive_worker_message()
    assert coordinator.diagnostic_failure_category == "WORKER_MESSAGE_UNCLASSIFIED_ERROR"
    assert coordinator.state is CoordinatorState.FAILED


def test_parent_duplicate_candidate_is_rejected_without_overwriting_staged_report():
    transport = FakeTransport(
        [frame("READY", 0, sender="child"), candidate_frame(), candidate_frame(2)]
    )
    coordinator, _, _, _, _ = make_coordinator(transport=transport)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.wait_ready()
    coordinator.send_start()
    coordinator.receive_worker_message()
    original = coordinator.candidate_diagnostics
    with pytest.raises(ValueError):
        coordinator.receive_worker_message()
    assert coordinator.decision.facts.protocol_error
    assert coordinator.candidate_diagnostics == original


def test_invalid_ready_is_recorded_as_protocol_failure_and_cannot_send_start():
    transport = FakeTransport([frame("START", 0, sender="child", payload={"deadline": 110.0})])
    coordinator, _, _, _, _ = make_coordinator(transport=transport)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    with pytest.raises(ProtocolError):
        coordinator.wait_ready()
    assert coordinator.decision.facts.protocol_error
    assert not coordinator.decision.start_permitted
    assert transport.sent == []


def test_job_creation_failure_does_not_resume():
    job = FakeJob(start_error=RuntimeError("job"))
    coordinator, _, _, _, job = make_coordinator(job=job)
    with pytest.raises(RuntimeError):
        coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    assert not any(call[0] == "resume" for call in job.calls)
    assert coordinator.state is CoordinatorState.FAILED


def test_association_failure_is_not_recovered_as_running():
    job = FakeJob(start_error=RuntimeError("association"))
    coordinator, _, _, _, _ = make_coordinator(job=job)
    with pytest.raises(RuntimeError):
        coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    assert coordinator.decision.result_available is False


def test_resume_failure_attempts_cleanup():
    job = FakeJob(resume_error=RuntimeError("resume"))
    coordinator, _, _, _, job = make_coordinator(job=job)
    with pytest.raises(RuntimeError):
        coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    assert ("close",) in job.calls
    assert coordinator.state is CoordinatorState.FAILED


def test_ready_without_authorization_does_not_send_start_when_deadline_reached():
    coordinator, clock, _, transport, _, _ = start_ready()
    clock.value = 110.0
    decision = coordinator.send_start()
    assert not decision.start_permitted
    assert transport.sent == []


def test_stop_observed_is_not_process_exit():
    coordinator, _, _, _, job, _ = start_ready()
    coordinator.send_start()
    coordinator.request_stop(StopReason.USER_REQUEST)
    coordinator.send_stop(StopReason.USER_REQUEST)
    decision = coordinator.receive_stop_observed()
    assert decision.facts.stop_observed
    assert decision.facts.resources.worker_exited is EvidenceStatus.UNKNOWN
    assert not any(call[0] == "wait" for call in job.calls)


def test_process_exit_and_job_observation_are_independent():
    coordinator, _, _, _, job, _ = start_ready()
    decision = coordinator.observe_process(100)
    assert decision.facts.resources.worker_exited is EvidenceStatus.CONFIRMED
    assert decision.facts.resources.job_observed is EvidenceStatus.UNKNOWN
    decision = coordinator.observe_job()
    assert decision.facts.resources.job_observed is EvidenceStatus.CONFIRMED
    assert decision.facts.resources.job_active_processes == 0
    assert [call[0] for call in job.calls if call[0] in {"wait", "job_empty"}] == [
        "wait",
        "job_empty",
    ]


def test_nonzero_exit_cannot_succeed():
    job = FakeJob(wait_observation=WaitObservation(CreationState.PROCESS_EXITED, 7))
    coordinator, _, _, _, _ = make_coordinator(job=job)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.wait_ready()
    decision = coordinator.observe_process(100)
    assert decision.lifecycle.stop_reason is StopReason.FAILURE
    assert coordinator.supervisor.result is None


def test_job_query_failure_is_unconfirmed():
    job = FakeJob()
    job.observe_job_empty = lambda: (_ for _ in ()).throw(RuntimeError("query"))
    coordinator, _, _, _, _ = make_coordinator(job=job)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    decision = coordinator.observe_job()
    assert decision.facts.resources.job_observed is EvidenceStatus.UNCONFIRMED
    assert decision.result_available is False


def test_nonzero_job_count_does_not_confirm_cleanup():
    job = FakeJob(snapshot=replace(confirmed_snapshot(), job_active_processes=1))
    coordinator, _, _, _, _ = make_coordinator(job=job)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    decision = coordinator.observe_job()
    assert decision.facts.resources.job_active_processes == 1
    assert not decision.result_available


def test_ipc_unconfirmed_and_live_thread_evidence_cannot_succeed():
    transport = FakeTransport(close_state=IpcState.UNCONFIRMED)
    coordinator, _, _, _, _ = make_coordinator(transport=transport)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    decision = coordinator.close_ipc()
    assert decision.facts.resources.ipc_closed is EvidenceStatus.UNCONFIRMED
    assert decision.facts.resources.threads_finished is EvidenceStatus.UNCONFIRMED
    assert not decision.result_available


def test_start_send_failure_attempts_cleanup():
    transport = FakeTransport(send_error=RuntimeError("send"))
    coordinator, _, _, _, job, _ = start_ready_with(transport)
    with pytest.raises(RuntimeError):
        coordinator.send_start()
    assert ("close",) in job.calls
    assert coordinator.state is CoordinatorState.FAILED


def start_ready_with(transport):
    if not transport.incoming:
        transport.incoming.extend(
            [
                frame("READY", 0, sender="child"),
                frame(
                    "STOP_OBSERVED",
                    1,
                    sender="child",
                    payload={"reason": "user_request"},
                ),
            ]
        )
    coordinator, clock, pipe, _, job = make_coordinator(transport=transport)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.wait_ready()
    return coordinator, clock, pipe, transport, job, coordinator.decision


def test_no_candidate_report_can_enter_success():
    coordinator, _, _, _, _, _ = start_ready()
    coordinator.send_start()
    coordinator.request_stop(StopReason.USER_REQUEST)
    coordinator.send_stop(StopReason.USER_REQUEST)
    coordinator.receive_stop_observed()
    coordinator.observe_process(100)
    coordinator.observe_job()
    coordinator.close_ipc()
    decision = coordinator.close_resources()
    assert not decision.result_available
    assert coordinator.supervisor.result is None
    assert coordinator.state is CoordinatorState.CLOSED


def test_old_session_does_not_change_current_supervisor():
    coordinator, _, _, _, _ = make_coordinator()
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    before = coordinator.decision
    coordinator.supervisor.request_stop("b" * 32, StopReason.WINDOW_CLOSE)
    assert coordinator.decision == before


def test_two_coordinators_do_not_share_resources():
    first, _, first_pipe, _, first_job = make_coordinator()
    second, _, second_pipe, _, second_job = make_coordinator()
    first.start(("one",), remaining_timeout_ms=500)
    second.start(("two",), remaining_timeout_ms=500)
    assert first_pipe is not second_pipe
    assert first_job is not second_job
    assert first.decision.session_id == second.decision.session_id


def test_repeated_close_does_not_turn_unknown_cleanup_into_success():
    transport = FakeTransport(close_state=IpcState.UNCONFIRMED)
    coordinator, _, _, _, job, _ = start_ready_with(transport)
    coordinator.close_ipc()
    first = coordinator.close_resources()
    second = coordinator.close_resources()
    assert not first.result_available and not second.result_available
    assert job.calls.count(("close",)) >= 2


def test_parent_resource_evidence_confirms_only_after_all_parent_resources_close():
    coordinator, _, _, _, _, _ = start_ready()
    decision = coordinator.close_resources()
    assert decision.facts.resources.parent_resources_closed is EvidenceStatus.CONFIRMED
    assert not decision.result_available
    assert coordinator.state is CoordinatorState.CLOSED


def test_parent_resource_cleanup_failure_is_unconfirmed():
    job = FakeJob(snapshot=confirmed_snapshot(cleanup=CleanupObservation.UNCONFIRMED))
    coordinator, _, _, _, _ = make_coordinator(job=job)
    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.close_ipc()

    decision = coordinator.close_resources()

    assert decision.facts.resources.parent_resources_closed is EvidenceStatus.UNCONFIRMED


def test_diagnostic_observer_records_real_coordinator_stages_without_affecting_flow():
    transport = FakeTransport([frame("READY", 0, sender="child"), candidate_frame()])
    events = []
    coordinator, _, _, _, _ = make_coordinator(transport=transport)
    coordinator.set_diagnostic_observer(events.append)

    coordinator.start(("fixed-worker",), remaining_timeout_ms=500)
    coordinator.wait_ready()
    coordinator.send_start()
    coordinator.receive_worker_message()

    stages = [event.stage for event in events]
    assert DiagnosticStage.STARTING_RESOURCES in stages
    assert DiagnosticStage.STARTING_WORKER in stages
    assert DiagnosticStage.WAITING_READY in stages
    assert DiagnosticStage.SENDING_START in stages
    assert DiagnosticStage.RECEIVING_WORKER_MESSAGE in stages
    assert DiagnosticStage.VALIDATING_RESULT in stages
    assert all(event.error_code is None for event in events)
