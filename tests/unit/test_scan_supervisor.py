import json
import struct
from dataclasses import FrozenInstanceError, replace
from unittest.mock import Mock

import pytest

from dev_env_doctor.core.scan_control import (
    CleanupStatus,
    ScanDeadline,
    StopReason,
)
from dev_env_doctor.core.scan_control import (
    ScanLifecycleState as State,
)
from dev_env_doctor.core.scan_protocol import MAX_MESSAGES, ProtocolError, encode_message

SESSION = "a" * 32
OLD_SESSION = "b" * 32


class ManualClock:
    def __init__(self, value=100.0):
        self.value = value
        self.readings = []

    def __call__(self):
        if self.readings:
            reading = self.readings.pop(0)
            if isinstance(reading, BaseException):
                raise reading
            self.value = reading
        return self.value


@pytest.fixture
def api():
    from dev_env_doctor.core import scan_supervisor

    return scan_supervisor


def make_supervisor(api):
    clock = ManualClock()
    return api.ScanSupervisor(SESSION, ScanDeadline(10, clock=clock)), clock


def resources(api, **changes):
    confirmed = api.EvidenceStatus.CONFIRMED
    return replace(
        api.ResourceEvidence(
            creation_finished=confirmed,
            worker_exited=confirmed,
            exit_code=0,
            job_observed=confirmed,
            job_active_processes=0,
            ipc_closed=confirmed,
            parent_resources_closed=confirmed,
            threads_finished=confirmed,
        ),
        **changes,
    )


def diagnostic():
    return {
        "rule_id": "COMMAND_VERSION",
        "title": "python version",
        "summary": "Version checked.",
        "severity": "info",
        "status": "passed",
        "suggestion": "",
        "evidence": ["Verified version: 3.13.9"],
    }


def candidate_report(diagnostics):
    return {
        "schema_version": "1.0",
        "metadata": {
            "scan_time": "2026-01-01T00:00:00+00:00",
            "app_version": "0.1.0",
            "platform": "Windows",
            "python_version": "3.13.0",
        },
        "diagnostics": diagnostics,
    }


def send(supervisor, kind, sequence, *, sender="child", payload=None, route=SESSION):
    payload = {} if payload is None else payload
    if kind == "RESULT_CANDIDATE" and "diagnostics" in payload:
        payload = {"report": candidate_report(payload["diagnostics"])}
    return supervisor.observe_message(
        route,
        encode_message(
            {
                "version": 1,
                "session_id": SESSION,
                "sequence": sequence,
                "type": kind,
                "payload": payload,
            }
        ),
        sender=sender,
    )


def running(api):
    supervisor, clock = make_supervisor(api)
    supervisor.begin(SESSION)
    supervisor.process_started(SESSION)
    supervisor.observe_resources(
        SESSION,
        api.ResourceEvidence(creation_finished=api.EvidenceStatus.CONFIRMED),
    )
    send(supervisor, "READY", 0)
    assert supervisor.decision.start_permitted
    send(supervisor, "START", 0, sender="parent", payload={"deadline": 110.0})
    assert supervisor.decision.lifecycle.state is State.RUNNING
    return supervisor, clock


def candidate(api):
    supervisor, clock = running(api)
    send(supervisor, "RESULT_CANDIDATE", 1, payload={"diagnostics": [diagnostic()]})
    assert supervisor.decision.lifecycle.state is State.FINALIZING
    return supervisor, clock


def test_initial_state_and_snapshots_are_not_success(api):
    supervisor, _ = make_supervisor(api)
    decision = supervisor.decision
    assert decision.lifecycle.state is State.IDLE
    assert decision.lifecycle.cleanup_status is CleanupStatus.PENDING
    assert not decision.result_available and supervisor.result is None
    assert decision.facts.resources.exit_code is None
    with pytest.raises(FrozenInstanceError):
        decision.facts.ready = True
    with pytest.raises(ValueError, match="session"):
        supervisor.observe_report_validation(SESSION, accepted=True)


def test_complete_success_requires_candidate_validation_and_all_cleanup(api):
    supervisor, _ = candidate(api)
    supervisor.observe_resources(SESSION, resources(api))
    assert supervisor.result is None
    assert supervisor.decision.lifecycle.state is State.FINALIZING
    decision = supervisor.observe_report_validation(SESSION, accepted=True)
    assert decision.lifecycle.state is State.SUCCEEDED
    assert decision.lifecycle.cleanup_status is CleanupStatus.CONFIRMED
    assert decision.result_available and not decision.cleanup_required
    assert supervisor.result == [diagnostic()]
    assert supervisor.candidate_report == candidate_report([diagnostic()])
    assert supervisor.result_report == candidate_report([diagnostic()])
    result_report = supervisor.result_report
    assert result_report is not None
    result_report["metadata"]["platform"] = "mutated"
    assert supervisor.result_report == candidate_report([diagnostic()])
    supervisor.result[0]["summary"] = "modified externally"
    assert supervisor.result == [diagnostic()]
    with pytest.raises(ValueError):
        supervisor.begin(SESSION)


@pytest.mark.parametrize(
    "field,value",
    [
        ("creation_finished", "unknown"),
        ("creation_finished", "pending"),
        ("worker_exited", "unknown"),
        ("exit_code", None),
        ("job_observed", "unknown"),
        ("job_active_processes", None),
        ("job_active_processes", 1),
        ("ipc_closed", "unknown"),
        ("parent_resources_closed", "pending"),
        ("threads_finished", "unknown"),
        ("threads_finished", "pending"),
    ],
)
def test_each_missing_resource_fact_prevents_success(api, field, value):
    supervisor, _ = candidate(api)
    supervisor.observe_report_validation(SESSION, accepted=True)
    if isinstance(value, str):
        value = api.EvidenceStatus(value)
    changes = {field: value}
    if field == "worker_exited":
        changes["exit_code"] = None
    supervisor.observe_resources(SESSION, resources(api, **changes))
    assert not supervisor.decision.result_available
    assert supervisor.result is None
    assert supervisor.decision.lifecycle.state is State.FINALIZING
    assert supervisor.decision.lifecycle.cleanup_status is CleanupStatus.PENDING


@pytest.mark.parametrize("code", [1, -1])
def test_nonzero_exit_after_candidate_is_failure_not_success(api, code):
    supervisor, _ = candidate(api)
    supervisor.observe_report_validation(SESSION, accepted=True)
    decision = supervisor.observe_resources(SESSION, resources(api, exit_code=code))
    assert decision.lifecycle.state is State.FAILED
    assert decision.lifecycle.stop_reason is StopReason.FAILURE
    assert supervisor.result is None


@pytest.mark.parametrize(
    "moment,expected",
    [(109.0, State.SUCCEEDED), (110.0, State.TIMED_OUT), (111.0, State.TIMED_OUT)],
)
def test_final_commit_checks_actual_deadline(api, moment, expected):
    supervisor, clock = candidate(api)
    supervisor.observe_report_validation(SESSION, accepted=True)
    clock.value = moment
    decision = supervisor.observe_resources(SESSION, resources(api))
    assert decision.lifecycle.state is expected
    assert decision.result_available is (expected is State.SUCCEEDED)
    assert supervisor.deadline.expires_at == 110.0


def test_early_timeout_notification_does_not_stop_or_restart_budget(api):
    supervisor, clock = running(api)
    decision = supervisor.request_stop(SESSION, StopReason.DEADLINE_EXCEEDED)
    assert decision.lifecycle.state is State.RUNNING
    assert decision.lifecycle.stop_reason is None
    clock.value = 110
    decision = supervisor.tick(SESSION)
    assert decision.lifecycle.state is State.STOPPING
    assert decision.lifecycle.stop_reason is StopReason.DEADLINE_EXCEEDED
    assert decision.lifecycle.cleanup_status is CleanupStatus.PENDING


@pytest.mark.parametrize("first", [StopReason.USER_REQUEST, StopReason.WINDOW_CLOSE])
def test_first_stop_reason_and_close_intent_survive_competing_events(api, first):
    supervisor, clock = running(api)
    supervisor.request_stop(SESSION, first)
    clock.value = 110
    supervisor.request_stop(SESSION, StopReason.WINDOW_CLOSE)
    supervisor.execution_failed(SESSION)
    assert supervisor.decision.lifecycle.stop_reason is first
    assert supervisor.decision.close_pending
    decision = supervisor.observe_resources(SESSION, resources(api))
    assert decision.lifecycle.state is State.STOPPED
    assert decision.close_pending and not decision.result_available


def test_explicit_failure_wins_at_deadline_and_terminal_is_unchanged(api):
    supervisor, clock = running(api)
    clock.value = 110
    supervisor.execution_failed(SESSION)
    decision = supervisor.observe_resources(SESSION, resources(api))
    assert decision.lifecycle.state is State.FAILED
    assert decision.lifecycle.stop_reason is StopReason.FAILURE
    assert supervisor.request_stop(SESSION, StopReason.WINDOW_CLOSE).close_pending
    assert supervisor.decision.lifecycle == decision.lifecycle


@pytest.mark.parametrize(
    "kind,sequence,sender,payload",
    [
        ("START", 0, "parent", {"deadline": 110}),
        ("RESULT_CANDIDATE", 0, "child", {"diagnostics": []}),
        ("STOP_OBSERVED", 0, "child", {"reason": "user_request"}),
        ("READY", 1, "child", {}),
    ],
)
def test_illegal_protocol_order_fails_before_any_result(api, kind, sequence, sender, payload):
    supervisor, _ = make_supervisor(api)
    supervisor.begin(SESSION)
    supervisor.process_started(SESSION)
    decision = send(supervisor, kind, sequence, sender=sender, payload=payload)
    assert decision.facts.protocol_error
    assert decision.lifecycle.state is State.STOPPING
    assert decision.cleanup_required
    assert supervisor.result is None


def test_duplicate_candidate_poison_is_sticky(api):
    supervisor, _ = candidate(api)
    decision = send(supervisor, "RESULT_CANDIDATE", 2, payload={"diagnostics": []})
    assert decision.facts.protocol_error and decision.facts.candidate_count == 1
    supervisor.observe_report_validation(SESSION, accepted=True)
    supervisor.observe_resources(SESSION, resources(api))
    assert supervisor.decision.lifecycle.state is State.FAILED
    assert supervisor.result is None


def test_stop_crossing_candidate_preserves_reason_and_rejects_result(api):
    supervisor, _ = running(api)
    supervisor.request_stop(SESSION, StopReason.USER_REQUEST)
    send(supervisor, "STOP", 1, sender="parent", payload={"reason": "user_request"})
    decision = send(supervisor, "RESULT_CANDIDATE", 1, payload={"diagnostics": []})
    assert decision.facts.protocol_error
    assert decision.lifecycle.stop_reason is StopReason.USER_REQUEST
    supervisor.observe_resources(SESSION, resources(api))
    assert supervisor.decision.lifecycle.state is State.STOPPED
    assert supervisor.result is None


def test_stop_observed_and_cleanup_request_are_not_cleanup_evidence(api):
    supervisor, _ = running(api)
    supervisor.request_stop(SESSION, StopReason.USER_REQUEST)
    send(supervisor, "STOP", 1, sender="parent", payload={"reason": "user_request"})
    decision = send(supervisor, "STOP_OBSERVED", 1, payload={"reason": "user_request"})
    assert decision.facts.stop_observed and decision.cleanup_required
    assert decision.lifecycle.cleanup_status is CleanupStatus.PENDING
    assert decision.lifecycle.state is State.STOPPING


def test_cleanup_unconfirmed_can_only_resolve_to_stop_terminal(api):
    supervisor, _ = candidate(api)
    supervisor.request_stop(SESSION, StopReason.USER_REQUEST)
    decision = supervisor.cleanup_unconfirmed(SESSION)
    assert decision.lifecycle.state is State.STOP_UNCONFIRMED
    assert decision.lifecycle.cleanup_status is CleanupStatus.UNCONFIRMED
    supervisor.observe_report_validation(SESSION, accepted=True)
    assert supervisor.decision.lifecycle.state is State.STOP_UNCONFIRMED
    supervisor.observe_resources(SESSION, resources(api))
    assert supervisor.decision.lifecycle.state is State.STOPPED
    assert supervisor.result is None


@pytest.mark.parametrize("phase", ["starting", "running", "candidate"])
def test_worker_exit_without_complete_success_never_returns_partial_report(api, phase):
    if phase == "starting":
        supervisor, _ = make_supervisor(api)
        supervisor.begin(SESSION)
        supervisor.process_started(SESSION)
    elif phase == "running":
        supervisor, _ = running(api)
    else:
        supervisor, _ = candidate(api)
    code = 1 if phase == "candidate" else 0
    supervisor.observe_resources(SESSION, resources(api, exit_code=code))
    assert supervisor.decision.lifecycle.state is State.FAILED
    assert supervisor.result is None


@pytest.mark.parametrize(
    "kind,payload", [("FAILED", {"code": "SCAN_FAILED"}), ("CLEANUP_UNCONFIRMED", {})]
)
def test_child_failure_after_candidate_cannot_become_success(api, kind, payload):
    supervisor, _ = candidate(api)
    decision = send(supervisor, kind, 2, payload=payload)
    assert decision.facts.execution_failed
    assert decision.lifecycle.state in {State.STOPPING, State.STOP_UNCONFIRMED}
    supervisor.observe_resources(SESSION, resources(api))
    assert supervisor.decision.lifecycle.state is State.FAILED
    assert supervisor.result is None


def test_parent_report_rejection_is_fixed_failure(api):
    supervisor, _ = candidate(api)
    decision = supervisor.observe_report_validation(SESSION, accepted=False)
    assert decision.facts.report_validation is api.EvidenceStatus.UNCONFIRMED
    assert decision.lifecycle.stop_reason is StopReason.FAILURE
    supervisor.observe_resources(SESSION, resources(api))
    assert supervisor.decision.lifecycle.state is State.FAILED


def test_old_session_events_do_not_change_current_session(api):
    supervisor, _ = running(api)
    original = supervisor.decision
    send(supervisor, "FAILED", 1, payload={"code": "SCAN_FAILED"}, route=OLD_SESSION)
    supervisor.request_stop(OLD_SESSION, StopReason.WINDOW_CLOSE)
    supervisor.observe_resources(OLD_SESSION, resources(api))
    supervisor.observe_report_validation(OLD_SESSION, accepted=False)
    supervisor.protocol_failed(OLD_SESSION)
    supervisor.cleanup_unconfirmed(OLD_SESSION)
    assert supervisor.decision == original


def test_message_is_revalidated_and_candidate_is_detached(api):
    supervisor, _ = running(api)
    item = diagnostic()
    item["summary"] = r"C:\Users\ImaginaryUser\private\secret.txt"
    send(supervisor, "RESULT_CANDIDATE", 1, payload={"diagnostics": [item]})
    item["summary"] = "changed"
    detached = supervisor.candidate_diagnostics
    assert "ImaginaryUser" not in str(detached) and "secret.txt" not in str(detached)
    detached.clear()
    assert len(supervisor.candidate_diagnostics) == 1
    assert supervisor.result is None


def test_start_requires_launch_evidence_and_same_absolute_deadline(api):
    supervisor, _ = make_supervisor(api)
    supervisor.begin(SESSION)
    supervisor.process_started(SESSION)
    send(supervisor, "READY", 0)
    assert not supervisor.decision.start_permitted
    decision = send(supervisor, "START", 0, sender="parent", payload={"deadline": 110})
    assert decision.facts.protocol_error and not decision.facts.start_authorized

    supervisor, _ = running(api)
    assert supervisor.deadline.expires_at == 110
    assert supervisor.decision.facts.start_authorized


def test_deadline_cannot_be_replaced_by_start_message(api):
    supervisor, _ = make_supervisor(api)
    supervisor.begin(SESSION)
    supervisor.process_started(SESSION)
    supervisor.observe_resources(
        SESSION, api.ResourceEvidence(creation_finished=api.EvidenceStatus.CONFIRMED)
    )
    send(supervisor, "READY", 0)
    decision = send(supervisor, "START", 0, sender="parent", payload={"deadline": 999})
    assert decision.facts.protocol_error and supervisor.deadline.expires_at == 110


@pytest.mark.parametrize(
    "changes",
    [{"exit_code": True}, {"job_active_processes": -1}, {"ipc_closed": True}, {"worker_absent": 1}],
)
def test_resource_evidence_rejects_wrong_types_without_values_in_errors(api, changes):
    with pytest.raises((TypeError, ValueError)):
        api.ResourceEvidence(**changes)


def test_creation_failure_can_finish_failed_without_inventing_process_exit(api):
    supervisor, _ = make_supervisor(api)
    supervisor.begin(SESSION)
    supervisor.execution_failed(SESSION)
    evidence = resources(
        api, worker_absent=True, worker_exited=api.EvidenceStatus.UNKNOWN, exit_code=None
    )
    decision = supervisor.observe_resources(SESSION, evidence)
    assert decision.lifecycle.state is State.FAILED
    assert decision.facts.worker_started is api.EvidenceStatus.UNKNOWN
    assert decision.facts.resources.worker_exited is api.EvidenceStatus.UNKNOWN


def test_core_does_not_execute_scan_or_create_resources(api, monkeypatch):
    from dev_env_doctor.core import runner

    forbidden = Mock(side_effect=AssertionError("Real scan is forbidden"))
    monkeypatch.setattr(runner, "run_scan", forbidden)
    supervisor, _ = candidate(api)
    supervisor.observe_report_validation(SESSION, accepted=True)
    supervisor.observe_resources(SESSION, resources(api))
    assert supervisor.decision.lifecycle.state is State.SUCCEEDED
    forbidden.assert_not_called()


def test_existing_protocol_budget_is_not_reset_or_bypassed(api):
    supervisor, _ = running(api)
    supervisor.request_stop(SESSION, StopReason.USER_REQUEST)
    for sequence in range(1, MAX_MESSAGES):
        send(supervisor, "STOP", sequence, sender="parent", payload={"reason": "user_request"})
    assert supervisor.decision.facts.protocol_error
    supervisor.observe_resources(SESSION, resources(api))
    assert supervisor.result is None


def test_invalid_session_id_uses_existing_protocol_error(api):
    with pytest.raises(ProtocolError):
        api.ScanSupervisor("not a session", ScanDeadline(1, clock=ManualClock()))


def test_candidate_after_stop_intent_before_stop_frame_is_safe_failure(api):
    supervisor, _ = running(api)
    supervisor.request_stop(SESSION, StopReason.USER_REQUEST)
    decision = send(supervisor, "RESULT_CANDIDATE", 1, payload={"diagnostics": []})
    assert decision.facts.protocol_error
    assert decision.lifecycle.state is State.STOPPING
    assert decision.lifecycle.stop_reason is StopReason.USER_REQUEST
    assert supervisor.candidate_diagnostics is None
    assert supervisor.result is None


def test_stop_actions_are_idempotent_and_poisoned_protocol_is_not_used(api):
    supervisor, _ = running(api)
    assert supervisor.request_stop(SESSION, StopReason.USER_REQUEST).stop_required
    decision = send(supervisor, "STOP", 1, sender="parent", payload={"reason": "user_request"})
    assert not decision.stop_required and decision.cleanup_required
    assert decision.facts.stop_sent
    supervisor.protocol_failed(SESSION)
    assert not supervisor.decision.stop_required
    assert supervisor.decision.cleanup_required


def test_report_validation_failure_is_sticky(api):
    supervisor, _ = candidate(api)
    supervisor.observe_report_validation(SESSION, accepted=False)
    supervisor.observe_report_validation(SESSION, accepted=True)
    assert supervisor.decision.facts.report_validation is api.EvidenceStatus.UNCONFIRMED
    assert supervisor.decision.facts.execution_failed
    assert supervisor.result is None


def test_cumulative_budget_accounts_for_original_wire_whitespace(api):
    supervisor, _ = running(api)
    supervisor.request_stop(SESSION, StopReason.USER_REQUEST)
    for sequence in range(1, 7):
        value = {
            "version": 1,
            "session_id": SESSION,
            "sequence": sequence,
            "type": "STOP",
            "payload": {"reason": "user_request"},
        }
        body = json.dumps(value).encode() + b" " * 200_000
        frame = struct.pack("!I", len(body)) + body
        supervisor.observe_message(SESSION, frame, sender="parent")
    assert supervisor.decision.facts.protocol_error
    assert supervisor.result is None


@pytest.mark.parametrize(
    "body",
    [
        b'{"version":1,"version":1}',
        b"{}",
        b"not JSON",
    ],
)
def test_raw_invalid_frames_are_delegated_and_never_echoed(api, body):
    supervisor, _ = running(api)
    frame = struct.pack("!I", len(body)) + body
    decision = supervisor.observe_message(SESSION, frame, sender="child")
    assert decision.facts.protocol_error and decision.cleanup_required
    assert supervisor.result is None


def test_unknown_exit_code_is_not_fabricated_by_stop_handling(api):
    supervisor, _ = candidate(api)
    supervisor.observe_report_validation(SESSION, accepted=True)
    supervisor.observe_resources(SESSION, resources(api, exit_code=None))
    assert supervisor.decision.lifecycle.state is State.FINALIZING
    supervisor.request_stop(SESSION, StopReason.USER_REQUEST)
    assert supervisor.decision.lifecycle.state is State.STOPPED
    assert supervisor.decision.facts.resources.exit_code is None


@pytest.mark.parametrize(
    "field",
    [
        "creation_finished",
        "worker_exited",
        "job_observed",
        "ipc_closed",
        "parent_resources_closed",
        "threads_finished",
    ],
)
def test_explicit_resource_uncertainty_is_never_confirmed(api, field):
    supervisor, _ = candidate(api)
    changes = {field: api.EvidenceStatus.UNCONFIRMED}
    if field == "worker_exited":
        changes["exit_code"] = None
    decision = supervisor.observe_resources(SESSION, resources(api, **changes))
    assert decision.lifecycle.state is State.STOP_UNCONFIRMED
    assert decision.lifecycle.cleanup_status is CleanupStatus.UNCONFIRMED
    assert supervisor.result is None


def test_each_success_authorization_fact_cannot_be_skipped(api):
    supervisor, _ = make_supervisor(api)
    supervisor.begin(SESSION)
    supervisor.observe_resources(SESSION, resources(api))
    assert supervisor.decision.lifecycle.state is State.FAILED
    assert supervisor.decision.facts.worker_started is not api.EvidenceStatus.CONFIRMED
    assert not supervisor.decision.facts.ready
    assert not supervisor.decision.facts.start_authorized
    assert supervisor.decision.facts.candidate_count == 0
    assert supervisor.result is None


def test_wrong_inner_session_fails_current_protocol_without_leaking_input(api):
    supervisor, _ = running(api)
    frame = encode_message(
        {
            "version": 1,
            "session_id": OLD_SESSION,
            "sequence": 1,
            "type": "FAILED",
            "payload": {"code": "SCAN_FAILED"},
        }
    )
    decision = supervisor.observe_message(SESSION, frame, sender="child")
    assert decision.facts.protocol_error
    assert OLD_SESSION not in repr(decision)


def test_empty_candidate_is_a_valid_report_only_after_final_confirmation(api):
    supervisor, _ = running(api)
    send(supervisor, "RESULT_CANDIDATE", 1, payload={"diagnostics": []})
    supervisor.observe_report_validation(SESSION, accepted=True)
    assert supervisor.result is None
    supervisor.observe_resources(SESSION, resources(api))
    assert supervisor.decision.lifecycle.state is State.SUCCEEDED
    assert supervisor.result == []


def test_clock_crossing_expiry_during_final_adjudication_cannot_leave_stale_state(api):
    supervisor, clock = candidate(api)
    supervisor.observe_report_validation(SESSION, accepted=True)
    clock.readings = [109.0, 110.0, 110.0]
    decision = supervisor.observe_resources(SESSION, resources(api))
    assert decision.lifecycle.state is State.TIMED_OUT
    assert decision.lifecycle.cleanup_status is CleanupStatus.CONFIRMED
    assert supervisor.result is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("rule_id", "UNKNOWN_RULE"),
        ("severity", "unknown"),
        ("status", "unknown"),
        ("evidence", ["Verified version: ٣.١.٢"]),
        ("summary", "x" * 4097),
        ("suggestion", chr(0xD800)),
    ],
)
def test_candidate_privacy_and_type_boundary_cannot_be_bypassed(api, field, value):
    supervisor, _ = running(api)
    item = diagnostic()
    item[field] = value
    body = json.dumps(
        {
            "version": 1,
            "session_id": SESSION,
            "sequence": 1,
            "type": "RESULT_CANDIDATE",
            "payload": {"report": candidate_report([item])},
        }
    ).encode()
    decision = supervisor.observe_message(
        SESSION, struct.pack("!I", len(body)) + body, sender="child"
    )
    assert decision.facts.protocol_error
    assert decision.facts.candidate_count == 0
    assert supervisor.candidate_diagnostics is None
    assert supervisor.result is None


def test_start_at_expiry_is_not_authorized(api):
    supervisor, clock = make_supervisor(api)
    supervisor.begin(SESSION)
    supervisor.process_started(SESSION)
    supervisor.observe_resources(
        SESSION, api.ResourceEvidence(creation_finished=api.EvidenceStatus.CONFIRMED)
    )
    send(supervisor, "READY", 0)
    clock.value = 110
    decision = send(supervisor, "START", 0, sender="parent", payload={"deadline": 110})
    assert not decision.facts.start_authorized
    assert not decision.start_permitted
    assert decision.lifecycle.state is State.STOPPING
    assert decision.lifecycle.stop_reason is StopReason.DEADLINE_EXCEEDED


def test_early_stop_crosses_ready_without_start_or_cleanup_claim(api):
    supervisor, _ = make_supervisor(api)
    supervisor.begin(SESSION)
    supervisor.process_started(SESSION)
    supervisor.request_stop(SESSION, StopReason.WINDOW_CLOSE)
    send(supervisor, "STOP", 0, sender="parent", payload={"reason": "window_close"})
    send(supervisor, "READY", 0)
    decision = send(supervisor, "STOP_OBSERVED", 1, payload={"reason": "window_close"})
    assert decision.facts.ready and decision.facts.stop_observed
    assert not decision.facts.start_authorized
    assert not decision.start_permitted
    assert decision.close_pending
    assert decision.lifecycle.cleanup_status is CleanupStatus.PENDING
    assert supervisor.result is None


def test_terminal_result_is_not_overwritten_by_late_failure(api):
    supervisor, clock = candidate(api)
    supervisor.observe_report_validation(SESSION, accepted=True)
    supervisor.observe_resources(SESSION, resources(api))
    original = supervisor.decision
    clock.value = 1000
    supervisor.execution_failed(SESSION)
    supervisor.cleanup_unconfirmed(SESSION)
    supervisor.protocol_failed(SESSION)
    send(supervisor, "FAILED", 2, payload={"code": "SCAN_FAILED"})
    assert supervisor.decision == original
    assert supervisor.result == [diagnostic()]


@pytest.mark.parametrize("reason", [StopReason.USER_REQUEST, StopReason.WINDOW_CLOSE])
@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_accepted_stop_survives_clock_error_and_cannot_later_succeed(api, reason, error_type):
    supervisor, clock = candidate(api)
    supervisor.observe_report_validation(SESSION, accepted=True)
    original = error_type("fictional clock failure")
    clock.readings = [original]
    with pytest.raises(error_type) as raised:
        send(supervisor, "STOP", 1, sender="parent", payload={"reason": reason.value})
    assert raised.value is original
    interrupted = supervisor.decision
    assert interrupted.facts.stop_sent
    assert interrupted.lifecycle.cleanup_status is CleanupStatus.PENDING
    assert supervisor.result is None

    decision = supervisor.observe_resources(SESSION, resources(api))
    assert decision.lifecycle.state is State.STOPPED
    assert not decision.result_available and supervisor.result is None
    assert interrupted.facts.stop_intent is reason
    assert decision.facts.stop_intent is reason
    assert decision.lifecycle.stop_reason is reason
    assert interrupted.cleanup_required
    assert interrupted.close_pending is (reason is StopReason.WINDOW_CLOSE)
    assert decision.close_pending is (reason is StopReason.WINDOW_CLOSE)
    supervisor.tick(SESSION)
    supervisor.observe_report_validation(SESSION, accepted=True)
    assert supervisor.decision.lifecycle.state is State.STOPPED
    assert supervisor.result is None


def test_close_request_survives_clock_error_before_any_stop_is_sent(api):
    supervisor, clock = candidate(api)
    supervisor.observe_report_validation(SESSION, accepted=True)
    original = RuntimeError("fictional close arbitration failure")
    clock.readings = [original]
    with pytest.raises(RuntimeError) as raised:
        supervisor.request_stop(SESSION, StopReason.WINDOW_CLOSE)
    assert raised.value is original
    interrupted = supervisor.decision

    supervisor.request_stop(SESSION, StopReason.USER_REQUEST)
    decision = supervisor.observe_resources(SESSION, resources(api))
    assert decision.lifecycle.state is State.STOPPED
    assert decision.lifecycle.stop_reason is StopReason.WINDOW_CLOSE
    assert decision.facts.stop_intent is StopReason.WINDOW_CLOSE
    assert interrupted.close_pending and decision.close_pending
    assert not interrupted.facts.stop_sent
    assert not decision.result_available and supervisor.result is None


def test_success_predicate_rejects_stop_intent_when_arbitration_is_still_pending(api):
    supervisor, clock = candidate(api)
    supervisor.observe_report_validation(SESSION, accepted=True)
    original = RuntimeError("fictional stop arbitration failure")
    clock.readings = [original]
    with pytest.raises(RuntimeError) as raised:
        send(supervisor, "STOP", 1, sender="parent", payload={"reason": "user_request"})
    assert raised.value is original
    cleanup_error = RuntimeError("fictional later clock failure")
    clock.readings = [cleanup_error]
    with pytest.raises(RuntimeError) as raised:
        supervisor.observe_resources(SESSION, resources(api))
    assert raised.value is cleanup_error

    decision = supervisor.decision
    assert decision.lifecycle.state is State.FINALIZING
    assert decision.lifecycle.stop_reason is None
    assert decision.facts.resources == resources(api)
    assert decision.facts.report_validation is api.EvidenceStatus.CONFIRMED
    assert not supervisor._success_conditions_met()
    assert decision.facts.stop_intent is StopReason.USER_REQUEST
    assert supervisor.result is None
    assert supervisor.tick(SESSION).lifecycle.state is State.STOPPED
