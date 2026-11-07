import importlib
import json
import struct

import pytest

SESSION = "a" * 32


@pytest.fixture
def protocol():
    return importlib.import_module("dev_env_doctor.core.scan_protocol")


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


def message(kind="READY", payload=None, sequence=0, session_id=SESSION):
    payload = {} if payload is None else payload
    if kind == "RESULT_CANDIDATE" and "diagnostics" in payload:
        extras = {key: value for key, value in payload.items() if key != "diagnostics"}
        payload = {"report": candidate_report(payload["diagnostics"]), **extras}
    return {
        "version": 1,
        "session_id": session_id,
        "sequence": sequence,
        "type": kind,
        "payload": payload,
    }


def raw_frame(value):
    data = json.dumps(value, ensure_ascii=False).encode("utf-8")
    return struct.pack("!I", len(data)) + data


def test_ready_roundtrip_and_explicit_envelope(protocol):
    original = message()
    frame = protocol.encode_message(original)
    assert struct.unpack("!I", frame[:4])[0] == len(frame) - 4
    assert protocol.decode_frame(frame) == original


def test_session_rejects_start_before_ready_without_partial_budget(protocol):
    session = protocol.ProtocolSession(SESSION)
    with pytest.raises(protocol.ProtocolError):
        session.accept_frame(raw_frame(message("START", {"deadline": 100})), sender="parent")
    assert session.failed
    assert session.budget.message_count == session.budget.total_bytes == 0


CASES = [
    ("READY", {}),
    ("START", {"deadline": 123.5}),
    ("STOP", {"reason": "user_request"}),
    ("RESULT_CANDIDATE", {"diagnostics": []}),
    ("FAILED", {"code": "SCAN_FAILED"}),
    ("STOP_OBSERVED", {"reason": "window_close"}),
    ("CLEANUP_UNCONFIRMED", {}),
]


@pytest.mark.parametrize("kind,payload", CASES)
def test_every_message_roundtrips(protocol, kind, payload):
    value = message(kind, payload)
    assert protocol.decode_frame(protocol.encode_message(value)) == value


@pytest.mark.parametrize("kind,payload", CASES)
@pytest.mark.parametrize("field", ["version", "session_id", "sequence", "type", "payload"])
def test_required_envelope_fields(protocol, kind, payload, field):
    value = message(kind, payload)
    del value[field]
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_frame(raw_frame(value))


@pytest.mark.parametrize("kind,payload", CASES)
def test_unknown_envelope_and_payload_fields_are_rejected(protocol, kind, payload):
    for value in (
        {**message(kind, payload), "stdout": "fictional-secret"},
        message(kind, {**payload, "cleanup_status": "confirmed"}),
    ):
        for operation in (
            protocol.encode_message,
            lambda data: protocol.decode_frame(raw_frame(data)),
        ):
            with pytest.raises(protocol.ProtocolError) as error:
                operation(value)
            assert "fictional-secret" not in str(error.value)


@pytest.mark.parametrize("kind,payload", [(k, p) for k, p in CASES if p])
def test_required_payload_fields(protocol, kind, payload):
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_frame(raw_frame(message(kind)))


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", True),
        ("version", 2),
        ("sequence", True),
        ("sequence", -1),
        ("sequence", 1.0),
        ("sequence", "0"),
        ("sequence", 32),
        ("session_id", ""),
        ("session_id", "A" * 32),
        ("session_id", "a" * 31),
        ("session_id", "../fictional"),
        ("type", "UNKNOWN"),
        ("payload", []),
    ],
)
def test_invalid_envelope_types_and_values(protocol, field, value):
    invalid = {**message(), field: value}
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_frame(raw_frame(invalid))


@pytest.mark.parametrize(
    "kind,payload",
    [
        ("START", {"deadline": True}),
        ("START", {"deadline": "100"}),
        ("START", {"deadline": None}),
        ("STOP", {"reason": "unknown"}),
        ("STOP_OBSERVED", {"reason": False}),
        ("FAILED", {"code": "raw exception"}),
        ("RESULT_CANDIDATE", {"diagnostics": {}}),
    ],
)
def test_wrong_payload_types_and_enums(protocol, kind, payload):
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_frame(raw_frame(message(kind, payload)))


@pytest.mark.parametrize(
    "data",
    [
        b"\xff",
        b"{",
        b"{}{}",
        b'{"version":1,"version":1}',
        b'{"payload":{"reason":0,"reason":1}}',
        b"NaN",
        b"Infinity",
        b"-Infinity",
        b'{"payload":1e999}',
        b'"\\ud800"',
        b"[" * 1000 + b"]" * 1000,
    ],
)
def test_malformed_json_is_rejected_with_fixed_error(protocol, data):
    with pytest.raises(protocol.ProtocolError) as error:
        protocol.decode_frame(struct.pack("!I", len(data)) + data)
    assert str(error.value) == "Invalid scan protocol message."


@pytest.mark.parametrize("data", [b"", b"\0", b"\0" * 4, b"\0\0\0\xff{}"])
def test_incomplete_frames_are_not_results(protocol, data):
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_frame(data)


def test_frame_exact_size_boundary_and_no_extra_or_truncated_bytes(protocol):
    data = json.dumps(message()).encode()
    data += b" " * (protocol.MAX_FRAME_BYTES - 4 - len(data))
    frame = struct.pack("!I", len(data)) + data
    assert protocol.decode_frame(frame) == message()
    for invalid in (frame + b" ", frame[:-1], raw_frame(message()) + b"trailing"):
        with pytest.raises(protocol.ProtocolError):
            protocol.decode_frame(invalid)
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_frame(struct.pack("!I", len(data) + 1) + data + b" ")


def test_budget_limits_latch_and_never_reset_counters(protocol):
    budget = protocol.MessageBudget()
    for _ in range(4):
        budget.consume(protocol.MAX_FRAME_BYTES)
    assert budget.total_bytes == 1024 * 1024 and budget.message_count == 4
    with pytest.raises(protocol.ProtocolError):
        budget.consume(5)
    assert budget.total_bytes == 1024 * 1024 and budget.message_count == 4
    with pytest.raises(protocol.ProtocolError):
        budget.consume(5)
    count_budget = protocol.MessageBudget()
    for _ in range(32):
        count_budget.consume(5)
    with pytest.raises(protocol.ProtocolError):
        count_budget.consume(5)
    assert count_budget.message_count == 32 and count_budget.total_bytes == 160


@pytest.mark.parametrize("size", [True, -1, 0, 4, 262145, 1.0, "5"])
def test_budget_rejects_invalid_sizes(protocol, size):
    budget = protocol.MessageBudget()
    with pytest.raises(protocol.ProtocolError):
        budget.consume(size)
    assert budget.message_count == budget.total_bytes == 0


def diagnostic():
    return {
        "rule_id": "COMMAND_VERSION",
        "title": "python version",
        "summary": "A version was verified.",
        "severity": "info",
        "status": "passed",
        "suggestion": "",
        "evidence": ["Verified version: 3.13.9"],
    }


def test_candidate_uses_shared_privacy_boundary_without_metadata(protocol):
    item = diagnostic()
    item["summary"] = r"C:\Users\FictionalUser\Private\tool.exe"
    item["suggestion"] = "password=fictional phrase"
    value = message("RESULT_CANDIDATE", {"diagnostics": [item]})
    frame = protocol.encode_message(value)
    restored = protocol.decode_frame(frame)
    assert restored["payload"]["report"]["diagnostics"][0]["evidence"] == item["evidence"]
    for secret in (b"FictionalUser", b"tool.exe", b"fictional phrase"):
        assert secret not in frame
    assert item["suggestion"] == "password=fictional phrase"


def test_candidate_report_metadata_roundtrips_without_collecting_defaults(protocol):
    value = message("RESULT_CANDIDATE", {"diagnostics": [diagnostic()]})
    restored = protocol.decode_frame(protocol.encode_message(value))
    report = restored["payload"]["report"]
    assert report["schema_version"] == "1.0"
    assert report["metadata"] == {
        "scan_time": "2026-01-01T00:00:00+00:00",
        "app_version": "0.1.0",
        "platform": "Windows",
        "python_version": "3.13.0",
    }
    assert report["diagnostics"] == [diagnostic()]


@pytest.mark.parametrize("field", ["schema_version", "metadata", "diagnostics"])
def test_candidate_report_missing_top_level_fields_are_rejected(protocol, field):
    report = candidate_report([diagnostic()])
    del report[field]
    value = message("RESULT_CANDIDATE", {"report": report})
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_message(value)
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_frame(raw_frame(value))


@pytest.mark.parametrize("field", ["scan_time", "app_version", "platform", "python_version"])
def test_candidate_report_missing_metadata_fields_are_rejected(protocol, field):
    report = candidate_report([diagnostic()])
    del report["metadata"][field]
    value = message("RESULT_CANDIDATE", {"report": report})
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_message(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "0.9"),
        ("schema_version", 1),
        ("metadata", []),
        ("metadata", {"scan_time": "2026-01-01T00:00:00+00:00"}),
        ("scan_time", "2026-01-01T00:00:00"),
        ("scan_time", "not-a-timestamp"),
        ("scan_time", "x" * 129),
        ("app_version", ""),
        ("platform", None),
        ("python_version", 3.13),
    ],
)
def test_candidate_report_metadata_values_are_strictly_validated(protocol, field, value):
    report = candidate_report([diagnostic()])
    if field in {"schema_version", "metadata"}:
        report[field] = value
    else:
        report["metadata"][field] = value
    value = message("RESULT_CANDIDATE", {"report": report})
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_message(value)


def test_candidate_report_unknown_metadata_field_is_rejected(protocol):
    report = candidate_report([diagnostic()])
    report["metadata"]["secret"] = "fictional"
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_message(message("RESULT_CANDIDATE", {"report": report}))


@pytest.mark.parametrize(
    "field,value",
    [
        ("rule_id", "UNKNOWN_RULE"),
        ("title", None),
        ("summary", 12),
        ("suggestion", {}),
        ("severity", "critical"),
        ("status", "unknown"),
        ("evidence", "raw output"),
        ("evidence", ["raw token=fictional"]),
        ("evidence", ["Verified version: ٣.١.٢"]),
        ("evidence", ["Verified version: 3.13.9\n"]),
        ("title", "x" * 4097),
        ("summary", chr(0xD800)),
        ("suggestion", chr(0xDC00)),
        ("evidence", ["x"] * 65),
    ],
)
def test_invalid_diagnostics_cannot_become_partial_candidates(protocol, field, value):
    invalid = {**diagnostic(), field: value}
    candidate = message("RESULT_CANDIDATE", {"diagnostics": [diagnostic(), invalid]})
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_message(candidate)


@pytest.mark.parametrize("field", list(diagnostic()))
def test_missing_diagnostic_fields_are_rejected(protocol, field):
    item = diagnostic()
    del item[field]
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_frame(raw_frame(message("RESULT_CANDIDATE", {"diagnostics": [item]})))


@pytest.mark.parametrize("field", ["cleanup_status", "stdout", "stderr", "metadata", "future"])
def test_extra_diagnostic_fields_are_rejected(protocol, field):
    item = {**diagnostic(), field: "fictional-secret"}
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_message(message("RESULT_CANDIDATE", {"diagnostics": [item]}))


def test_candidate_diagnostic_count_boundary(protocol):
    candidate = message("RESULT_CANDIDATE", {"diagnostics": [diagnostic()] * 64})
    restored = protocol.decode_frame(protocol.encode_message(candidate))
    assert len(restored["payload"]["report"]["diagnostics"]) == 64
    candidate["payload"]["report"]["diagnostics"].append(diagnostic())
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_message(candidate)


def advance_to_running(protocol):
    session = protocol.ProtocolSession(SESSION)
    session.accept_frame(raw_frame(message()), sender="child")
    session.accept_frame(raw_frame(message("START", {"deadline": 100})), sender="parent")
    return session


def test_session_valid_success_and_stop_sequences(protocol):
    session = advance_to_running(protocol)
    candidate = message("RESULT_CANDIDATE", {"diagnostics": []}, sequence=1)
    assert session.accept_frame(raw_frame(candidate), sender="child") == candidate
    assert session.phase == "candidate" and not session.failed
    assert session.budget.message_count == 3
    stopped = advance_to_running(protocol)
    stopped.accept_frame(raw_frame(message("STOP", {"reason": "user_request"}, 1)), sender="parent")
    stopped.accept_frame(
        raw_frame(message("STOP_OBSERVED", {"reason": "user_request"}, 1)), sender="child"
    )
    assert stopped.phase == "stop_observed"


@pytest.mark.parametrize("sequence", [0, -1, True, 2, 1.0])
def test_repeated_out_of_order_sequences_reject_session(protocol, sequence):
    session = advance_to_running(protocol)
    before = session.budget.total_bytes
    with pytest.raises(protocol.ProtocolError):
        session.accept_frame(
            raw_frame(message("FAILED", {"code": "SCAN_FAILED"}, sequence)), sender="child"
        )
    assert session.failed and session.budget.total_bytes == before
    with pytest.raises(protocol.ProtocolError):
        session.accept_frame(
            raw_frame(message("FAILED", {"code": "SCAN_FAILED"}, 1)), sender="child"
        )


def test_old_session_and_wrong_direction_are_rejected(protocol):
    for value, sender in ((message(session_id="b" * 32), "child"), (message(), "parent")):
        session = protocol.ProtocolSession(SESSION)
        with pytest.raises(protocol.ProtocolError):
            session.accept_frame(raw_frame(value), sender=sender)
        assert session.failed and session.budget.message_count == 0


def test_stop_before_start_and_terminal_message_order(protocol):
    session = protocol.ProtocolSession(SESSION)
    session.accept_frame(raw_frame(message("STOP", {"reason": "window_close"})), sender="parent")
    session.accept_frame(
        raw_frame(message("STOP_OBSERVED", {"reason": "window_close"})), sender="child"
    )
    with pytest.raises(protocol.ProtocolError):
        session.accept_frame(raw_frame(message("READY", sequence=1)), sender="child")


def test_unknown_stop_reason_cannot_replace_first_or_authorize_result(protocol):
    for kind, payload in (
        ("STOP", {"reason": "deadline_exceeded"}),
        ("STOP_OBSERVED", {"reason": "window_close"}),
        ("RESULT_CANDIDATE", {"diagnostics": []}),
    ):
        session = advance_to_running(protocol)
        session.accept_frame(
            raw_frame(message("STOP", {"reason": "user_request"}, 1)), sender="parent"
        )
        with pytest.raises(protocol.ProtocolError):
            session.accept_frame(
                raw_frame(message(kind, payload, 2 if kind == "STOP" else 1)),
                sender="parent" if kind == "STOP" else "child",
            )


def test_codec_is_pure_and_does_not_execute_scan_or_collect_environment(protocol, monkeypatch):
    from dev_env_doctor.core import runner

    def forbidden(*args, **kwargs):
        pytest.fail("protocol must not invoke scanning")

    monkeypatch.setattr(runner, "run_scan", forbidden)
    monkeypatch.setattr(runner, "probe_tool", forbidden)
    monkeypatch.setattr(runner, "inspect_process_path", forbidden)
    assert protocol.decode_frame(protocol.encode_message(message())) == message()


def test_stop_after_candidate_is_allowed_until_supervisor_accepts_result(protocol):
    session = advance_to_running(protocol)
    session.accept_frame(
        raw_frame(message("RESULT_CANDIDATE", {"diagnostics": []}, 1)), sender="child"
    )
    session.accept_frame(raw_frame(message("STOP", {"reason": "window_close"}, 1)), sender="parent")
    session.accept_frame(
        raw_frame(message("STOP_OBSERVED", {"reason": "window_close"}, 2)), sender="child"
    )
    assert session.phase == "stop_observed" and not session.failed


def test_duplicate_candidate_is_not_accepted(protocol):
    session = advance_to_running(protocol)
    session.accept_frame(
        raw_frame(message("RESULT_CANDIDATE", {"diagnostics": []}, 1)), sender="child"
    )
    with pytest.raises(protocol.ProtocolError):
        session.accept_frame(
            raw_frame(message("RESULT_CANDIDATE", {"diagnostics": []}, 2)), sender="child"
        )
    assert session.failed and session.budget.message_count == 3


@pytest.mark.parametrize(
    "kind,payload", [("FAILED", {"code": "SCAN_FAILED"}), ("CLEANUP_UNCONFIRMED", {})]
)
def test_failure_after_candidate_prevents_success(protocol, kind, payload):
    session = advance_to_running(protocol)
    session.accept_frame(
        raw_frame(message("RESULT_CANDIDATE", {"diagnostics": []}, 1)), sender="child"
    )
    session.accept_frame(raw_frame(message(kind, payload, 2)), sender="child")
    assert session.phase == "finished"


def test_session_message_limit_counts_both_directions_and_repeated_stop(protocol):
    session = protocol.ProtocolSession(SESSION)
    for index in range(32):
        session.accept_frame(
            raw_frame(message("STOP", {"reason": "user_request"}, index)), sender="parent"
        )
    before = session.budget.total_bytes
    with pytest.raises(protocol.ProtocolError):
        session.accept_frame(
            raw_frame(message("STOP_OBSERVED", {"reason": "user_request"})), sender="child"
        )
    assert session.failed
    assert session.budget.message_count == 32 and session.budget.total_bytes == before


def test_session_wire_byte_limit_uses_received_size_not_canonical_encoding(protocol):
    session = protocol.ProtocolSession(SESSION)
    for index in range(4):
        data = json.dumps(message("STOP", {"reason": "user_request"}, index)).encode()
        data += b" " * (protocol.MAX_FRAME_BYTES - 4 - len(data))
        session.accept_frame(struct.pack("!I", len(data)) + data, sender="parent")
    with pytest.raises(protocol.ProtocolError):
        session.accept_frame(
            raw_frame(message("STOP_OBSERVED", {"reason": "user_request"})), sender="child"
        )
    assert session.failed and session.budget.total_bytes == protocol.MAX_SESSION_BYTES
    assert session.budget.message_count == 4


def test_candidate_does_not_read_platform_defaults(protocol, monkeypatch):
    from dev_env_doctor.core import models

    def forbidden():
        pytest.fail("protocol must not collect metadata")

    monkeypatch.setattr(models.platform_info, "platform", forbidden)
    monkeypatch.setattr(models.platform_info, "python_version", forbidden)
    # Default factories capture their original callables at model definition;
    # guard model construction too, not just the module's current attributes.
    monkeypatch.setattr(models.ScanMetadata, "__init__", lambda *args, **kwargs: forbidden())
    monkeypatch.setattr(models.ScanReport, "__init__", lambda *args, **kwargs: forbidden())
    assert protocol.decode_frame(
        protocol.encode_message(message("RESULT_CANDIDATE", {"diagnostics": [diagnostic()]}))
    )["payload"]["report"]["diagnostics"] == [diagnostic()]


def test_rejects_excessive_outbound_depth_and_encoded_size(protocol):
    nested = "fictional"
    for _ in range(10):
        nested = [nested]
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_message(message("START", {"deadline": nested}))
    item = {**diagnostic(), "summary": "文" * 4096, "suggestion": "文" * 4096}
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_message(message("RESULT_CANDIDATE", {"diagnostics": [item] * 64}))


@pytest.mark.parametrize("invalid", [None, True, "f" * 31, "../bad", "F" * 32])
def test_session_constructor_rejects_invalid_identity(protocol, invalid):
    with pytest.raises(protocol.ProtocolError):
        protocol.ProtocolSession(invalid)


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), -float("inf"), 2**53 + 1])
def test_start_rejects_nonfinite_or_lossy_absolute_deadline(protocol, deadline):
    value = message("START", {"deadline": deadline})
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_message(value)
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_frame(raw_frame(value))


@pytest.mark.parametrize("reason", ["user_request", "window_close", "deadline_exceeded", "failure"])
def test_all_fixed_stop_reasons_roundtrip(protocol, reason):
    for kind in ("STOP", "STOP_OBSERVED"):
        value = message(kind, {"reason": reason})
        assert protocol.decode_frame(protocol.encode_message(value)) == value


def test_bad_candidate_is_transactional_at_session_boundary(protocol):
    session = advance_to_running(protocol)
    before = (session.budget.message_count, session.budget.total_bytes)
    candidate = message(
        "RESULT_CANDIDATE",
        {"diagnostics": [diagnostic(), {**diagnostic(), "stdout": "fictional-secret"}]},
        sequence=1,
    )
    with pytest.raises(protocol.ProtocolError) as error:
        session.accept_frame(raw_frame(candidate), sender="child")
    assert str(error.value) == "Invalid scan protocol message."
    assert session.failed and session.phase == "running"
    assert (session.budget.message_count, session.budget.total_bytes) == before


def test_decode_applies_shared_redaction_even_to_manually_formed_input(protocol):
    item = {**diagnostic(), "summary": "api_key=fictional-wire-secret"}
    restored = protocol.decode_frame(
        raw_frame(message("RESULT_CANDIDATE", {"diagnostics": [item]}))
    )
    assert "fictional-wire-secret" not in json.dumps(restored)
    assert restored["payload"]["report"]["diagnostics"][0]["evidence"] == diagnostic()["evidence"]


def test_dictionary_key_and_value_surrogates_are_rejected(protocol):
    for value in ({**message(), chr(0xD800): "value"}, {**message(), "type": chr(0xDC00)}):
        with pytest.raises(protocol.ProtocolError):
            protocol.encode_message(value)


@pytest.mark.parametrize("frame", [None, "{}", bytearray(b"\0\0\0\2{}"), True])
def test_decoder_accepts_only_raw_bytes(protocol, frame):
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_frame(frame)


def test_ready_crossing_early_stop_does_not_authorize_scanning(protocol):
    session = protocol.ProtocolSession(SESSION)
    session.accept_frame(raw_frame(message("STOP", {"reason": "window_close"})), sender="parent")
    session.accept_frame(raw_frame(message()), sender="child")
    assert session.phase == "stopping"
    session.accept_frame(
        raw_frame(message("STOP_OBSERVED", {"reason": "window_close"}, 1)), sender="child"
    )
    assert session.phase == "stop_observed"
    with pytest.raises(protocol.ProtocolError):
        session.accept_frame(raw_frame(message("START", {"deadline": 100}, 1)), sender="parent")


def test_stop_observation_is_not_exit_or_cleanup_confirmation(protocol):
    session = advance_to_running(protocol)
    session.accept_frame(raw_frame(message("STOP", {"reason": "user_request"}, 1)), sender="parent")
    session.accept_frame(
        raw_frame(message("STOP_OBSERVED", {"reason": "user_request"}, 1)), sender="child"
    )
    assert session.phase == "stop_observed"
    session.accept_frame(raw_frame(message("CLEANUP_UNCONFIRMED", sequence=2)), sender="child")
    assert session.phase == "finished" and not session.failed
