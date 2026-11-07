"""Pure, bounded scan-control wire format; no transport or process operations.

Sequences start at zero independently for parent and child. A coordinator must
record both sent and received frames in order. RESULT_CANDIDATE is not lifecycle
success or cleanup evidence. Future transports must bound reads before calling
decode_frame; this module accepts exactly one complete frame, never partial I/O.
"""

import json
import math
import re
import struct
from datetime import datetime
from enum import StrEnum

from dev_env_doctor.core.models import DiagnosticResult, Severity
from dev_env_doctor.core.scan_control import StopReason
from dev_env_doctor.reports.json_report import (
    JSON_SCHEMA_VERSION,
    REVIEWED_RULE_IDS,
    _diagnostic_payload,
)

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 256 * 1024  # Includes the four-byte, unsigned network-order length.
MAX_SESSION_BYTES = 1024 * 1024  # Includes every frame prefix, in both directions.
MAX_MESSAGES = 32
MAX_DIAGNOSTICS = 64
MAX_DEPTH = 8
PATH_SNAPSHOT_KIND = "path_snapshot_v1"
MAX_PATH_CHARS = 4096
MAX_PATH_BYTES = 8192
MAX_PATH_POSITIONS = 128
MAX_PATH_ENTRY_BYTES = 1024
_SESSION_ID = re.compile(r"[0-9a-f]{32}")
_ENVELOPE_FIELDS = {"version", "session_id", "sequence", "type", "payload"}
_DIAGNOSTIC_FIELDS = {"rule_id", "title", "summary", "severity", "status", "suggestion", "evidence"}
_REASONS = frozenset(reason.value for reason in StopReason)
_FAILURE_CODES = frozenset({"SCAN_FAILED", "STARTUP_FAILED", "PROTOCOL_ERROR", "INTERRUPTED"})


class ProtocolError(ValueError):
    """Fixed public error; never include rejected input or exception details."""

    def __init__(self) -> None:
        super().__init__("Invalid scan protocol message.")


class MessageType(StrEnum):
    """The complete version-one message allowlist."""

    READY = "READY"
    START = "START"
    STOP = "STOP"
    RESULT_CANDIDATE = "RESULT_CANDIDATE"
    FAILED = "FAILED"
    STOP_OBSERVED = "STOP_OBSERVED"
    CLEANUP_UNCONFIRMED = "CLEANUP_UNCONFIRMED"


_PAYLOAD_FIELDS = {
    MessageType.READY: set(),
    MessageType.START: {"deadline"},
    MessageType.STOP: {"reason"},
    MessageType.RESULT_CANDIDATE: {"report"},
    MessageType.FAILED: {"code"},
    MessageType.STOP_OBSERVED: {"reason"},
    MessageType.CLEANUP_UNCONFIRMED: set(),
}
_EXTENDED_START_FIELDS = _PAYLOAD_FIELDS[MessageType.START] | {"diagnostic_input"}
_REPORT_FIELDS = {"schema_version", "metadata", "diagnostics"}
_METADATA_FIELDS = {"scan_time", "app_version", "platform", "python_version"}


def _validate_tree(value: object, depth: int = 0, nodes: list[int] | None = None) -> None:
    """Bound containers, strings and visits before schema conversion/encoding."""
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if depth > MAX_DEPTH or nodes[0] > 4096:
        raise ProtocolError()
    if type(value) is dict:
        if len(value) > 8:
            raise ProtocolError()
        for key, item in value.items():
            if type(key) is not str or len(key) > 64:
                raise ProtocolError()
            key.encode("utf-8", errors="strict")
            _validate_tree(item, depth + 1, nodes)
    elif type(value) is list:
        if len(value) > MAX_DIAGNOSTICS:
            raise ProtocolError()
        for item in value:
            _validate_tree(item, depth + 1, nodes)
    elif type(value) is str:
        if len(value) > 4096:
            raise ProtocolError()
        value.encode("utf-8", errors="strict")
    elif type(value) in (int, float):
        if not math.isfinite(value):
            raise ProtocolError()
    elif value is not None and type(value) is not bool:
        raise ProtocolError()


def _validate_diagnostics(items: object) -> list[dict[str, object]]:
    if type(items) is not list or len(items) > MAX_DIAGNOSTICS:
        raise ProtocolError()
    result = []
    for item in items:
        if type(item) is not dict or set(item) != _DIAGNOSTIC_FIELDS:
            raise ProtocolError()
        if any(type(item[key]) is not str for key in _DIAGNOSTIC_FIELDS - {"evidence"}):
            raise ProtocolError()
        if item["rule_id"] not in REVIEWED_RULE_IDS:
            raise ProtocolError()
        if item["severity"] not in {severity.value for severity in Severity}:
            raise ProtocolError()
        if item["status"] not in {"found", "passed", "skipped", "error"}:
            raise ProtocolError()
        evidence = item["evidence"]
        if type(evidence) is not list or len(evidence) > 1:
            raise ProtocolError()
        if any(type(value) is not str for value in evidence):
            raise ProtocolError()
        diagnostic = DiagnosticResult(**item)
        # Reuse the existing field/rule/redaction/evidence boundary, not a new
        # permissive serializer. No report metadata/default factories are used.
        safe = _diagnostic_payload(diagnostic, machine_names=())
        if safe["evidence"] != evidence:
            raise ProtocolError()
        result.append(safe)
    return result


def _validate_report(report: object) -> dict[str, object]:
    if type(report) is not dict or set(report) != _REPORT_FIELDS:
        raise ProtocolError()
    if report["schema_version"] != JSON_SCHEMA_VERSION:
        raise ProtocolError()
    metadata = report["metadata"]
    if type(metadata) is not dict or set(metadata) != _METADATA_FIELDS:
        raise ProtocolError()
    scan_time = metadata["scan_time"]
    if type(scan_time) is not str or len(scan_time) > 128:
        raise ProtocolError()
    try:
        parsed_time = datetime.fromisoformat(scan_time)
    except (TypeError, ValueError):
        raise ProtocolError() from None
    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
        raise ProtocolError()
    safe_metadata: dict[str, str] = {"scan_time": scan_time}
    for key in ("app_version", "platform", "python_version"):
        value = metadata[key]
        if type(value) is not str or not value.strip() or len(value) > 256:
            raise ProtocolError()
        value.encode("utf-8", errors="strict")
        safe_metadata[key] = value
    return {
        "schema_version": JSON_SCHEMA_VERSION,
        "metadata": safe_metadata,
        "diagnostics": _validate_diagnostics(report["diagnostics"]),
    }


def validate_path_snapshot(value: object) -> str:
    """Accept one bounded diagnostic string without expanding or rewriting it."""
    if type(value) is not str or len(value) > MAX_PATH_CHARS:
        raise ProtocolError()
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise ProtocolError()
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        size = MAX_PATH_BYTES + 1
    if size > MAX_PATH_BYTES or value.count(";") >= MAX_PATH_POSITIONS:
        raise ProtocolError()
    for raw_entry in value.split(";"):
        if len(raw_entry.encode("utf-8", errors="strict")) > MAX_PATH_ENTRY_BYTES:
            raise ProtocolError()
        entry = raw_entry.strip(" ")
        if '"' in entry and not (
            entry.startswith('"') and entry.endswith('"') and entry.count('"') == 2
        ):
            raise ProtocolError()
    return value


def _validated_message(value: object) -> dict[str, object]:
    _validate_tree(value)
    if type(value) is not dict or set(value) != _ENVELOPE_FIELDS:
        raise ProtocolError()
    if type(value["version"]) is not int or value["version"] != PROTOCOL_VERSION:
        raise ProtocolError()
    session_id = value["session_id"]
    if type(session_id) is not str or _SESSION_ID.fullmatch(session_id) is None:
        raise ProtocolError()
    sequence = value["sequence"]
    if type(sequence) is not int or not 0 <= sequence < MAX_MESSAGES:
        raise ProtocolError()
    if type(value["type"]) is not str:
        raise ProtocolError()
    kind = MessageType(value["type"])
    payload = value["payload"]
    if type(payload) is not dict:
        raise ProtocolError()
    fields = set(payload)
    extended_start = kind is MessageType.START and fields == _EXTENDED_START_FIELDS
    if fields != _PAYLOAD_FIELDS[kind] and not extended_start:
        raise ProtocolError()
    safe_payload = dict(payload)
    if kind is MessageType.START:
        deadline = payload["deadline"]
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise ProtocolError()
        if type(deadline) is int and float(deadline) != deadline:
            raise ProtocolError()
        if extended_start:
            diagnostic_input = payload["diagnostic_input"]
            if (
                type(diagnostic_input) is not dict
                or set(diagnostic_input) != {"kind", "value"}
                or type(diagnostic_input["kind"]) is not str
                or diagnostic_input["kind"] != PATH_SNAPSHOT_KIND
            ):
                raise ProtocolError()
            validate_path_snapshot(diagnostic_input["value"])
    elif kind in (MessageType.STOP, MessageType.STOP_OBSERVED):
        if type(payload["reason"]) is not str or payload["reason"] not in _REASONS:
            raise ProtocolError()
    elif kind is MessageType.FAILED:
        if type(payload["code"]) is not str or payload["code"] not in _FAILURE_CODES:
            raise ProtocolError()
    elif kind is MessageType.RESULT_CANDIDATE:
        safe_payload = {"report": _validate_report(payload["report"])}
    return {**value, "payload": safe_payload}


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError()
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ProtocolError()


def _check_json_depth(text: str) -> None:
    """Reject excessive nesting before the standard JSON parser allocates it."""
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ProtocolError()
        elif char in "]}":
            depth -= 1


def encode_message(message: object) -> bytes:
    """Validate/redact an explicit message and encode one complete bounded frame."""
    try:
        safe = _validated_message(message)
        data = json.dumps(safe, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        body = data.encode("utf-8", errors="strict")
        if len(body) + 4 > MAX_FRAME_BYTES:
            raise ProtocolError()
        return struct.pack("!I", len(body)) + body
    except (ValueError, TypeError, OverflowError, RecursionError):
        pass
    raise ProtocolError() from None


def decode_frame(frame: bytes) -> dict[str, object]:
    """Validate exactly one frame; reject incomplete, oversized or trailing data."""
    try:
        if type(frame) is not bytes or not 4 < len(frame) <= MAX_FRAME_BYTES:
            raise ProtocolError()
        size = struct.unpack("!I", frame[:4])[0]
        if size != len(frame) - 4:
            raise ProtocolError()
        text = frame[4:].decode("utf-8", errors="strict")
        _check_json_depth(text)
        value = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        return _validated_message(value)
    except (ValueError, TypeError, OverflowError, RecursionError):
        pass
    raise ProtocolError() from None


class MessageBudget:
    """Account wire bytes (including prefixes) and messages; overflow is sticky."""

    __slots__ = ("_total_bytes", "_message_count", "_rejected")

    def __init__(self) -> None:
        self._total_bytes = self._message_count = 0
        self._rejected = False

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    @property
    def message_count(self) -> int:
        return self._message_count

    def consume(self, frame_bytes: int) -> None:
        """Commit a whole frame or reject without changing accepted counters."""
        if (
            self._rejected
            or type(frame_bytes) is not int
            or not 4 < frame_bytes <= MAX_FRAME_BYTES
            or self._total_bytes + frame_bytes > MAX_SESSION_BYTES
            or self._message_count >= MAX_MESSAGES
        ):
            self._rejected = True
            raise ProtocolError()
        self._total_bytes += frame_bytes
        self._message_count += 1


class ProtocolSession:
    """Validate both directions for one session; any rejection poisons the session.

    A candidate leaves stop/failure messages possible until the supervisor
    confirms cleanup. STOP_OBSERVED only acknowledges receipt, not exit or
    cleanup; later cleanup failure remains possible. No protocol phase is scan
    success. Process exit and lifecycle decisions belong to the future supervisor.
    Instances have no
    reset method and must not be shared concurrently without a single owner.
    """

    def __init__(self, session_id: str) -> None:
        if type(session_id) is not str or _SESSION_ID.fullmatch(session_id) is None:
            raise ProtocolError()
        self._session_id = session_id
        self._next = {"parent": 0, "child": 0}
        self._phase = "waiting"
        self._stop_reason: str | None = None
        self._failed = False
        self._budget = MessageBudget()

    @property
    def phase(self) -> str:
        return self._phase

    @property
    def failed(self) -> bool:
        return self._failed

    @property
    def budget(self) -> MessageBudget:
        return self._budget

    def _next_phase(self, message: dict[str, object], sender: str) -> str:
        kind = MessageType(message["type"])
        if self._phase == "finished":
            raise ProtocolError()
        if sender == "parent":
            if kind is MessageType.START and self._phase == "ready":
                return "running"
            if kind is MessageType.STOP:
                reason = message["payload"]["reason"]
                if self._stop_reason is not None and reason != self._stop_reason:
                    raise ProtocolError()
                return "stop_observed" if self._phase == "stop_observed" else "stopping"
        else:
            if kind is MessageType.READY and self._phase == "waiting":
                return "ready"
            if kind is MessageType.READY and self._phase == "stopping" and self._next["child"] == 0:
                # READY may already be in flight when the parent requests stop.
                # It must never reopen the START authorization path.
                return "stopping"
            if kind in (MessageType.FAILED, MessageType.CLEANUP_UNCONFIRMED):
                return "finished"
            if kind is MessageType.RESULT_CANDIDATE and self._phase == "running":
                return "candidate"
            if kind is MessageType.STOP_OBSERVED and self._phase == "stopping":
                if message["payload"]["reason"] == self._stop_reason:
                    return "stop_observed"
        raise ProtocolError()

    def accept_frame(self, frame: bytes, *, sender: str) -> dict[str, object]:
        """Validate fully before committing sequence, phase and byte/message counts."""
        try:
            if self._failed or type(sender) is not str or sender not in self._next:
                raise ProtocolError()
            message = decode_frame(frame)
            if message["session_id"] != self._session_id:
                raise ProtocolError()
            if message["sequence"] != self._next[sender]:
                raise ProtocolError()
            phase = self._next_phase(message, sender)
            self._budget.consume(len(frame))
        except ProtocolError:
            self._failed = True
            raise
        self._next[sender] += 1
        self._phase = phase
        if message["type"] == MessageType.STOP:
            self._stop_reason = message["payload"]["reason"]
        return message
