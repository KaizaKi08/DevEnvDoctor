"""Fixed worker entry for one bounded diagnostic candidate session."""

import argparse
from enum import IntEnum

from dev_env_doctor.core import runner
from dev_env_doctor.core.environment_probe import run_probe
from dev_env_doctor.core.models import DiagnosticResult, ScanReport
from dev_env_doctor.core.scan_control import ScanCleanupUnconfirmedError
from dev_env_doctor.core.scan_ipc import FramedTransport, PipeEndpoint
from dev_env_doctor.core.scan_protocol import MessageType, ProtocolSession, encode_message
from dev_env_doctor.core.worker_task import WorkerTaskMode
from dev_env_doctor.reports.json_report import _diagnostic_payload


class WorkerExitCode(IntEnum):
    """Internal exit reasons; zero and generic failure remain compatible."""

    SUCCESS = 0
    SCAN_FAILED = 1
    CANDIDATE_BUILD_FAILED = 2
    CANDIDATE_SEND_FAILED = 3
    FAILED_MESSAGE_SEND_FAILED = 4
    STARTUP_FAILED = 5
    FAILED_MESSAGE_SENT = 6


def _message(
    session_id: str, sequence: int, kind: MessageType, payload: dict[str, object]
) -> bytes:
    return encode_message(
        {
            "version": 1,
            "session_id": session_id,
            "sequence": sequence,
            "type": kind.value,
            "payload": payload,
        }
    )


def _candidate_payload(report: ScanReport) -> dict[str, object]:
    """Convert a report through the existing reviewed diagnostic boundary."""
    if not isinstance(report, ScanReport) or not isinstance(report.diagnostics, list):
        raise ValueError("The scan report is invalid.")
    if any(not isinstance(item, DiagnosticResult) for item in report.diagnostics):
        raise ValueError("The scan report is invalid.")
    return {
        "schema_version": report.schema_version,
        "metadata": {
            "scan_time": report.metadata.scan_time.isoformat(),
            "app_version": report.metadata.app_version,
            "platform": report.metadata.platform,
            "python_version": report.metadata.python_version,
        },
        "diagnostics": [_diagnostic_payload(item, machine_names=()) for item in report.diagnostics],
    }


def _send_failed(
    session: ProtocolSession,
    transport: FramedTransport,
    session_id: str,
    sequence: int,
    code: str,
    sent_code: WorkerExitCode = WorkerExitCode.SCAN_FAILED,
) -> WorkerExitCode:
    failed = _message(session_id, sequence, MessageType.FAILED, {"code": code})
    session.accept_frame(failed, sender="child")
    try:
        transport.send(failed)
    except Exception:
        return WorkerExitCode.FAILED_MESSAGE_SEND_FAILED
    return sent_code


def run_worker(
    session_id: str,
    read_handle: int,
    write_handle: int,
    mode: WorkerTaskMode = WorkerTaskMode.FULL_SCAN,
    *,
    require_path_snapshot: bool = False,
) -> int:
    transport = FramedTransport(PipeEndpoint.from_inherited_handles(read_handle, write_handle))
    session = ProtocolSession(session_id)
    child_sequence = 0
    try:
        try:
            ready = _message(session_id, child_sequence, MessageType.READY, {})
            session.accept_frame(ready, sender="child")
            transport.send(ready)
            child_sequence += 1
            start = session.accept_frame(transport.receive(), sender="parent")
            if start["type"] != MessageType.START.value:
                raise ValueError("START is required before scanning.")
            diagnostic_input = start["payload"].get("diagnostic_input")
            del start
            if require_path_snapshot != (diagnostic_input is not None) or (
                mode is not WorkerTaskMode.FULL_SCAN and diagnostic_input is not None
            ):
                return int(WorkerExitCode.STARTUP_FAILED)
            path_snapshot = diagnostic_input["value"] if diagnostic_input is not None else None
            del diagnostic_input
        except Exception:
            return int(WorkerExitCode.STARTUP_FAILED)
        try:
            if mode is WorkerTaskMode.FULL_SCAN:
                report = (
                    runner.run_scan()
                    if path_snapshot is None
                    else runner.run_scan(path_snapshot=path_snapshot)
                )
            elif mode is WorkerTaskMode.ENVIRONMENT_PROBE:
                report = run_probe()
            else:
                return int(WorkerExitCode.STARTUP_FAILED)
        except ScanCleanupUnconfirmedError:
            return int(
                _send_failed(
                    session,
                    transport,
                    session_id,
                    child_sequence,
                    "INTERRUPTED",
                    WorkerExitCode.FAILED_MESSAGE_SENT,
                )
            )
        except Exception:
            return int(_send_failed(session, transport, session_id, child_sequence, "SCAN_FAILED"))
        finally:
            path_snapshot = None
        try:
            candidate = _message(
                session_id,
                child_sequence,
                MessageType.RESULT_CANDIDATE,
                {"report": _candidate_payload(report)},
            )
            session.accept_frame(candidate, sender="child")
        except Exception:
            return int(
                _send_failed(
                    session,
                    transport,
                    session_id,
                    child_sequence,
                    "SCAN_FAILED",
                    WorkerExitCode.CANDIDATE_BUILD_FAILED,
                )
            )
        try:
            transport.send(candidate)
        except Exception:
            return int(WorkerExitCode.CANDIDATE_SEND_FAILED)
        return int(WorkerExitCode.SUCCESS)
    finally:
        transport.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--session", required=True)
    parser.add_argument("--read-handle", required=True, type=int)
    parser.add_argument("--write-handle", required=True, type=int)
    parser.add_argument("--mode", choices=[mode.value for mode in WorkerTaskMode], required=True)
    parser.add_argument("--require-path-snapshot", action="store_true")
    args = parser.parse_args(argv)
    return run_worker(
        args.session,
        args.read_handle,
        args.write_handle,
        WorkerTaskMode(args.mode),
        require_path_snapshot=args.require_path_snapshot,
    )


if __name__ == "__main__":
    raise SystemExit(main())
