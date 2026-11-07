"""Read-only lookup and bounded version probes for allowlisted tools."""

import ntpath
import re
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import BinaryIO, Literal

from dev_env_doctor.collectors.executable_lookup import (
    find_local_executable,
    is_trusted_executable,
)
from dev_env_doctor.core.models import ProcessCleanupStatus
from dev_env_doctor.core.process_environment import (
    PROBE_UNICODE_NAME,
    PROBE_UNICODE_VALUE,
    EnvironmentConstructionError,
    build_tool_environment,
)
from dev_env_doctor.core.scan_control import ScanCleanupUnconfirmedError
from dev_env_doctor.privacy.redaction import redact_text

DEFAULT_TIMEOUT_SECONDS = 5
CLEANUP_WAIT_SECONDS = 1.0
READER_JOIN_SECONDS = 1.0
READER_FINAL_JOIN_SECONDS = 0.25
MAX_VERSION_LENGTH = 160
MAX_OUTPUT_BYTES_PER_STREAM = 4096
_RECEIPT_OUTPUT_LIMIT = 64
_READ_CHUNK_BYTES = 1024
_VERSION_PATTERNS = {
    "python": re.compile(r"Python ([0-9]+\.[0-9]+\.[0-9]+)"),
    "git": re.compile(r"git version ([0-9]+\.[0-9]+\.[0-9]+(?:\.windows\.[0-9]+)?)"),
    "node": re.compile(r"v([0-9]+\.[0-9]+\.[0-9]+)"),
}
_ENVIRONMENT_RECEIPT_SCRIPT = (
    "import os,sys; "
    f"marker='PASS' if os.environ.get({ascii(PROBE_UNICODE_NAME)})"
    f"=={ascii(PROBE_UNICODE_VALUE)} else 'FAIL'; "
    "sensitive='FAIL' if any(k.upper() in "
    "{'PYTHONPATH','NODE_OPTIONS','GIT_CONFIG_GLOBAL','CODEX_API_KEY','HTTPS_PROXY','TOKEN'} "
    "for k in os.environ) else 'PASS'; "
    "sys.stdout.buffer.write(f'ENV_RECEIPT_V1 MARKER={marker} SENSITIVE={sensitive}\\n'"
    ".encode('ascii'))"
)
_RECEIPT_OUTPUT = re.compile(rb"ENV_RECEIPT_V1 MARKER=(PASS|FAIL) SENSITIVE=(PASS|FAIL)\n")
_ReceiptStatus = Literal["PASS", "FAIL", "NOT_VERIFIED"]


@dataclass(frozen=True)
class ToolReceipt:
    """Independent, privacy-safe observations of the fixed Python probe."""

    started: _ReceiptStatus = "NOT_VERIFIED"
    environment_received: _ReceiptStatus = "NOT_VERIFIED"
    sensitive_variables_absent: _ReceiptStatus = "NOT_VERIFIED"
    exit_success: _ReceiptStatus = "NOT_VERIFIED"
    output_valid: _ReceiptStatus = "NOT_VERIFIED"


@dataclass(frozen=True)
class ToolSpec:
    """Fixed executable name and optional version arguments for a tool."""

    executable: str
    version_args: tuple[str, ...] | None


TOOL_SPECS = {
    "python": ToolSpec("python", ("--version",)),
    "git": ToolSpec("git", ("--version",)),
    "node": ToolSpec("node", ("--version",)),
    "npm": ToolSpec("npm", None),
    "codex": ToolSpec("codex", None),
}


class ProbeStatus(StrEnum):
    """Outcome of executable lookup and optional version verification."""

    MISSING = "missing"
    FOUND_UNVERIFIED = "found_unverified"
    VERIFIED = "verified"
    NONZERO_EXIT = "nonzero_exit"
    TIMEOUT = "timeout"
    ERROR = "error"


_EXECUTED_CLEANUP_STATUSES = frozenset(
    {ProcessCleanupStatus.CONFIRMED, ProcessCleanupStatus.UNCONFIRMED}
)
_ALLOWED_CLEANUP_STATUSES = {
    ProbeStatus.MISSING: frozenset({ProcessCleanupStatus.NOT_STARTED}),
    # Codex/batch launchers are lookup-only; rejected version output is post-launch.
    ProbeStatus.FOUND_UNVERIFIED: frozenset(ProcessCleanupStatus),
    ProbeStatus.VERIFIED: _EXECUTED_CLEANUP_STATUSES,
    ProbeStatus.NONZERO_EXIT: _EXECUTED_CLEANUP_STATUSES,
    ProbeStatus.TIMEOUT: _EXECUTED_CLEANUP_STATUSES,
    ProbeStatus.ERROR: frozenset(ProcessCleanupStatus),
}


@dataclass(frozen=True)
class CommandProbeResult:
    """Privacy-safe command probe result; executable paths are redacted."""

    tool: str
    status: ProbeStatus
    executable: str | None = None
    version: str | None = None
    message: str = ""
    cleanup_status: ProcessCleanupStatus = ProcessCleanupStatus.NOT_STARTED

    def __post_init__(self) -> None:
        validate_probe_result(self)


def validate_probe_result(result: object) -> None:
    """Validate internal result types and stage consistency, without coercion.

    Both construction and the runner boundary use this pure check. It never
    reads command output or incorporates an untrusted value into its errors.
    """
    if not isinstance(result, CommandProbeResult):
        raise TypeError("result must be a CommandProbeResult.")
    status = getattr(result, "status", None)
    cleanup = getattr(result, "cleanup_status", None)
    if not isinstance(status, ProbeStatus):
        raise TypeError("status must be a ProbeStatus.")
    if not isinstance(cleanup, ProcessCleanupStatus):
        raise TypeError("cleanup_status must be a ProcessCleanupStatus.")
    if cleanup not in _ALLOWED_CLEANUP_STATUSES[status]:
        raise ValueError("Probe status and cleanup_status are inconsistent.")


class _ReaderStartState(StrEnum):
    """What the caller knows about its single attempt to start a reader."""

    NOT_ATTEMPTED = "not_attempted"
    RETURNED = "returned"
    UNCERTAIN = "uncertain"


@dataclass
class _OutputReader:
    """Private startup record; ``started`` stores positive startup evidence."""

    thread: threading.Thread
    started: threading.Event
    start_state: _ReaderStartState = _ReaderStartState.NOT_ATTEMPTED


def _read_bounded_stream(
    stream: BinaryIO,
    limit: int,
    on_limit: Callable[[], None] | None = None,
) -> tuple[bytes, bool, bool]:
    """Retain at most ``limit`` bytes and signal once a stream exceeds it."""
    captured = bytearray()
    exceeded = False
    failed = False
    try:
        while True:
            chunk = stream.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                failed = True
                break
            remaining = max(0, limit - len(captured))
            if len(chunk) > remaining:
                exceeded = True
                if on_limit is not None:
                    on_limit()
                    on_limit = None
            if remaining:
                captured.extend(chunk[:remaining])
    except Exception:
        failed = True
    return bytes(captured), exceeded, failed


def _close_process_pipes(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except Exception:
                pass


def _process_has_exited(process: subprocess.Popen[bytes]) -> bool:
    """Only an observed integer exit code confirms direct-child exit."""
    try:
        return type(process.poll()) is int
    except Exception:
        return False


def _stop_process(
    process: subprocess.Popen[bytes] | None,
    threads: list[_OutputReader],
) -> ProcessCleanupStatus:
    """Confirm the direct child and every managed reader, not descendants.

    A kill request is not exit evidence. Each wait/join has a timeout, but
    OS calls such as pipe close have no independently enforced time bound.
    """
    if process is None:
        return ProcessCleanupStatus.NOT_STARTED
    exited = _process_has_exited(process)
    if not exited:
        try:
            process.kill()
        except Exception:
            pass
        try:
            exited = type(process.wait(timeout=CLEANUP_WAIT_SECONDS)) is int
        except Exception:
            pass
        if not exited:
            exited = _process_has_exited(process)
    if not exited:
        _close_process_pipes(process)
    _captured, readers_stopped = _finish_output_readers(process, {}, threads)
    if exited and readers_stopped:
        return ProcessCleanupStatus.CONFIRMED
    return ProcessCleanupStatus.UNCONFIRMED


def _start_output_readers(
    process: subprocess.Popen[bytes],
    captured: dict[str, tuple[bytes, bool, bool]],
    threads: list[_OutputReader],
    *,
    limit: int | None = None,
) -> None:
    """Keep caller-owned reader references even when a later start fails."""
    if process.stdout is None or process.stderr is None:
        raise OSError("Child output pipes were unavailable")
    output_limit = MAX_OUTPUT_BYTES_PER_STREAM if limit is None else limit
    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        started = threading.Event()

        def collect_output(
            key: str = name,
            pipe: BinaryIO = stream,
            startup: threading.Event = started,
        ) -> None:
            # Entry into the target proves bootstrap reached the running phase.
            # This is not an assertion that the target or thread has ended.
            startup.set()
            captured[key] = _read_bounded_stream(pipe, output_limit, on_limit=process.kill)

        thread = threading.Thread(
            target=collect_output,
            daemon=True,
        )
        reader = _OutputReader(thread, started)
        threads.append(reader)
        # Leave UNCERTAIN in place if start raises any Exception/BaseException.
        reader.start_state = _ReaderStartState.UNCERTAIN
        thread.start()
        reader.start_state = _ReaderStartState.RETURNED


def _reader_start_confirmed(reader: _OutputReader) -> bool:
    """Use positive evidence, never absence of identity/liveness, for startup."""
    if reader.start_state is _ReaderStartState.RETURNED:
        return True
    if reader.start_state is _ReaderStartState.UNCERTAIN:
        if reader.started.is_set():
            return True
        if reader.thread.is_alive() is True:
            # Retain this observation even if a later check sees it has ended.
            reader.started.set()
            return True
    return False


def _readers_have_stopped(threads: list[_OutputReader]) -> bool:
    """False includes unknown liveness; never infer exit from join returning."""
    stopped = True
    for reader in threads:
        try:
            if reader.start_state is _ReaderStartState.NOT_ATTEMPTED:
                continue
            if not _reader_start_confirmed(reader) or reader.thread.is_alive() is not False:
                stopped = False
        except Exception:
            stopped = False
    return stopped


def _join_readers(threads: list[_OutputReader], timeout: float) -> None:
    for reader in threads:
        try:
            if not _reader_start_confirmed(reader):
                continue
            reader.thread.join(timeout=timeout)
        except Exception:
            # Failed state inspection or joining is not exit confirmation.
            pass


def _finish_output_readers(
    process: subprocess.Popen[bytes],
    captured: dict[str, tuple[bytes, bool, bool]],
    threads: list[_OutputReader],
) -> tuple[dict[str, tuple[bytes, bool, bool]], bool]:
    """Confirm reader exit separately from whether output collection succeeded."""
    _join_readers(threads, READER_JOIN_SECONDS)
    if not _readers_have_stopped(threads):
        _close_process_pipes(process)
        _join_readers(threads, READER_FINAL_JOIN_SECONDS)
        return captured, _readers_have_stopped(threads)
    return captured, True


def probe_python_environment(executable: str) -> ToolReceipt:
    """Run only the fixed internal environment receipt probe for trusted Python."""
    if (
        not isinstance(executable, str)
        or not ntpath.isabs(executable)
        or ntpath.basename(executable).lower() != "python.exe"
    ):
        return ToolReceipt()
    try:
        if not is_trusted_executable(executable):
            return ToolReceipt()
        environment = build_tool_environment(executable, include_probe_marker=True)
        if not is_trusted_executable(executable):
            return ToolReceipt()
    except Exception:
        return ToolReceipt()
    try:
        process = subprocess.Popen(
            [executable, "-I", "-S", "-c", _ENVIRONMENT_RECEIPT_SCRIPT],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            bufsize=0,
            env=environment,
        )
    except Exception:
        return ToolReceipt(started="FAIL")
    captured: dict[str, tuple[bytes, bool, bool]] = {}
    readers: list[_OutputReader] = []
    exit_success: _ReceiptStatus = "NOT_VERIFIED"
    waited = False
    try:
        _start_output_readers(process, captured, readers, limit=_RECEIPT_OUTPUT_LIMIT)
        try:
            wait_code = process.wait(timeout=DEFAULT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            exit_success = "FAIL"
        else:
            waited = True
            returncode = process.returncode
            if type(returncode) is int and type(wait_code) is int and returncode == wait_code:
                exit_success = "PASS" if returncode == 0 else "FAIL"
    except Exception:
        pass
    finally:
        try:
            cleanup = _stop_process(process, readers)
        except Exception:
            cleanup = ProcessCleanupStatus.UNCONFIRMED
        if cleanup is not ProcessCleanupStatus.CONFIRMED:
            raise ScanCleanupUnconfirmedError() from None

    if any(exceeded for _, exceeded, _ in captured.values()):
        return ToolReceipt(started="PASS", exit_success=exit_success, output_valid="FAIL")
    if not waited or len(captured) != 2:
        return ToolReceipt(started="PASS", exit_success=exit_success)
    stdout, _, stdout_failed = captured["stdout"]
    stderr, _, stderr_failed = captured["stderr"]
    if stdout_failed or stderr_failed:
        return ToolReceipt(started="PASS", exit_success=exit_success)
    match = _RECEIPT_OUTPUT.fullmatch(stdout) if not stderr else None
    if match is None:
        return ToolReceipt(started="PASS", exit_success=exit_success, output_valid="FAIL")
    if exit_success != "PASS":
        return ToolReceipt(started="PASS", exit_success=exit_success, output_valid="PASS")
    return ToolReceipt(
        started="PASS",
        environment_received="PASS" if match[1] == b"PASS" else "FAIL",
        sensitive_variables_absent="PASS" if match[2] == b"PASS" else "FAIL",
        exit_success=exit_success,
        output_valid="PASS",
    )


def probe_tool(tool: str, *, path_snapshot: str | None = None) -> CommandProbeResult:
    """Find an allowlisted tool and optionally run its fixed version command."""
    spec = TOOL_SPECS.get(tool)
    if spec is None:
        return CommandProbeResult(
            tool="unknown",
            status=ProbeStatus.ERROR,
            message="Tool is not in the supported probe list.",
        )

    try:
        executable = (
            find_local_executable(spec.executable)
            if path_snapshot is None
            else find_local_executable(spec.executable, path_value=path_snapshot)
        )
    except Exception:
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.ERROR,
            message="Executable lookup could not be completed.",
        )

    if executable is None:
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.MISSING,
            message="Executable was not found in the permitted search locations.",
        )

    safe_executable = redact_text(executable)
    if spec.version_args is None:
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.FOUND_UNVERIFIED,
            executable=safe_executable,
            message="Executable was found; version was not checked.",
        )
    if executable.lower().endswith((".bat", ".cmd")):
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.FOUND_UNVERIFIED,
            executable=safe_executable,
            message="Script launcher was found; version was not run without a shell.",
        )

    try:
        trusted = is_trusted_executable(executable)
    except Exception:
        trusted = False
    if not trusted:
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.FOUND_UNVERIFIED,
            executable=safe_executable,
            message="Executable was found; version was not verified.",
        )
    try:
        probe_environment = build_tool_environment(executable)
    except EnvironmentConstructionError:
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.FOUND_UNVERIFIED,
            executable=safe_executable,
            message="Executable was found; version was not verified.",
        )

    process: subprocess.Popen[bytes] | None = None
    captured: dict[str, tuple[bytes, bool, bool]] = {}
    threads: list[_OutputReader] = []
    timed_out = False
    probe_failed = True
    returncode: int | None = None
    trust_failed = False
    try:
        try:
            trusted = is_trusted_executable(executable)
        except Exception:
            trusted = False
        if not trusted:
            trust_failed = True
        else:
            process = subprocess.Popen(
                [executable, *spec.version_args],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                bufsize=0,
                env=probe_environment,
            )
            _start_output_readers(process, captured, threads)
            try:
                returncode = process.wait(timeout=DEFAULT_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
    except Exception:
        pass
    else:
        probe_failed = False
    finally:
        # A BaseException still propagates after this single cleanup attempt.
        # Ordinary cleanup errors must not replace a pending interruption or
        # turn a successfully created child's unknown cleanup into NOT_STARTED.
        cleanup_status = (
            ProcessCleanupStatus.NOT_STARTED
            if process is None
            else ProcessCleanupStatus.UNCONFIRMED
        )
        try:
            cleanup_status = _stop_process(process, threads)
        except Exception:
            probe_failed = True
        if probe_failed and process is not None:
            try:
                _close_process_pipes(process)
            except Exception:
                cleanup_status = ProcessCleanupStatus.UNCONFIRMED

    if trust_failed:
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.FOUND_UNVERIFIED,
            executable=safe_executable,
            message="Executable was found; version was not verified.",
            cleanup_status=cleanup_status,
        )
    if probe_failed:
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.ERROR,
            executable=safe_executable,
            message="Version check could not be completed.",
            cleanup_status=cleanup_status,
        )
    if timed_out:
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.TIMEOUT,
            executable=safe_executable,
            message=(
                "Version check timed out; direct-child exit and reader cleanup were confirmed."
                if cleanup_status is ProcessCleanupStatus.CONFIRMED
                else "Version check timed out; cleanup could not be confirmed."
            ),
            cleanup_status=cleanup_status,
        )
    if cleanup_status is not ProcessCleanupStatus.CONFIRMED or len(captured) != 2:
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.FOUND_UNVERIFIED,
            executable=safe_executable,
            message="Version output could not be collected safely.",
            cleanup_status=cleanup_status,
        )

    if any(captured[name][1] for name in ("stdout", "stderr")):
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.FOUND_UNVERIFIED,
            executable=safe_executable,
            message="Version output exceeded its safe collection limit; no version was accepted.",
            cleanup_status=cleanup_status,
        )

    if returncode != 0:
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.NONZERO_EXIT,
            executable=safe_executable,
            message=f"Version check exited with code {returncode}.",
            cleanup_status=cleanup_status,
        )

    stdout, stdout_exceeded, stdout_failed = captured["stdout"]
    _stderr, stderr_exceeded, stderr_failed = captured["stderr"]
    if stdout_exceeded or stderr_exceeded or stdout_failed or stderr_failed:
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.FOUND_UNVERIFIED,
            executable=safe_executable,
            message="Version output exceeded its safe collection limit or was unreadable.",
            cleanup_status=cleanup_status,
        )

    try:
        decoded = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        decoded = ""
    lines = decoded.splitlines()
    pattern = _VERSION_PATTERNS.get(tool)
    match = pattern.fullmatch(lines[0].strip()) if pattern is not None and len(lines) == 1 else None
    if match is None:
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.FOUND_UNVERIFIED,
            executable=safe_executable,
            message="Executable was found, but returned no recognizable version.",
            cleanup_status=cleanup_status,
        )

    version = match.group(1)
    if len(version) > MAX_VERSION_LENGTH:
        return CommandProbeResult(
            tool=tool,
            status=ProbeStatus.FOUND_UNVERIFIED,
            executable=safe_executable,
            message="Executable was found, but returned no recognizable version.",
            cleanup_status=cleanup_status,
        )
    return CommandProbeResult(
        tool=tool,
        status=ProbeStatus.VERIFIED,
        executable=safe_executable,
        version=version,
        message="Version check succeeded.",
        cleanup_status=cleanup_status,
    )
