import io
import subprocess
import threading
from unittest.mock import Mock, call

import pytest

from dev_env_doctor.collectors import commands
from dev_env_doctor.collectors.commands import ProbeStatus, probe_tool
from dev_env_doctor.core import models


@pytest.fixture(autouse=True)
def trusted_executable_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep existing probe tests focused on process handling."""
    monkeypatch.setattr(commands, "is_trusted_executable", lambda _path: True)
    monkeypatch.setattr(
        commands,
        "build_tool_environment",
        lambda _path: {"SystemRoot": r"C:\Windows", "PATH": r"C:\Windows\System32"},
    )


class FakeProcess:
    def __init__(
        self,
        stdout: bytes = b"git version 1.0.0\n",
        stderr: bytes = b"",
        returncode: int = 0,
        timeout_once: bool = False,
    ) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = returncode
        self.timeout_once = timeout_once
        self.killed = False
        self.exited = False
        self.wait_calls: list[float | None] = []

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls.append(timeout)
        if self.timeout_once and not self.killed:
            raise subprocess.TimeoutExpired("fake-tool", timeout)
        self.exited = True
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode if self.exited else None

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


class DrainAwareProcess(FakeProcess):
    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.drained = [threading.Event(), threading.Event()]

        class SignalingStream(io.BytesIO):
            def __init__(self, value: bytes, drained: threading.Event) -> None:
                super().__init__(value)
                self.drained = drained

            def read(self, size: int = -1) -> bytes:
                chunk = super().read(size)
                if self.tell() == len(self.getbuffer()):
                    self.drained.set()
                return chunk

        self.stdout = SignalingStream(self.stdout.getvalue(), self.drained[0])
        self.stderr = SignalingStream(self.stderr.getvalue(), self.drained[1])

    def wait(self, timeout: float | None = None) -> int:
        for drained in self.drained:
            if not drained.wait(timeout=1.0):
                raise subprocess.TimeoutExpired("fake-tool", timeout)
        return super().wait(timeout)


def _returned_reader(thread) -> commands._OutputReader:
    return commands._OutputReader(thread, threading.Event(), commands._ReaderStartState.RETURNED)


@pytest.mark.parametrize("tool", ["python", "git", "node", "codex"])
def test_tool_lookup_uses_fixed_allowlist(tool: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(commands, "find_local_executable", lambda name: f"C:/Tools/{name}.exe")
    outputs = {
        "python": b"Python 3.13.9\n",
        "git": b"git version 2.53.0.windows.3\n",
        "node": b"v22.1.0\n",
    }
    popen = Mock(side_effect=lambda *_args, **_kwargs: FakeProcess(stdout=outputs.get(tool, b"")))
    monkeypatch.setattr(commands.subprocess, "Popen", popen)

    result = probe_tool(tool)

    expected_status = ProbeStatus.FOUND_UNVERIFIED if tool == "codex" else ProbeStatus.VERIFIED
    assert result.status is expected_status
    expected_cleanup = (
        models.ProcessCleanupStatus.NOT_STARTED
        if tool == "codex"
        else models.ProcessCleanupStatus.CONFIRMED
    )
    assert result.cleanup_status is expected_cleanup
    assert result.executable == "<PATH>"
    if tool == "codex":
        assert result.version is None
        popen.assert_not_called()
    else:
        popen.assert_called_once()
        assert popen.call_args.args == ([f"C:/Tools/{tool}.exe", "--version"],)
        assert popen.call_args.kwargs["shell"] is False
        assert popen.call_args.kwargs["env"] == {
            "SystemRoot": r"C:\Windows",
            "PATH": r"C:\Windows\System32",
        }


@pytest.mark.parametrize("suffix", [".exe", ".com", ".cmd", ".bat"])
@pytest.mark.parametrize(
    ("directory", "trusted", "expected_path"),
    [
        (r"C:\Program Files\nodejs", True, "<PATH>"),
        (r"C:\Users\Alice\bin", False, "<USER_DIR>"),
    ],
)
def test_npm_is_lookup_only_in_all_locations(
    monkeypatch, suffix, directory, trusted, expected_path
) -> None:
    lookup = Mock(return_value=directory + "\\npm" + suffix)
    trust = Mock(return_value=trusted)
    build_environment = Mock()
    popen = Mock()
    monkeypatch.setattr(commands, "find_local_executable", lookup)
    monkeypatch.setattr(commands, "is_trusted_executable", trust)
    monkeypatch.setattr(commands, "build_tool_environment", build_environment)
    monkeypatch.setattr(commands.subprocess, "Popen", popen)

    result = probe_tool("npm")

    lookup.assert_called_once_with("npm")
    assert result.status is ProbeStatus.FOUND_UNVERIFIED
    assert result.executable == expected_path
    assert result.version is None
    assert result.cleanup_status is models.ProcessCleanupStatus.NOT_STARTED
    trust.assert_not_called()
    build_environment.assert_not_called()
    popen.assert_not_called()


def test_missing_tool_has_explicit_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: None)

    result = probe_tool("git")

    assert result.status is ProbeStatus.MISSING
    assert result.executable is None
    assert result.message == "Executable was not found in the permitted search locations."


def test_missing_tool_cleanup_does_not_claim_a_child_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: None)
    launch = Mock(side_effect=AssertionError("lookup must not launch a child"))
    monkeypatch.setattr(commands.subprocess, "Popen", launch)

    result = probe_tool("git")

    assert result.cleanup_status is models.ProcessCleanupStatus.NOT_STARTED
    launch.assert_not_called()


def test_untrusted_executable_is_found_but_never_executed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: r"C:\Users\Alice\git.exe")
    monkeypatch.setattr(commands, "is_trusted_executable", lambda _path: False)
    launch = Mock(side_effect=AssertionError("untrusted executable must not launch"))
    monkeypatch.setattr(commands.subprocess, "Popen", launch)

    result = probe_tool("git")

    assert result.status is ProbeStatus.FOUND_UNVERIFIED
    assert result.cleanup_status is models.ProcessCleanupStatus.NOT_STARTED
    assert result.executable == "<USER_DIR>"
    launch.assert_not_called()


def test_trust_check_exception_fails_closed_without_launching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: r"C:\Tools\git.exe")
    monkeypatch.setattr(
        commands,
        "is_trusted_executable",
        Mock(side_effect=OSError("private ACL detail")),
    )
    launch = Mock(side_effect=AssertionError("uncertain trust must not launch"))
    monkeypatch.setattr(commands.subprocess, "Popen", launch)

    result = probe_tool("git")

    assert result.status is ProbeStatus.FOUND_UNVERIFIED
    assert result.cleanup_status is models.ProcessCleanupStatus.NOT_STARTED
    assert "private ACL detail" not in str(result)
    launch.assert_not_called()


def test_trust_recheck_failure_blocks_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: r"C:\Tools\git.exe")
    trust = Mock(side_effect=[True, False])
    monkeypatch.setattr(commands, "is_trusted_executable", trust)
    launch = Mock(side_effect=AssertionError("trust changed before launch"))
    monkeypatch.setattr(commands.subprocess, "Popen", launch)

    result = probe_tool("git")

    assert result.status is ProbeStatus.FOUND_UNVERIFIED
    assert result.cleanup_status is models.ProcessCleanupStatus.NOT_STARTED
    assert trust.call_count == 2
    launch.assert_not_called()


def test_lookup_exception_has_fixed_private_error_and_does_not_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        commands,
        "find_local_executable",
        lambda _name: (_ for _ in ()).throw(
            OSError(r"C:\Users\FictionalUser\private token=lookup-secret")
        ),
    )
    launch = Mock(side_effect=AssertionError("failed lookup must not execute"))
    monkeypatch.setattr(commands.subprocess, "Popen", launch)

    result = probe_tool("git")

    assert result.status is ProbeStatus.ERROR
    assert result.message == "Executable lookup could not be completed."
    assert result.executable is None
    assert all(marker not in str(result) for marker in ("FictionalUser", "lookup-secret"))
    assert result.cleanup_status is models.ProcessCleanupStatus.NOT_STARTED
    launch.assert_not_called()


def test_version_success_uses_fixed_args_and_no_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: r"C:\Tools\git.exe")
    trust = Mock(return_value=True)
    monkeypatch.setattr(commands, "is_trusted_executable", trust)
    captured: dict[str, object] = {}
    process = FakeProcess(stdout=b"git version 2.53.0\n")

    def fake_popen(args: list[str], **kwargs: object) -> FakeProcess:
        captured["args"] = args
        captured.update(kwargs)
        return process

    monkeypatch.setattr(commands.subprocess, "Popen", fake_popen)

    result = probe_tool("git")

    assert result.status is ProbeStatus.VERIFIED
    assert result.cleanup_status is models.ProcessCleanupStatus.CONFIRMED
    assert result.version == "2.53.0"
    assert captured["args"] == [r"C:\Tools\git.exe", "--version"]
    assert captured["shell"] is False
    assert process.wait_calls == [commands.DEFAULT_TIMEOUT_SECONDS]
    assert captured["stdout"] is commands.subprocess.PIPE
    assert captured["stderr"] is commands.subprocess.PIPE
    assert captured["env"] == {"SystemRoot": r"C:\Windows", "PATH": r"C:\Windows\System32"}
    assert trust.call_args_list == [call(r"C:\Tools\git.exe"), call(r"C:\Tools\git.exe")]


def test_nonzero_exit_is_reported_without_raw_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: r"C:\Users\Alice\git.exe")
    monkeypatch.setattr(
        commands.subprocess,
        "Popen",
        lambda *_args, **_kwargs: FakeProcess(
            stdout=b"private output", stderr=b"secret", returncode=2
        ),
    )

    result = probe_tool("git")

    assert result.status is ProbeStatus.NONZERO_EXIT
    assert result.cleanup_status is models.ProcessCleanupStatus.CONFIRMED
    assert "private output" not in result.message
    assert "secret" not in result.message
    assert r"C:\Users\Alice" not in str(result)


def test_timeout_kills_and_reaps_process_without_returning_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess(stdout=b"private", timeout_once=True)
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)

    result = probe_tool("git")

    assert result.status is ProbeStatus.TIMEOUT
    assert result.cleanup_status is models.ProcessCleanupStatus.CONFIRMED
    assert process.killed is True
    assert process.wait_calls == [
        commands.DEFAULT_TIMEOUT_SECONDS,
        commands.CLEANUP_WAIT_SECONDS,
    ]
    assert "private" not in str(result)


def test_timeout_cleanup_wait_is_bounded_and_closes_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess(stdout=b"private", timeout_once=True)

    def wait_never_finishes(timeout: float | None = None) -> int:
        process.wait_calls.append(timeout)
        raise subprocess.TimeoutExpired("fake-tool", timeout)

    process.wait = wait_never_finishes  # type: ignore[method-assign]
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)

    result = probe_tool("git")

    assert result.status is ProbeStatus.TIMEOUT
    assert result.cleanup_status is models.ProcessCleanupStatus.UNCONFIRMED
    assert process.killed is True
    assert process.wait_calls == [
        commands.DEFAULT_TIMEOUT_SECONDS,
        commands.CLEANUP_WAIT_SECONDS,
    ]
    assert "cleanup could not be confirmed" in result.message
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_execution_error_is_handled_without_exception_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "git.exe")

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("C:/Users/Alice/private failure")

    monkeypatch.setattr(commands.subprocess, "Popen", fail)

    result = probe_tool("git")

    assert result.status is ProbeStatus.ERROR
    assert result.cleanup_status is models.ProcessCleanupStatus.NOT_STARTED
    assert "Alice" not in result.message
    assert "private failure" not in result.message


def test_found_path_is_privacy_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        commands, "find_local_executable", lambda _name: r"C:\Users\Alice\bin\codex.exe"
    )
    monkeypatch.setattr(
        commands.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("Codex lookup must not execute a command"),
    )

    result = probe_tool("codex")

    assert result.executable == "<USER_DIR>"
    assert result.cleanup_status is models.ProcessCleanupStatus.NOT_STARTED
    assert "Alice" not in str(result)


def test_batch_launcher_is_not_executed_through_a_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: r"C:\Tools\git.cmd")
    monkeypatch.setattr(
        commands.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("batch launchers are never shell-executed"),
    )

    result = probe_tool("git")

    assert result.status is ProbeStatus.FOUND_UNVERIFIED
    assert result.cleanup_status is models.ProcessCleanupStatus.NOT_STARTED
    assert "without a shell" in result.message


def test_bounded_stream_retains_only_limit_and_drains_remaining_bytes() -> None:
    size = commands.MAX_OUTPUT_BYTES_PER_STREAM + 9000
    stream = io.BytesIO(b"x" * size)

    captured, exceeded, failed = commands._read_bounded_stream(
        stream, commands.MAX_OUTPUT_BYTES_PER_STREAM
    )

    assert len(captured) == commands.MAX_OUTPUT_BYTES_PER_STREAM
    assert exceeded is True
    assert failed is False
    assert stream.tell() == size


def test_stream_reads_are_chunk_bounded_and_overflow_signals_once() -> None:
    class TrackingStream(io.BytesIO):
        def __init__(self, value: bytes) -> None:
            super().__init__(value)
            self.requests: list[int] = []

        def read(self, size: int = -1) -> bytes:
            self.requests.append(size)
            return super().read(size)

    stream = TrackingStream(b"x" * 20_000)
    signaled: list[bool] = []

    captured, exceeded, failed = commands._read_bounded_stream(
        stream,
        commands.MAX_OUTPUT_BYTES_PER_STREAM,
        on_limit=lambda: signaled.append(True),
    )

    assert len(captured) == 4096
    assert exceeded is True
    assert failed is False
    assert max(stream.requests) == 1024
    assert signaled == [True]


@pytest.mark.parametrize("overflow_stream", ["stdout", "stderr"])
def test_oversized_stdout_or_stderr_is_drained_but_not_verified(
    overflow_stream: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    valid = b"git version 2.53.0\n"
    oversized = b"fictional-secret" * commands.MAX_OUTPUT_BYTES_PER_STREAM
    stdout = oversized if overflow_stream == "stdout" else valid
    stderr = oversized if overflow_stream == "stderr" else b""
    process = FakeProcess(stdout=stdout, stderr=stderr)
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)

    result = probe_tool("git")

    assert result.status is ProbeStatus.FOUND_UNVERIFIED
    assert result.version is None
    assert result.cleanup_status is models.ProcessCleanupStatus.CONFIRMED
    assert "fictional-secret" not in str(result)
    assert process.stdout.tell() == len(stdout)
    assert process.stderr.tell() == len(stderr)


def test_both_pipes_are_drained_while_child_is_running(monkeypatch: pytest.MonkeyPatch) -> None:
    process = DrainAwareProcess(
        stdout=b"v" * (commands.MAX_OUTPUT_BYTES_PER_STREAM + 10000),
        stderr=b"e" * (commands.MAX_OUTPUT_BYTES_PER_STREAM + 10000),
    )
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)

    result = probe_tool("git")

    assert process.killed is True
    assert result.status is ProbeStatus.FOUND_UNVERIFIED
    assert process.stdout.tell() == len(process.stdout.getbuffer())
    assert process.stderr.tell() == len(process.stderr.getbuffer())


def test_reader_joins_are_bounded_and_stuck_pipes_are_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    join_timeouts: list[float] = []

    class StuckThread:
        def __init__(self, **_kwargs: object) -> None:
            self.ident = 1

        def start(self) -> None:
            pass

        def join(self, timeout: float | None = None) -> None:
            assert timeout is not None
            join_timeouts.append(timeout)

        def is_alive(self) -> bool:
            return True

    process = FakeProcess()
    monkeypatch.setattr(commands.threading, "Thread", StuckThread)

    captured: dict[str, tuple[bytes, bool, bool]] = {}
    threads = []
    commands._start_output_readers(process, captured, threads)
    captured, finished = commands._finish_output_readers(process, captured, threads)

    assert captured == {}
    assert finished is False
    assert join_timeouts == [1.0, 1.0, 0.25, 0.25]
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_nonzero_exit_does_not_return_captured_output(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess(
        stdout=b"fictional-private-output", stderr=b"fictional-secret", returncode=7
    )
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)

    result = probe_tool("git")

    assert result.status is ProbeStatus.NONZERO_EXIT
    assert result.cleanup_status is models.ProcessCleanupStatus.CONFIRMED
    assert "fictional-private-output" not in str(result)
    assert "fictional-secret" not in str(result)


def test_wait_error_terminates_process_and_hides_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess()

    def fail_wait(*_args: object, **_kwargs: object) -> int:
        raise OSError("fictional private exception")

    process.wait = fail_wait  # type: ignore[method-assign]
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)

    result = probe_tool("git")

    assert result.status is ProbeStatus.ERROR
    assert process.killed is True
    assert result.cleanup_status is models.ProcessCleanupStatus.UNCONFIRMED
    assert "fictional private exception" not in str(result)


def test_invalid_utf8_is_decoded_with_replacement(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess(stdout=b"version \xff\n")
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)

    result = probe_tool("git")

    assert result.status is ProbeStatus.FOUND_UNVERIFIED
    assert result.version is None
    assert result.cleanup_status is models.ProcessCleanupStatus.CONFIRMED


def test_empty_version_output_is_found_but_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess(stdout=b"", stderr=b"")
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)

    result = probe_tool("git")

    assert result.status is ProbeStatus.FOUND_UNVERIFIED
    assert result.version is None
    assert result.cleanup_status is models.ProcessCleanupStatus.CONFIRMED


def test_version_result_keeps_only_recognizable_version_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess(stdout=b"git version 2.53.0.windows.3\n")
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)

    result = probe_tool("git")

    assert result.status is ProbeStatus.VERIFIED
    assert result.version == "2.53.0.windows.3"
    assert "fictional-secret" not in str(result)


@pytest.mark.parametrize(
    ("tool", "output", "expected"),
    [
        ("python", b"Python 3.13.9\n", "3.13.9"),
        ("git", b"git version 2.53.0.windows.3\n", "2.53.0.windows.3"),
        ("node", b"v22.1.0\n", "22.1.0"),
    ],
)
def test_strict_tool_specific_version_formats_are_accepted(
    tool: str, output: bytes, expected: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: f"{tool}.exe")
    monkeypatch.setattr(
        commands.subprocess,
        "Popen",
        lambda *_args, **_kwargs: FakeProcess(stdout=output),
    )

    result = probe_tool(tool)

    assert result.status is ProbeStatus.VERIFIED
    assert result.version == expected
    assert result.cleanup_status is models.ProcessCleanupStatus.CONFIRMED
    assert result.version in output.decode()


@pytest.mark.parametrize(
    ("tool", "output"),
    [
        ("git", b"git version 1.2.fake-secret-token\n"),
        ("git", b"git version v1.2.3 secret=example-value\n"),
        ("git", b"git version 1.2.3 token=example-value\n"),
        ("python", b"Python 3.13.9 private-string\n"),
        ("node", b"v22.1.0 arbitrary-secret\n"),
        ("python", b"3.13.9\n"),
        ("node", b"22.1.0\n"),
    ],
)
def test_unrecognized_or_extra_version_text_is_never_returned(
    tool: str, output: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: f"{tool}.exe")
    monkeypatch.setattr(
        commands.subprocess,
        "Popen",
        lambda *_args, **_kwargs: FakeProcess(stdout=output),
    )

    result = probe_tool(tool)

    assert result.status is ProbeStatus.FOUND_UNVERIFIED
    assert result.version is None
    assert result.cleanup_status is models.ProcessCleanupStatus.CONFIRMED
    assert all(secret not in str(result) for secret in ("secret", "token", "cookie", "private"))


@pytest.mark.parametrize(
    ("initial_exit", "kill_error", "wait_exit", "final_exit", "expected"),
    [
        (0, False, None, None, "confirmed"),
        (None, False, -9, None, "confirmed"),
        (None, False, None, None, "unconfirmed"),
        (None, True, None, -9, "confirmed"),
        (None, True, None, None, "unconfirmed"),
    ],
)
def test_stop_process_requires_observed_exit_not_a_successful_kill_request(
    initial_exit: int | None,
    kill_error: bool,
    wait_exit: int | None,
    final_exit: int | None,
    expected: str,
) -> None:
    process = Mock(stdout=None, stderr=None)
    process.poll.side_effect = [initial_exit, final_exit]
    if kill_error:
        process.kill.side_effect = OSError("fictional-secret C:/Users/Fictional/private")
    if wait_exit is None:
        process.wait.side_effect = subprocess.TimeoutExpired("fictional-secret", 1)
    else:
        process.wait.return_value = wait_exit

    result = commands._stop_process(process, [])

    assert result is models.ProcessCleanupStatus(expected)
    if initial_exit is not None:
        process.kill.assert_not_called()
        process.wait.assert_not_called()
    else:
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=commands.CLEANUP_WAIT_SECONDS)
    assert "fictional-secret" not in str(result)
    assert "Fictional" not in str(result)


@pytest.mark.parametrize("ends_after_pipe_close", [True, False])
def test_cleanup_rechecks_readers_after_final_bounded_join(ends_after_pipe_close: bool) -> None:
    process = FakeProcess()
    process.exited = True
    reader = Mock()
    reader.is_alive.side_effect = [True, not ends_after_pipe_close]

    result = commands._stop_process(process, [_returned_reader(reader)])

    expected = "confirmed" if ends_after_pipe_close else "unconfirmed"
    assert result is models.ProcessCleanupStatus(expected)
    assert reader.join.call_args_list == [
        call(timeout=commands.READER_JOIN_SECONDS),
        call(timeout=commands.READER_FINAL_JOIN_SECONDS),
    ]
    assert process.killed is False
    assert process.stdout.closed and process.stderr.closed


def test_unknown_process_or_reader_state_is_not_cleanup_confirmation() -> None:
    process = Mock(stdout=None, stderr=None)
    process.poll.side_effect = OSError("fictional poll secret")
    process.wait.side_effect = OSError("fictional wait secret")
    reader = Mock()
    reader.is_alive.side_effect = OSError("fictional thread secret")

    result = commands._stop_process(process, [_returned_reader(reader)])

    assert result is models.ProcessCleanupStatus.UNCONFIRMED
    assert all(call.kwargs["timeout"] > 0 for call in reader.join.call_args_list)
    assert "secret" not in str(result)
    assert commands._stop_process(None, []) is models.ProcessCleanupStatus.NOT_STARTED


@pytest.mark.parametrize("first_reader_stuck", [False, True])
@pytest.mark.parametrize("second_started_before_error", [False, True])
def test_second_reader_start_failure_keeps_first_reader_for_cleanup(
    first_reader_stuck: bool,
    second_started_before_error: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    readers = []

    class PartialThread:
        def __init__(self, **_kwargs: object) -> None:
            self.number = len(readers)
            self.started = False
            self.alive = False
            self.ident = None
            self.joins: list[float] = []
            readers.append(self)

        def start(self) -> None:
            if self.number == 1:
                self.started = self.alive = second_started_before_error
                self.ident = self.number + 1 if self.started else None
                raise OSError("fictional-start-secret C:/Users/Fictional/private")
            self.started = self.alive = True
            self.ident = self.number + 1

        def join(self, timeout: float | None = None) -> None:
            assert timeout is not None and timeout > 0
            self.joins.append(timeout)
            if not self.started:
                raise RuntimeError("cannot join before start")
            self.alive = first_reader_stuck

        def is_alive(self) -> bool:
            return self.alive

    process = FakeProcess()
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(commands.threading, "Thread", PartialThread)

    result = probe_tool("git")

    assert result.status is ProbeStatus.ERROR
    # A failed start with no positive startup evidence remains uncertain;
    # ident=None/is_alive=False cannot prove that launch was never scheduled.
    expected = (
        "unconfirmed" if first_reader_stuck or not second_started_before_error else "confirmed"
    )
    assert result.cleanup_status is models.ProcessCleanupStatus(expected)
    assert len(readers) == 2
    assert readers[0].started and readers[0].joins
    assert readers[1].started is second_started_before_error
    if not second_started_before_error:
        assert readers[1].joins == []
    assert process.killed
    assert process.wait_calls == [commands.CLEANUP_WAIT_SECONDS]
    assert process.stdout.closed and process.stderr.closed
    assert "fictional-start-secret" not in str(result)
    assert "Fictional" not in str(result)


def test_missing_pipe_does_not_start_or_lose_any_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess()
    process.stderr = None
    factory = Mock(side_effect=AssertionError("both pipes must be checked before starting readers"))
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(commands.threading, "Thread", factory)

    result = probe_tool("git")

    assert result.status is ProbeStatus.ERROR
    assert result.cleanup_status is models.ProcessCleanupStatus.CONFIRMED
    assert process.killed and process.exited
    assert process.stdout.closed
    factory.assert_not_called()


@pytest.mark.parametrize("stream_name", ["stdout", "stderr"])
def test_reader_io_failure_has_safe_output_but_confirmed_thread_exit(
    stream_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FailingStream(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            raise OSError("fictional-read-secret C:/Users/Fictional/private")

    process = FakeProcess()
    setattr(process, stream_name, FailingStream())
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)

    result = probe_tool("git")

    assert result.status is ProbeStatus.FOUND_UNVERIFIED
    assert result.cleanup_status is models.ProcessCleanupStatus.CONFIRMED
    assert result.version is None
    assert "fictional-read-secret" not in str(result)
    assert "Fictional" not in str(result)


def test_timeout_with_live_readers_does_not_claim_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = Mock()
    reader.is_alive.return_value = True
    monkeypatch.setattr(commands.threading, "Thread", lambda **_kwargs: reader)
    process = FakeProcess(timeout_once=True)
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)

    result = probe_tool("git")

    assert result.status is ProbeStatus.TIMEOUT
    assert process.exited
    assert result.cleanup_status is models.ProcessCleanupStatus.UNCONFIRMED
    assert "cleanup could not be confirmed" in result.message
    assert all(call.kwargs["timeout"] > 0 for call in reader.join.call_args_list)


def test_natural_child_exit_with_live_readers_is_not_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess(stdout=b"git version 2.53.0\n")
    reader = Mock()
    reader.is_alive.return_value = True
    monkeypatch.setattr(commands.threading, "Thread", lambda **_kwargs: reader)
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)

    result = probe_tool("git")

    assert process.exited and not process.killed
    assert result.status is ProbeStatus.FOUND_UNVERIFIED
    assert result.version is None
    assert result.cleanup_status is models.ProcessCleanupStatus.UNCONFIRMED
    assert process.stdout.closed and process.stderr.closed


def test_unknown_reader_liveness_after_confirmed_child_exit_is_unconfirmed() -> None:
    process = FakeProcess()
    process.exited = True
    reader = Mock()
    reader.is_alive.side_effect = OSError("fictional reader-state-secret")

    result = commands._stop_process(process, [_returned_reader(reader)])

    assert result is models.ProcessCleanupStatus.UNCONFIRMED
    assert process.killed is False
    assert reader.join.call_args_list == [
        call(timeout=commands.READER_JOIN_SECONDS),
        call(timeout=commands.READER_FINAL_JOIN_SECONDS),
    ]
    assert "fictional reader-state-secret" not in str(result)


def test_overflow_and_unconfirmed_exit_cannot_be_reported_as_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captures: list[tuple[bytes, bool, bool]] = []
    read = commands._read_bounded_stream

    def tracked_read(*args: object, **kwargs: object) -> tuple[bytes, bool, bool]:
        result = read(*args, **kwargs)
        captures.append(result)
        return result

    class InlineThread:
        def __init__(self, *, target, **_kwargs: object) -> None:
            self.target = target
            self.ident = None

        def start(self) -> None:
            self.ident = 1
            self.target()

        def join(self, timeout: float | None = None) -> None:
            assert timeout is not None and timeout > 0

        def is_alive(self) -> bool:
            return False

    process = FakeProcess(stdout=b"fictional-output-secret" * 5000)

    def fail_wait(timeout: float | None = None) -> int:
        process.wait_calls.append(timeout)
        raise subprocess.TimeoutExpired("fictional-wait-secret", timeout)

    process.wait = fail_wait
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(commands.threading, "Thread", InlineThread)
    monkeypatch.setattr(commands, "_read_bounded_stream", tracked_read)

    result = probe_tool("git")

    assert result.cleanup_status is models.ProcessCleanupStatus.UNCONFIRMED
    assert result.status is ProbeStatus.TIMEOUT
    assert result.version is None and process.killed
    assert sorted(len(capture[0]) for capture in captures) == [0, 4096]
    assert any(capture[1] for capture in captures)
    assert process.wait_calls == [commands.DEFAULT_TIMEOUT_SECONDS, commands.CLEANUP_WAIT_SECONDS]
    assert all(secret not in str(result) for secret in ("fictional-output", "fictional-wait"))


class CompletedReader:
    """Deterministic reader double; no native threads or processes are started."""

    def __init__(self, *, target, **_kwargs: object) -> None:
        self.target = target
        self.ident = None
        self.joins: list[float] = []

    def start(self) -> None:
        self.ident = 1
        self.target()

    def join(self, timeout: float | None = None) -> None:
        assert self.ident is not None, "an unstarted thread must not be joined"
        assert timeout is not None and timeout > 0
        self.joins.append(timeout)

    def is_alive(self) -> bool:
        return False


@pytest.mark.parametrize("exception_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
@pytest.mark.parametrize("cleanup_confirmed", [True, False])
def test_wait_base_exception_cleans_once_and_propagates_original(
    exception_type: type[BaseException],
    cleanup_confirmed: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = exception_type("fictional interrupt detail")
    process = FakeProcess()
    cleanup_wait = (
        -9
        if cleanup_confirmed
        else subprocess.TimeoutExpired("fake-tool", commands.CLEANUP_WAIT_SECONDS)
    )
    process.wait = Mock(side_effect=[original, cleanup_wait])
    cleanup_results = []
    stop_process = commands._stop_process

    def observed_cleanup(child, threads):
        status = stop_process(child, threads)
        cleanup_results.append((status, list(threads)))
        return status

    cleanup = Mock(side_effect=observed_cleanup)
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(commands.threading, "Thread", CompletedReader)
    monkeypatch.setattr(commands, "_stop_process", cleanup)

    with pytest.raises(exception_type) as raised:
        probe_tool("git")

    assert raised.value is original
    cleanup.assert_called_once()
    expected_cleanup = (
        models.ProcessCleanupStatus.CONFIRMED
        if cleanup_confirmed
        else models.ProcessCleanupStatus.UNCONFIRMED
    )
    assert cleanup_results[0][0] is expected_cleanup
    assert len(cleanup_results[0][1]) == 2
    assert all(
        reader.thread.joins == [commands.READER_JOIN_SECONDS] for reader in cleanup_results[0][1]
    )
    assert process.killed
    assert process.wait.call_args_list == [
        call(timeout=commands.DEFAULT_TIMEOUT_SECONDS),
        call(timeout=commands.CLEANUP_WAIT_SECONDS),
    ]
    assert process.stdout.closed and process.stderr.closed


def test_partial_reader_start_interrupt_cleans_started_reader_without_joining_unstarted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    readers = []
    original = KeyboardInterrupt("fictional partial-start detail")

    class InterruptingReader(CompletedReader):
        def __init__(self, **kwargs: object) -> None:
            super().__init__(**kwargs)
            self.number = len(readers)
            self.alive = False
            readers.append(self)

        def start(self) -> None:
            if self.number == 1:
                raise original
            self.ident = 1
            self.alive = True

        def join(self, timeout: float | None = None) -> None:
            self.joins.append(timeout)
            assert self.ident is not None, "unstarted reader joined"
            assert timeout is not None and timeout > 0
            self.alive = False

        def is_alive(self) -> bool:
            return self.alive

    process = FakeProcess()
    cleanup = Mock(wraps=commands._stop_process)
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(commands.threading, "Thread", InterruptingReader)
    monkeypatch.setattr(commands, "_stop_process", cleanup)

    with pytest.raises(KeyboardInterrupt) as raised:
        probe_tool("git")

    assert raised.value is original
    cleanup.assert_called_once()
    child, managed_readers = cleanup.call_args.args
    assert child is process
    assert [reader.thread for reader in managed_readers] == readers
    assert len(readers) == 2
    assert readers[0].joins == [
        commands.READER_JOIN_SECONDS,
        commands.READER_FINAL_JOIN_SECONDS,
    ]
    assert not readers[0].alive
    assert readers[1].ident is None and readers[1].joins == []
    assert process.killed and process.exited
    assert process.wait_calls == [commands.CLEANUP_WAIT_SECONDS]


def test_cleanup_exception_does_not_replace_pending_keyboard_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = KeyboardInterrupt("fictional original interrupt")
    process = FakeProcess()
    process.wait = Mock(side_effect=original)
    cleanup = Mock(side_effect=OSError("fictional-cleanup-secret C:/Users/Fictional/private"))
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(commands.threading, "Thread", CompletedReader)
    monkeypatch.setattr(commands, "_stop_process", cleanup)

    with pytest.raises(KeyboardInterrupt) as raised:
        probe_tool("git")

    assert raised.value is original
    cleanup.assert_called_once()
    assert "fictional-cleanup-secret" not in str(raised.value)
    assert process.stdout.closed and process.stderr.closed


def test_cleanup_helper_error_after_launch_cannot_default_to_confirmed_or_not_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess()
    cleanup = Mock(side_effect=OSError("fictional-cleanup-secret C:/Users/Fictional/private"))
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(commands.threading, "Thread", CompletedReader)
    monkeypatch.setattr(commands, "_stop_process", cleanup)

    result = probe_tool("git")

    cleanup.assert_called_once()
    assert result.status is ProbeStatus.ERROR
    assert result.cleanup_status is models.ProcessCleanupStatus.UNCONFIRMED
    assert result.version is None
    assert "fictional-cleanup-secret" not in str(result)
    assert "Fictional" not in str(result)


@pytest.mark.parametrize("exception_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
@pytest.mark.parametrize(
    "start_evidence", ["pending", "identity_only", "target_finished", "observed_alive"]
)
def test_interrupted_reader_start_requires_positive_start_evidence(
    exception_type: type[BaseException],
    start_evidence: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = exception_type("fictional startup interruption")
    readers = []
    observations = []

    class StartupWindowThread:
        def __init__(self, *, target, **_kwargs: object) -> None:
            self.target = target
            self.number = len(readers)
            self.ident = None
            self.alive = False
            self.scheduled = False
            self.join_ready = False
            self.joins: list[float] = []
            readers.append(self)

        def start(self) -> None:
            self.scheduled = True
            if self.number == 0:
                self.ident = 1
                self.alive = True
                self.join_ready = True
                return
            # Run reader 1 only after reader 2's callback has been created:
            # startup acknowledgements must remain bound to their own reader.
            readers[0].target()
            if start_evidence == "target_finished":
                self.ident = 2
                self.join_ready = True
                self.target()
            elif start_evidence == "observed_alive":
                self.ident = 2
                self.alive = True
                self.join_ready = True
            elif start_evidence == "identity_only":
                self.ident = 2
            # "pending" has work scheduled but no currently visible identity
            # or liveness. Neither observation proves that it cannot run later.
            raise original

        def join(self, timeout: float | None = None) -> None:
            self.joins.append(timeout)
            assert self.ident is not None, "a pending reader must not be joined"
            assert self.join_ready, "identity alone does not satisfy join prerequisites"
            assert timeout is not None and timeout > 0
            self.alive = False

        def is_alive(self) -> bool:
            return self.alive

    process = FakeProcess()
    stop_process = commands._stop_process

    def observed_cleanup(child, managed_readers):
        status = stop_process(child, managed_readers)
        observations.append((status, list(managed_readers)))
        return status

    cleanup = Mock(side_effect=observed_cleanup)
    monkeypatch.setattr(commands, "find_local_executable", lambda _name: "C:/Tools/git.exe")
    monkeypatch.setattr(commands.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(commands.threading, "Thread", StartupWindowThread)
    monkeypatch.setattr(commands, "_stop_process", cleanup)

    with pytest.raises(exception_type) as raised:
        probe_tool("git")

    assert raised.value is original
    cleanup.assert_called_once()
    unknown_start = start_evidence in {"pending", "identity_only"}
    expected = (
        models.ProcessCleanupStatus.UNCONFIRMED
        if unknown_start
        else models.ProcessCleanupStatus.CONFIRMED
    )
    assert observations[0][0] is expected
    assert len(observations[0][1]) == len(readers) == 2
    assert [reader.thread for reader in observations[0][1]] == readers
    assert [reader.start_state for reader in observations[0][1]] == [
        commands._ReaderStartState.RETURNED,
        commands._ReaderStartState.UNCERTAIN,
    ]
    assert observations[0][1][0].started.is_set()
    assert observations[0][1][1].started.is_set() is not unknown_start
    expected_first_joins = [commands.READER_JOIN_SECONDS]
    if unknown_start:
        expected_first_joins.append(commands.READER_FINAL_JOIN_SECONDS)
    assert readers[0].joins == expected_first_joins
    assert not readers[0].alive
    assert readers[1].scheduled
    if unknown_start:
        assert readers[1].ident == (None if start_evidence == "pending" else 2)
        assert not readers[1].join_ready
        assert readers[1].is_alive() is False
        assert readers[1].joins == []
    else:
        assert readers[1].joins == [commands.READER_JOIN_SECONDS]
        assert readers[1].is_alive() is False
    assert process.killed and process.exited
    assert process.wait_calls == [commands.CLEANUP_WAIT_SECONDS]


def test_unattempted_reader_does_not_require_join_or_liveness_inference() -> None:
    thread = Mock()
    reader = commands._OutputReader(thread, threading.Event())
    process = FakeProcess()
    process.exited = True

    status = commands._stop_process(process, [reader])

    assert reader.start_state is commands._ReaderStartState.NOT_ATTEMPTED
    assert status is models.ProcessCleanupStatus.CONFIRMED
    thread.start.assert_not_called()
    thread.join.assert_not_called()
    thread.is_alive.assert_not_called()
    assert not process.killed
