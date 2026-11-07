import struct
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from dev_env_doctor.core import scan_ipc
from dev_env_doctor.core.scan_ipc import FramedTransport, IpcError, IpcState, PipeEndpoint


class Endpoint:
    def __init__(self, incoming=b"", *, write_limit=None, read_limit=None):
        self.incoming = bytearray(incoming)
        self.outgoing = bytearray()
        self.write_limit = write_limit
        self.read_limit = read_limit
        self.closed = False
        self.close_result = True
        self.timeout_calls = []

    def read(self, size, timeout_ms):
        self.timeout_calls.append(timeout_ms)
        if not self.incoming:
            return b""
        count = min(size, self.read_limit if self.read_limit is not None else size)
        value = bytes(self.incoming[:count])
        del self.incoming[:count]
        return value

    def write(self, data, timeout_ms):
        count = min(len(data), self.write_limit if self.write_limit is not None else len(data))
        self.outgoing.extend(data[:count])
        return count

    def close(self):
        self.closed = True
        return self.close_result


def frame(body=b"abc"):
    return struct.pack("!I", len(body)) + body


def test_partial_write_and_read_are_completed_with_bounded_calls():
    outgoing = Endpoint(write_limit=1)
    transport = FramedTransport(outgoing)
    transport.send(frame())
    assert bytes(outgoing.outgoing) == frame()

    incoming = Endpoint(frame(), read_limit=1)
    received = FramedTransport(incoming).receive()
    assert received == frame()


def test_receive_uses_explicit_timeout_budget_for_each_read():
    endpoint = Endpoint(frame(), read_limit=1)
    received = FramedTransport(endpoint).receive(timeout_ms=5000)
    assert received == frame()
    assert endpoint.timeout_calls
    assert set(endpoint.timeout_calls) == {5000}


@pytest.mark.parametrize("data", [b"", b"\x00", b"\x00\x00\x00", b"\x00\x00\x00\xff{}"])
def test_incomplete_or_invalid_length_fails_closed(data):
    endpoint = Endpoint(data)
    transport = FramedTransport(endpoint)
    with pytest.raises(IpcError):
        transport.receive()
    assert transport.state is IpcState.FAILED
    with pytest.raises(IpcError):
        transport.receive()


def test_oversized_frame_and_decode_failure_are_rejected_without_echoing_input():
    endpoint = Endpoint(struct.pack("!I", 300_000))
    transport = FramedTransport(endpoint)
    with pytest.raises(IpcError) as error:
        transport.receive()
    assert str(error.value) == "IPC frame was invalid."
    assert transport.state is IpcState.FAILED


def test_write_failure_poison_and_close_are_idempotent():
    endpoint = Endpoint(write_limit=0)
    transport = FramedTransport(endpoint)
    with pytest.raises(IpcError):
        transport.send(frame())
    assert transport.state is IpcState.FAILED
    assert transport.close() is IpcState.CLOSED
    assert transport.close() is IpcState.CLOSED


def test_close_failure_is_unconfirmed_and_does_not_claim_closed():
    endpoint = Endpoint()
    endpoint.close_result = False
    transport = FramedTransport(endpoint)
    assert transport.close() is IpcState.UNCONFIRMED
    assert transport.state is IpcState.UNCONFIRMED


def test_timeout_and_endpoint_eof_are_distinct():
    endpoint = Endpoint()
    endpoint.read = lambda size, timeout_ms: (_ for _ in ()).throw(TimeoutError())
    transport = FramedTransport(endpoint)
    with pytest.raises(IpcError, match="IPC read timed out"):
        transport.receive()
    assert transport.state is IpcState.FAILED


class _ControlledThread:
    instances = []
    start_error = None
    alive_after_start = True
    run_target = False
    keep_alive_after_target = False
    alive_error = None
    join_error = None

    def __init__(self, *, target, daemon):
        self.target = target
        self.daemon = daemon
        self.ident = None
        self._alive = False
        self.join_calls = []
        type(self).instances.append(self)

    def start(self):
        if type(self).start_error is not None:
            raise type(self).start_error
        self.ident = 1
        self._alive = type(self).alive_after_start
        if type(self).run_target:
            self.target()
            self._alive = type(self).keep_alive_after_target

    def join(self, timeout=None):
        self.join_calls.append(timeout)
        if type(self).join_error is not None:
            raise type(self).join_error

    def is_alive(self):
        if type(self).alive_error is not None:
            raise type(self).alive_error
        return self._alive


def _endpoint_with_fake_threads(monkeypatch):
    _ControlledThread.instances = []
    _ControlledThread.start_error = None
    _ControlledThread.alive_after_start = True
    _ControlledThread.run_target = False
    _ControlledThread.keep_alive_after_target = False
    _ControlledThread.alive_error = None
    _ControlledThread.join_error = None
    monkeypatch.setattr(scan_ipc.threading, "Thread", _ControlledThread)
    monkeypatch.setattr(scan_ipc.os, "close", Mock())
    return PipeEndpoint(10, 11)


def test_pipe_endpoint_close_does_not_confirm_live_background_thread(monkeypatch):
    endpoint = _endpoint_with_fake_threads(monkeypatch)
    with pytest.raises(TimeoutError):
        endpoint.read(1, 0)

    assert endpoint.close() is False
    assert _ControlledThread.instances[0].join_calls
    assert endpoint.close() is False


def test_pipe_pair_confirms_all_child_copy_closes(monkeypatch):
    pair = scan_ipc.PipePair(object(), (10, 11), (10, 11))
    calls = []
    monkeypatch.setattr(scan_ipc.os, "close", lambda fd: calls.append(fd))

    assert pair.close_child_copies() is True
    assert pair.close_child_copies() is True
    assert calls == [10, 11]


def test_pipe_pair_partial_close_failure_is_sticky_and_does_not_retry_unknown_fd(monkeypatch):
    pair = scan_ipc.PipePair(object(), (10, 11), (10, 11))
    calls = []

    def close_fd(fd):
        calls.append(fd)
        if fd == 10:
            raise OSError("close failed")

    monkeypatch.setattr(scan_ipc.os, "close", close_fd)
    assert pair.close_child_copies() is False
    assert pair.close_child_copies() is False
    assert calls == [10, 11]


def test_pipe_pair_base_exception_still_attempts_other_child_copy(monkeypatch):
    pair = scan_ipc.PipePair(object(), (10, 11), (10, 11))
    error = KeyboardInterrupt()
    calls = []

    def close_fd(fd):
        calls.append(fd)
        if fd == 10:
            raise error

    monkeypatch.setattr(scan_ipc.os, "close", close_fd)
    with pytest.raises(KeyboardInterrupt) as raised:
        pair.close_child_copies()
    assert raised.value is error
    assert calls == [10, 11]
    assert pair.close_child_copies() is False


def test_pipe_endpoint_records_timed_out_write_thread(monkeypatch):
    endpoint = _endpoint_with_fake_threads(monkeypatch)
    with pytest.raises(TimeoutError):
        endpoint.write(b"x", 0)

    assert endpoint.close() is False
    assert len(_ControlledThread.instances) == 1


def test_pipe_endpoint_confirms_finished_thread_and_closed_handles(monkeypatch):
    endpoint = _endpoint_with_fake_threads(monkeypatch)
    _ControlledThread.run_target = True
    monkeypatch.setattr(scan_ipc.os, "read", lambda fd, size: b"x")
    assert endpoint.read(1, 100) == b"x"

    assert endpoint.close() is True
    assert endpoint.close() is True


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit()])
def test_pipe_endpoint_uncertain_thread_start_is_not_confirmed(monkeypatch, error):
    endpoint = _endpoint_with_fake_threads(monkeypatch)
    _ControlledThread.start_error = error
    with pytest.raises(type(error)) as raised:
        endpoint.read(1, 100)

    assert raised.value is error
    assert endpoint.close() is False
    assert _ControlledThread.instances[0].join_calls == []


def test_pipe_endpoint_does_not_forget_failed_handle_close(monkeypatch):
    endpoint = _endpoint_with_fake_threads(monkeypatch)
    _ControlledThread.run_target = True
    monkeypatch.setattr(scan_ipc.os, "read", lambda fd, size: b"x")
    close_calls = []

    def close_fd(fd):
        close_calls.append(fd)
        if fd == 10:
            raise OSError("close failed")

    monkeypatch.setattr(scan_ipc.os, "close", close_fd)
    assert endpoint.read(1, 100) == b"x"
    assert endpoint.close() is False
    assert endpoint.close() is False
    assert close_calls.count(10) <= 1
    assert close_calls.count(11) == 1


def test_pipe_endpoint_partial_handle_close_failure_stays_unconfirmed(monkeypatch):
    endpoint = _endpoint_with_fake_threads(monkeypatch)
    _ControlledThread.run_target = True
    monkeypatch.setattr(scan_ipc.os, "read", lambda fd, size: b"x")

    def close_fd(fd):
        if fd == 11:
            raise OSError()

    monkeypatch.setattr(scan_ipc.os, "close", close_fd)
    assert endpoint.read(1, 100) == b"x"
    assert endpoint.close() is False
    assert endpoint.close() is False


@pytest.mark.parametrize("error", [RuntimeError("alive"), KeyboardInterrupt()])
def test_pipe_endpoint_thread_state_error_is_unconfirmed(monkeypatch, error):
    endpoint = _endpoint_with_fake_threads(monkeypatch)
    _ControlledThread.run_target = True
    _ControlledThread.alive_error = error
    monkeypatch.setattr(scan_ipc.os, "read", lambda fd, size: b"x")
    assert endpoint.read(1, 100) == b"x"
    assert endpoint.close() is False


def test_pipe_endpoint_join_error_and_live_thread_are_unconfirmed(monkeypatch):
    endpoint = _endpoint_with_fake_threads(monkeypatch)
    _ControlledThread.join_error = RuntimeError("join")
    with pytest.raises(TimeoutError):
        endpoint.read(1, 0)
    assert endpoint.close() is False


def test_pipe_endpoint_completed_event_does_not_override_live_thread(monkeypatch):
    endpoint = _endpoint_with_fake_threads(monkeypatch)
    _ControlledThread.run_target = True
    _ControlledThread.alive_after_start = True
    _ControlledThread.keep_alive_after_target = True
    monkeypatch.setattr(scan_ipc.os, "read", lambda fd, size: b"x")
    assert endpoint.read(1, 100) == b"x"
    assert endpoint.close() is False


def test_pipe_endpoint_dead_thread_without_completion_event_is_unconfirmed(monkeypatch):
    endpoint = _endpoint_with_fake_threads(monkeypatch)
    _ControlledThread.alive_after_start = False
    with pytest.raises(TimeoutError):
        endpoint.read(1, 0)

    assert endpoint.close() is False
    assert endpoint.close() is False


def test_framed_transport_keeps_unconfirmed_after_later_endpoint_success():
    class Endpoint:
        def __init__(self):
            self.calls = 0

        def close(self):
            self.calls += 1
            return self.calls > 1

    endpoint = Endpoint()
    transport = FramedTransport(endpoint)
    assert transport.close() is IpcState.UNCONFIRMED
    assert transport.close() is IpcState.UNCONFIRMED
    assert endpoint.calls == 2


def test_framed_transport_preserves_unconfirmed_endpoint_close():
    endpoint = SimpleNamespace(close=lambda: False)
    transport = FramedTransport(endpoint)
    assert transport.close() is IpcState.UNCONFIRMED
    assert transport.state is IpcState.UNCONFIRMED
