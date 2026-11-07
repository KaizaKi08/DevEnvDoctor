"""Bounded byte transport for the existing scan protocol.

This layer never interprets protocol fields. Callers pass complete encoded
frames to ``send`` and receive complete frames from ``receive``; validation and
session accounting remain in ``scan_protocol.ProtocolSession``.
"""

import math
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from enum import StrEnum

from dev_env_doctor.core.scan_protocol import MAX_FRAME_BYTES


class IpcError(RuntimeError):
    """Fixed transport error with no endpoint, path, or exception details."""

    def __init__(self, message: str = "IPC frame was invalid.") -> None:
        super().__init__(message)


class IpcState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FAILED = "failed"
    UNCONFIRMED = "unconfirmed"


class _HandleState(StrEnum):
    OPEN = "open"
    CLOSED_CONFIRMED = "closed_confirmed"
    CLOSE_UNKNOWN = "close_unknown"


@dataclass(slots=True)
class _OperationRecord:
    thread: threading.Thread
    completed: threading.Event = field(default_factory=threading.Event)
    start_attempted: bool = False
    start_returned: bool = False
    start_uncertain: bool = False


class FramedTransport:
    """Read and write one bounded length-prefixed frame at a time.

    ``endpoint`` is an injected object with ``read(size, timeout_ms)``,
    ``write(data, timeout_ms)`` and ``close()`` methods. It may wrap an
    overlapped Windows pipe in a later resource adapter.
    """

    def __init__(self, endpoint: object, *, timeout_ms: int = 1000) -> None:
        if type(timeout_ms) is not int or timeout_ms < 0:
            raise ValueError("IPC timeout must be a nonnegative integer.")
        self._endpoint = endpoint
        self._timeout_ms = timeout_ms
        self._state = IpcState.OPEN
        self._cleanup_unconfirmed = False

    @property
    def state(self) -> IpcState:
        return self._state

    def _ensure_open(self) -> None:
        if self._state is not IpcState.OPEN:
            raise IpcError("IPC session is no longer usable.")

    def send(self, frame: bytes) -> None:
        self._ensure_open()
        if type(frame) is not bytes or not 4 < len(frame) <= MAX_FRAME_BYTES:
            self._state = IpcState.FAILED
            raise IpcError()
        offset = 0
        try:
            while offset < len(frame):
                written = self._endpoint.write(frame[offset:], self._timeout_ms)
                if type(written) is not int or written <= 0 or written > len(frame) - offset:
                    raise IpcError()
                offset += written
        except TimeoutError:
            self._state = IpcState.FAILED
            raise IpcError("IPC write timed out.") from None
        except IpcError:
            self._state = IpcState.FAILED
            raise
        except Exception:
            self._state = IpcState.FAILED
            raise IpcError("IPC write failed.") from None

    def receive(self, timeout_ms: int | None = None) -> bytes:
        self._ensure_open()
        timeout = self._timeout_ms if timeout_ms is None else self._validate_timeout(timeout_ms)
        deadline = time.monotonic() + timeout / 1000
        try:
            prefix = self._read_exact(4, self._remaining_timeout_ms(deadline))
            size = int.from_bytes(prefix, "big")
            if not 1 <= size <= MAX_FRAME_BYTES - 4:
                raise IpcError()
            return prefix + self._read_exact(size, self._remaining_timeout_ms(deadline))
        except TimeoutError:
            self._state = IpcState.FAILED
            raise IpcError("IPC read timed out.") from None
        except IpcError:
            self._state = IpcState.FAILED
            raise
        except Exception:
            self._state = IpcState.FAILED
            raise IpcError("IPC read failed.") from None

    def _validate_timeout(self, value: object) -> int:
        if type(value) is not int or value < 0:
            raise ValueError("IPC timeout must be a nonnegative integer.")
        return value

    @staticmethod
    def _remaining_timeout_ms(deadline: float) -> int:
        remaining = deadline - time.monotonic()
        return max(0, math.ceil(remaining * 1000))

    def _read_exact(self, size: int, timeout_ms: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = self._endpoint.read(size - len(chunks), timeout_ms)
            if type(chunk) is not bytes:
                raise IpcError()
            if not chunk:
                raise IpcError("IPC endpoint closed before a complete frame arrived.")
            chunks.extend(chunk)
        return bytes(chunks)

    def close(self) -> IpcState:
        if self._state is IpcState.CLOSED:
            return self._state
        try:
            closed = self._endpoint.close()
        except Exception:
            self._state = IpcState.UNCONFIRMED
            self._cleanup_unconfirmed = True
            return self._state
        except BaseException:
            self._state = IpcState.UNCONFIRMED
            self._cleanup_unconfirmed = True
            raise
        if self._cleanup_unconfirmed:
            self._state = IpcState.UNCONFIRMED
            return self._state
        if closed is not True:
            self._cleanup_unconfirmed = True
            self._state = IpcState.UNCONFIRMED
            return self._state
        self._state = IpcState.CLOSED
        return self._state


class PipeEndpoint:
    """Bounded wrapper around two OS pipe descriptors."""

    def __init__(self, read_fd: int, write_fd: int) -> None:
        self._read_fd = read_fd
        self._write_fd = write_fd
        self._closed = False
        self._cleanup_confirmed = False
        self._operations: list[_OperationRecord] = []
        self._lock = threading.Lock()
        self._handle_states = {
            "_read_fd": _HandleState.OPEN,
            "_write_fd": _HandleState.OPEN,
        }

    _CLOSE_JOIN_TIMEOUT_SECONDS = 0.1

    @classmethod
    def from_inherited_handles(cls, read_handle: int, write_handle: int) -> "PipeEndpoint":
        if os.name != "nt":
            raise IpcError("Windows pipe endpoints are unavailable on this platform.")
        import msvcrt

        return cls(
            msvcrt.open_osfhandle(read_handle, os.O_BINARY | os.O_RDONLY),
            msvcrt.open_osfhandle(write_handle, os.O_BINARY | os.O_WRONLY),
        )

    def _call(self, operation, timeout_ms: int):
        with self._lock:
            if self._closed:
                raise IpcError("IPC endpoint is closed.")
        result: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)
        record: _OperationRecord

        def invoke() -> None:
            try:
                result.put((True, operation()))
            except BaseException as error:
                result.put((False, error))
            finally:
                record.completed.set()

        thread = threading.Thread(target=invoke, daemon=True)
        record = _OperationRecord(thread)
        with self._lock:
            if self._closed:
                raise IpcError("IPC endpoint is closed.")
            record.start_attempted = True
            self._operations.append(record)
            try:
                thread.start()
            except BaseException:
                record.start_uncertain = True
                raise
            record.start_returned = True
        try:
            ok, value = result.get(timeout=timeout_ms / 1000)
        except queue.Empty:
            raise TimeoutError() from None
        if ok:
            return value
        raise value

    def read(self, size: int, timeout_ms: int) -> bytes:
        return self._call(lambda: os.read(self._read_fd, size), timeout_ms)

    def write(self, data: bytes, timeout_ms: int) -> int:
        return self._call(lambda: os.write(self._write_fd, data), timeout_ms)

    def close(self) -> bool:
        with self._lock:
            already_closed = self._closed
            self._closed = True
        success = True
        first_error: BaseException | None = None
        if not already_closed:
            for attr in ("_read_fd", "_write_fd"):
                state = self._handle_states[attr]
                if state is _HandleState.CLOSE_UNKNOWN:
                    success = False
                    continue
                if state is _HandleState.CLOSED_CONFIRMED:
                    continue
                fd = getattr(self, attr)
                if fd is None:
                    self._handle_states[attr] = _HandleState.CLOSE_UNKNOWN
                    success = False
                    continue
                try:
                    os.close(fd)
                except Exception:
                    self._handle_states[attr] = _HandleState.CLOSE_UNKNOWN
                    success = False
                except BaseException as error:
                    self._handle_states[attr] = _HandleState.CLOSE_UNKNOWN
                    success = False
                    if first_error is None:
                        first_error = error
                else:
                    self._handle_states[attr] = _HandleState.CLOSED_CONFIRMED
                setattr(self, attr, None)
        else:
            for state in self._handle_states.values():
                if state is not _HandleState.CLOSED_CONFIRMED:
                    success = False

        with self._lock:
            operations = tuple(self._operations)
        for record in operations:
            if not record.start_returned or record.start_uncertain:
                success = False
                continue
            try:
                record.thread.join(self._CLOSE_JOIN_TIMEOUT_SECONDS)
                alive = record.thread.is_alive()
            except BaseException:
                success = False
                continue
            if alive or not record.completed.is_set():
                success = False
        if success:
            self._cleanup_confirmed = True
        if first_error is not None:
            raise first_error
        return self._cleanup_confirmed


@dataclass(slots=True)
class PipePair:
    """Parent endpoint and explicitly inherited child handles."""

    parent: PipeEndpoint
    child_handles: tuple[int, int]
    _child_fds: tuple[int, int]
    _child_handle_states: tuple[_HandleState, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._child_handle_states = tuple(_HandleState.OPEN for _ in self._child_fds)

    @classmethod
    def create(cls) -> "PipePair":
        if os.name != "nt":
            raise IpcError("Windows pipe endpoints are unavailable on this platform.")
        import msvcrt

        parent_to_child_read, parent_to_child_write = os.pipe()
        child_to_parent_read, child_to_parent_write = os.pipe()
        parent_fds = (child_to_parent_read, parent_to_child_write)
        child_fds = (parent_to_child_read, child_to_parent_write)
        try:
            for fd in parent_fds:
                os.set_handle_inheritable(msvcrt.get_osfhandle(fd), False)
            handles = tuple(msvcrt.get_osfhandle(fd) for fd in child_fds)
            for fd in child_fds:
                os.set_handle_inheritable(msvcrt.get_osfhandle(fd), True)
            return cls(PipeEndpoint(*parent_fds), handles, child_fds)
        except BaseException:
            for fd in (*parent_fds, *child_fds):
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise

    def close_child_copies(self) -> bool:
        """Close inherited child descriptors and return only confirmed success."""
        states = list(self._child_handle_states)
        first_base: BaseException | None = None
        for index, fd in enumerate(self._child_fds):
            if states[index] is _HandleState.CLOSED_CONFIRMED:
                continue
            if states[index] is _HandleState.CLOSE_UNKNOWN:
                continue
            try:
                os.close(fd)
            except Exception:
                states[index] = _HandleState.CLOSE_UNKNOWN
            except BaseException as error:
                states[index] = _HandleState.CLOSE_UNKNOWN
                if first_base is None:
                    first_base = error
            else:
                states[index] = _HandleState.CLOSED_CONFIRMED
        self._child_handle_states = tuple(states)
        if first_base is not None:
            raise first_base
        return all(state is _HandleState.CLOSED_CONFIRMED for state in states)
