"""Bounded transport for the native Keychain helper protocol."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import selectors
import subprocess

from . import native_build
from .contracts import ERROR_LINE, MAX_SECRET, RECOVERY_LINE, KeychainError, keychain_error, remaining


@dataclass(repr=False)
class _PumpState:
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    outgoing: bytes = b""
    parsed: int = 0
    recovery_id: str | None = None


def _notify_recovery(fd: int, recovery_id: str, deadline: float) -> None:
    message = f"Old value saved in recovery backup {recovery_id}."
    try:
        result = subprocess.run(
            ["/usr/bin/printf", "%s\n", message], stdin=subprocess.DEVNULL,
            stdout=fd, stderr=subprocess.DEVNULL, env=native_build.child_env(),
            timeout=remaining(deadline), check=False,
        )
    except subprocess.TimeoutExpired:
        raise keychain_error("timeout", recovery_id) from None
    except OSError:
        raise keychain_error("failure", recovery_id) from None
    if result.returncode:
        raise keychain_error("failure", recovery_id)


def _write(state: _PumpState, selector, stream) -> None:
    try:
        count = os.write(stream.fileno(), state.outgoing)
    except BlockingIOError:
        return
    except BrokenPipeError:
        selector.unregister(stream)
        return
    state.outgoing = state.outgoing[count:]
    if not state.outgoing:
        selector.unregister(stream)


def _status(state: _PumpState, process, selector, notify_fd: int, deadline: float) -> None:
    while b"\n" in state.stdout[state.parsed:]:
        end = state.stdout.index(b"\n", state.parsed)
        line = bytes(state.stdout[state.parsed:end]).decode("ascii", "strict")
        state.parsed = end + 1
        match = RECOVERY_LINE.fullmatch(line)
        if not match:
            continue
        if state.recovery_id is not None:
            raise keychain_error("failure", state.recovery_id)
        state.recovery_id = match.group(1)
        # The child waits for this ACK before changing the original. A failed
        # or timed-out notice leaves the pending backup and original intact.
        _notify_recovery(notify_fd, state.recovery_id, deadline)
        state.outgoing = b"\x01"
        selector.register(process.stdin, selectors.EVENT_WRITE, "in")


def _read(state: _PumpState, process, selector, stream, name: str,
          command: str, notify_fd: int, deadline: float) -> None:
    try:
        chunk = os.read(stream.fileno(), 65536)
    except BlockingIOError:
        return
    if not chunk:
        selector.unregister(stream)
        return
    buffer = state.stdout if name == "out" else state.stderr
    buffer.extend(chunk)
    maximum = MAX_SECRET if command == "read" and name == "out" else 65536
    if len(buffer) > maximum:
        raise keychain_error("failure", state.recovery_id)
    if command == "write" and name == "out":
        _status(state, process, selector, notify_fd, deadline)


def _pump(state: _PumpState, process, selector, command: str,
          value: bytes | None, notify_fd: int, deadline: float) -> None:
    for stream, name in ((process.stdout, "out"), (process.stderr, "err")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    if value is not None:
        state.outgoing = len(value).to_bytes(4, "big") + value
        os.set_blocking(process.stdin.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, "in")
    while selector.get_map():
        for key, _ in selector.select(remaining(deadline)):
            if key.data == "in":
                _write(state, selector, key.fileobj)
            else:
                _read(state, process, selector, key.fileobj, key.data, command, notify_fd, deadline)


def _check_result(stderr: bytes, recovery_id: str | None) -> None:
    try:
        match = ERROR_LINE.fullmatch(stderr.decode("ascii", "strict").strip())
    except UnicodeDecodeError:
        match = None
    if match:
        raise keychain_error(match.group(1), match.group(2) or recovery_id)
    raise keychain_error("failure", recovery_id)


def run_helper(command: str, target: tuple[str, str, str], *, deadline: float,
               extra: tuple[str, ...] = (), value: bytes | None = None, notify_fd: int = 1) -> bytes:
    if command == "write" and (not isinstance(notify_fd, int) or isinstance(notify_fd, bool) or notify_fd < 0):
        raise keychain_error("invalid")
    helper = native_build.build_helper(deadline)
    try:
        process = subprocess.Popen(
            [helper, command, *target, *extra], stdin=subprocess.PIPE if value is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=native_build.child_env(), close_fds=True,
        )
    except OSError:
        raise keychain_error("unavailable") from None
    selector = None
    state = _PumpState()
    try:
        selector = selectors.DefaultSelector()
        _pump(state, process, selector, command, value, notify_fd, deadline)
        try:
            return_code = process.wait(timeout=remaining(deadline))
        except subprocess.TimeoutExpired:
            raise keychain_error("timeout", state.recovery_id) from None
        if return_code:
            _check_result(bytes(state.stderr), state.recovery_id)
        return bytes(state.stdout)
    except (UnicodeError, OSError):
        raise keychain_error("failure", state.recovery_id) from None
    except KeychainError as exc:
        if exc.kind == "timeout" and state.recovery_id and not exc.recovery_id:
            raise keychain_error("timeout", state.recovery_id) from None
        raise
    finally:
        if selector is not None:
            selector.close()
        try:
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    process.poll()
                try:
                    process.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    raise keychain_error("timeout", state.recovery_id) from None
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
