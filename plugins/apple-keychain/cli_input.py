"""Bounded terminal prompts and standard-input handling for secret commands."""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
import os
import select
import signal
import sys
import time

from .cli_common import CommandError
from .contracts import MAX_SECRET


INPUT_TIMEOUT_SECONDS = 120.0
_TRUTHY = {"1", "true", "yes", "on"}
_UNATTENDED = ("HERMES_GATEWAY_SESSION", "HERMES_CRON_SESSION", "HERMES_SINGLE_QUERY_SESSION")


def require_interactive() -> None:
    """Reject unattended commands before they prompt or access Keychain."""
    unattended = any(os.environ.get(name, "").strip().lower() in _TRUTHY for name in _UNATTENDED)
    unattended = unattended or bool(os.environ.get("HERMES_SESSION_PLATFORM", "").strip())
    try:
        tty = sys.stdin.isatty() and os.isatty(sys.stdin.fileno())
    except (AttributeError, OSError, ValueError):
        tty = False
    if unattended or not tty:
        print("An interactive terminal is required; use --stdin for noninteractive secret input.", file=sys.stderr)
        raise CommandError("interactive terminal required")


def _interrupted(signum, frame) -> None:
    raise KeyboardInterrupt


@contextmanager
def _hidden_terminal(fd: int):
    """Suppress echo only for the prompt and restore terminal and signal state."""
    try:
        import termios
    except ImportError:
        print("Hidden input is unavailable; use --stdin from a trusted input source.", file=sys.stderr)
        raise CommandError("hidden input unavailable") from None
    try:
        original = termios.tcgetattr(fd)
    except (termios.error, OSError, ValueError):
        print("Hidden input is unavailable; use --stdin from a trusted input source.", file=sys.stderr)
        raise CommandError("hidden input unavailable") from None
    installed = []
    changed = False
    try:
        # Cancel quit and suspend too, so echo is restored before returning to the shell.
        for sig in (signal.SIGTERM, getattr(signal, "SIGHUP", None),
                    getattr(signal, "SIGQUIT", None), getattr(signal, "SIGTSTP", None)):
            if sig is None:
                continue
            previous = signal.getsignal(sig)
            signal.signal(sig, _interrupted)
            installed.append((sig, previous))
        updated = original[:]
        updated[3] &= ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSANOW, updated)
        changed = True
        yield
    except (termios.error, OSError, ValueError):
        print("Hidden input is unavailable; use --stdin from a trusted input source.", file=sys.stderr)
        raise CommandError("hidden input unavailable") from None
    finally:
        try:
            if changed:
                try:
                    termios.tcsetattr(fd, termios.TCSANOW, original)
                except (termios.error, OSError, ValueError):
                    print("Could not restore terminal settings; run `stty echo` in your terminal.", file=sys.stderr)
                    raise CommandError("terminal restore failed") from None
        finally:
            for sig, previous in installed:
                signal.signal(sig, previous)


def _read_bytes(fd: int, *, line: bool, limit: int, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    value = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print("Input timed out.", file=sys.stderr)
            raise CommandError("input timed out")
        try:
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                print("Input timed out.", file=sys.stderr)
                raise CommandError("input timed out")
            # One byte at a time prevents a terminal read from consuming the next answer.
            chunk = os.read(fd, 1 if line else min(65536, limit + 1 - len(value)))
        except (OSError, ValueError):
            print("Input could not be read.", file=sys.stderr)
            raise CommandError("input failed") from None
        if not chunk:
            return bytes(value)
        value.extend(chunk)
        if len(value) > limit:
            print("Input is too large.", file=sys.stderr)
            raise CommandError("input too large")
        if line and chunk == b"\n":
            return bytes(value)


def _decode(value: bytes) -> str:
    try:
        return value.decode("utf-8", "strict")
    except UnicodeError:
        print("Input must be valid UTF-8.", file=sys.stderr)
        raise CommandError("invalid input encoding") from None


def _strip_final_line_ending(value: str) -> str:
    if value.endswith("\n"):
        return value[:-1].removesuffix("\r")
    return value


def prompt(message: str, *, hidden: bool = False, timeout: float = INPUT_TIMEOUT_SECONDS) -> str:
    try:
        fd = sys.stdin.fileno()
    except (AttributeError, OSError, ValueError):
        print("Interactive input is unavailable.", file=sys.stderr)
        raise CommandError("input unavailable") from None
    with _hidden_terminal(fd) if hidden else nullcontext():
        try:
            print(message, end="", file=sys.stderr, flush=True)
            value = _read_bytes(fd, line=True, limit=MAX_SECRET + 2, timeout=timeout)
        finally:
            if hidden:
                print(file=sys.stderr, flush=True)
    if not value:
        raise EOFError
    return _strip_final_line_ending(_decode(value))


def confirm(message: str, *, default: bool = False) -> bool:
    answer = prompt(message).strip().lower()
    return default if not answer else answer in {"y", "yes"}


def read_secret(name: str, use_stdin: bool) -> str:
    if use_stdin:
        try:
            fd = sys.stdin.fileno()
        except (AttributeError, OSError, ValueError):
            print("Standard input is unavailable.", file=sys.stderr)
            raise CommandError("stdin unavailable") from None
        data = _read_bytes(fd, line=False, limit=MAX_SECRET + 2, timeout=INPUT_TIMEOUT_SECONDS)
        value = _strip_final_line_ending(_decode(data))
    else:
        value = prompt(f"Secret for {name} (input hidden): ", hidden=True)
    if not value:
        print(f"{name}: empty secret refused.", file=sys.stderr)
        raise CommandError("empty secret")
    return value
