"""Profile .env import and conditional, explicitly confirmed cleanup."""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
import sys

from . import backend, configuration
from .cli_common import CommandError, find_item


@dataclass(frozen=True)
class EnvCandidate:
    path: Path
    config_path: Path
    name: str
    value: str = field(repr=False)
    raw: bytes = field(repr=False)
    identity: tuple = field(repr=False)


def _snapshot(path: Path) -> tuple[bytes, tuple] | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        actual = os.fstat(stream.fileno())
        if not stat.S_ISREG(actual.st_mode) or (before.st_dev, before.st_ino) != (actual.st_dev, actual.st_ino):
            raise ValueError("file changed")
        raw = stream.read()
        after = os.fstat(stream.fileno())
    current = path.lstat()
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_mtime_ns, info.st_ctime_ns, info.st_size)
    if identity(actual) != identity(after) or identity(after) != identity(current):
        raise ValueError("file changed")
    return raw, identity(after)


def _paths_match(config_path: Path, env_path: Path) -> bool:
    from hermes_cli.config import get_config_path, get_env_path

    return get_config_path() == config_path and get_env_path() == env_path and env_path == config_path.parent / ".env"


def capture(name: str, config_path: Path) -> EnvCandidate | None:
    from agent.secret_scope import load_env_file
    from hermes_cli.config import get_env_path

    path = get_env_path()
    try:
        if not _paths_match(config_path, path):
            raise ValueError("profile changed")
        before = _snapshot(path)
        if before is None:
            return None
        parsed = load_env_file(path)
        if _snapshot(path) != before or not _paths_match(config_path, path):
            raise ValueError("file changed")
    except (OSError, ValueError):
        print("The active profile's .env could not be safely read; check the file and retry.", file=sys.stderr)
        raise CommandError("unsafe environment file") from None
    value = parsed.get(name, "")
    if not value:
        return None
    if value.lstrip().startswith("op://"):
        print(f"{name}: the .env entry is a secret reference and cannot be imported automatically.")
        return None
    return EnvCandidate(path, config_path, name, value, before[0], before[1])


def unchanged(candidate: EnvCandidate) -> bool:
    from agent.secret_scope import load_env_file

    if not _paths_match(candidate.config_path, candidate.path):
        return False
    pinned = (candidate.raw, candidate.identity)
    return (_snapshot(candidate.path) == pinned and load_env_file(candidate.path).get(candidate.name) == candidate.value
            and _snapshot(candidate.path) == pinned and _paths_match(candidate.config_path, candidate.path))


def _current_mapping(config_path: Path, document: dict, item: dict) -> bool:
    current, source, path = configuration.load_source_config()
    items, problems = configuration.normalize_items(source)
    return (path == config_path and current == document and not problems and source.get("enabled") is True
            and find_item(items, item["env"]) == item)


def _same_target(item: dict, identity: str) -> bool:
    state = backend.probe_item(item)
    return (state.get("keychain_identity") == identity and bool(state.get("exists"))
            and not any(entry.get("state") == "pending" for entry in state.get("recoveries", [])))


def _verified(candidate: EnvCandidate, item: dict, document: dict, identity: str) -> bool:
    return (unchanged(candidate) and _current_mapping(candidate.config_path, document, item)
            and _same_target(item, identity) and backend.read_item(item) == candidate.value
            and _same_target(item, identity))


def _remove_selected(candidate: EnvCandidate) -> None:
    # Hermes has no public compare-and-remove API. Its reentrant lock and line
    # matcher serialize with the other .env writers and preserve their parsing
    # rules; the atomic writer preserves every unrelated UTF-8 byte and mode.
    from hermes_cli.config import _env_line_defines_key, _publish_env_value, _write_env_lines, invalidate_env_cache

    text = candidate.raw.decode("utf-8", "strict")
    lines = text.splitlines(keepends=True)
    retained = [line for index, line in enumerate(lines)
                if not _env_line_defines_key(line.removeprefix("\ufeff") if index == 0 else line, candidate.name)]
    if len(retained) == len(lines):
        raise ValueError("assignment missing")
    _write_env_lines(candidate.path, retained, preserve_mode=True)
    _publish_env_value(candidate.name, None)
    invalidate_env_cache()


def maybe_cleanup(candidate: EnvCandidate, item: dict, document: dict, identity: str) -> int:
    from hermes_cli.config import _env_write_lock, require_env_writable
    from . import cli_input

    try:
        if not _verified(candidate, item, document, identity):
            raise ValueError("verification changed")
        if not cli_input.confirm(f"Saved and checked. Remove {candidate.name} from .env? [y/N]: "):
            return 0
        # This private lock is the only shared CAS boundary provided by Hermes:
        # its public remove operation takes the same reentrant lock internally.
        with _env_write_lock(candidate.path):
            require_env_writable(candidate.name, "remove")
            if not _verified(candidate, item, document, identity):
                raise ValueError("verification changed")
            # A non-Hermes writer may have changed the file while Keychain was read.
            if not unchanged(candidate) or not _current_mapping(candidate.config_path, document, item):
                raise ValueError("verification changed")
            require_env_writable(candidate.name, "remove")
            _remove_selected(candidate)
    except (OSError, ValueError, TimeoutError, backend.KeychainError, CommandError, EOFError, KeyboardInterrupt):
        print("The Keychain item was saved, but .env was left alone; check the profile, access and file before retrying.",
              file=sys.stderr)
        return 1
    print(f"Removed {candidate.name} from .env.")
    return 0
