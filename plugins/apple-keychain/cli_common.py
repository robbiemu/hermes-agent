"""Shared configuration, validation, and preflight for Keychain commands."""
from __future__ import annotations

from pathlib import Path
import shlex
import sys
import time
import uuid

from . import backend, configuration
from .contracts import remaining


class CommandError(Exception):
    """An already-reported user-facing error."""


def profile_command(config_path: Path) -> str:
    home = config_path.parent
    profile = "" if home.parent.name == "profiles" else " -p default"
    return f"HERMES_HOME={shlex.quote(str(home))} hermes{profile}"


_ERROR_MESSAGES = {
    "missing": "item not found",
    "locked": "keychain is locked",
    "denied": "access denied; authorize the helper in Keychain Access",
    "timeout": "Keychain operation timed out",
    "unavailable": "Keychain is unavailable",
    "conflict": "the item changed during the operation; retry",
    "recovery_pending": "a recovery needs attention before another write",
    "recovery_preparing": "an unfinished preparation must be discarded before another write",
    "access_mismatch": "Keychain access controls changed; the item was not updated",
    "verify": "Keychain read-back failed; check recovery records",
    "failure": "Keychain operation failed; check Keychain access and recovery records",
    "invalid": "invalid Keychain target or secret value",
}


def error_text(exc: Exception) -> str:
    kind = getattr(exc, "kind", "")
    message = _ERROR_MESSAGES.get(kind, "operation failed; check Keychain access and configuration")
    recovery_id = getattr(exc, "recovery_id", None)
    try:
        recovery_id = str(uuid.UUID(recovery_id)) if isinstance(recovery_id, str) else None
    except ValueError:
        recovery_id = None
    if recovery_id:
        message += f"; saved old value ID: {recovery_id} (see `hermes keychain recovery list`)"
    return message


def load_items():
    document, source, path = configuration.load_source_config()
    items, problems = configuration.normalize_items(source)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        raise CommandError("invalid keychain mappings")
    return document, source, path, items


def find_item(items: list[dict], name: str) -> dict | None:
    return next((item for item in items if item["env"] == name), None)


def require_explicit_target(item: dict) -> None:
    if not item.get("keychain"):
        print(f"{item['env']}: this legacy mapping uses the Keychain search list. "
              "Run `hermes keychain setup` to select an explicit keychain before writing.", file=sys.stderr)
        raise CommandError("implicit target")


def deadline_for(source: dict) -> float:
    timeout = configuration.timeout_seconds(source.get("timeout_seconds"))
    return time.monotonic() + timeout - min(0.25, timeout * 0.1)


def probe_all(items: list[dict], deadline: float, replace: bool, *, require_existing: bool = False) -> list[bool]:
    states = []
    physical_targets = set()
    for item in items:
        require_explicit_target(item)
        state = backend.probe_item(item, timeout=remaining(deadline))
        identity = state.get("keychain_identity")
        if not identity:
            print("Could not verify the physical Keychain target; no items were written.", file=sys.stderr)
            raise CommandError("missing keychain identity")
        physical_target = (identity, item["service"], item["account"])
        if physical_target in physical_targets:
            print("Selected references point to the same physical Keychain item; no items were written.", file=sys.stderr)
            raise CommandError("duplicate physical target")
        physical_targets.add(physical_target)
        recoveries = state.get("recoveries", [])
        if any(entry.get("state") == "preparing" for entry in recoveries):
            print(f"{item['env']}: an unfinished preparation cannot be restored. "
                  "Use `hermes keychain recovery list` and discard it first.", file=sys.stderr)
            raise CommandError("preparing recovery")
        if any(entry.get("state") == "pending" for entry in recoveries):
            print(f"{item['env']}: an unfinished rotation has a saved old value. "
                  "Use `hermes keychain recovery list` and restore or discard it first.", file=sys.stderr)
            raise CommandError("pending recovery")
        exists = bool(state.get("exists"))
        if exists and not replace:
            print(f"{item['env']}: item already exists; use --replace-existing to rotate it.", file=sys.stderr)
            raise CommandError("item exists")
        if require_existing and not exists:
            print(f"{item['env']}: item does not exist; omit --replace-existing to create it.", file=sys.stderr)
            raise CommandError("item missing")
        states.append(exists)
    return states


def revalidate_targets(selected: list[dict], config_path: Path) -> None:
    _, source, current_path, current = load_items()
    if (current_path != config_path or source.get("enabled") is not True
            or any(find_item(current, item["env"]) != item for item in selected)):
        print("The effective Keychain references changed; no further items will be written.", file=sys.stderr)
        raise CommandError("reference changed")


def print_write_result(name: str, result: dict, *, keep_backup: bool) -> None:
    if result["result"] == "updated":
        state = "retained" if keep_backup else "removed"
        print(f"{name}: new value verified; backup {result['recovery_id']} {state}.")
    else:
        print(f"{name}: new item created and verified.")
