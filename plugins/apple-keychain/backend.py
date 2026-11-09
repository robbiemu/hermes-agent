"""Noninteractive Keychain operations through the native helper."""

from __future__ import annotations

import os
import re
from typing import Literal, cast

from . import native_build, native_io
from .contracts import (
    MAX_SECRET, RECOVERY_ENTRY, RECOVERY_ID, RECOVERY_LINE, RECOVERY_PREFIX,
    KeychainError, KeychainTarget, ProbeResult, Recovery, RecoveryResult, WriteResult,
    keychain_error, make_deadline,
)


def validate_value(value: object) -> None:
    """Validate the whole batch before any write; never include a value in errors."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise keychain_error("invalid")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise keychain_error("invalid") from None
    if len(encoded) > MAX_SECRET:
        raise keychain_error("invalid")


def _target(item: KeychainTarget, *, management: bool) -> tuple[str, str, str]:
    if not isinstance(item, dict):
        raise keychain_error("invalid")
    service, account, keychain = item.get("service"), item.get("account"), item.get("keychain", "")
    if not all(isinstance(part, str) for part in (service, account, keychain)):
        raise keychain_error("invalid")
    if not service or not account or service.startswith(RECOVERY_PREFIX):
        raise keychain_error("invalid")
    try:
        if any("\x00" in part or len(part.encode("utf-8", "strict")) > 4096 for part in (service, account, keychain)):
            raise keychain_error("invalid")
    except UnicodeEncodeError:
        raise keychain_error("invalid") from None
    if not keychain:
        if management:
            raise keychain_error("invalid")
    else:
        keychain = os.path.expanduser(keychain)
        if management and not os.path.isabs(keychain):
            raise keychain_error("invalid")
    return keychain, service, account


def helper_path(*, timeout: float = 10) -> str:
    """Return the current helper path, building it once in a private cache if needed."""
    return native_build.build_helper(make_deadline(timeout))


def read_item(item: KeychainTarget, *, timeout: float = 10) -> str:
    data = native_io.run_helper("read", _target(item, management=False), deadline=make_deadline(timeout))
    try:
        value = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise keychain_error("invalid") from None
    if value:
        validate_value(value)
    return value


def _recoveries(lines: list[str]) -> list[Recovery]:
    result: list[Recovery] = []
    for line in lines:
        match = RECOVERY_ENTRY.fullmatch(line)
        if not match:
            raise keychain_error("failure")
        result.append({"id": match.group(2), "state": cast(Literal["preparing", "pending", "kept"], match.group(1))})
    return result


def probe_item(item: KeychainTarget, *, timeout: float = 10) -> ProbeResult:
    try:
        lines = native_io.run_helper("probe", _target(item, management=True),
                                     deadline=make_deadline(timeout)).decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        raise keychain_error("failure") from None
    if len(lines) < 2 or lines[0] not in ("PRESENT", "MISSING") or not re.fullmatch(r"IDENTITY [0-9a-f]{64}", lines[1]):
        raise keychain_error("failure")
    return {"exists": lines[0] == "PRESENT", "keychain_identity": lines[1].removeprefix("IDENTITY "),
            "recoveries": _recoveries(lines[2:])}


def write_item(item: KeychainTarget, value: str, *, allow_any_app: bool = False, keep_backup: bool = False,
               expected_exists: bool | None = None, notify_fd: int | None = None,
               timeout: float = 10) -> WriteResult:
    validate_value(value)
    if not isinstance(allow_any_app, bool) or not isinstance(keep_backup, bool) or (expected_exists is not None and type(expected_exists) is not bool):
        raise keychain_error("invalid")
    expected = "-1" if expected_exists is None else str(int(expected_exists))
    fd = 1 if notify_fd is None else notify_fd
    output = native_io.run_helper("write", _target(item, management=True), deadline=make_deadline(timeout),
                                  extra=(str(int(allow_any_app)), str(int(keep_backup)), expected),
                                  value=value.encode("utf-8"), notify_fd=fd)
    try:
        lines = output.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        raise keychain_error("failure") from None
    if lines == ["OK created"]:
        return {"result": "created", "recovery_id": None}
    if len(lines) == 2 and (match := RECOVERY_LINE.fullmatch(lines[0])) and lines[1] == f"OK updated {match.group(1)}":
        return {"result": "updated", "recovery_id": match.group(1)}
    raise keychain_error("failure")


def list_recoveries(item: KeychainTarget, *, timeout: float = 10) -> list[Recovery]:
    try:
        lines = native_io.run_helper("list", _target(item, management=True),
                                     deadline=make_deadline(timeout)).decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        raise keychain_error("failure") from None
    return _recoveries(lines)


def _recovery_action(command: Literal["restore", "discard"], item: KeychainTarget, recovery_id: str,
                     *, timeout: float) -> RecoveryResult:
    if not isinstance(recovery_id, str) or not RECOVERY_ID.fullmatch(recovery_id):
        raise keychain_error("invalid")
    result = native_io.run_helper(command, _target(item, management=True), deadline=make_deadline(timeout),
                                  extra=(recovery_id,))
    expected = {"restore": b"OK restored\n", "discard": b"OK discarded\n"}[command]
    if result != expected:
        raise keychain_error("failure", recovery_id)
    return {"result": "restored" if command == "restore" else "discarded", "recovery_id": recovery_id}


def restore_backup(item: KeychainTarget, recovery_id: str, *, timeout: float = 10) -> RecoveryResult:
    return _recovery_action("restore", item, recovery_id, timeout=timeout)


def discard_backup(item: KeychainTarget, recovery_id: str, *, timeout: float = 10) -> RecoveryResult:
    return _recovery_action("discard", item, recovery_id, timeout=timeout)
