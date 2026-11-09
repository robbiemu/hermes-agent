"""Keychain target, outcome, and safe error contracts."""

from __future__ import annotations

import re
import time
from typing import Literal, TypedDict


class KeychainTarget(TypedDict):
    env: str
    service: str
    account: str
    keychain: str


class Recovery(TypedDict):
    id: str
    state: Literal["preparing", "pending", "kept"]


class ProbeResult(TypedDict):
    exists: bool
    keychain_identity: str
    recoveries: list[Recovery]


class WriteResult(TypedDict):
    result: Literal["created", "updated"]
    recovery_id: str | None


class RecoveryResult(TypedDict):
    result: Literal["restored", "discarded"]
    recovery_id: str


MAX_SECRET = 1024 * 1024
RECOVERY_PREFIX = "com.hermes.apple-keychain.recovery.v1."
UUID_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
RECOVERY_ID = re.compile(rf"^{UUID_PATTERN}$")
ERROR_LINE = re.compile(rf"^ERR ([a-z_]+)(?: ({UUID_PATTERN}))?$", re.ASCII)
RECOVERY_LINE = re.compile(rf"^RECOVERY ({UUID_PATTERN})$", re.ASCII)
RECOVERY_ENTRY = re.compile(rf"^RECOVERY (preparing|pending|kept) ({UUID_PATTERN})$", re.ASCII)
_MESSAGES = {
    "missing": "The Keychain item or recovery backup was not found.",
    "locked": "The target Keychain is locked; unlock it before trying again.",
    "denied": "Keychain access was denied. Authorize the current helper in Keychain Access; an upgrade may require reauthorization.",
    "timeout": "The Keychain operation timed out.",
    "invalid": "The Keychain target or value is invalid.",
    "unavailable": "The native Keychain helper is unavailable; install the Xcode Command Line Tools if needed.",
    "recovery_pending": "An unfinished rotation has a recovery backup; restore or discard it before writing.",
    "recovery_preparing": "An unfinished preparation cannot be restored; discard it before writing.",
    "conflict": "The Keychain item changed since it was checked; repeat the operation.",
    "access_mismatch": "The item's access controls differ from the recovery entry; check recovery records.",
    "verify": "Keychain verification failed; any recovery backup was retained.",
    "failure": "The Keychain operation failed; any recovery backup was retained.",
}


class KeychainError(Exception):
    def __init__(self, kind: str, message: str, recovery_id: str | None = None):
        super().__init__(message)
        self.kind = kind
        self.recovery_id = recovery_id


def keychain_error(kind: str, recovery_id: str | None = None) -> KeychainError:
    if kind not in _MESSAGES:
        kind = "failure"
    message = _MESSAGES[kind]
    if recovery_id and RECOVERY_ID.fullmatch(recovery_id):
        message += f" Recovery ID: {recovery_id}."
    else:
        recovery_id = None
    return KeychainError(kind, message, recovery_id)


def make_deadline(timeout: float) -> float:
    try:
        value = float(timeout)
    except (TypeError, ValueError, OverflowError):
        raise keychain_error("invalid") from None
    if not 0 < value < float("inf"):
        raise keychain_error("invalid")
    return time.monotonic() + value


def remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise keychain_error("timeout")
    return value
