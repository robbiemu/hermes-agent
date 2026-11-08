"""Shared Apple Keychain mappings and profile-aware configuration access."""

from __future__ import annotations

import copy
import math
import re
import unicodedata
from pathlib import Path
from typing import Any

from .contracts import KeychainTarget

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ITEM_KEYS = frozenset({"env", "service", "account", "keychain"})


def valid_env_name(value: object) -> bool:
    return isinstance(value, str) and bool(_ENV_NAME.fullmatch(value))


def _positive_timeout(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if math.isfinite(parsed) and parsed > 0 else None


def timeout_seconds(value: object) -> float:
    """Shared source budget: default 10 seconds, capped at 30."""
    parsed = _positive_timeout(value)
    return min(parsed, 30.0) if parsed is not None else 10.0


def _string_value(mapping: dict, key: str, default: str, location: str,
                  warnings: list[str]) -> str:
    if key not in mapping:
        return default
    value = mapping[key]
    if not isinstance(value, str):
        warnings.append(f"{location}.{key} must be a string; using its default.")
        return default
    if any(unicodedata.category(char).startswith("C") for char in value):
        warnings.append(f"{location}.{key} must not contain control characters.")
    return value.strip() or default


def _sequence(cfg: dict, key: str, warnings: list[str]) -> list:
    if key not in cfg:
        return []
    value = cfg[key]
    if not isinstance(value, list):
        warnings.append(f"apple_keychain.{key} must be a list; ignoring it.")
        return []
    return value


def _validate_settings(cfg: dict, warnings: list[str]) -> None:
    for key in ("enabled", "override_existing"):
        if key in cfg and not isinstance(cfg[key], bool):
            warnings.append(f"apple_keychain.{key} must be true or false.")
    if "binary_path" in cfg:
        binary = cfg["binary_path"]
        if not isinstance(binary, str) or (binary.strip() and binary.strip() != "/usr/bin/security"):
            warnings.append("apple_keychain.binary_path is no longer used; remove it after switching to native Keychain access.")
    if "timeout_seconds" in cfg and _positive_timeout(cfg["timeout_seconds"]) is None:
        warnings.append("apple_keychain.timeout_seconds must be a positive finite number.")


def normalize_items(cfg: dict[str, Any]) -> tuple[list[KeychainTarget], list[str]]:
    """Resolve accounts and per-item overrides in their historic first-wins order.

    An empty keychain retains the legacy Keychain search-list behavior. New
    configurations should store an explicit keychain path. Warnings never quote
    malformed input; management commands must refuse to write if any are present.
    """
    if not isinstance(cfg, dict):
        return [], ["apple_keychain configuration must be a mapping."]

    warnings: list[str] = []
    items: list[KeychainTarget] = []
    _validate_settings(cfg, warnings)
    service = _string_value(cfg, "service", "hermes", "apple_keychain", warnings)
    keychain = ""
    if "default_keychain" in cfg:
        keychain = _string_value(cfg, "default_keychain", "", "apple_keychain", warnings)
        # The historical loader fell back to the deprecated alias if the
        # documented field had a non-string value, but not if it was empty.
        if not isinstance(cfg["default_keychain"], str) and "keychain" in cfg:
            keychain = _string_value(cfg, "keychain", "", "apple_keychain", warnings)
    elif "keychain" in cfg:
        keychain = _string_value(cfg, "keychain", "", "apple_keychain", warnings)

    for index, account in enumerate(_sequence(cfg, "accounts", warnings), 1):
        if not valid_env_name(account):
            warnings.append(f"apple_keychain.accounts entry {index} must be an environment variable name; skipping it.")
            continue
        items.append({"env": account, "service": service, "account": account, "keychain": keychain})

    for index, raw in enumerate(_sequence(cfg, "items", warnings), 1):
        location = f"apple_keychain.items entry {index}"
        if not isinstance(raw, dict):
            warnings.append(f"{location} must be a mapping; skipping it.")
            continue
        if any(key not in _ITEM_KEYS for key in raw):
            warnings.append(f"{location} has an unrecognized field.")
        env = raw.get("env")
        if not valid_env_name(env):
            warnings.append(f"{location} must contain a valid env name; skipping it.")
            continue
        item_service = _string_value(raw, "service", service, location, warnings)
        account = _string_value(raw, "account", env, location, warnings)
        item_keychain = _string_value(raw, "keychain", keychain, location, warnings)
        items.append({"env": env, "service": item_service, "account": account, "keychain": item_keychain})

    seen_env: set[str] = set()
    seen_targets: set[tuple[str, str, str]] = set()
    deduped: list[KeychainTarget] = []
    for item in items:
        if item["env"] in seen_env:
            warnings.append("Duplicate apple_keychain env target; keeping the first mapping.")
            continue
        seen_env.add(item["env"])
        target = (item["service"], item["account"], item["keychain"])
        if target in seen_targets:
            warnings.append("Multiple apple_keychain entries point to the same Keychain item.")
        seen_targets.add(target)
        deduped.append(item)
    return deduped, warnings


def _source_section(document: dict) -> dict:
    secrets = document.get("secrets", {})
    if not isinstance(secrets, dict):
        raise ValueError("Hermes secrets configuration must be a mapping.")
    source = secrets.get("apple_keychain", {})
    if not isinstance(source, dict):
        raise ValueError("Hermes apple_keychain configuration must be a mapping.")
    return source


def load_source_config() -> tuple[dict[str, Any], dict[str, Any], Path]:
    """Return editable document, runtime source section, and active config path.

    Hermes' startup secret-source loader reads the raw profile config, so use
    that same unexpanded section for management target selection. The document
    is read through Hermes' fail-closed guard before a write.
    """
    from hermes_cli.config import get_config_path, require_readable_config_before_write

    path = get_config_path()
    document = require_readable_config_before_write(path)
    return document, copy.deepcopy(_source_section(document)), path
