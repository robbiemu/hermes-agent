"""Resolve configured Apple Keychain secrets during Hermes startup.

The reader and management commands share the same normalized item identities.
Existing configurations with no keychain path retain search-list reads; new
setup chooses and stores an explicit keychain path.
"""

from __future__ import annotations

import time
from pathlib import Path

from agent.secret_sources.base import ErrorKind, FetchResult, SecretSource
from hermes_platform.host.facts import os_family

from .configuration import normalize_items, timeout_seconds


_FAILURES = {
    "missing": (ErrorKind.REF_INVALID, "No Keychain item was found for {env}. Check its service, account, and keychain."),
    "locked": (ErrorKind.AUTH_FAILED, "The Keychain for {env} is locked. Unlock it and try again."),
    "denied": (ErrorKind.AUTH_FAILED, "Access to the Keychain item for {env} was denied. Grant access and try again."),
    "timeout": (ErrorKind.TIMEOUT, "Reading the Keychain item for {env} timed out. Check Keychain access and retry."),
    "invalid": (ErrorKind.NOT_CONFIGURED, "The Keychain target for {env} is invalid. Check its configuration."),
    "unavailable": (ErrorKind.BINARY_MISSING, "The native Keychain helper is unavailable. Check the Xcode Command Line Tools and helper access."),
    "recovery_pending": (ErrorKind.INTERNAL, "A Keychain operation for {env} needs recovery before it can be read."),
    "failure": (ErrorKind.INTERNAL, "Apple Keychain could not read the item for {env}."),
}


def _failure(kind: str, env: str) -> tuple[ErrorKind, str]:
    error_kind, message = _FAILURES.get(kind, _FAILURES["failure"])
    return error_kind, message.format(env=env)


class AppleKeychainSource(SecretSource):
    name = "apple_keychain"
    label = "Apple Keychain"
    shape = "mapped"
    remediation_hints = {
        ErrorKind.NOT_CONFIGURED: "Run `hermes keychain setup` to configure a Keychain reference.",
        ErrorKind.AUTH_FAILED: "Unlock the Keychain or authorize the helper in Keychain Access.",
        ErrorKind.BINARY_MISSING: "Install the Xcode Command Line Tools and check Keychain access.",
    }

    def is_enabled(self, cfg: dict) -> bool:
        return os_family() == "darwin" and isinstance(cfg, dict) and cfg.get("enabled") is True

    def override_existing(self, cfg: dict) -> bool:
        # Keep the original plugin's default for existing configurations.
        if not isinstance(cfg, dict):
            return True
        value = cfg.get("override_existing", True)
        return value if isinstance(value, bool) else False

    def fetch_timeout_seconds(self, cfg: dict) -> float:
        return timeout_seconds(cfg.get("timeout_seconds")) if isinstance(cfg, dict) else 10.0

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Enable Apple Keychain secret resolution.", "default": False},
            "service": {"description": "Default Keychain generic-password service name.", "default": "hermes"},
            "accounts": {"description": "Environment variable names to resolve using the defaults.", "default": []},
            "items": {"description": "Per-secret env, service, account, and keychain mappings.", "default": []},
            "default_keychain": {
                "description": "Default Keychain file. An empty value keeps the legacy search-list behavior.",
                "default": "",
            },
            "override_existing": {"description": "Whether Keychain values override env/.env values.", "default": True},
            "timeout_seconds": {"description": "Wall-clock timeout for this source.", "default": 10},
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        if os_family() != "darwin":
            return result.fail("Apple Keychain secret source only works on macOS.", ErrorKind.NOT_CONFIGURED)
        if not isinstance(cfg, dict):
            return result.fail("secrets.apple_keychain must be a mapping.", ErrorKind.NOT_CONFIGURED)
        items, warnings = normalize_items(cfg)
        result.warnings.extend(warnings)
        if not items:
            return result.fail("Apple Keychain has no valid accounts or items configured.", ErrorKind.NOT_CONFIGURED)

        # The registry enforces an outer timeout and discards late results. Keep
        # a small margin so earlier successes survive a later timed-out item.
        budget = self.fetch_timeout_seconds(cfg)
        deadline = time.monotonic() + budget - min(0.25, budget * 0.1)
        first_failure: tuple[ErrorKind, str] | None = None
        try:
            from .backend import KeychainError, read_item

            for item in items:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = _failure("timeout", item["env"])
                    result.warnings.append(failure[1])
                    first_failure = first_failure or failure
                    break
                try:
                    value = read_item(item, timeout=remaining)
                except KeychainError as exc:
                    failure = _failure(exc.kind, item["env"])
                    result.warnings.append(failure[1])
                    first_failure = first_failure or failure
                    if exc.kind == "timeout":
                        break
                    continue
                if not isinstance(value, str) or not value:
                    failure = (ErrorKind.EMPTY_VALUE, f"Apple Keychain returned an empty value for {item['env']}.")
                    result.warnings.append(failure[1])
                    first_failure = first_failure or failure
                    continue
                result.secrets[item["env"]] = value
        except Exception:  # health: allow BLE001 -- secret-source boundary must never expose arbitrary exception details
            failure = (ErrorKind.INTERNAL, "Apple Keychain could not complete the configured read.")
            result.warnings.append(failure[1])
            first_failure = first_failure or failure

        if result.secrets:
            return result
        if first_failure:
            return result.fail(first_failure[1], first_failure[0])
        return result.fail("Apple Keychain source resolved no secrets.", ErrorKind.EMPTY_VALUE)


def register(ctx):
    ctx.register_secret_source(AppleKeychainSource())
    from .cli import register_cli

    register_cli(ctx)
