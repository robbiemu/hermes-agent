"""Interactive setup and profile configuration writes."""
from __future__ import annotations

import argparse
import copy
import os
from pathlib import Path
import shlex
import subprocess
import sys

from . import backend, cli_import, cli_input, configuration, native_build
from .cli_common import CommandError, deadline_for, find_item, load_items, print_write_result, revalidate_targets
from .contracts import remaining


def login_keychain() -> str:
    try:
        result = subprocess.run(["/usr/bin/security", "login-keychain"], capture_output=True,
                                text=True, timeout=10, check=True, stdin=subprocess.DEVNULL,
                                env=native_build.child_env())
        paths = shlex.split(result.stdout.strip())
    except (OSError, subprocess.SubprocessError, ValueError):
        print("Could not locate the login keychain. Check macOS Keychain access and retry.", file=sys.stderr)
        raise CommandError("cannot find login keychain") from None
    if len(paths) != 1 or not os.path.isabs(paths[0]):
        print("Could not locate the login keychain. Check macOS Keychain access and retry.", file=sys.stderr)
        raise CommandError("cannot find login keychain")
    return paths[0]


def ensure_writable(document: dict) -> None:
    from hermes_cli import managed_scope
    from hermes_cli.config import is_managed

    keys = managed_scope.managed_config_keys()
    def present(key: str) -> bool:
        node = document
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                return False
            node = node[part]
        return True

    if is_managed() or any(key == "secrets" or key.startswith("secrets.") or present(key) for key in keys):
        print("Configuration contains administrator-managed settings that cannot be safely preserved; "
              "ask the administrator to set the Keychain reference.", file=sys.stderr)
        raise CommandError("managed configuration")


def save_mapping(document: dict, item: dict, *, config_path: Path, set_default: bool) -> dict:
    from hermes_cli.config import save_config

    current, _, current_path = configuration.load_source_config()
    if current_path != config_path or current != document:
        print("The profile configuration changed while this command was running; retry after reviewing it. "
              "No secret was written.", file=sys.stderr)
        raise CommandError("configuration changed")
    ensure_writable(document)
    secrets = document.setdefault("secrets", {})
    raw = secrets.setdefault("apple_keychain", {})
    if not isinstance(raw, dict):
        raise CommandError("invalid source")
    raw["enabled"] = True
    if set_default:
        raw["default_keychain"] = item["keychain"]
    accounts = raw.get("accounts", []) or []
    entries = raw.get("items", []) or []
    if not isinstance(accounts, list) or not isinstance(entries, list):
        raise CommandError("invalid mappings")
    raw["accounts"] = [name for name in accounts if name != item["env"]]
    raw["items"] = [entry for entry in entries if not isinstance(entry, dict) or entry.get("env") != item["env"]]
    raw["items"].append(dict(item))
    save_config(document)
    persisted, effective, saved_path, items = load_items()
    effective_default = effective.get("default_keychain", effective.get("keychain", ""))
    if (saved_path != config_path or effective.get("enabled") is not True or find_item(items, item["env"]) != item
            or (set_default and effective_default != item["keychain"])):
        print("The saved reference is not the effective runtime target; check managed settings before retrying. "
              "No secret was written.", file=sys.stderr)
        raise CommandError("effective config differs")
    return persisted


def _candidate(source: dict, name: str, target: str, service: str, account: str) -> dict | None:
    item = {"env": name, "service": service, "account": account, "keychain": target}
    candidate = copy.deepcopy(source)
    candidate["accounts"] = [entry for entry in candidate.get("accounts", []) or [] if entry != name]
    candidate["items"] = [entry for entry in candidate.get("items", []) or []
                          if not isinstance(entry, dict) or entry.get("env") != name] + [item]
    candidate_items, problems = configuration.normalize_items(candidate)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return None
    return find_item(candidate_items, name)


def _select_item(source: dict, old: dict | None, name: str, target: str, imported: bool):
    service = old["service"] if old else (source.get("service") or "hermes")
    account = old["account"] if old else name
    while True:
        item = _candidate(source, name, target, service, account)
        if item is None:
            return None
        if old and old.get("keychain") and old != item:
            old_state = backend.probe_item(old, timeout=remaining(deadline_for(source)))
            if old_state.get("recoveries"):
                print(f"{name}: the current target has saved old values. Restore or discard them before changing the target.", file=sys.stderr)
                return None
        state = backend.probe_item(item, timeout=remaining(deadline_for(source)))
        if any(entry.get("state") == "pending" for entry in state.get("recoveries", [])):
            print("An unfinished rotation needs recovery before another write.", file=sys.stderr)
            return None
        identity = state.get("keychain_identity")
        if not identity:
            print("Could not verify the physical Keychain target; no items were written.", file=sys.stderr)
            return None
        if not state.get("exists"):
            return item, False, False, identity
        replacement = "the value being imported" if imported else "a new value"
        different = "the imported value" if imported else "the new value"
        choice = cli_input.prompt(
            f"'{item['account']}' already exists in Keychain.\n1. Keep the value already in Keychain\n"
            f"2. Replace it with {replacement}\n3. Save {different} under a different name\n"
            "Enter 1, 2 or 3: ").strip()
        if choice == "1":
            return item, True, True, identity
        if choice == "2":
            return item, True, False, identity
        if choice == "3":
            account = cli_input.prompt("New Keychain item name: ").strip()
            if not account:
                print("Enter a nonempty Keychain item name.", file=sys.stderr)
                account = item["account"]
        else:
            print("Enter 1, 2 or 3.", file=sys.stderr)


def _recheck_item(item: dict, identity: str, exists: bool, source: dict) -> bool:
    state = backend.probe_item(item, timeout=remaining(deadline_for(source)))
    return (state.get("keychain_identity") == identity and bool(state.get("exists")) == exists
            and not any(entry.get("state") == "pending" for entry in state.get("recoveries", [])))


def _keep_existing(document: dict, source: dict, path: Path, items: list, item: dict, candidate, identity: str) -> int:
    ensure_writable(document)
    backend.validate_value(backend.read_item(item, timeout=remaining(deadline_for(source))))
    if not cli_input.confirm("Save this reference and keep the existing Keychain value? [y/N]: "):
        print("Cancelled; no changes made.")
        return 1
    backend.validate_value(backend.read_item(item, timeout=remaining(deadline_for(source))))
    if not _recheck_item(item, identity, True, source):
        print("The Keychain target changed during setup; no reference was saved.", file=sys.stderr)
        return 1
    save_mapping(document, item, config_path=path, set_default=not items)
    revalidate_targets([item], path)
    print(f"{item['env']}: existing Keychain value is readable; reference saved.")
    secrets = document.get("secrets", {})
    if candidate and (source.get("override_existing", True) is False
                      or item["env"] in (secrets.get("preserve_existing") or [])):
        print("Your settings preserve the existing .env value, which can take priority over the Keychain value.")
    return 0


def setup(args: argparse.Namespace) -> int:
    cli_input.require_interactive()
    document, source, path, items = load_items()
    print(f"Config: {path}", flush=True)
    if args.headless:
        mode = "2"
    else:
        print("1. Personal Mac (login keychain)\n2. Headless service (an existing keychain)", flush=True)
        mode = cli_input.prompt("Choose [1]: ").strip() or "1"
    if mode == "1":
        target = login_keychain()
    elif mode == "2":
        target = cli_input.prompt("Existing keychain file path: ").strip()
        if not target or not os.path.isabs(os.path.expanduser(target)):
            print("Enter an absolute keychain file path.", file=sys.stderr)
            return 1
        target = os.path.expanduser(target)
    else:
        print("Choose 1 or 2.", file=sys.stderr)
        return 1
    name = cli_input.prompt("Environment variable name: ").strip()
    if not configuration.valid_env_name(name):
        print("Enter a valid environment variable name.", file=sys.stderr)
        return 1
    candidate = cli_import.capture(name, path)
    selected = _select_item(source, find_item(items, name), name, target, candidate is not None)
    if selected is None:
        return 1
    item, exists, keep, identity = selected
    print(f"Target: {name} <- configured service and account; keychain={target}")
    if keep:
        return _keep_existing(document, source, path, items, item, candidate, identity)
    ensure_writable(document)
    imported = candidate is not None and cli_input.confirm(f"Found {name} in your .env. Use it? [Y/n]: ", default=True)
    allow_any = False
    if not exists:
        print("New-item access: the helper and /usr/bin/security are trusted. Other programs can invoke /usr/bin/security.")
        allow_any = cli_input.confirm("Allow any application to read a new item? This broadens access [y/N]: ")
        if allow_any:
            print("Warning: any application with Keychain access can read the new item.", flush=True)
    else:
        print("Existing item access controls are preserved during rotation.")
    if not cli_input.confirm("Save this reference and write the secret? [y/N]: "):
        print("Cancelled; no changes made.")
        return 1
    value = candidate.value if imported else cli_input.read_secret(name, False)
    backend.validate_value(value)
    if imported:
        try:
            if not cli_import.unchanged(candidate):
                raise ValueError("environment changed")
        except (OSError, ValueError):
            print("The profile or .env changed during setup; no secret was written.", file=sys.stderr)
            return 1
    if not _recheck_item(item, identity, exists, source):
        print("The Keychain target changed during setup; no secret was written.", file=sys.stderr)
        return 1
    saved_document = save_mapping(document, item, config_path=path, set_default=not items)
    print("Reference saved; writing the Keychain item.")
    revalidate_targets([item], path)
    current_document, _, saved_path = configuration.load_source_config()
    if saved_path != path or current_document != saved_document:
        print("The profile configuration changed; no secret was written.", file=sys.stderr)
        return 1
    if not _recheck_item(item, identity, exists, source):
        print("Reference saved, but the Keychain target changed; no secret was written.", file=sys.stderr)
        return 1
    sys.stdout.flush()
    result = backend.write_item(item, value, allow_any_app=allow_any, expected_exists=exists)
    print_write_result(name, result, keep_backup=False)
    return cli_import.maybe_cleanup(candidate, item, saved_document, identity) if imported else 0
