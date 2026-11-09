"""Single-item operations, diagnostics, and recovery."""
from __future__ import annotations

import argparse
import copy
import re
import sys

from . import backend, cli_input, configuration
from .cli_common import CommandError, deadline_for, error_text, find_item, load_items, print_write_result, probe_all, profile_command, require_explicit_target, revalidate_targets
from .cli_setup import ensure_writable, save_mapping
from .contracts import remaining


def set_secret(args: argparse.Namespace) -> int:
    if not args.stdin:
        cli_input.require_interactive()
    document, source, path, items = load_items()
    name = args.env
    if not configuration.valid_env_name(name):
        print("Enter a valid environment variable name.", file=sys.stderr)
        return 1
    if source.get("enabled") is not True:
        print("Run `hermes keychain setup` first.", file=sys.stderr)
        return 1
    item = find_item(items, name)
    new_mapping = item is None
    if new_mapping:
        candidate = copy.deepcopy(source)
        candidate["items"] = (candidate.get("items") or []) + [{"env": name}]
        candidate_items, problems = configuration.normalize_items(candidate)
        if problems:
            for problem in problems:
                print(problem, file=sys.stderr)
            return 1
        item = find_item(candidate_items, name)
    require_explicit_target(item)
    state = probe_all([item], deadline_for(source), args.replace_existing,
                       require_existing=args.replace_existing)[0]
    if args.allow_any_app:
        print("Warning: any-app access applies to newly created items; rotation preserves existing access controls.")
    print(f"Target: {name}; using the configured service, account and keychain in {path}.", flush=True)
    if new_mapping:
        ensure_writable(document)
    value = cli_input.read_secret(name, args.stdin)
    backend.validate_value(value)
    if new_mapping:
        save_mapping(document, item, config_path=path, set_default=False)
        print("Reference saved; writing the Keychain item.")
    revalidate_targets([item], path)
    sys.stdout.flush()
    result = backend.write_item(item, value, allow_any_app=args.allow_any_app,
                                keep_backup=args.keep_backup, expected_exists=state)
    print_write_result(name, result, keep_backup=args.keep_backup)
    return 0


def _print_cleanup_guidance(path, items: list[dict]) -> None:
    names = [item["env"] for item in items]
    supported = [name for name in names if re.fullmatch(r"[A-Z][A-Z0-9_]*", name)]
    unsupported = [name for name in names if name not in supported]
    print("\nKeychain access does not verify provider authentication or whether values match. "
          "Restart Hermes and test a fresh request.\n"
          "If you no longer need copies of these names in this profile's .env, review the list before running. "
          "`config unset` also clears related credential and configuration records; "
          "managed settings stay under Hermes' control.")
    if supported:
        command = f"{profile_command(path)} config unset"
        if len(supported) == 1:
            print(f"  {command} {supported[0]}")
        else:
            print(f"  for name in {' '.join(supported)}; do {command} \"$name\"; done")
    if unsupported:
        print(f"No cleanup command shown for {', '.join(unsupported)}; Hermes may treat these as config keys.")


def doctor(args: argparse.Namespace) -> int:
    _, source, path, items = load_items()
    print(f"Config: {path}")
    if source.get("enabled") is not True or not items:
        print("Apple Keychain is disabled or has no references; run `hermes keychain setup`.")
        return 1
    deadline = deadline_for(source)
    try:
        print(f"Keychain helper: {backend.helper_path(timeout=remaining(deadline))}")
    except backend.KeychainError as exc:
        print(f"Keychain helper: {error_text(exc)}")
        return 1
    from . import AppleKeychainSource

    remaining_source = dict(source, timeout_seconds=remaining(deadline))
    result = AppleKeychainSource().fetch(remaining_source, path.parent)
    failed = bool(result.error)
    for warning in result.warnings:
        print(warning)
    for item in items:
        available = item["env"] in result.secrets
        if not available:
            failed = True
        status = "available" if available else "unavailable"
        print(f"{item['env']}: {status}")
        if not item.get("keychain"):
            print(f"{item['env']}: legacy search-list target; select an explicit keychain before writing.")
            continue
        try:
            state = backend.probe_item(item, timeout=remaining(deadline))
        except backend.KeychainError as exc:
            print(f"{item['env']}: {error_text(exc)}")
            failed = True
            continue
        for recovery in state.get("recoveries", []):
            if recovery.get("state") == "preparing":
                print(f"{item['env']}: unfinished preparation; discard it using `hermes keychain recovery list`.")
                failed = True
            elif recovery.get("state") == "pending":
                print(f"{item['env']}: unfinished update; old value saved. Use `hermes keychain recovery list`.")
                failed = True
            else:
                print(f"{item['env']}: saved old value available in `hermes keychain recovery list`.")
    if not failed:
        _print_cleanup_guidance(path, items)
    return int(failed)


def recovery(args: argparse.Namespace) -> int:
    _, _, _, items = load_items()
    action = args.recovery_action
    if action not in {"list", "restore", "discard"}:
        print("Usage: hermes keychain recovery {list|restore|discard}", file=sys.stderr)
        return 2
    name = getattr(args, "env", None)
    if name:
        item = find_item(items, name)
        if not item:
            print("Requested environment variable is not configured.", file=sys.stderr)
            return 1
        items = [item]
    if not items:
        print("No Keychain references are configured.", file=sys.stderr)
        return 1
    for item in items:
        require_explicit_target(item)
    if action == "list":
        found = False
        for item in items:
            for entry in backend.list_recoveries(item):
                state = {
                    "preparing": "unfinished preparation; discard only",
                    "pending": "unfinished update; old value saved",
                    "kept": "saved old value",
                }[entry["state"]]
                print(f"{item['env']}: {entry['id']} ({state})")
                found = True
        if not found:
            print("No saved old values.")
        return 0
    item = items[0]
    sys.stdout.flush()
    if action == "restore":
        backend.restore_backup(item, args.recovery_id)
        print(f"{item['env']}: saved old value restored; the saved copy is retained until discarded.")
    else:
        backend.discard_backup(item, args.recovery_id)
        print(f"{item['env']}: recovery entry discarded; current value unchanged.")
    return 0
