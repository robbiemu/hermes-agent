"""Batch provisioning from explicitly supplied values."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from . import backend, cli_input
from .cli_common import CommandError, deadline_for, find_item, load_items, print_write_result, probe_all, revalidate_targets


def check_legacy_overrides(items: list[dict], path: Path, inherited: dict) -> None:
    configured = inherited.get("HERMES_CONFIG", "")
    if configured and Path(configured).expanduser().resolve() != path.expanduser().resolve():
        print("HERMES_CONFIG does not match the active profile config. Select the profile with Hermes or HERMES_HOME.", file=sys.stderr)
        raise CommandError("config mismatch")
    requested = inherited.get("KEYCHAIN", "")
    if requested:
        requested_path = Path(requested).expanduser().resolve()
        if any(not item.get("keychain") or Path(item["keychain"]).expanduser().resolve() != requested_path for item in items):
            print("KEYCHAIN does not match every selected runtime reference. Update config with `hermes keychain setup` first.", file=sys.stderr)
            raise CommandError("keychain mismatch")


def provision(args: argparse.Namespace) -> int:
    _, source, path, items = load_items()
    if source.get("enabled") is not True:
        print("Run `hermes keychain setup` first.", file=sys.stderr)
        return 1
    name = args.only or args.stdin
    if name:
        selected = find_item(items, name)
        if not selected:
            print("Requested environment variable is not configured.", file=sys.stderr)
            return 1
        items = [selected]
    if not items:
        print("No Keychain references are configured.", file=sys.stderr)
        return 1
    inherited = getattr(args, "inherited_env", None)
    if inherited is None:
        inherited = os.environ
    check_legacy_overrides(items, path, inherited)
    # Collect and validate every input and target before the first Keychain write.
    if args.stdin:
        values = [cli_input.read_secret(args.stdin, True)]
    else:
        values = [inherited.get(item["env"], "") for item in items]
        missing = [item["env"] for item, value in zip(items, values) if not value]
        if missing:
            print(f"Missing inherited values: {', '.join(missing)}", file=sys.stderr)
            return 1
        if getattr(args, "inherited_env", None) is None:
            from hermes_cli.env_loader import get_secret_source
            if any(get_secret_source(item["env"]) for item in items):
                print("Hermes has already hydrated at least one selected variable. "
                      "Use --stdin or the legacy provision-secrets.sh wrapper to pass the original input.", file=sys.stderr)
                return 1
    for value in values:
        backend.validate_value(value)
    states = probe_all(items, deadline_for(source), args.replace_existing)
    revalidate_targets(items, path)
    if args.allow_any_app:
        print("Warning: any-app access applies to newly created items; rotation preserves existing access controls.")
    for item, value, exists in zip(items, values, states):
        revalidate_targets(items, path)
        print(f"Target: {item['env']}; using the configured service, account and keychain in {path}.")
        sys.stdout.flush()
        result = backend.write_item(item, value, allow_any_app=args.allow_any_app,
                                    keep_backup=args.keep_backup, expected_exists=exists)
        print_write_result(item["env"], result, keep_backup=args.keep_backup)
    return 0
