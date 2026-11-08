"""Argparse registration and dispatch for Keychain management."""
from __future__ import annotations

import argparse
import sys

from . import backend
from .cli_common import CommandError, error_text
from .cli_operations import doctor, recovery, set_secret
from .cli_provision import provision
from .cli_setup import setup


def register_cli(ctx) -> None:
    ctx.register_cli_command(
        name="keychain", help="Manage Apple Keychain secret references",
        setup_fn=build_parser, handler_fn=keychain_command,
        description="Set up and manage the active profile's Apple Keychain references.",
    )


def build_parser(parser: argparse.ArgumentParser) -> None:
    actions = parser.add_subparsers(dest="keychain_action")
    setup = actions.add_parser("setup", help="Set up an explicit Keychain target")
    setup.add_argument("--headless", action="store_true", help="configure an existing headless keychain")
    set_cmd = actions.add_parser("set", help="Create or rotate a configured secret")
    set_cmd.add_argument("env", help="environment variable name")
    set_cmd.add_argument("--stdin", action="store_true", help="read the secret from standard input")
    add_write_options(set_cmd)
    actions.add_parser("doctor", help="Check each configured reference without showing values")
    provision = actions.add_parser("provision", help="Provision configured references from inherited environment")
    selection = provision.add_mutually_exclusive_group()
    selection.add_argument("--only", metavar="ENV", help="select one inherited environment variable")
    selection.add_argument("--stdin", metavar="ENV", help="read one secret from standard input")
    add_write_options(provision)
    recovery = actions.add_parser("recovery", help="List, restore or discard saved old values")
    recovery_actions = recovery.add_subparsers(dest="recovery_action")
    listing = recovery_actions.add_parser("list", help="list recovery records")
    listing.add_argument("env", nargs="?", help="limit to one configured variable")
    for action in ("restore", "discard"):
        command = recovery_actions.add_parser(action, help=f"{action} a saved old value")
        command.add_argument("env")
        command.add_argument("recovery_id")


def add_write_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--replace-existing", action="store_true", help="allow rotation of an existing item")
    parser.add_argument("--keep-backup", action="store_true", help="retain the saved old value after rotation")
    parser.add_argument("--allow-any-app", action="store_true", help="allow any application to read a newly created item")


def keychain_command(args: argparse.Namespace) -> int:
    handlers = {"setup": setup, "set": set_secret, "doctor": doctor,
                "provision": provision, "recovery": recovery}
    handler = handlers.get(getattr(args, "keychain_action", None))
    if handler is None:
        print("Usage: hermes keychain {setup|set|doctor|provision|recovery}", file=sys.stderr)
        return 2
    try:
        return handler(args)
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 1
    except CommandError:
        return 1
    except backend.KeychainError as exc:
        print(f"Keychain: {error_text(exc)}", file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        # Configuration diagnostics are intentionally fixed, not arbitrary YAML or OS contents.
        print(f"Keychain command could not use the configuration ({type(exc).__name__}).", file=sys.stderr)
        return 1
