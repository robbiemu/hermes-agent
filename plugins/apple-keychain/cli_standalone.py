"""Legacy provisioner entry point; capture input before importing Hermes."""
from __future__ import annotations

import argparse
import importlib
import importlib.util
import os
from pathlib import Path
import sys


if __name__ == "__main__" and not __package__:
    inherited = dict(os.environ)
    directory = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location(
        "_hermes_apple_keychain_standalone", directory / "__init__.py",
        submodule_search_locations=[str(directory)],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    standalone = importlib.import_module(spec.name + ".cli_standalone")
    raise SystemExit(standalone.main(sys.argv[1:], inherited))

from .cli import add_write_options, keychain_command


def main(argv: list[str], inherited: dict) -> int:
    parser = argparse.ArgumentParser(prog="provision-secrets.sh")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--only", metavar="ENV")
    selection.add_argument("--stdin", metavar="ENV")
    add_write_options(parser)
    args = parser.parse_args(argv)
    args.keychain_action = "provision"
    args.inherited_env = inherited
    from hermes_constants import get_hermes_home, reset_hermes_home_override, set_hermes_home_override
    token = None
    try:
        if get_hermes_home().parent.name != "profiles":
            from hermes_cli.profiles import get_active_profile, resolve_profile_env
            active = get_active_profile()
            if active != "default":
                token = set_hermes_home_override(resolve_profile_env(active))
        return keychain_command(args)
    finally:
        if token is not None:
            reset_hermes_home_override(token)
