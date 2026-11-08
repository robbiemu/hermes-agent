"""Operator CLI behavior through real plugin discovery and parser wiring."""
from __future__ import annotations

import argparse
import builtins
import getpass
import importlib
import io
import os
import shlex
import signal
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
import hermes_yaml as yaml


@pytest.fixture
def cli(tmp_path, monkeypatch):
    home = tmp_path / "profiles" / "work"
    home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    initial = {"plugins": {"enabled": ["apple-keychain"]}, "secrets": {"apple_keychain": {"enabled": False}}}
    (home / "config.yaml").write_text(yaml.safe_dump(initial), encoding="utf-8")

    from hermes_cli.plugins import PluginManager
    from hermes_cli.main import _attach_plugin_cli_command

    manager = PluginManager(scope_key=str(home))
    manager.discover_and_load()
    info = manager._cli_commands["keychain"]
    command_module = importlib.import_module(info["handler_fn"].__module__)
    package = command_module.__package__
    input_module = importlib.import_module(package + ".cli_input")
    setup_module = importlib.import_module(package + ".cli_setup")
    common_module = importlib.import_module(package + ".cli_common")
    module = SimpleNamespace(backend=command_module.backend, input=input_module, setup=setup_module,
                             getpass=getpass, CommandError=common_module.CommandError,
                             real_require=input_module.require_interactive, real_prompt=input_module.prompt)
    monkeypatch.setattr(input_module, "require_interactive", lambda: None)
    monkeypatch.setattr(input_module, "prompt", lambda text, hidden=False: getpass.getpass(text) if hidden else builtins.input(text))
    parser = argparse.ArgumentParser()
    _attach_plugin_cli_command(parser.add_subparsers(dest="command"), info)

    def seed(source, **secrets):
        document = {"plugins": {"enabled": ["apple-keychain"]}, "unchanged": {"setting": "keep"},
                    "secrets": {**secrets, "apple_keychain": source}}
        (home / "config.yaml").write_text(yaml.safe_dump(document), encoding="utf-8")
        return document

    def run(*args):
        parsed = parser.parse_args(["keychain", *args])
        return parsed.func(parsed)

    yield home, module, seed, run, parser
    manager.unload()


def _pipe_input(monkeypatch, value):
    read_fd, write_fd = os.pipe()
    os.write(write_fd, value.encode("utf-8"))
    os.close(write_fd)
    stream = os.fdopen(read_fd, "r", encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stream)


def _state(item, *, exists=False, recoveries=None, identity=None):
    return {"exists": exists, "status": "present" if exists else "missing",
            "recoveries": recoveries or [], "keychain_identity": identity or item["keychain"]}


def test_setup_saves_only_profile_references_and_uses_hidden_input(cli, monkeypatch, capsys, tmp_path):
    home, module, seed, run, _ = cli
    parent_config = tmp_path / "config.yaml"
    parent_config.write_text("original: keep\n", encoding="utf-8")
    seed({"enabled": False, "override_existing": False}, sources=["other", "apple_keychain"])
    prompts = iter(["", "OPENAI_API_KEY", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(prompts))
    monkeypatch.setattr(module.setup, "login_keychain", lambda: "/tmp/work-login.keychain-db")
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: "synthetic-secret")
    monkeypatch.setattr(module.backend, "probe_item", lambda item, **kw: _state(item))
    writes = []
    monkeypatch.setattr(module.backend, "write_item", lambda item, value, **kw: writes.append((dict(item), value, kw)) or {"result": "created"})

    assert run("setup") == 0
    config = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    source = config["secrets"]["apple_keychain"]
    assert config["unchanged"] == {"setting": "keep"}
    assert config["secrets"]["sources"] == ["other", "apple_keychain"]
    assert source["override_existing"] is False
    assert source["default_keychain"] == "/tmp/work-login.keychain-db"
    assert source["items"][0]["env"] == "OPENAI_API_KEY"
    assert writes[0][0] == source["items"][0]
    assert writes[0][1] == "synthetic-secret"
    assert writes[0][2]["expected_exists"] is False
    assert parent_config.read_text(encoding="utf-8") == "original: keep\n"
    output = capsys.readouterr()
    assert "synthetic-secret" not in output.out + output.err
    assert "synthetic-secret" not in (home / "config.yaml").read_text(encoding="utf-8")


def test_set_never_prints_secret_and_requires_explicit_replacement(cli, monkeypatch, capsys):
    _, module, seed, run, _ = cli
    seed({"enabled": True, "default_keychain": "/tmp/login.keychain-db", "accounts": ["API_KEY"]})
    monkeypatch.setattr(module.backend, "probe_item", lambda item, **kw: _state(item, exists=True))
    writes = []
    monkeypatch.setattr(module.backend, "write_item", lambda *a, **kw: writes.append((a, kw)) or {"result": "updated", "recovery_id": "00000000-0000-0000-0000-000000000001"})
    _pipe_input(monkeypatch, "synthetic-new-secret\n")
    assert run("set", "API_KEY", "--stdin") == 1
    assert writes == []
    assert run("set", "API_KEY", "--stdin", "--replace-existing") == 0
    assert writes[0][0][1] == "synthetic-new-secret"
    assert writes[0][1]["expected_exists"] is True
    captured = capsys.readouterr()
    assert "synthetic-new-secret" not in captured.out + captured.err


def test_new_set_uses_normalizer_default_precedence_and_rejects_implicit_target(cli, monkeypatch):
    _, module, seed, run, _ = cli
    seed({"enabled": True, "default_keychain": "", "keychain": "/tmp/legacy.keychain-db"})
    writes = []
    monkeypatch.setattr(module.backend, "write_item", lambda *a, **kw: writes.append((a, kw)) or {"result": "updated", "recovery_id": "00000000-0000-0000-0000-000000000001"})
    assert run("set", "API_KEY", "--stdin") == 1
    assert writes == []


def test_batch_validates_all_inputs_before_any_write(cli, monkeypatch, capsys):
    _, module, seed, _, parser = cli
    seed({"enabled": True, "default_keychain": "/tmp/login.keychain-db", "accounts": ["FIRST", "SECOND"]})
    writes = []
    monkeypatch.setattr(module.backend, "probe_item", lambda item, **kw: _state(item))
    monkeypatch.setattr(module.backend, "write_item", lambda *a, **kw: writes.append((a, kw)) or {"result": "updated", "recovery_id": "00000000-0000-0000-0000-000000000001"})
    args = parser.parse_args(["keychain", "provision"])
    args.inherited_env = {"FIRST": "first-synthetic", "SECOND": "bad\x00value"}
    assert args.func(args) == 1
    assert writes == []
    captured = capsys.readouterr()
    assert "first-synthetic" not in captured.out + captured.err
    assert "bad\x00value" not in captured.out + captured.err


@pytest.mark.platforms("posix")
def test_batch_rejects_aliases_of_same_physical_item_before_any_write(cli, monkeypatch, tmp_path, capsys):
    _, module, seed, _, parser = cli
    keychain = tmp_path / "actual.keychain-db"
    alias = tmp_path / "alias.keychain-db"
    keychain.touch()
    alias.symlink_to(keychain)
    seed({"enabled": True, "items": [
        {"env": "FIRST", "service": "svc", "account": "same", "keychain": str(keychain)},
        {"env": "SECOND", "service": "svc", "account": "same", "keychain": str(alias)},
    ]})
    writes = []
    monkeypatch.setattr(module.backend, "probe_item", lambda item, **kw: _state(item, identity="same-physical-file"))
    monkeypatch.setattr(module.backend, "write_item", lambda *a, **kw: writes.append((a, kw)) or {"result": "updated", "recovery_id": "00000000-0000-0000-0000-000000000001"})
    args = parser.parse_args(["keychain", "provision"])
    args.inherited_env = {"FIRST": "first-synthetic", "SECOND": "second-synthetic"}
    assert args.func(args) == 1
    assert writes == []
    output = capsys.readouterr().err
    assert "same physical Keychain item" in output or "same Keychain item" in output


def test_legacy_keychain_override_cannot_redirect_provisioning(cli, monkeypatch, capsys):
    _, module, seed, _, parser = cli
    seed({"enabled": True, "default_keychain": "/tmp/runtime.keychain-db", "accounts": ["API_KEY"]})
    writes = []
    monkeypatch.setattr(module.backend, "write_item", lambda *a, **kw: writes.append((a, kw)) or {"result": "updated", "recovery_id": "00000000-0000-0000-0000-000000000001"})
    args = parser.parse_args(["keychain", "provision", "--only", "API_KEY"])
    args.inherited_env = {"API_KEY": "synthetic", "KEYCHAIN": "/tmp/other.keychain-db"}
    assert args.func(args) == 1
    assert writes == []
    assert "does not match" in capsys.readouterr().err


def test_hidden_prompt_rejects_non_tty_before_any_keychain_access(cli, monkeypatch, capsys):
    _, module, seed, run, _ = cli
    seed({"enabled": True, "default_keychain": "/tmp/login.keychain-db", "accounts": ["API_KEY"]})
    monkeypatch.setattr(module.input, "require_interactive", module.real_require)
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    monkeypatch.setattr(module.backend, "probe_item", lambda *a, **kw: pytest.fail("must not access Keychain"))
    assert run("set", "API_KEY") == 1
    assert "interactive terminal is required" in capsys.readouterr().err


def test_setup_rejects_non_tty_before_prompt_or_keychain_access(cli, monkeypatch, capsys):
    _, module, _, run, _ = cli
    monkeypatch.setattr(module.input, "require_interactive", module.real_require)
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    monkeypatch.setattr(module.setup, "load_items", lambda: pytest.fail("must not read config"))
    monkeypatch.setattr(module.backend, "probe_item", lambda *a, **kw: pytest.fail("must not access Keychain"))
    assert run("setup") == 1
    assert "interactive terminal is required" in capsys.readouterr().err


@pytest.mark.platforms("macos")
def test_doctor_uses_runtime_reader_and_reports_pending_recovery(cli, monkeypatch, capsys):
    _, module, seed, run, _ = cli
    seed({"enabled": True, "default_keychain": "/tmp/login.keychain-db", "accounts": ["API_KEY"]})
    monkeypatch.setattr(module.backend, "helper_path", lambda **kw: "/tmp/helper")
    monkeypatch.setattr(module.backend, "read_item", lambda item, **kw: "synthetic-not-for-output")
    monkeypatch.setattr(module.backend, "probe_item", lambda item, **kw: _state(
        item, exists=True, recoveries=[{"id": "00000000-0000-0000-0000-000000000001", "state": "pending"}]))
    assert run("doctor") == 1
    output = capsys.readouterr().out
    assert "API_KEY: available" in output
    assert "unfinished update; old value saved" in output
    assert "synthetic-not-for-output" not in output


def test_recovery_lists_and_resolves_by_id_without_values(cli, monkeypatch, capsys):
    _, module, seed, run, _ = cli
    seed({"enabled": True, "default_keychain": "/tmp/login.keychain-db", "accounts": ["API_KEY"]})
    recovery_id = "00000000-0000-0000-0000-000000000001"
    monkeypatch.setattr(module.backend, "list_recoveries", lambda item: [{"id": recovery_id, "state": "pending"}])
    calls = []
    monkeypatch.setattr(module.backend, "restore_backup", lambda item, rid: calls.append((item["env"], rid)))
    assert run("recovery", "list") == 0
    assert "unfinished update; old value saved" in capsys.readouterr().out
    assert run("recovery", "restore", "API_KEY", recovery_id) == 0
    assert calls == [("API_KEY", recovery_id)]
    assert "retained" in capsys.readouterr().out


@pytest.mark.platforms("posix")
def test_wrapper_ignores_shell_shebang_of_hermes_launcher(tmp_path):
    project = Path(__file__).resolve().parents[2]
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    python = fake_bin / "python3"
    python.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} \"$@\"\n", encoding="utf-8")
    python.chmod(0o755)
    launcher = fake_bin / "hermes"
    marker = tmp_path / "launcher-ran"
    launcher.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    launcher.chmod(0o755)
    env = dict(os.environ, PATH=f"{fake_bin}:/usr/bin:/bin", HERMES_HOME=str(tmp_path / "home"))
    env.pop("HERMES_PY", None)
    env.pop("HERMES_PYTHON", None)
    result = subprocess.run([str(project / "plugins/apple-keychain/provision-secrets.sh"), "--help"],
                            cwd=project, env=env, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert "--replace-existing" in result.stdout
    assert not marker.exists()


def test_setup_refuses_managed_secret_settings_before_config_or_keychain_write(cli, monkeypatch, tmp_path, capsys):
    home, module, seed, run, _ = cli
    seed({"enabled": False, "override_existing": False}, sources=["other"])
    original = (home / "config.yaml").read_bytes()
    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / "config.yaml").write_text("secrets:\n  sources: [managed-source]\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    prompts = iter(["", "API_KEY", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(prompts))
    monkeypatch.setattr(module.setup, "login_keychain", lambda: "/tmp/login.keychain-db")
    monkeypatch.setattr(module.backend, "probe_item", lambda item, **kw: _state(item))
    writes = []
    monkeypatch.setattr(module.backend, "write_item", lambda *a, **kw: writes.append((a, kw)) or {"result": "updated", "recovery_id": "00000000-0000-0000-0000-000000000001"})
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: pytest.fail("should not ask for a secret"))
    assert run("setup") == 1
    assert (home / "config.yaml").read_bytes() == original
    assert writes == []
    assert "administrator-managed" in capsys.readouterr().err


def test_batch_rejects_distinct_paths_resolved_to_one_native_identity(cli, monkeypatch, capsys):
    _, module, seed, _, parser = cli
    seed({"enabled": True, "items": [
        {"env": "FIRST", "service": "svc", "account": "same", "keychain": "/tmp/store.keychain"},
        {"env": "SECOND", "service": "svc", "account": "same", "keychain": "/tmp/store.keychain-db"},
    ]})
    writes = []
    monkeypatch.setattr(module.backend, "probe_item", lambda item, **kw: _state(item, identity="same-native-file"))
    monkeypatch.setattr(module.backend, "write_item", lambda *a, **kw: writes.append((a, kw)) or {"result": "updated", "recovery_id": "00000000-0000-0000-0000-000000000001"})
    args = parser.parse_args(["keychain", "provision"])
    args.inherited_env = {"FIRST": "first-synthetic", "SECOND": "second-synthetic"}
    assert args.func(args) == 1
    assert writes == []
    assert "same physical Keychain item" in capsys.readouterr().err


def test_profile_flag_routes_parser_and_write_to_named_profile(cli, monkeypatch, tmp_path):
    home, module, seed, _, parser = cli
    seed({"enabled": True, "default_keychain": "/tmp/work.keychain-db", "accounts": ["API_KEY"]})
    default_config = tmp_path / "config.yaml"
    default_config.write_text("marker: default-profile\n", encoding="utf-8")
    from hermes_cli import main
    monkeypatch.setattr(main, "_explicit_cli_profile", main._explicit_cli_profile)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["hermes", "-p", "work", "keychain", "set", "API_KEY", "--stdin"])
    main._apply_profile_override()
    _pipe_input(monkeypatch, "synthetic-profile-value\n")
    monkeypatch.setattr(module.backend, "probe_item", lambda item, **kw: _state(item))
    writes = []
    monkeypatch.setattr(module.backend, "write_item", lambda item, value, **kw: writes.append((item, value)) or {"result": "created"})
    args = parser.parse_args(sys.argv[1:])
    assert args.func(args) == 0
    assert Path(os.environ["HERMES_HOME"]) == home
    assert writes[0][0]["keychain"] == "/tmp/work.keychain-db"
    assert default_config.read_text(encoding="utf-8") == "marker: default-profile\n"


def test_setup_preserves_unrelated_user_setting_pinned_by_administrator(cli, monkeypatch, tmp_path):
    home, module, seed, run, _ = cli
    document = seed({"enabled": False})
    document["model"] = {"default": "user-choice"}
    (home / "config.yaml").write_text(yaml.safe_dump(document), encoding="utf-8")
    original = (home / "config.yaml").read_bytes()
    managed = tmp_path / "managed-model"
    managed.mkdir()
    (managed / "config.yaml").write_text("model:\n  default: admin-choice\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    prompts = iter(["", "API_KEY", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(prompts))
    monkeypatch.setattr(module.setup, "login_keychain", lambda: "/tmp/login.keychain-db")
    monkeypatch.setattr(module.backend, "probe_item", lambda item, **kw: _state(item))
    monkeypatch.setattr(module.backend, "write_item", lambda *a, **kw: pytest.fail("must not write"))
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: pytest.fail("must not ask for a secret"))
    assert run("setup") == 1
    assert (home / "config.yaml").read_bytes() == original


def test_setup_refuses_to_overwrite_config_changed_during_prompt(cli, monkeypatch, capsys):
    home, module, seed, run, _ = cli
    document = seed({"enabled": False})
    prompts = iter(["", "API_KEY", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(prompts))
    monkeypatch.setattr(module.setup, "login_keychain", lambda: "/tmp/login.keychain-db")
    monkeypatch.setattr(module.backend, "probe_item", lambda item, **kw: _state(item))
    writes = []
    monkeypatch.setattr(module.backend, "write_item", lambda *a, **kw: writes.append((a, kw)) or {"result": "updated", "recovery_id": "00000000-0000-0000-0000-000000000001"})
    def enter_secret(prompt):
        document["unchanged"]["setting"] = "changed-elsewhere"
        (home / "config.yaml").write_text(yaml.safe_dump(document), encoding="utf-8")
        return "synthetic-secret"
    monkeypatch.setattr(module.getpass, "getpass", enter_secret)
    assert run("setup") == 1
    assert yaml.safe_load((home / "config.yaml").read_text())["unchanged"]["setting"] == "changed-elsewhere"
    assert writes == []
    captured = capsys.readouterr()
    assert "configuration changed" in captured.err
    assert "synthetic-secret" not in captured.out + captured.err


def test_set_refuses_profile_change_during_hidden_prompt(cli, monkeypatch, tmp_path, capsys):
    home, module, seed, run, _ = cli
    seed({"enabled": True, "default_keychain": "/tmp/login.keychain-db", "accounts": ["API_KEY"]})
    other = tmp_path / "other"
    other.mkdir()
    (other / "config.yaml").write_bytes((home / "config.yaml").read_bytes())
    monkeypatch.setattr(module.backend, "probe_item", lambda item, **kw: _state(item))
    writes = []
    monkeypatch.setattr(module.backend, "write_item", lambda *a, **kw: writes.append((a, kw)) or {"result": "updated", "recovery_id": "00000000-0000-0000-0000-000000000001"})
    def enter_secret(prompt):
        monkeypatch.setenv("HERMES_HOME", str(other))
        return "synthetic-secret"
    monkeypatch.setattr(module.getpass, "getpass", enter_secret)
    assert run("set", "API_KEY") == 1
    assert writes == []
    captured = capsys.readouterr()
    assert "references changed" in captured.err
    assert "synthetic-secret" not in captured.out + captured.err


@pytest.mark.platforms("posix")
def test_hidden_prompt_timeout_restores_real_terminal_and_signal_handlers(cli, monkeypatch, capsys):
    import pty
    import signal
    import termios

    _, module, _, _, _ = cli
    master, slave = pty.openpty()
    stream = os.fdopen(os.dup(slave), "r", encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stream)
    before = termios.tcgetattr(slave)
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGHUP)}
    try:
        with pytest.raises(module.CommandError):
            module.real_prompt("Secret: ", hidden=True, timeout=0.01)
        assert termios.tcgetattr(slave) == before
        assert {sig: signal.getsignal(sig) for sig in handlers} == handlers
        assert "timed out" in capsys.readouterr().err
    finally:
        stream.close()
        os.close(slave)
        os.close(master)


@pytest.mark.platforms("posix")
def test_hidden_prompt_disables_echo_and_restores_terminal(cli, monkeypatch, capsys):
    import pty
    import select
    import termios

    _, module, _, _, _ = cli
    master, slave = pty.openpty()
    stream = os.fdopen(os.dup(slave), "r", encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stream)
    before = termios.tcgetattr(slave)
    real_select = select.select
    sent = False
    def send_after_echo_disabled(*args):
        nonlocal sent
        if not sent:
            assert not termios.tcgetattr(slave)[3] & termios.ECHO
            os.write(master, b"synthetic-hidden-value\n")
            sent = True
        return real_select(*args)
    monkeypatch.setattr(module.input.select, "select", send_after_echo_disabled)
    try:
        assert module.real_prompt("Secret: ", hidden=True, timeout=2) == "synthetic-hidden-value"
        assert termios.tcgetattr(slave) == before
        captured = capsys.readouterr()
        assert "synthetic-hidden-value" not in captured.out + captured.err
    finally:
        stream.close()
        os.close(slave)
        os.close(master)


@pytest.mark.platforms("posix")
def test_known_unattended_session_rejects_interactive_pty(cli, monkeypatch, capsys):
    import pty

    _, module, _, run, _ = cli
    master, slave = pty.openpty()
    stream = os.fdopen(os.dup(slave), "r", encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stream)
    monkeypatch.setattr(module.input, "require_interactive", module.real_require)
    monkeypatch.setenv("HERMES_CRON_SESSION", "1")
    monkeypatch.setattr(module.setup, "load_items", lambda: pytest.fail("must reject before config or Keychain"))
    try:
        assert run("setup") == 1
        assert "interactive terminal is required" in capsys.readouterr().err
    finally:
        stream.close()
        os.close(slave)
        os.close(master)


@pytest.mark.platforms("posix")
def test_explicit_stdin_is_bounded_and_times_out(cli, monkeypatch, tmp_path, capsys):
    _, module, _, _, _ = cli
    monkeypatch.setattr(module.input, "MAX_SECRET", 8)
    path = tmp_path / "too-large"
    path.write_bytes(b"x" * 11)
    with path.open("r", encoding="utf-8") as stream:
        monkeypatch.setattr(sys, "stdin", stream)
        with pytest.raises(module.CommandError):
            module.input.read_secret("API_KEY", True)
    assert "too large" in capsys.readouterr().err
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(read_fd, "r", encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stream)
    monkeypatch.setattr(module.input, "INPUT_TIMEOUT_SECONDS", 0.01)
    try:
        with pytest.raises(module.CommandError):
            module.input.read_secret("API_KEY", True)
        assert "timed out" in capsys.readouterr().err
    finally:
        stream.close()
        os.close(write_fd)


def test_login_keychain_discloses_no_environment_credentials(cli, monkeypatch):
    _, module, _, _, _ = cli
    monkeypatch.setenv("SYNTHETIC_CREDENTIAL", "synthetic-not-for-child")
    calls = []
    def run(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(stdout='"/tmp/login.keychain-db"\n')
    monkeypatch.setattr(module.setup.subprocess, "run", run)
    assert module.setup.login_keychain() == "/tmp/login.keychain-db"
    assert calls[0][1]["stdin"] is subprocess.DEVNULL
    assert "SYNTHETIC_CREDENTIAL" not in calls[0][1]["env"]
    assert "synthetic-not-for-child" not in calls[0][1]["env"].values()


def test_set_preview_and_write_receipt_do_not_disclose_configured_values(cli, monkeypatch, capsys):
    _, module, seed, run, _ = cli
    seed({"enabled": True, "items": [{"env": "API_KEY", "service": "sensitive-service-metadata",
          "account": "sensitive-account-metadata", "keychain": "/tmp/login.keychain-db"}]})
    monkeypatch.setattr(module.backend, "probe_item", lambda item, **kw: _state(item, exists=True))
    monkeypatch.setattr(module.backend, "write_item", lambda *a, **kw: {
        "result": "updated", "recovery_id": "00000000-0000-0000-0000-000000000001"})
    _pipe_input(monkeypatch, "synthetic-secret-value\n")
    assert run("set", "API_KEY", "--stdin", "--replace-existing", "--keep-backup") == 0
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "API_KEY" in output and "backup" in output and "retained" in output
    assert "sensitive-service-metadata" not in output
    assert "sensitive-account-metadata" not in output
    assert "synthetic-secret-value" not in output


@pytest.mark.platforms("posix")
def test_termios_failure_has_safe_error_and_no_echo_fallback(cli, monkeypatch, capsys):
    import pty
    import termios

    _, module, _, _, _ = cli
    master, slave = pty.openpty()
    stream = os.fdopen(os.dup(slave), "r", encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stream)
    def fail_terminal(fd):
        raise termios.error("sensitive-unexpected-diagnostic")
    monkeypatch.setattr(termios, "tcgetattr", fail_terminal)
    try:
        with pytest.raises(module.CommandError):
            module.real_prompt("Secret: ", hidden=True, timeout=1)
        output = capsys.readouterr().err
        assert "Hidden input is unavailable" in output
        assert "sensitive-unexpected-diagnostic" not in output
    finally:
        stream.close()
        os.close(slave)
        os.close(master)


@pytest.mark.platforms("posix")
@pytest.mark.parametrize("sig", [getattr(signal, name) for name in ("SIGTERM", "SIGHUP", "SIGQUIT", "SIGTSTP")
                                 if hasattr(signal, name)])
def test_signal_during_hidden_prompt_restores_terminal(cli, monkeypatch, sig):
    import pty
    import termios

    _, module, _, _, _ = cli
    master, slave = pty.openpty()
    stream = os.fdopen(os.dup(slave), "r", encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stream)
    before = termios.tcgetattr(slave)
    previous = signal.getsignal(sig)
    def interrupt(*args):
        assert signal.getsignal(sig) is module.input._interrupted
        os.kill(os.getpid(), sig)
        return [], [], []
    monkeypatch.setattr(module.input.select, "select", interrupt)
    try:
        with pytest.raises(KeyboardInterrupt):
            module.real_prompt("Secret: ", hidden=True, timeout=1)
        assert termios.tcgetattr(slave) == before
        assert signal.getsignal(sig) is previous
    finally:
        stream.close()
        os.close(slave)
        os.close(master)


@pytest.mark.platforms("posix")
def test_terminal_restore_error_is_reported_without_exception_details(cli, monkeypatch, capsys):
    import pty
    import signal
    import termios

    _, module, _, _, _ = cli
    master, slave = pty.openpty()
    stream = os.fdopen(os.dup(slave), "r", encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stream)
    before = termios.tcgetattr(slave)
    real_setattr = termios.tcsetattr
    previous = signal.getsignal(signal.SIGTERM)
    calls = 0
    def fail_after_actual_restore(fd, when, attrs):
        nonlocal calls
        calls += 1
        real_setattr(fd, when, attrs)
        if calls == 2:
            raise termios.error("private-terminal-diagnostic")
    monkeypatch.setattr(termios, "tcsetattr", fail_after_actual_restore)
    try:
        with pytest.raises(module.CommandError):
            module.real_prompt("Secret: ", hidden=True, timeout=0.01)
        assert termios.tcgetattr(slave) == before
        assert signal.getsignal(signal.SIGTERM) is previous
        output = capsys.readouterr().err
        assert "Could not restore terminal settings" in output
        assert "private-terminal-diagnostic" not in output
    finally:
        stream.close()
        os.close(slave)
        os.close(master)
