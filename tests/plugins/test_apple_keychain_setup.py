"""Setup and doctor never inspect or mutate the profile's environment file."""
from __future__ import annotations

import builtins
from contextlib import contextmanager
import io
import os
from pathlib import Path
import shlex

import hermes_yaml as yaml
import pytest

pytest_plugins = ("tests.plugins.test_apple_keychain_cli",)


def _prepare(cli, monkeypatch, *, existing=None):
    home, module, seed, run, _ = cli
    seed({"enabled": False, "service": "hermes"})
    monkeypatch.setattr(module.setup, "login_keychain", lambda: "/tmp/isolated.keychain-db")
    store = dict(existing or {})
    writes = []

    def probe(item, **kwargs):
        return {"exists": item["account"] in store, "recoveries": [], "keychain_identity": "fixture"}

    def write(item, value, **kwargs):
        name = item["account"]
        assert kwargs["expected_exists"] == (name in store)
        writes.append((name, value, kwargs))
        existed = name in store
        store[name] = value
        return {"result": "updated" if existed else "created",
                "recovery_id": "00000000-0000-0000-0000-000000000001" if existed else None}

    monkeypatch.setattr(module.backend, "probe_item", probe)
    monkeypatch.setattr(module.backend, "write_item", write)
    monkeypatch.setattr(module.backend, "read_item", lambda item, **kwargs: store[item["account"]])
    return home, module, run, store, writes


def _answers(monkeypatch, answers):
    pending = iter(answers)
    asked = []

    def respond(prompt=""):
        asked.append(prompt)
        return next(pending)

    monkeypatch.setattr("builtins.input", respond)
    return asked


@contextmanager
def _forbid_env_access(monkeypatch):
    # The plugin is loaded by the fixture before this guard; core startup may read its own .env.
    from agent import secret_scope

    original_open = builtins.open
    original_io_open = io.open
    original_os_open = os.open

    def check(path):
        if isinstance(path, (str, bytes, os.PathLike)) and os.path.basename(os.fsdecode(path)) == ".env":
            pytest.fail("plugin must not access the profile environment file")

    def guarded_open(path, *args, **kwargs):
        check(path)
        return original_open(path, *args, **kwargs)

    def guarded_io_open(path, *args, **kwargs):
        check(path)
        return original_io_open(path, *args, **kwargs)

    def guarded_os_open(path, *args, **kwargs):
        check(path)
        return original_os_open(path, *args, **kwargs)

    with monkeypatch.context() as guard:
        guard.setattr(secret_scope, "load_env_file", lambda *args, **kwargs: pytest.fail("unexpected env reader"))
        guard.setattr(builtins, "open", guarded_open)
        guard.setattr(io, "open", guarded_io_open)
        guard.setattr(os, "open", guarded_os_open)
        yield


@pytest.mark.parametrize(("choice", "answers", "account"), [
    ("new", ["", "API_KEY", "n", "y"], "API_KEY"),
    ("replace", ["", "API_KEY", "2", "y"], "API_KEY"),
    ("keep", ["", "API_KEY", "1", "y"], None),
    ("different", ["", "API_KEY", "3", "alternate", "n", "y"], "alternate"),
])
def test_setup_uses_only_hidden_input_and_leaves_env_untouched(cli, monkeypatch, capsys, choice, answers, account):
    existing = None if choice == "new" else {"API_KEY": "synthetic-old"}
    home, module, run, store, writes = _prepare(cli, monkeypatch, existing=existing)
    sentinel = b"API_KEY=synthetic-file\nOTHER=preserved\n"
    (home / ".env").write_bytes(sentinel)
    monkeypatch.setenv("API_KEY", "synthetic-process")
    asked = _answers(monkeypatch, answers)
    hidden = []
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: hidden.append(prompt) or "synthetic-typed")

    with _forbid_env_access(monkeypatch):
        assert run("setup") == 0

    assert (home / ".env").read_bytes() == sentinel
    assert not any(".env" in prompt for prompt in asked)
    if account is None:
        assert not writes and not hidden
        assert store == existing
    else:
        assert len(hidden) == 1 and "input hidden" in hidden[0]
        assert [(write[0], write[1]) for write in writes] == [(account, "synthetic-typed")]
        assert writes[0][2]["expected_exists"] is (choice == "replace")
        assert writes[0][2]["allow_any_app"] is False
    config = yaml.safe_load((home / "config.yaml").read_text())
    assert config["secrets"]["apple_keychain"]["items"][0]["account"] == (account or "API_KEY")
    output = capsys.readouterr()
    assert "hermes keychain doctor" in output.out
    assert all(value not in output.out + output.err for value in ("synthetic-file", "synthetic-process", "synthetic-typed"))


def test_alternate_collision_requires_another_explicit_choice(cli, monkeypatch):
    _, module, run, store, writes = _prepare(
        cli, monkeypatch, existing={"API_KEY": "synthetic-old", "alternate": "synthetic-other"})
    asked = _answers(monkeypatch, ["", "API_KEY", "", "3", "alternate", "3", "third", "n", "y"])
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: "synthetic-typed")
    assert run("setup") == 0
    assert store == {"API_KEY": "synthetic-old", "alternate": "synthetic-other", "third": "synthetic-typed"}
    assert [entry[0] for entry in writes] == ["third"]
    assert sum("Enter 1, 2 or 3" in prompt for prompt in asked) == 3
    assert any("'alternate' already exists" in prompt for prompt in asked)


@pytest.mark.parametrize("named", [False, True])
def test_setup_suggests_doctor_for_the_same_profile(cli, monkeypatch, tmp_path, capsys, named):
    old_home, module, run, _, _ = _prepare(cli, monkeypatch)
    root = tmp_path / "custom root's profile"
    home = root / "profiles" / "work" if named else root
    home.mkdir(parents=True)
    (home / "config.yaml").write_bytes((old_home / "config.yaml").read_bytes())
    (root / "active_profile").write_text("another-profile\n")
    monkeypatch.setenv("HERMES_HOME", str(home))
    _answers(monkeypatch, ["", "API_KEY", "n", "y"])
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: "synthetic-typed")

    assert run("setup") == 0
    profile = "" if named else " -p default"
    command = f"HERMES_HOME={shlex.quote(str(home))} hermes{profile} keychain doctor"
    assert command in capsys.readouterr().out


def _ready_doctor(cli, monkeypatch, names):
    home, module, seed, run, _ = cli
    seed({"enabled": True, "default_keychain": "/tmp/login.keychain-db", "accounts": names})
    monkeypatch.setattr(module.backend, "helper_path", lambda **kwargs: "/tmp/helper")
    monkeypatch.setattr(module.backend, "read_item", lambda item, **kwargs: "synthetic-doctor-secret")
    monkeypatch.setattr(module.backend, "probe_item", lambda item, **kwargs: {
        "exists": True, "recoveries": [], "keychain_identity": "fixture"})
    return home, module, run


@pytest.mark.platforms("macos")
def test_doctor_guidance_uses_quoted_profile_once_for_multiple_names(cli, monkeypatch, tmp_path, capsys):
    old_home, _, run = _ready_doctor(cli, monkeypatch, ["API_KEY", "OTHER_TOKEN", "bad_API_KEY", "_OTHER_TOKEN"])
    home = tmp_path / "custom root's profile"
    home.mkdir()
    (home / "config.yaml").write_bytes((old_home / "config.yaml").read_bytes())
    (home / "active_profile").write_text("sticky-profile\n")
    sentinel = b"API_KEY=synthetic-file\n"
    (home / ".env").write_bytes(sentinel)
    monkeypatch.setenv("HERMES_HOME", str(home))

    with _forbid_env_access(monkeypatch):
        assert run("doctor") == 0

    assert (home / ".env").read_bytes() == sentinel
    output = capsys.readouterr().out
    command = (f"for name in API_KEY OTHER_TOKEN; do HERMES_HOME={shlex.quote(str(home))} "
               'hermes -p default config unset "$name"; done')
    assert command in output
    assert output.count("HERMES_HOME=") == 1
    assert output.count("If you no longer need copies") == 1
    assert "No cleanup command shown for bad_API_KEY, _OTHER_TOKEN" in output
    assert "credential and configuration records" in output
    assert "does not verify provider authentication or whether values match" in output
    assert "Restart Hermes and test a fresh request" in output
    assert "synthetic-file" not in output and "synthetic-doctor-secret" not in output


@pytest.mark.platforms("macos")
def test_doctor_uses_named_profile_for_single_cleanup_command(cli, monkeypatch, capsys):
    home, _, run = _ready_doctor(cli, monkeypatch, ["API_KEY"])
    assert run("doctor") == 0
    output = capsys.readouterr().out
    assert f"HERMES_HOME={shlex.quote(str(home))} hermes config unset API_KEY" in output
    assert "for name in" not in output


@pytest.mark.platforms("macos")
@pytest.mark.parametrize("failure", ["disabled", "helper", "read", "probe", "pending"])
def test_doctor_failures_never_offer_cleanup(cli, monkeypatch, capsys, failure):
    _, module, run = _ready_doctor(cli, monkeypatch, ["API_KEY"])
    _, _, seed, _, _ = cli

    def keychain_failure(kind):
        def fail(*args, **kwargs):
            raise module.backend.keychain_error(kind)
        return fail

    scenarios = {
        "disabled": lambda: seed({"enabled": False, "accounts": ["API_KEY"]}),
        "helper": lambda: monkeypatch.setattr(module.backend, "helper_path", keychain_failure("unavailable")),
        "read": lambda: monkeypatch.setattr(module.backend, "read_item", keychain_failure("denied")),
        "probe": lambda: monkeypatch.setattr(module.backend, "probe_item", keychain_failure("denied")),
        "pending": lambda: monkeypatch.setattr(module.backend, "probe_item", lambda item, **kwargs: {
            "exists": True, "keychain_identity": "fixture", "recoveries": [{"state": "pending"}]}),
    }
    scenarios[failure]()
    with _forbid_env_access(monkeypatch):
        assert run("doctor") == 1
    output = capsys.readouterr()
    assert "config unset" not in output.out + output.err
    assert "cleanup command" not in output.out + output.err
    assert ".env" not in output.out + output.err


@pytest.mark.platforms("macos")
def test_core_cleanup_keeps_keychain_available_for_fresh_provider_request(cli, monkeypatch, capsys):
    import json

    import httpx
    from openai import OpenAI

    from agent.credential_pool import load_pool
    from hermes_cli.config import unset_config_value
    from hermes_cli.env_loader import load_hermes_dotenv, reset_secret_source_cache
    from hermes_cli.runtime_provider import resolve_runtime_provider

    home, module, run, store, _ = _prepare(cli, monkeypatch)
    old = "fixture-old-credential"
    new = "fixture-keychain-credential"
    (home / ".env").write_text(f"OPENAI_API_KEY={old}\n")
    monkeypatch.setenv("OPENAI_API_KEY", old)
    assert any(entry.source == "env:OPENAI_API_KEY" for entry in load_pool("openai-api").entries())
    _answers(monkeypatch, ["", "OPENAI_API_KEY", "n", "y"])
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: new)
    monkeypatch.setattr(module.backend, "helper_path", lambda **kwargs: "/tmp/helper")

    assert run("setup") == 0
    assert store["OPENAI_API_KEY"] == new
    assert run("doctor") == 0
    assert "hermes config unset OPENAI_API_KEY" in capsys.readouterr().out

    # This is Hermes' public cleanup operation, acting only on synthetic test state.
    unset_config_value("OPENAI_API_KEY")
    auth = json.loads((home / "auth.json").read_text())
    entries = auth.get("credential_pool", {}).get("openai-api", [])
    assert not any(entry.get("source") == "env:OPENAI_API_KEY" for entry in entries)
    reset_secret_source_cache(home)
    try:
        load_hermes_dotenv(hermes_home=home)
        assert not load_pool("openai-api").has_credentials()
        runtime = resolve_runtime_provider(requested="openai-api")
        assert runtime["api_key"] == new
        captured = []

        def respond(request):
            captured.append(request.headers.get("Authorization"))
            return httpx.Response(200, json={"id": "fixture", "choices": []})

        with OpenAI(api_key=runtime["api_key"], base_url="http://localhost:1234/v1",
                    http_client=httpx.Client(transport=httpx.MockTransport(respond)), max_retries=0) as client:
            client.chat.completions.create(model="fixture", messages=[])
        assert captured == [f"Bearer {new}"]
    finally:
        reset_secret_source_cache(home)
