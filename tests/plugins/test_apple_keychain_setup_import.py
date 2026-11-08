"""Setup imports only the active profile's verified .env value."""
from __future__ import annotations

import pytest
import hermes_yaml as yaml

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


def _answers(monkeypatch, answers, callback=None):
    pending = iter(answers)
    asked = []
    def respond(prompt=""):
        asked.append(prompt)
        if callback:
            callback(prompt)
        return next(pending)
    monkeypatch.setattr("builtins.input", respond)
    return asked


def test_import_with_consent_removes_only_selected_assignments(cli, monkeypatch, capsys):
    home, module, run, store, writes = _prepare(cli, monkeypatch)
    original = b'# note\r\n  OTHER = "keep # value"\r\nexport API_KEY="synthetic-import"\r\nLAST=untouched'
    (home / ".env").write_bytes(original)
    (home / ".env").chmod(0o640)
    asked = _answers(monkeypatch, ["", "API_KEY", "", "n", "y", "y"])
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: pytest.fail("import should not ask for hidden input"))
    assert run("setup") == 0
    assert store["API_KEY"] == "synthetic-import"
    assert writes[0][2]["expected_exists"] is False
    assert (home / ".env").read_bytes() == b'# note\r\n  OTHER = "keep # value"\r\nLAST=untouched'
    assert (home / ".env").stat().st_mode & 0o777 == 0o640
    assert any("Found API_KEY in your .env. Use it? [Y/n]" in p for p in asked)
    assert any("Saved and checked. Remove API_KEY from .env? [y/N]" in p for p in asked)
    output = capsys.readouterr()
    assert "synthetic-import" not in output.out + output.err
    assert "synthetic-import" not in (home / "config.yaml").read_text()


def test_default_cleanup_leaves_imported_file_and_process_env_is_not_source(cli, monkeypatch):
    home, module, run, store, _ = _prepare(cli, monkeypatch)
    original = b"API_KEY=synthetic-file\nOTHER=keep\n"
    (home / ".env").write_bytes(original)
    monkeypatch.setenv("API_KEY", "synthetic-process")
    _answers(monkeypatch, ["", "API_KEY", "", "n", "y", ""])
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: pytest.fail("unexpected hidden prompt"))
    assert run("setup") == 0
    assert store["API_KEY"] == "synthetic-file"
    assert (home / ".env").read_bytes() == original


def test_declining_import_uses_hidden_input_and_never_offers_cleanup(cli, monkeypatch):
    home, module, run, store, _ = _prepare(cli, monkeypatch)
    original = b"API_KEY=synthetic-file\n"
    (home / ".env").write_bytes(original)
    asked = _answers(monkeypatch, ["", "API_KEY", "n", "n", "y"])
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: "synthetic-manual")
    assert run("setup") == 0
    assert store["API_KEY"] == "synthetic-manual"
    assert (home / ".env").read_bytes() == original
    assert not any("Remove API_KEY" in p for p in asked)


def test_existing_item_requires_explicit_replace_and_preserves_access_choice(cli, monkeypatch):
    home, module, run, store, writes = _prepare(cli, monkeypatch, existing={"API_KEY": "synthetic-old"})
    (home / ".env").write_text("API_KEY=synthetic-new\n")
    asked = _answers(monkeypatch, ["", "API_KEY", "", "other", "2", "", "y", ""])
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: pytest.fail("unexpected hidden prompt"))
    assert run("setup") == 0
    assert store["API_KEY"] == "synthetic-new"
    assert writes[0][2]["expected_exists"] is True
    assert writes[0][2]["allow_any_app"] is False
    assert sum("Enter 1, 2 or 3" in p for p in asked) == 3
    assert not any("Allow any application" in p for p in asked)


def test_choose_different_item_name_keeps_original_env_and_never_writes_original(cli, monkeypatch):
    home, module, run, store, writes = _prepare(cli, monkeypatch, existing={"API_KEY": "synthetic-old"})
    (home / ".env").write_text("API_KEY=synthetic-new\nOTHER=keep\n")
    asked = _answers(monkeypatch, ["", "API_KEY", "3", "alternate", "", "n", "y", "y"])
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: pytest.fail("unexpected hidden prompt"))
    assert run("setup") == 0
    assert store == {"API_KEY": "synthetic-old", "alternate": "synthetic-new"}
    assert [entry[0] for entry in writes] == ["alternate"]
    assert (home / ".env").read_text() == "OTHER=keep\n"
    config = yaml.safe_load((home / "config.yaml").read_text())
    assert config["secrets"]["apple_keychain"]["items"][0]["env"] == "API_KEY"
    assert config["secrets"]["apple_keychain"]["items"][0]["account"] == "alternate"
    assert any("New Keychain item name" in p for p in asked)


def test_keep_existing_verifies_without_writing_or_removing_env(cli, monkeypatch, capsys):
    home, module, run, store, writes = _prepare(cli, monkeypatch, existing={"API_KEY": "synthetic-old"})
    config_path = home / "config.yaml"
    config = yaml.safe_load(config_path.read_text())
    config["secrets"]["apple_keychain"]["override_existing"] = False
    config_path.write_text(yaml.safe_dump(config))
    original = b"API_KEY=synthetic-file\n"
    (home / ".env").write_bytes(original)
    asked = _answers(monkeypatch, ["", "API_KEY", "1", "y"])
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: pytest.fail("unexpected hidden prompt"))
    assert run("setup") == 0
    assert store == {"API_KEY": "synthetic-old"}
    assert not writes
    assert (home / ".env").read_bytes() == original
    config = yaml.safe_load(config_path.read_text())
    assert config["secrets"]["apple_keychain"]["override_existing"] is False
    assert config["secrets"]["apple_keychain"]["items"][0]["env"] == "API_KEY"
    assert not any("Found API_KEY" in p or "Remove API_KEY" in p or "Allow any application" in p for p in asked)
    output = capsys.readouterr()
    assert ".env" in output.out and "priority" in output.out
    assert "synthetic-old" not in output.out + output.err
    assert "synthetic-file" not in output.out + output.err


@pytest.mark.parametrize("change", ["file", "profile", "config", "target", "managed", "keychain", "identity"])
def test_changes_before_cleanup_leave_env_untouched(cli, monkeypatch, tmp_path, capsys, change):
    home, module, run, store, _ = _prepare(cli, monkeypatch)
    env = home / ".env"
    original = b"API_KEY=synthetic-value\nOTHER=keep\n"
    env.write_bytes(original)
    other = tmp_path / "alternate-profile"
    other.mkdir()
    (other / "config.yaml").write_bytes((home / "config.yaml").read_bytes())
    def change_config(target):
        doc = yaml.safe_load((home / "config.yaml").read_text())
        if target:
            doc["secrets"]["apple_keychain"]["items"][0]["service"] = "changed"
        else:
            doc["unrelated"] = "concurrent"
        (home / "config.yaml").write_text(yaml.safe_dump(doc))
    def manage_env():
        managed = tmp_path / "managed"
        managed.mkdir()
        (managed / ".env").write_text("API_KEY=synthetic-managed\n")
        monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    def change_identity():
        monkeypatch.setattr(module.backend, "probe_item", lambda item, **kwargs: {
            "exists": True, "recoveries": [], "keychain_identity": "other-physical-keychain"})
    changes = {
        "file": lambda: env.write_bytes(original + b"CONCURRENT=preserved\n"),
        "profile": lambda: monkeypatch.setenv("HERMES_HOME", str(other)),
        "config": lambda: change_config(False),
        "target": lambda: change_config(True),
        "managed": manage_env,
        "keychain": lambda: store.update(API_KEY="synthetic-changed"),
        "identity": change_identity,
    }
    def change_during_prompt(prompt):
        if prompt.startswith("Saved and checked."):
            changes[change]()
    _answers(monkeypatch, ["", "API_KEY", "", "n", "y", "y"], change_during_prompt)
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: pytest.fail("unexpected hidden prompt"))
    assert run("setup") == 1
    assert env.read_bytes() == original + (b"CONCURRENT=preserved\n" if change == "file" else b"")
    output = capsys.readouterr()
    assert "left" in output.err and ".env" in output.err
    assert "synthetic-value" not in output.out + output.err
    assert "private detail" not in output.out + output.err


def test_write_failure_leaves_env_and_never_offers_cleanup(cli, monkeypatch, capsys):
    home, module, run, _, _ = _prepare(cli, monkeypatch)
    original = b"API_KEY=synthetic-value\n"
    (home / ".env").write_bytes(original)
    asked = _answers(monkeypatch, ["", "API_KEY", "", "n", "y"])
    def fail(*args, **kwargs):
        raise module.backend.keychain_error("failure")
    monkeypatch.setattr(module.backend, "write_item", fail)
    assert run("setup") == 1
    assert (home / ".env").read_bytes() == original
    assert not any("Remove API_KEY" in p for p in asked)
    output = capsys.readouterr()
    assert "synthetic-value" not in output.out + output.err


def test_readback_failure_leaves_env_without_cleanup_question(cli, monkeypatch, capsys):
    home, module, run, _, _ = _prepare(cli, monkeypatch)
    original = b"API_KEY=synthetic-value\n"
    (home / ".env").write_bytes(original)
    asked = _answers(monkeypatch, ["", "API_KEY", "", "n", "y"])
    def fail(*args, **kwargs):
        raise module.backend.keychain_error("denied")
    monkeypatch.setattr(module.backend, "read_item", fail)
    assert run("setup") == 1
    assert (home / ".env").read_bytes() == original
    assert not any("Remove API_KEY" in p for p in asked)
    output = capsys.readouterr()
    assert "left" in output.err and ".env" in output.err
    assert "synthetic-value" not in output.out + output.err


def test_secret_reference_is_not_imported(cli, monkeypatch):
    home, module, run, store, _ = _prepare(cli, monkeypatch)
    original = b"API_KEY=op://Private/Fixture/key\n"
    (home / ".env").write_bytes(original)
    asked = _answers(monkeypatch, ["", "API_KEY", "n", "y"])
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: "synthetic-manual")
    assert run("setup") == 0
    assert store["API_KEY"] == "synthetic-manual"
    assert (home / ".env").read_bytes() == original
    assert not any("Found API_KEY" in p or "Remove API_KEY" in p for p in asked)


def test_unsafe_env_is_reported_and_never_imported(cli, monkeypatch, tmp_path, capsys):
    home, module, run, _, writes = _prepare(cli, monkeypatch)
    other = tmp_path / "outside"
    other.write_text("API_KEY=synthetic-outside\n")
    (home / ".env").symlink_to(other)
    _answers(monkeypatch, ["", "API_KEY"])
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: pytest.fail("unsafe file must be reported"))
    assert run("setup") == 1
    assert not writes
    assert other.read_text() == "API_KEY=synthetic-outside\n"
    assert ".env" in capsys.readouterr().err


@pytest.mark.parametrize("reason", ["timeout", "eof", "interrupt"])
def test_cleanup_cancellation_reports_saved_item_and_leaves_env(cli, monkeypatch, capsys, reason):
    home, module, run, store, _ = _prepare(cli, monkeypatch)
    original = b"API_KEY=synthetic-value\n"
    (home / ".env").write_bytes(original)
    def cancel(prompt):
        if prompt.startswith("Saved and checked."):
            if reason == "timeout":
                raise module.CommandError("timeout")
            if reason == "eof":
                raise EOFError
            raise KeyboardInterrupt
    _answers(monkeypatch, ["", "API_KEY", "", "n", "y"], cancel)
    assert run("setup") == 1
    assert store["API_KEY"] == "synthetic-value"
    assert (home / ".env").read_bytes() == original
    output = capsys.readouterr()
    assert "Keychain item was saved" in output.err and ".env was left alone" in output.err
    assert "synthetic-value" not in output.out + output.err


def test_alternate_item_collision_names_the_actual_account_and_requires_another_choice(cli, monkeypatch):
    home, module, run, store, writes = _prepare(
        cli, monkeypatch, existing={"API_KEY": "synthetic-original", "alternate": "synthetic-other"})
    (home / ".env").write_text("API_KEY=synthetic-new\n")
    asked = _answers(monkeypatch, ["", "API_KEY", "3", "alternate", "3", "third", "", "n", "y", ""])
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: pytest.fail("unexpected hidden prompt"))
    assert run("setup") == 0
    assert store == {"API_KEY": "synthetic-original", "alternate": "synthetic-other", "third": "synthetic-new"}
    assert [entry[0] for entry in writes] == ["third"]
    assert any("'alternate' already exists" in prompt for prompt in asked)


def test_physical_target_change_before_write_does_not_import_or_clean(cli, monkeypatch, capsys):
    home, module, run, _, writes = _prepare(cli, monkeypatch)
    original = b"API_KEY=synthetic-value\n"
    (home / ".env").write_bytes(original)
    save_mapping = module.setup.save_mapping
    def save_then_retarget(*args, **kwargs):
        result = save_mapping(*args, **kwargs)
        monkeypatch.setattr(module.backend, "probe_item", lambda item, **kw: {
            "exists": False, "recoveries": [], "keychain_identity": "other-physical-keychain"})
        return result
    monkeypatch.setattr(module.setup, "save_mapping", save_then_retarget)
    asked = _answers(monkeypatch, ["", "API_KEY", "", "n", "y"])
    assert run("setup") == 1
    assert not writes
    assert (home / ".env").read_bytes() == original
    assert not any("Remove API_KEY" in prompt for prompt in asked)
    output = capsys.readouterr()
    assert "Reference saved" in output.err and "no secret was written" in output.err
    assert "synthetic-value" not in output.out + output.err
