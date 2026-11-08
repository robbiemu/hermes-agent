"""Apple Keychain source behavior through real Hermes plugin discovery."""

from __future__ import annotations

import copy
import importlib
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import hermes_yaml as yaml
import pytest

from agent.secret_sources.base import ErrorKind, FetchResult, SecretSource
from agent.secret_sources.registry import apply_all, get_source, register_source, restore_registration
from hermes_constants import reset_hermes_home_override, set_hermes_home_override
from tests.secret_sources.conformance import SecretSourceConformance


@pytest.fixture
def discovered(tmp_path, monkeypatch):
    """Discover the real plugin but never consult a real Keychain."""
    home = tmp_path / "home"
    home.mkdir()
    bundled = tmp_path / "bundled"
    bundled.mkdir()
    plugin = Path(__file__).resolve().parents[2] / "plugins" / "apple-keychain"
    shutil.copytree(plugin, bundled / "apple-keychain", ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_BUNDLED_PLUGINS", str(bundled))
    monkeypatch.delenv("HERMES_ENABLE_PROJECT_PLUGINS", raising=False)
    monkeypatch.chdir(tmp_path)
    (home / "config.yaml").write_text(yaml.safe_dump({"plugins": {"enabled": ["apple-keychain"]}}))
    from hermes_cli.plugins import PluginManager

    manager = PluginManager()
    manager.discover_and_load()
    loaded = manager._plugins["apple-keychain"]
    assert loaded.enabled, loaded.error
    source = get_source("apple_keychain", scope=manager.scope_key)
    assert source is not None
    assert "keychain" in manager._cli_commands
    assert loaded.tools_registered == []
    try:
        yield home, manager, loaded.module, source
    finally:
        manager.unload()


def test_shared_mapping_preserves_legacy_and_per_item_targets(discovered):
    _, _, module, _ = discovered
    normalize = module.configuration.normalize_items
    items, warnings = normalize({
        "service": "common",
        "keychain": "/legacy.keychain-db",
        "accounts": ["FIRST_TOKEN"],
        "items": [
            {"env": "SECOND_TOKEN", "account": "different", "service": "other",
             "keychain": "/specific.keychain-db"},
            {"env": "THIRD_TOKEN"},
        ],
    })
    assert warnings == []
    assert items == [
        {"env": "FIRST_TOKEN", "service": "common", "account": "FIRST_TOKEN", "keychain": "/legacy.keychain-db"},
        {"env": "SECOND_TOKEN", "service": "other", "account": "different", "keychain": "/specific.keychain-db"},
        {"env": "THIRD_TOKEN", "service": "common", "account": "THIRD_TOKEN", "keychain": "/legacy.keychain-db"},
    ]
    implicit, warnings = normalize({"default_keychain": "", "keychain": "/ignored", "accounts": ["FIRST_TOKEN"]})
    assert warnings == []
    assert implicit[0]["keychain"] == ""  # Existing installations used the search list.
    assert normalize({"binary_path": " ", "accounts": ["FIRST_TOKEN"]})[1] == []


def test_malformed_and_duplicate_mappings_warn_without_disclosing_values(discovered):
    _, _, module, source = discovered
    private = "sensitive_fixture_value_42"
    items, warnings = module.configuration.normalize_items({
        "enabled": "false", "override_existing": "false", "timeout_seconds": -1,
        "binary_path": private,
        "service": [private],
        "accounts": ["TOKEN_A", {"password": private}],
        "items": [
            {"env": "TOKEN_A", "account": private},
            {"env": "TOKEN_B", "account": "shared"},
            {"env": "TOKEN_C", "account": "shared"},
            {"env": private + "!", "password": private},
            {"env": "TOKEN_D", "keychain": {"secret": private}, "account": private + "\x1b"},
        ],
    })
    assert [item["env"] for item in items] == ["TOKEN_A", "TOKEN_B", "TOKEN_C", "TOKEN_D"]
    assert any("Duplicate" in warning for warning in warnings)
    assert any("same Keychain item" in warning for warning in warnings)
    assert any("binary_path" in warning for warning in warnings)
    assert any("control characters" in warning for warning in warnings)
    assert private not in " ".join(warnings)
    assert source.override_existing({}) is True
    assert source.override_existing({"override_existing": False}) is False
    assert source.override_existing({"override_existing": "false"}) is False


def test_configuration_follows_active_profile_and_does_not_mutate_cache(discovered, tmp_path):
    home, _, module, _ = discovered
    (home / "config.yaml").write_text(yaml.safe_dump({
        "secrets": {"apple_keychain": {"service": "default", "accounts": ["DEFAULT_TOKEN"]}},
        "other": {"keep": "default"},
    }))
    profile = tmp_path / "profiles" / "work"
    profile.mkdir(parents=True)
    (profile / "config.yaml").write_text(yaml.safe_dump({
        "secrets": {"apple_keychain": {"service": "work", "accounts": ["WORK_TOKEN"], "override_existing": False}},
        "other": {"keep": "work"},
    }))
    token = set_hermes_home_override(profile)
    try:
        document, source, path = module.configuration.load_source_config()
        assert path == profile / "config.yaml"
        assert document["other"] == {"keep": "work"}
        assert source["service"] == "work"
        source["accounts"].append("MUTATED_TOKEN")
        assert module.configuration.load_source_config()[1]["accounts"] == ["WORK_TOKEN"]
    finally:
        reset_hermes_home_override(token)
    _, source, path = module.configuration.load_source_config()
    assert path == home / "config.yaml"
    assert source["accounts"] == ["DEFAULT_TOKEN"]


def test_configuration_rejects_malformed_source_without_echoing_it(discovered):
    home, _, module, _ = discovered
    sensitive = "private_invalid_source_value"
    (home / "config.yaml").write_text(yaml.safe_dump({"secrets": {"apple_keychain": sensitive}}))
    with pytest.raises(ValueError) as exc:
        module.configuration.load_source_config()
    assert sensitive not in str(exc.value)


@pytest.mark.platforms("macos")
def test_resolution_applies_successes_and_keeps_one_shared_timeout(discovered, monkeypatch):
    home, _, module, _ = discovered
    backend = importlib.import_module(f"{module.__name__}.backend")
    clock = SimpleNamespace(now=100.0)
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock.now))
    observed = []
    private = "fixture_secret_from_backend"

    def read_item(item, *, timeout):
        observed.append((dict(item), timeout))
        clock.now += 1.0
        if item["env"] == "GOOD_TOKEN":
            return private + "\n"
        raise backend.KeychainError("timeout", "never show backend details " + private)

    monkeypatch.setattr(backend, "read_item", read_item)
    cfg = {
        "sources": ["apple_keychain"],
        "apple_keychain": {
            "enabled": True, "default_keychain": "/one.keychain-db", "timeout_seconds": 3,
            "accounts": ["GOOD_TOKEN"],
            "items": [{"env": "FAIL_TOKEN", "account": "remote-account", "service": "remote",
                       "keychain": "/two.keychain-db"}, {"env": "UNTOUCHED_TOKEN"}],
        },
    }
    original = os.environ.get("GOOD_TOKEN")
    env = {"GOOD_TOKEN": "old"}
    report = apply_all(cfg, home, environ=env)
    result = next(row.result for row in report.sources if row.name == "apple_keychain")
    assert env["GOOD_TOKEN"] == private + "\n"  # Prior default allows overriding existing values.
    assert os.environ.get("GOOD_TOKEN") == original
    assert result.ok and result.secrets == {"GOOD_TOKEN": private + "\n"}
    assert "timed out" in " ".join(result.warnings)
    assert private not in " ".join(result.warnings)
    assert observed[0][0] == {"env": "GOOD_TOKEN", "service": "hermes", "account": "GOOD_TOKEN",
                              "keychain": "/one.keychain-db"}
    assert observed[1][0] == {"env": "FAIL_TOKEN", "service": "remote", "account": "remote-account",
                              "keychain": "/two.keychain-db"}
    assert len(observed) == 2
    assert 0 < observed[1][1] < observed[0][1] < 3

    preserve_cfg = copy.deepcopy(cfg)
    preserve_cfg["apple_keychain"]["override_existing"] = False
    preserved_env = {"GOOD_TOKEN": "old"}
    report = apply_all(preserve_cfg, home, environ=preserved_env)
    source_report = next(row for row in report.sources if row.name == "apple_keychain")
    assert preserved_env["GOOD_TOKEN"] == "old"
    assert source_report.skipped_existing == ["GOOD_TOKEN"]


@pytest.mark.platforms("macos")
def test_keychain_mappings_beat_bulk_source_listed_first(discovered, monkeypatch):
    home, manager, module, _ = discovered
    backend = importlib.import_module(f"{module.__name__}.backend")
    monkeypatch.setattr(backend, "read_item", lambda item, *, timeout: f"keychain-{item['env']}")

    class BulkSource(SecretSource):
        name = "fixture_bulk"
        label = "Fixture bulk"
        shape = "bulk"

        def fetch(self, cfg, home_path):
            return FetchResult(secrets={
                "ACCOUNT_TOKEN": "bulk-account", "ITEM_TOKEN": "bulk-item", "BULK_ONLY": "bulk-only",
            })

    bulk = BulkSource()
    assert register_source(bulk, scope=manager.scope_key)
    try:
        env = {}
        report = apply_all({
            "sources": ["fixture_bulk", "apple_keychain"],
            "fixture_bulk": {"enabled": True},
            "apple_keychain": {
                "enabled": True,
                "accounts": ["ACCOUNT_TOKEN"],
                "items": [{"env": "ITEM_TOKEN", "account": "other-account"}],
            },
        }, home, environ=env)
    finally:
        restore_registration(bulk.name, bulk, None, scope=manager.scope_key)

    assert env == {
        "ACCOUNT_TOKEN": "keychain-ACCOUNT_TOKEN", "ITEM_TOKEN": "keychain-ITEM_TOKEN", "BULK_ONLY": "bulk-only",
    }
    assert report.provenance["ACCOUNT_TOKEN"].source == "apple_keychain"
    assert report.provenance["ITEM_TOKEN"].source == "apple_keychain"
    bulk_report = next(row for row in report.sources if row.name == "fixture_bulk")
    assert bulk_report.skipped_claimed == ["ACCOUNT_TOKEN", "ITEM_TOKEN"]
    assert len(report.conflicts) == 2


@pytest.mark.platforms("macos")
@pytest.mark.parametrize(("kind", "error_kind", "description"), [
    ("missing", ErrorKind.REF_INVALID, "No Keychain item"),
    ("locked", ErrorKind.AUTH_FAILED, "locked"),
    ("denied", ErrorKind.AUTH_FAILED, "denied"),
    ("timeout", ErrorKind.TIMEOUT, "timed out"),
])
def test_failures_are_distinct_and_do_not_expose_backend_details(discovered, monkeypatch, kind, error_kind, description):
    home, _, module, source = discovered
    backend = importlib.import_module(f"{module.__name__}.backend")
    private = "fixture_secret_in_backend_exception"

    def read_item(item, *, timeout):
        raise backend.KeychainError(kind, private)

    monkeypatch.setattr(backend, "read_item", read_item)
    result = source.fetch({"accounts": ["TOKEN"], "timeout_seconds": 5}, home)
    assert result.error_kind == error_kind
    assert description in result.error
    assert private not in str((result.error, result.warnings))


@pytest.mark.platforms("macos")
def test_invalid_enable_and_override_fail_safely(discovered):
    _, _, _, source = discovered
    assert source.is_enabled({"enabled": True})
    assert not source.is_enabled({"enabled": "false"})
    assert source.override_existing({"override_existing": "true"}) is False


def test_management_mapping_matches_startup_when_managed_overlay_exists(discovered, tmp_path, monkeypatch):
    home, _, module, _ = discovered
    (home / "config.yaml").write_text(yaml.safe_dump({
        "secrets": {"apple_keychain": {"service": "local", "accounts": ["TOKEN"]}},
    }))
    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / "config.yaml").write_text(yaml.safe_dump({
        "secrets": {"apple_keychain": {"service": "admin"}},
    }))
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    document, source, path = module.configuration.load_source_config()
    assert path == home / "config.yaml"
    assert document["secrets"]["apple_keychain"]["service"] == "local"
    # Hermes' startup loader reads raw source config; management must target the
    # same item even when the general config layer has an administrator overlay.
    from hermes_cli.env_loader import _load_secrets_config
    assert source == _load_secrets_config(home)["apple_keychain"]
    assert source["service"] == "local"
    assert source["accounts"] == ["TOKEN"]


@pytest.mark.platforms("macos")
def test_resolution_uses_each_profiles_configuration(discovered, tmp_path, monkeypatch):
    home, _, module, _ = discovered
    profile = tmp_path / "profiles" / "work"
    profile.mkdir(parents=True)
    for target, service in ((home, "default-service"), (profile, "work-service")):
        (target / "config.yaml").write_text(yaml.safe_dump({
            "plugins": {"enabled": ["apple-keychain"]},
            "secrets": {"apple_keychain": {"service": service, "accounts": ["PROFILE_TOKEN"]}},
        }))
    from hermes_cli.plugins import PluginManager

    token = set_hermes_home_override(profile)
    try:
        profile_manager = PluginManager()
        profile_manager.discover_and_load()
    finally:
        reset_hermes_home_override(token)
    try:
        profile_module = profile_manager._plugins["apple-keychain"].module
        observed = []
        for current in (module, profile_module):
            backend = importlib.import_module(f"{current.__name__}.backend")
            monkeypatch.setattr(backend, "read_item", lambda item, *, timeout: observed.append(dict(item)) or item["service"])
        outcomes = []
        for target, current in ((home, module), (profile, profile_module)):
            token = set_hermes_home_override(target)
            try:
                _, section, _ = current.configuration.load_source_config()
            finally:
                reset_hermes_home_override(token)
            section["enabled"] = True
            env = {}
            report = apply_all({"sources": ["apple_keychain"], "apple_keychain": section}, target, environ=env)
            assert report.applied_any
            outcomes.append(env["PROFILE_TOKEN"])
        assert outcomes == ["default-service", "work-service"]
        assert [item["service"] for item in observed] == outcomes
    finally:
        profile_manager.unload()


@pytest.mark.platforms("macos")
def test_unexpected_failure_never_echoes_exception(discovered, monkeypatch):
    home, _, module, source = discovered
    backend = importlib.import_module(f"{module.__name__}.backend")
    private = "fixture_secret_in_unexpected_error"

    def read_item(item, *, timeout):
        raise RuntimeError(private)

    monkeypatch.setattr(backend, "read_item", read_item)
    result = source.fetch({"accounts": ["TOKEN"]}, home)
    assert result.error_kind == ErrorKind.INTERNAL
    assert private not in str((result.error, result.warnings))


@pytest.mark.platforms("macos")
def test_profile_hydration_uses_same_literal_mapping_as_management(discovered, tmp_path, monkeypatch):
    profile = tmp_path / "profiles" / "routed"
    profile.mkdir(parents=True)
    monkeypatch.setenv("FIXTURE_REFERENCE", "expanded-value")
    monkeypatch.delenv("ROUTED_FIXTURE_TOKEN", raising=False)
    config = {
        "plugins": {"enabled": ["apple-keychain"]},
        "secrets": {"sources": ["apple_keychain"], "apple_keychain": {
            "enabled": False, "service": "service-${FIXTURE_REFERENCE}",
            "default_keychain": "/fixture.keychain-db",
            "items": [{"env": "ROUTED_FIXTURE_TOKEN", "account": "account-${FIXTURE_REFERENCE}"}],
        }},
    }
    path = profile / "config.yaml"
    path.write_text(yaml.safe_dump(config))
    from hermes_cli.plugins import PluginManager
    from hermes_cli.env_loader import hydrate_profile_secret_sources, reset_secret_source_cache

    token = set_hermes_home_override(profile)
    try:
        manager = PluginManager()
        manager.discover_and_load()
    finally:
        reset_hermes_home_override(token)
    try:
        module = manager._plugins["apple-keychain"].module
        backend = importlib.import_module(f"{module.__name__}.backend")
        observed = []
        monkeypatch.setattr(backend, "read_item", lambda item, *, timeout: observed.append(dict(item)) or "fixture-value")
        config["secrets"]["apple_keychain"]["enabled"] = True
        path.write_text(yaml.safe_dump(config))
        token = set_hermes_home_override(profile)
        try:
            _, source, _ = module.configuration.load_source_config()
            targets, warnings = module.configuration.normalize_items(source)
        finally:
            reset_hermes_home_override(token)
        assert warnings == []
        values = hydrate_profile_secret_sources(profile)
        assert values["ROUTED_FIXTURE_TOKEN"] == "fixture-value"
        assert observed == targets
        assert observed[0]["service"] == "service-${FIXTURE_REFERENCE}"
        assert observed[0]["account"] == "account-${FIXTURE_REFERENCE}"
        assert "ROUTED_FIXTURE_TOKEN" not in os.environ
    finally:
        reset_secret_source_cache(profile)
        manager.unload()



def test_shared_validation_and_actionable_remediation(discovered):
    _, _, module, source = discovered
    config = module.configuration
    assert config.valid_env_name("SAFE_TOKEN")
    assert not config.valid_env_name("unsafe-name")
    assert not config.valid_env_name("SAFE_TOKEN\n")
    for raw, expected in [(None, 10.0), (True, 10.0), ("bad", 10.0), ("2", 2.0), (100, 30.0)]:
        assert config.timeout_seconds(raw) == expected
        assert source.fetch_timeout_seconds({"timeout_seconds": raw}) == expected
    hints = {kind: source.remediation(kind, {}) for kind in (
        ErrorKind.NOT_CONFIGURED, ErrorKind.AUTH_FAILED, ErrorKind.BINARY_MISSING,
    )}
    assert "hermes keychain setup" in hints[ErrorKind.NOT_CONFIGURED]
    assert "Unlock" in hints[ErrorKind.AUTH_FAILED] and "authorize" in hints[ErrorKind.AUTH_FAILED]
    assert "Xcode" in hints[ErrorKind.BINARY_MISSING]
    assert all("hermes secrets apple_keychain" not in hint for hint in hints.values())


@pytest.mark.platforms("macos")
class TestAppleKeychainConformance(SecretSourceConformance):
    @pytest.fixture
    def source(self, discovered):
        return discovered[3]
