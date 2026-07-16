"""Focused tests for macOS system LaunchDaemon gateway support."""

import plistlib
from pathlib import Path
from types import SimpleNamespace

import hermes_cli.gateway as gateway_cli


def test_launchdaemon_uses_distinct_system_identity(monkeypatch):
    monkeypatch.setattr(gateway_cli, "_profile_suffix", lambda: "coder")

    assert gateway_cli.get_launchd_label(system=True) == "ai.hermes.daemon-coder"
    assert gateway_cli.get_launchd_plist_path(system=True) == Path(
        "/Library/LaunchDaemons/ai.hermes.daemon-coder.plist"
    )
    assert gateway_cli._launchd_domain(system=True) == "system"


def test_launchdaemon_plist_runs_as_target_user_without_session_limit(monkeypatch):
    monkeypatch.setattr(
        gateway_cli,
        "_system_service_identity",
        lambda run_as_user=None: ("alice", "staff", "/Users/alice"),
    )
    monkeypatch.setattr(
        gateway_cli,
        "_hermes_home_for_target_user",
        lambda target_home: f"{target_home}/.hermes",
    )
    monkeypatch.setattr(
        gateway_cli,
        "_remap_path_for_user",
        lambda path, target_home: str(path).replace(str(Path.home()), target_home),
    )
    monkeypatch.setattr(
        gateway_cli, "_stable_service_working_dir", lambda: "/Users/alice/.hermes"
    )
    monkeypatch.setattr(gateway_cli, "_detect_venv_dir", lambda: None)
    monkeypatch.setattr(gateway_cli, "_build_service_path_dirs", lambda: [])
    monkeypatch.setattr(gateway_cli.shutil, "which", lambda _name: None)

    plist = plistlib.loads(
        gateway_cli.generate_launchd_plist(system=True, run_as_user="alice").encode()
    )

    assert plist["Label"] == "ai.hermes.daemon"
    assert plist["UserName"] == "alice"
    assert plist["GroupName"] == "staff"
    assert plist["EnvironmentVariables"]["HOME"] == "/Users/alice"
    assert plist["EnvironmentVariables"]["HERMES_HOME"] == "/Users/alice/.hermes"
    assert "LimitLoadToSessionType" not in plist


def test_launchdaemon_install_prepares_and_bootstraps_system_scope(
    tmp_path, monkeypatch
):
    plist_path = tmp_path / "ai.hermes.daemon.plist"
    calls = []

    monkeypatch.setattr(
        gateway_cli,
        "_require_root_for_system_service",
        lambda action: calls.append(("root", action)),
    )
    monkeypatch.setattr(
        gateway_cli,
        "_system_service_identity",
        lambda run_as_user=None: ("alice", "staff", "/Users/alice"),
    )
    monkeypatch.setattr(
        gateway_cli,
        "_hermes_home_for_target_user",
        lambda target_home: f"{target_home}/.hermes",
    )
    monkeypatch.setattr(
        gateway_cli,
        "_prepare_system_launchd_log_dir",
        lambda username, log_dir: calls.append(("logs", username, log_dir)),
    )
    monkeypatch.setattr(
        gateway_cli,
        "_launchd_plist_path_for_scope",
        lambda system: plist_path,
    )
    monkeypatch.setattr(
        gateway_cli,
        "_generate_launchd_plist_for_scope",
        lambda system, run_as_user=None: "<plist><dict/></plist>",
    )
    monkeypatch.setattr(
        gateway_cli, "_refuse_temp_home_service_write", lambda *_args: False
    )
    monkeypatch.setattr(
        gateway_cli,
        "_enforce_system_launchd_plist_perms",
        lambda path: calls.append(("perms", path)),
    )
    monkeypatch.setattr(
        gateway_cli,
        "_launchctl_bootstrap",
        lambda domain, path, label, timeout: calls.append((
            "bootstrap",
            domain,
            path,
            label,
            timeout,
        )),
    )

    gateway_cli.launchd_install(force=True, system=True, run_as_user="alice")

    assert ("root", "install") in calls
    assert ("logs", "alice", Path("/Users/alice/.hermes/logs")) in calls
    assert ("perms", plist_path) in calls
    assert (
        "bootstrap",
        "system",
        plist_path,
        "ai.hermes.daemon",
        30,
    ) in calls


def test_launchdaemon_in_process_restart_requests_async_drain(monkeypatch):
    calls = []
    monkeypatch.setattr(
        gateway_cli,
        "_require_root_for_system_service",
        lambda action: calls.append(("root", action)),
    )
    monkeypatch.setattr(
        gateway_cli,
        "_refresh_launchd_plist_for_scope",
        lambda system: calls.append(("refresh", system)) or False,
    )
    monkeypatch.setattr(gateway_cli, "_launchd_system_pid", lambda label: 4242)
    monkeypatch.setattr(
        gateway_cli,
        "_request_gateway_self_restart",
        lambda pid: calls.append(("restart-request", pid)) or True,
    )
    monkeypatch.setattr(
        gateway_cli.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("graceful restart should not kickstart immediately")
        ),
    )

    gateway_cli.launchd_restart(system=True)

    assert calls == [
        ("root", "restart"),
        ("refresh", True),
        ("restart-request", 4242),
    ]


def test_launchdaemon_shell_restart_drains_and_waits_for_relaunch(monkeypatch):
    calls = []
    monkeypatch.setattr(
        gateway_cli, "_require_root_for_system_service", lambda _action: None
    )
    monkeypatch.setattr(
        gateway_cli, "_refresh_launchd_plist_for_scope", lambda _system: False
    )
    monkeypatch.setattr(gateway_cli, "_launchd_system_pid", lambda _label: 4242)
    monkeypatch.setattr(
        gateway_cli, "_request_gateway_self_restart", lambda _pid: False
    )
    monkeypatch.setattr(
        gateway_cli,
        "_get_restart_drain_timeout",
        lambda: 30.0,
    )
    monkeypatch.setattr(
        gateway_cli,
        "_graceful_restart_via_sigusr1",
        lambda pid, timeout: calls.append(("drain", pid, timeout)) or True,
    )
    monkeypatch.setattr(
        gateway_cli,
        "_wait_for_launchd_system_relaunch",
        lambda label, previous_pid: (
            calls.append(("relaunch", label, previous_pid)) or True
        ),
    )
    monkeypatch.setattr(
        gateway_cli.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("successful drain should not force kickstart")
        ),
    )

    gateway_cli.launchd_restart(system=True)

    assert calls == [
        ("drain", 4242, 30.0),
        ("relaunch", "ai.hermes.daemon", 4242),
    ]


def test_gateway_install_routes_system_flag_to_launchdaemon(monkeypatch):
    calls = []
    monkeypatch.setattr(gateway_cli, "is_managed", lambda: False)
    monkeypatch.setattr(gateway_cli, "is_termux", lambda: False)
    monkeypatch.setattr(gateway_cli, "supports_systemd_services", lambda: False)
    monkeypatch.setattr(gateway_cli, "is_macos", lambda: True)
    monkeypatch.setattr(
        gateway_cli,
        "_launchd_install_for_scope",
        lambda force, system, run_as_user: calls.append((force, system, run_as_user)),
    )

    gateway_cli.gateway_command(
        SimpleNamespace(
            gateway_command="install",
            force=True,
            system=True,
            run_as_user="alice",
        )
    )

    assert calls == [(True, True, "alice")]
