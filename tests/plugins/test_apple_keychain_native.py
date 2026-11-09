"""Real, disposable macOS Keychains exercise the native helper and recovery."""

from __future__ import annotations

import ctypes
import importlib
import importlib.util
import os
from pathlib import Path
import select
import subprocess
import sys
import time

import pytest


pytestmark = pytest.mark.platforms("macos")


def _preferences(home):
    snapshots = []
    for command in ("list-keychains", "default-keychain"):
        result = subprocess.run(
            ["/usr/bin/security", command], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False,
            env={"PATH": "/usr/bin:/bin", "HOME": str(home)},
        )
        snapshots.append((result.returncode, result.stdout))
    return snapshots


@pytest.fixture
def native(tmp_path, monkeypatch):
    actual_home = Path.home()
    preferences_before = _preferences(actual_home)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    plugin = Path(__file__).resolve().parents[2] / "plugins" / "apple-keychain"
    package_name = f"_apple_keychain_native_{os.urandom(6).hex()}"
    spec = importlib.util.spec_from_file_location(
        package_name, plugin / "__init__.py", submodule_search_locations=[str(plugin)]
    )
    package = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, package_name, package)
    spec.loader.exec_module(package)
    backend = importlib.import_module(f"{package_name}.backend")

    security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    core = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    security.SecKeychainCreate.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_void_p,
                                            ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    security.SecKeychainCreate.restype = ctypes.c_int32
    security.SecKeychainUnlock.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_bool]
    security.SecKeychainUnlock.restype = ctypes.c_int32
    security.SecKeychainLock.argtypes = [ctypes.c_void_p]
    security.SecKeychainLock.restype = ctypes.c_int32
    security.SecKeychainDelete.argtypes = [ctypes.c_void_p]
    security.SecKeychainDelete.restype = ctypes.c_int32
    core.CFRelease.argtypes = [ctypes.c_void_p]
    path = tmp_path / "isolated.keychain-db"
    password = b"temporary-test-keychain"
    keychain = ctypes.c_void_p()
    assert security.SecKeychainCreate(os.fsencode(path), len(password), password, False, None, ctypes.byref(keychain)) == 0
    null_fd = -1
    try:
        assert security.SecKeychainUnlock(keychain, len(password), password, True) == 0
        null_fd = os.open(os.devnull, os.O_WRONLY)
        item = {"env": "TEST_SECRET", "service": "test-service", "account": "test-account", "keychain": str(path)}
        yield backend, security, core, keychain, item, password, null_fd
    finally:
        if null_fd >= 0:
            os.close(null_fd)
        security.SecKeychainUnlock(keychain, len(password), password, True)
        deletion_status = security.SecKeychainDelete(keychain)
        core.CFRelease(keychain)
        for name in tuple(sys.modules):
            if name.startswith(package_name + "."):
                sys.modules.pop(name)
        if deletion_status != 0:
            pytest.fail(f"Could not delete the isolated test Keychain: {deletion_status}")
        if _preferences(actual_home) != preferences_before:
            pytest.fail("Keychain search list or default changed during the isolated test")


def _access_dump(item):
    result = subprocess.run(
        ["/usr/bin/security", "dump-keychain", "-a", item["keychain"]],
        stdin=subprocess.DEVNULL, capture_output=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}, timeout=10, check=True,
    )
    blocks = result.stdout.decode("utf-8").split('keychain: "')
    entries = {}
    for block in blocks:
        if "\naccess: " not in block:
            continue
        before, access = block.split("\naccess: ", 1)
        account_line = next(line for line in before.splitlines() if '"acct"<blob>=' in line)
        account = account_line.split('="', 1)[1].removesuffix('"')
        entries[account] = access
    return entries


def test_rotation_preserves_access_and_recovers_old_value(native):
    backend, _, _, _, item, _, null_fd = native
    assert backend.probe_item(item)["exists"] is False
    assert backend.write_item(item, "old fixture\n", expected_exists=False, notify_fd=null_fd)["result"] == "created"
    before = _access_dump(item)[item["account"]]
    assert "/usr/bin/security" in before
    assert "applications (2)" in before

    notice_read, notice_write = os.pipe()
    try:
        result = backend.write_item(item, "new fixture\n", expected_exists=True, allow_any_app=True,
                                    keep_backup=True, notify_fd=notice_write)
        notice = os.read(notice_read, 4096).decode("utf-8")
    finally:
        os.close(notice_read)
        os.close(notice_write)
    recovery_id = result["recovery_id"]
    assert backend.read_item(item) == "new fixture\n"
    entries = _access_dump(item)
    assert entries[item["account"]] == before
    assert entries[f"kept-{recovery_id}"] == before
    assert backend.list_recoveries(item) == [{"id": recovery_id, "state": "kept"}]
    assert recovery_id in notice and "Old value saved" in notice

    backend.restore_backup(item, recovery_id)
    assert backend.read_item(item) == "old fixture\n"
    assert backend.list_recoveries(item) == [{"id": recovery_id, "state": "kept"}]
    backend.discard_backup(item, recovery_id)
    assert backend.list_recoveries(item) == []
    assert backend.write_item(item, "final fixture", expected_exists=True, notify_fd=null_fd)["result"] == "updated"
    assert backend.read_item(item) == "final fixture"
    assert backend.list_recoveries(item) == []
    assert _access_dump(item)[item["account"]] == before


def test_interruption_and_alias_lock_preserve_recovery(native, tmp_path):
    backend, _, _, _, item, _, null_fd = native
    backend.write_item(item, "old fixture", notify_fd=null_fd)
    alias = tmp_path / "alias.keychain-db"
    alias.symlink_to(item["keychain"])
    alias_item = dict(item, keychain=str(alias))
    assert backend.probe_item(item)["keychain_identity"] == backend.probe_item(alias_item)["keychain_identity"]
    helper = backend.helper_path()
    process = subprocess.Popen(
        [helper, "write", item["keychain"], item["service"], item["account"], "0", "0", "1"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home())},
    )
    try:
        value = b"new fixture"
        process.stdin.write(len(value).to_bytes(4, "big") + value)
        process.stdin.flush()
        assert select.select([process.stdout], [], [], 10)[0]
        line = process.stdout.readline().decode("ascii").strip()
        assert line.startswith("RECOVERY ")
        recovery_id = line.split()[1]
        started = time.monotonic()
        with pytest.raises(backend.KeychainError) as exc:
            backend.write_item(alias_item, "concurrent fixture", timeout=2, notify_fd=null_fd)
        assert exc.value.kind == "timeout"
        assert time.monotonic() - started < 8
    finally:
        process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
    assert backend.read_item(item) == "old fixture"
    assert backend.list_recoveries(item) == [{"id": recovery_id, "state": "pending"}]
    with pytest.raises(backend.KeychainError) as exc:
        backend.write_item(item, "another fixture", notify_fd=null_fd)
    assert exc.value.kind == "recovery_pending"
    assert exc.value.recovery_id == recovery_id
    backend.restore_backup(item, recovery_id)
    assert backend.list_recoveries(item) == [{"id": recovery_id, "state": "kept"}]
    backend.discard_backup(item, recovery_id)


def test_closed_notification_leaves_original_and_backup(native):
    backend, _, _, _, item, _, null_fd = native
    backend.write_item(item, "old fixture", notify_fd=null_fd)
    notice_read, notice_write = os.pipe()
    os.close(notice_read)
    try:
        with pytest.raises(backend.KeychainError) as exc:
            backend.write_item(item, "new fixture", notify_fd=notice_write)
    finally:
        os.close(notice_write)
    assert exc.value.kind == "failure"
    assert backend.read_item(item) == "old fixture"
    recoveries = backend.list_recoveries(item)
    assert len(recoveries) == 1 and recoveries[0]["state"] == "pending"
    assert exc.value.recovery_id == recoveries[0]["id"]
    backend.discard_backup(item, recoveries[0]["id"])


def test_missing_locked_and_conflicting_targets_fail_without_prompt(native):
    backend, security, _, keychain, item, password, null_fd = native
    with pytest.raises(backend.KeychainError) as exc:
        backend.read_item(item, timeout=4)
    assert exc.value.kind == "missing"
    backend.write_item(item, "fixture", expected_exists=False, notify_fd=null_fd)
    with pytest.raises(backend.KeychainError) as exc:
        backend.write_item(item, "other fixture", expected_exists=False, notify_fd=null_fd)
    assert exc.value.kind == "conflict"
    assert security.SecKeychainLock(keychain) == 0
    started = time.monotonic()
    with pytest.raises(backend.KeychainError) as exc:
        backend.read_item(item, timeout=4)
    assert exc.value.kind == "locked"
    assert time.monotonic() - started < 8
    assert security.SecKeychainUnlock(keychain, len(password), password, True) == 0
    assert backend.read_item(item) == "fixture"


def test_any_app_is_explicit_for_new_items(native):
    backend, _, _, _, item, _, null_fd = native
    backend.write_item(item, "fixture", allow_any_app=True, notify_fd=null_fd)
    access = _access_dump(item)[item["account"]]
    decrypt = access.split("authorizations (6): decrypt", 1)[1].split("entry 2:", 1)[0]
    assert "applications: <null>" in decrypt


def test_untrusted_item_is_denied_without_prompt(native):
    backend, security, core, keychain, item, _, _ = native

    class Attribute(ctypes.Structure):
        _fields_ = [("tag", ctypes.c_uint32), ("length", ctypes.c_uint32), ("data", ctypes.c_void_p)]

    class AttributeList(ctypes.Structure):
        _fields_ = [("count", ctypes.c_uint32), ("attributes", ctypes.POINTER(Attribute))]

    core.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
    core.CFStringCreateWithCString.restype = ctypes.c_void_p
    security.SecAccessCreate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    security.SecAccessCreate.restype = ctypes.c_int32
    security.SecKeychainItemCreateFromContent.argtypes = [ctypes.c_uint32, ctypes.POINTER(AttributeList),
                                                          ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
                                                          ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    security.SecKeychainItemCreateFromContent.restype = ctypes.c_int32
    description = core.CFStringCreateWithCString(None, b"test-only restricted item", 0x08000100)
    access, created = ctypes.c_void_p(), ctypes.c_void_p()
    service = ctypes.create_string_buffer(item["service"].encode())
    account = ctypes.create_string_buffer(item["account"].encode())
    attrs = (Attribute * 2)(
        Attribute(0x73766365, len(item["service"]), ctypes.cast(service, ctypes.c_void_p)),
        Attribute(0x61636374, len(item["account"]), ctypes.cast(account, ctypes.c_void_p)),
    )
    attr_list = AttributeList(2, attrs)
    value = ctypes.create_string_buffer(b"fixture")
    try:
        assert security.SecAccessCreate(description, None, ctypes.byref(access)) == 0
        assert security.SecKeychainItemCreateFromContent(
            0x67656E70, ctypes.byref(attr_list), 7, value, keychain, access, ctypes.byref(created)
        ) == 0
        started = time.monotonic()
        with pytest.raises(backend.KeychainError) as exc:
            backend.read_item(item, timeout=4)
        assert exc.value.kind == "denied"
        assert time.monotonic() - started < 8
    finally:
        if created:
            core.CFRelease(created)
        if access:
            core.CFRelease(access)
        core.CFRelease(description)


def test_helper_does_not_inherit_tokens_or_expose_diagnostics(native, tmp_path, monkeypatch):
    backend, _, _, _, item, _, _ = native
    fake_helper = tmp_path / "fake-helper"
    fake_helper.write_text(
        '#!/bin/sh\nif [ "${SYNTHETIC_API_TOKEN+x}" ]; then printf leaked; else printf clean; fi\n'
    )
    fake_helper.chmod(0o700)
    monkeypatch.setenv("SYNTHETIC_API_TOKEN", "test-only-marker")
    monkeypatch.setattr(backend.native_build, "build_helper", lambda _deadline: str(fake_helper))
    assert backend.read_item(item) == "clean"
    fake_helper.write_text("#!/bin/sh\nprintf 'untrusted-diagnostic-marker\\n' >&2\nexit 1\n")
    with pytest.raises(backend.KeychainError) as exc:
        backend.read_item(item)
    assert exc.value.kind == "failure"
    assert "untrusted-diagnostic-marker" not in str(exc.value)


def test_blocked_notification_times_out_without_acknowledging_rotation(native):
    backend, _, _, _, item, _, null_fd = native
    backend.write_item(item, "old fixture", notify_fd=null_fd)
    notice_read, notice_write = os.pipe()
    os.set_blocking(notice_write, False)
    try:
        while True:
            try:
                os.write(notice_write, b"x" * 65536)
            except BlockingIOError:
                break
        os.set_blocking(notice_write, True)
        with pytest.raises(backend.KeychainError) as exc:
            backend.write_item(item, "new fixture", timeout=2, notify_fd=notice_write)
        assert exc.value.kind == "timeout"
        assert backend.read_item(item) == "old fixture"
        recoveries = backend.list_recoveries(item)
        assert len(recoveries) == 1 and recoveries[0]["state"] == "pending"
        assert exc.value.recovery_id == recoveries[0]["id"]
        backend.discard_backup(item, recoveries[0]["id"])
    finally:
        os.close(notice_write)
        os.close(notice_read)


def test_restore_refuses_another_backup_while_rotation_is_pending(native):
    backend, _, _, _, item, _, null_fd = native
    backend.write_item(item, "first fixture", notify_fd=null_fd)
    kept_id = backend.write_item(item, "second fixture", keep_backup=True, notify_fd=null_fd)["recovery_id"]
    notice_read, notice_write = os.pipe()
    os.close(notice_read)
    try:
        with pytest.raises(backend.KeychainError) as interrupted:
            backend.write_item(item, "third fixture", notify_fd=notice_write)
    finally:
        os.close(notice_write)
    pending_id = interrupted.value.recovery_id
    assert pending_id and pending_id != kept_id
    with pytest.raises(backend.KeychainError) as conflict:
        backend.restore_backup(item, kept_id)
    assert conflict.value.kind == "recovery_pending"
    assert conflict.value.recovery_id == pending_id
    assert backend.read_item(item) == "second fixture"
    assert {entry["id"]: entry["state"] for entry in backend.list_recoveries(item)} == {
        kept_id: "kept", pending_id: "pending"
    }
    assert backend.restore_backup(item, pending_id)["result"] == "restored"
    assert backend.read_item(item) == "second fixture"
    assert all(entry["state"] == "kept" for entry in backend.list_recoveries(item))
    backend.discard_backup(item, kept_id)
    backend.discard_backup(item, pending_id)


def test_foreign_caller_cannot_create_lock_but_can_use_valid_existing_lock(native, tmp_path):
    backend, _, _, _, _, _, _ = native
    # Ensure the developer tools are already configured; this must not trigger installation.
    backend.helper_path()
    source_dir = Path(backend.__file__).parent
    harness = tmp_path / "lock-test.c"
    harness.write_text('''#include "keychain-native.h"\n#include <stdlib.h>\n#include <unistd.h>\n
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    int fd = keychain_lock_file(argv[1], (uid_t)strtoul(argv[2], NULL, 10),
                                (uid_t)strtoul(argv[3], NULL, 10));
    close(fd);
    return 0;
}\n''')
    main_object = tmp_path / "native-main.o"
    executable = tmp_path / "lock-test"
    common = ["/usr/bin/clang", "-std=c11", "-Wno-deprecated-declarations", "-I", str(source_dir)]
    subprocess.run(
        [*common, "-Dmain=keychain_helper_main", "-c", str(source_dir / "keychain-write-stdin.c"),
         "-o", str(main_object)], capture_output=True, check=True, timeout=20,
    )
    subprocess.run(
        [*common, str(harness), str(main_object), str(source_dir / "keychain-access.c"),
         str(source_dir / "keychain-recovery.c"), "-framework", "Security", "-framework", "CoreFoundation",
         "-o", str(executable)], capture_output=True, check=True, timeout=20,
    )
    owner = tmp_path.stat().st_uid
    foreign = owner + 1
    lock_path = tmp_path / "item.lock"

    def try_lock(caller):
        return subprocess.run([str(executable), str(lock_path), str(owner), str(caller)],
                              capture_output=True, check=False, timeout=5)

    assert try_lock(foreign).returncode != 0
    assert not lock_path.exists()
    assert try_lock(owner).returncode == 0
    assert lock_path.exists()
    assert try_lock(foreign).returncode == 0
    assert lock_path.exists()


def test_setup_writes_hidden_input_and_preserves_profile_env(native, tmp_path, monkeypatch, capsys):
    import argparse
    import hermes_yaml as yaml

    backend, _, _, _, item, _, _ = native
    setup = importlib.import_module(f"{backend.__package__}.cli_setup")
    home = tmp_path / "profile"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(yaml.safe_dump({"secrets": {"apple_keychain": {
        "enabled": False, "service": "test-service"}}}), encoding="utf-8")
    sentinel = "TEST_SECRET=synthetic-file\nOTHER=preserved\n"
    (home / ".env").write_text(sentinel, encoding="utf-8")
    answers = iter(["", "TEST_SECRET", "n", "y"])
    monkeypatch.setattr(setup.cli_input, "require_interactive", lambda: None)
    monkeypatch.setattr(setup.cli_input, "prompt", lambda message, **kwargs: next(answers))
    monkeypatch.setattr(setup.cli_input, "read_secret", lambda *args: "synthetic-native-input")
    monkeypatch.setattr(setup, "login_keychain", lambda: item["keychain"])
    assert setup.setup(argparse.Namespace(headless=False)) == 0
    actual = dict(item, account="TEST_SECRET")
    assert backend.read_item(actual) == "synthetic-native-input"
    assert (home / ".env").read_text(encoding="utf-8") == sentinel
    config = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    assert config["secrets"]["apple_keychain"]["items"][0] == actual
    output = capsys.readouterr()
    assert "synthetic-native-input" not in output.out + output.err
