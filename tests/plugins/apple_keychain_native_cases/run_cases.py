"""Disposable native rotation checks; --login also exercises modern login Keychain ACLs."""
import ctypes
import hashlib
import os
from pathlib import Path
import secrets
import select
import struct
import subprocess
import sys
import tempfile

CASES = Path(__file__).resolve().parent
PLUGIN = CASES.parents[2] / "plugins" / "apple-keychain"
ACCOUNT = "diagnostic-only"
ENV = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}
SANITIZE = "--sanitize" in sys.argv
LOGIN = "--login" in sys.argv


def build(directory):
    flags = ["/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-Wno-deprecated-declarations", "-I", str(PLUGIN)]
    if SANITIZE:
        flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    inputs = [
        (PLUGIN / "keychain-write-stdin.c", []),
        (PLUGIN / "keychain-access.c", ["-DSecKeychainItemCopyAccess=test_copy_access"]),
        (PLUGIN / "keychain-recovery.c", ["-DSecKeychainItemModifyAttributesAndData=test_modify"]),
        (CASES / "hooks.c", []),
    ]
    objects = []
    for n, (source, define) in enumerate(inputs):
        obj = directory / f"part{n}.o"
        subprocess.run([*flags, *define, "-c", str(source), "-o", str(obj)], check=True, timeout=30)
        objects.append(str(obj))
    binary = directory / "helper"
    subprocess.run([*flags, *objects, "-framework", "Security", "-framework", "CoreFoundation",
                    "-o", str(binary)], check=True, timeout=30)
    return str(binary)


def build_access_checks(directory):
    binary = directory / "access-checks"
    flags = ["/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-Wno-deprecated-declarations", "-I", str(PLUGIN)]
    if SANITIZE:
        flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    subprocess.run([*flags, str(CASES / "access_checks.c"), str(PLUGIN / "keychain-access.c"),
                    "-framework", "Security", "-framework", "CoreFoundation", "-o", str(binary)],
                   check=True, timeout=30)
    return str(binary)


def preferences():
    return tuple(subprocess.run(["/usr/bin/security", name], stdin=subprocess.DEVNULL,
                                capture_output=True, env=ENV, timeout=10, check=True).stdout
                 for name in ("list-keychains", "default-keychain"))


def call(helper, keychain, service, command, args=(), value=None, extra_env=None):
    env = dict(ENV)
    if extra_env:
        env.update(extra_env)
    if SANITIZE:
        env["ASAN_OPTIONS"] = "detect_leaks=0"
    data = len(value).to_bytes(4, "big") + value + b"\1" if value is not None else None
    return subprocess.run([helper, command, keychain, service, ACCOUNT, *args], input=data,
                          capture_output=True, env=env, timeout=15, check=False)


def backup_service(service):
    digest = hashlib.sha256()
    for part in (service.encode(), ACCOUNT.encode()):
        digest.update(struct.pack("=Q", len(part)))
        digest.update(part)
    return "com.hermes.apple-keychain.recovery.v1." + digest.hexdigest()


def read_value(helper, keychain, service, account=ACCOUNT):
    result = subprocess.run([helper, "read", keychain, service, account], stdin=subprocess.DEVNULL,
                            capture_output=True, env=ENV, timeout=15, check=False)
    assert result.returncode == 0, "could not read diagnostic item"
    return result.stdout


def list_entries(helper, keychain, service):
    result = call(helper, keychain, service, "list")
    assert result.returncode == 0, "could not list recovery entries"
    return [line.split()[1:] for line in result.stdout.decode("ascii").splitlines()]


def cleanup(helper, keychain, service):
    try:
        for state, rid in list_entries(helper, keychain, service):
            assert call(helper, keychain, service, "discard", (rid,)).returncode == 0
    finally:
        result = subprocess.run(
            ["/usr/bin/security", "delete-generic-password", "-s", service, "-a", ACCOUNT, keychain],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=ENV, timeout=10, check=False)
        assert result.returncode == 0, "could not delete a diagnostic item"
    probe = call(helper, keychain, service, "probe")
    assert probe.returncode == 0 and probe.stdout.startswith(b"MISSING\n") and not list_entries(helper, keychain, service)


def new_item(helper, keychain):
    service = "hermes-keychain-fix-test-" + secrets.token_hex(12)
    value = os.urandom(32)
    created = call(helper, keychain, service, "write", ("0", "0", "0"), value)
    assert created.returncode == 0, "could not create diagnostic item"
    return service, value


def rotation_and_restore(helper, keychain):
    service, old = new_item(helper, keychain)
    try:
        new = os.urandom(32)
        rotated = call(helper, keychain, service, "write", ("0", "1", "1"), new)
        assert rotated.returncode == 0, f"rotation failed: {rotated.stderr.decode('ascii', 'replace')}"
        assert read_value(helper, keychain, service) == new
        entries = list_entries(helper, keychain, service)
        assert len(entries) == 1 and entries[0][0] == "kept"
        rid = entries[0][1]
        restored = call(helper, keychain, service, "restore", (rid,))
        assert restored.returncode == 0, f"restore failed: {restored.stderr.decode('ascii', 'replace')}"
        assert read_value(helper, keychain, service) == old
        assert call(helper, keychain, service, "discard", (rid,)).returncode == 0
        assert not list_entries(helper, keychain, service)
        assert call(helper, keychain, service, "write", ("0", "0", "1"), new).returncode == 0
        assert read_value(helper, keychain, service) == new
        assert not list_entries(helper, keychain, service)
    finally:
        cleanup(helper, keychain, service)


def preparing_interruption(helper, keychain, stop):
    service, old = new_item(helper, keychain)
    try:
        result = call(helper, keychain, service, "write", ("0", "1", "1"), os.urandom(32),
                      {"HERMES_TEST_INTERRUPT_AT": str(stop)})
        assert result.returncode == -9, f"expected interruption at step {stop}"
        entries = list_entries(helper, keychain, service)
        assert len(entries) == 1 and entries[0][0] == "preparing"
        rid = entries[0][1]
        stored = read_value(helper, keychain, backup_service(service), "preparing-" + rid)
        assert stored == (b"\0" if stop == 1 else b"\1" if stop == 2 else old)
        assert read_value(helper, keychain, service) == old
        restored = call(helper, keychain, service, "restore", (rid,))
        assert restored.returncode != 0 and b"ERR recovery_preparing" in restored.stderr
        rewritten = call(helper, keychain, service, "write", ("0", "0", "1"), os.urandom(32))
        assert rewritten.returncode != 0 and b"ERR recovery_preparing" in rewritten.stderr
        assert read_value(helper, keychain, service) == old
        assert call(helper, keychain, service, "discard", (rid,)).returncode == 0
        assert not list_entries(helper, keychain, service)
    finally:
        cleanup(helper, keychain, service)


def pending_interruption(helper, keychain):
    service, old = new_item(helper, keychain)
    process = None
    try:
        env = dict(ENV)
        if SANITIZE:
            env["ASAN_OPTIONS"] = "detect_leaks=0"
        process = subprocess.Popen([helper, "write", keychain, service, ACCOUNT, "0", "1", "1"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        new = os.urandom(32)
        process.stdin.write(len(new).to_bytes(4, "big") + new)
        process.stdin.flush()
        assert select.select([process.stdout], [], [], 10)[0]
        line = process.stdout.readline().decode("ascii").strip()
        assert line.startswith("RECOVERY ")
        rid = line.split()[1]
        process.kill()
        process.wait(timeout=5)
        assert list_entries(helper, keychain, service) == [["pending", rid]]
        assert read_value(helper, keychain, service) == old
        assert call(helper, keychain, service, "restore", (rid,)).returncode == 0
        assert read_value(helper, keychain, service) == old
        assert list_entries(helper, keychain, service) == [["kept", rid]]
    finally:
        if process:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        cleanup(helper, keychain, service)


def partition_rejection(helper, keychain):
    service, old = new_item(helper, keychain)
    try:
        result = call(helper, keychain, service, "write", ("0", "1", "1"), os.urandom(32),
                      {"HERMES_TEST_DIFFERENT_PARTITION": "1"})
        assert result.returncode != 0 and b"ERR access_mismatch" in result.stderr
        entries = list_entries(helper, keychain, service)
        assert len(entries) == 1 and entries[0][0] == "preparing"
        rid = entries[0][1]
        assert read_value(helper, keychain, backup_service(service), "preparing-" + rid) == b"\0"
        assert read_value(helper, keychain, service) == old
        assert call(helper, keychain, service, "restore", (rid,)).returncode != 0
    finally:
        cleanup(helper, keychain, service)


def restore_preflight(helper, keychain, mismatch):
    service, old = new_item(helper, keychain)
    try:
        new = os.urandom(32)
        assert call(helper, keychain, service, "write", ("0", "1", "1"), new).returncode == 0
        kept = list_entries(helper, keychain, service)
        assert len(kept) == 1 and kept[0][0] == "kept"
        rid = kept[0][1]
        env = {"HERMES_TEST_DIFFERENT_PARTITION": "2"} if mismatch else {"HERMES_TEST_INTERRUPT_AT": "1"}
        result = call(helper, keychain, service, "restore", (rid,), extra_env=env)
        if mismatch:
            assert result.returncode != 0 and b"ERR access_mismatch" in result.stderr
        else:
            assert result.returncode == -9
        entries = list_entries(helper, keychain, service)
        prep = [entry for entry in entries if entry[0] == "preparing"]
        assert len(prep) == 1 and ["kept", rid] in entries
        assert read_value(helper, keychain, backup_service(service), "preparing-" + prep[0][1]) == b"\0"
        assert read_value(helper, keychain, service) == new
        blocked = call(helper, keychain, service, "restore", (rid,))
        assert blocked.returncode != 0 and b"ERR recovery_preparing" in blocked.stderr
        assert call(helper, keychain, service, "discard", (prep[0][1],)).returncode == 0
        assert call(helper, keychain, service, "restore", (rid,)).returncode == 0
        assert read_value(helper, keychain, service) == old
    finally:
        cleanup(helper, keychain, service)


def access_comparisons(checks, helper, keychain, partition):
    service, _ = new_item(helper, keychain)
    try:
        env = dict(ENV)
        if SANITIZE:
            env["ASAN_OPTIONS"] = "detect_leaks=0"
        result = subprocess.run([checks, keychain, service, ACCOUNT, str(int(partition))],
                                stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=15, check=False)
        assert result.returncode == 0, f"access comparisons failed (exit {result.returncode})"
        print(result.stdout.decode("ascii").strip(), flush=True)
    finally:
        cleanup(helper, keychain, service)


def run_for_keychain(helper, checks, path, partition):
    access_comparisons(checks, helper, path, partition)
    rotation_and_restore(helper, path)
    print("rotation and restore: PASS", flush=True)
    for stop in (1, 2, 3):
        preparing_interruption(helper, path, stop)
    print("interrupted preparing before/after secret copy: PASS", flush=True)
    pending_interruption(helper, path)
    print("interrupted pending recovery: PASS", flush=True)
    restore_preflight(helper, path, False)
    print("interrupted restore preflight: PASS", flush=True)
    if partition:
        partition_rejection(helper, path)
        print("regenerated partition mismatch rejected before secret copy: PASS", flush=True)
        restore_preflight(helper, path, True)
        print("restore rejects a regenerated partition mismatch: PASS", flush=True)


before = preferences()
with tempfile.TemporaryDirectory(prefix="keychain-native-") as tmp:
    tmpdir = Path(tmp)
    helper = build(tmpdir)
    checks = build_access_checks(tmpdir)
    security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    core = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    security.SecKeychainCreate.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_void_p,
                                            ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    security.SecKeychainCreate.restype = ctypes.c_int32
    security.SecKeychainDelete.argtypes = [ctypes.c_void_p]
    security.SecKeychainDelete.restype = ctypes.c_int32
    core.CFRelease.argtypes = [ctypes.c_void_p]
    keychain = ctypes.c_void_p()
    path = tmpdir / "test.keychain-db"
    password = ctypes.create_string_buffer(os.urandom(32))
    status = security.SecKeychainCreate(os.fsencode(path), 32, password, False, None, ctypes.byref(keychain))
    assert status == 0, f"isolated Keychain creation failed: {status}"
    try:
        print("isolated Keychain", flush=True)
        run_for_keychain(helper, checks, str(path), False)
    finally:
        status = security.SecKeychainDelete(keychain)
        core.CFRelease(keychain)
        assert status == 0, f"isolated Keychain deletion failed: {status}"
    if LOGIN:
        print("disposable login Keychain items", flush=True)
        run_for_keychain(helper, checks, str(Path.home() / "Library/Keychains/login.keychain-db"), True)
assert before == preferences(), "Keychain search list or default changed"
print("Keychain search list and default unchanged: PASS", flush=True)
