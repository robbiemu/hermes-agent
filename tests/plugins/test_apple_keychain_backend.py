"""Native helper build and transport contracts without accessing a real Keychain."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

import pytest

pytest_plugins = ("tests.plugins.test_apple_keychain_runtime",)


@pytest.fixture
def modules(discovered):
    _, _, plugin, _ = discovered
    return (importlib.import_module(f"{plugin.__name__}.native_build"),
            importlib.import_module(f"{plugin.__name__}.native_io"),
            importlib.import_module(f"{plugin.__name__}.contracts"))


def test_compiler_uses_the_hashed_source_snapshot(modules, tmp_path, monkeypatch):
    build, _, _ = modules
    source = tmp_path / "original"
    source.mkdir()
    expected = {
        name: ("fixture " + name).encode() for name in (
            "keychain-write-stdin.c", "keychain-access.c", "keychain-recovery.c", "keychain-native.h",
        )
    }
    for name, content in expected.items():
        (source / name).write_bytes(content)
    snapshot = build._source_snapshot(source)
    original_digest = build._snapshot_digest(snapshot)
    (source / "keychain-native.h").write_bytes(b"changed after snapshot")
    assert build._snapshot_digest(build._source_snapshot(source)) != original_digest
    monkeypatch.setattr(build, "_compiler", lambda _deadline: ("fixture-clang", "fixture-sdk"))
    observed = {}

    def compile_snapshot(argv, **kwargs):
        source_files = [Path(arg) for arg in argv if arg.endswith(".c")]
        for path in source_files:
            observed[path.name] = path.read_bytes()
        observed["keychain-native.h"] = (source_files[0].parent / "keychain-native.h").read_bytes()
        Path(argv[argv.index("-o") + 1]).write_bytes(b"fixture executable")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(build.subprocess, "run", compile_snapshot)
    output = build._compile(snapshot, tmp_path, time.monotonic() + 5)
    assert observed == expected
    assert output.read_bytes() == b"fixture executable"


def _helper(tmp_path: Path) -> tuple[Path, Path, str]:
    marker = tmp_path / "acknowledged"
    recovery_id = "12345678-1234-1234-1234-123456789abc"
    helper = tmp_path / "helper"
    helper.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "stream = sys.stdin.buffer\n"
        "length = int.from_bytes(stream.read(4), 'big')\n"
        "stream.read(length)\n"
        f"print('RECOVERY {recovery_id}', flush=True)\n"
        "if stream.read(1) == b'\\x01':\n"
        f"    pathlib.Path({str(marker)!r}).write_text('acknowledged')\n"
        f"    print('OK updated {recovery_id}', flush=True)\n",
        encoding="utf-8",
    )
    helper.chmod(0o700)
    return helper, marker, recovery_id


@pytest.mark.platforms("posix")
def test_notice_precedes_ack_and_stale_write_readiness_is_retried(modules, tmp_path, monkeypatch):
    build, transport, _ = modules
    helper, marker, recovery_id = _helper(tmp_path)
    monkeypatch.setattr(build, "build_helper", lambda _deadline: str(helper))
    calls = []

    def write(fd, data):
        calls.append(True)
        if len(calls) == 1:
            raise BlockingIOError()
        return os.write(fd, data)

    monkeypatch.setattr(transport, "os", SimpleNamespace(write=write, read=os.read, set_blocking=os.set_blocking))
    read_fd, write_fd = os.pipe()
    try:
        output = transport.run_helper("write", ("/fixture", "service", "account"),
                                      value=b"synthetic", notify_fd=write_fd, deadline=time.monotonic() + 5)
        assert marker.read_text() == "acknowledged"
        assert output.endswith(f"OK updated {recovery_id}\n".encode())
        notice = os.read(read_fd, 512).decode()
        assert recovery_id in notice and "Old value saved" in notice
        assert len(calls) >= 2
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_transport_state_repr_does_not_disclose_secret_bytes(modules):
    _, transport, _ = modules
    marker = b"synthetic-secret-marker"
    state = transport._PumpState(stdout=bytearray(marker), outgoing=marker)
    assert marker.decode() not in repr(state)
