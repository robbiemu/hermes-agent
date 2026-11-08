"""Build a private, content-addressed Keychain helper from a source snapshot."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time

from hermes_platform.host import facts

from .contracts import keychain_error, remaining

_SOURCE_FILES = ("keychain-write-stdin.c", "keychain-access.c", "keychain-recovery.c", "keychain-native.h")


def child_env() -> dict[str, str]:
    # Credentials and unrelated caller settings never enter compiler/helper children.
    env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}
    if "TMPDIR" in os.environ:
        env["TMPDIR"] = os.environ["TMPDIR"]
    return env


def _user_id() -> int:
    get_user_id = getattr(os, "geteuid", None)
    if get_user_id is None:
        raise keychain_error("unavailable")
    return get_user_id()


def _private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != _user_id() or info.st_mode & 0o077:
            raise keychain_error("unavailable")
    except OSError:
        raise keychain_error("unavailable") from None


def _safe_helper(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise keychain_error("unavailable") from None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != _user_id() or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o700):
        raise keychain_error("unavailable")
    return True


def _compiler(deadline: float) -> tuple[str, str]:
    try:
        result = subprocess.run(
            ["/usr/bin/xcode-select", "-p"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=child_env(),
            timeout=remaining(deadline), check=False,
        )
        if result.returncode:
            raise keychain_error("unavailable")
        developer = Path(os.fsdecode(result.stdout.strip()))
        if not developer.is_absolute():
            raise keychain_error("unavailable")
        choices = (
            (developer / "usr/bin/clang", developer / "SDKs/MacOSX.sdk"),
            (developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
             developer / "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"),
        )
        for compiler, sdk in choices:
            if compiler.is_file() and os.access(compiler, os.X_OK) and sdk.is_dir():
                return str(compiler), str(sdk)
    except subprocess.TimeoutExpired:
        raise keychain_error("timeout") from None
    except OSError:
        raise keychain_error("unavailable") from None
    raise keychain_error("unavailable")


def _source_snapshot(directory: Path) -> tuple[tuple[str, bytes], ...]:
    try:
        return tuple((name, (directory / name).read_bytes()) for name in _SOURCE_FILES)
    except OSError:
        raise keychain_error("unavailable") from None


def _snapshot_digest(sources: tuple[tuple[str, bytes], ...]) -> str:
    digest = hashlib.sha256()
    for name, content in sources:
        encoded_name = name.encode("utf-8")
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _compile(sources: tuple[tuple[str, bytes], ...], cache: Path, deadline: float) -> Path:
    compiler, sdk = _compiler(deadline)
    with tempfile.TemporaryDirectory(prefix=".helper-source-", dir=cache) as tmp:
        directory = Path(tmp)
        for name, content in sources:
            (directory / name).write_bytes(content)
        fd, output = tempfile.mkstemp(prefix=".helper-build-", dir=cache)
        os.close(fd)
        completed = False
        try:
            argv = [compiler, "-isysroot", sdk, "-std=c11", "-Werror", "-Wno-deprecated-declarations",
                    "-framework", "Security", "-framework", "CoreFoundation"]
            argv.extend(str(directory / name) for name, _ in sources if name.endswith(".c"))
            argv.extend(["-o", output])
            try:
                result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, env=child_env(),
                                        timeout=remaining(deadline), check=False)
            except subprocess.TimeoutExpired:
                raise keychain_error("timeout") from None
            if result.returncode:
                raise keychain_error("unavailable")
            os.chmod(output, 0o700)
            completed = True
            return Path(output)
        finally:
            if not completed:
                Path(output).unlink(missing_ok=True)


def build_helper(deadline: float) -> str:
    if facts.os_family() != "darwin":
        raise keychain_error("unavailable")
    import fcntl

    sources = _source_snapshot(Path(__file__).parent)
    cache = Path.home() / "Library" / "Caches" / "hermes" / "apple-keychain"
    _private_directory(cache)
    helper = cache / f"helper-v2-{_snapshot_digest(sources)}"
    if _safe_helper(helper):
        return str(helper)
    lock_fd = -1
    output = None
    try:
        lock_fd = os.open(cache / "build.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        lock_stat = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_uid != _user_id() or lock_stat.st_mode & 0o077:
            raise keychain_error("unavailable")
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(min(0.025, remaining(deadline)))
        if _safe_helper(helper):
            return str(helper)
        output = _compile(sources, cache, deadline)
        os.replace(output, helper)
        output = None
        return str(helper)
    except OSError:
        raise keychain_error("unavailable") from None
    finally:
        if output is not None:
            try:
                output.unlink()
            except FileNotFoundError:
                pass
        if lock_fd >= 0:
            os.close(lock_fd)
