"""Exercise rotation and recovery in disposable macOS Keychains."""

import os
from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.platforms("macos")


def test_rotation_preflight_and_interrupted_recovery():
    script = Path(__file__).parent / "apple_keychain_native_cases" / "run_cases.py"
    args = [sys.executable, str(script)]
    env = {"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"]}
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                            env=env, timeout=120, check=False)
    assert result.returncode == 0, (
        result.stdout.decode("utf-8", "replace") + result.stderr.decode("utf-8", "replace")
    )
