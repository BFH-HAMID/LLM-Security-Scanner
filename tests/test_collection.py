"""The suite must collect no matter how pytest is launched."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_the_suite_collects_with_the_plain_pytest_command():
    """CI and `make test` run `pytest`, not `python -m pytest` (which adds the repo root to sys.path).

    Test modules import one another as ``tests.*``; an earlier version only worked under
    ``python -m pytest`` and failed CI at collection with exit code 2.
    """
    exe = Path(sys.executable).with_name("pytest")
    plain = str(exe) if exe.exists() else shutil.which("pytest")
    if plain is None:
        pytest.skip("no pytest console script next to this interpreter")
    result = subprocess.run(
        [plain, "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout[-1500:] + result.stderr[-500:]
    assert "error" not in result.stdout.lower().splitlines()[-1]
