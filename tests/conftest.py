"""Shared fixtures. Everything runs offline against the in-process demo target."""

from __future__ import annotations

import asyncio
import shutil
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from scanner.config import load_config
from scanner.models import RunReport
from scanner.probes import Probe, load_probes
from scanner.runner import ScanRequest, run_scan

DATA = Path(__file__).parent / "data"


@pytest.fixture(scope="session")
def probes() -> list[Probe]:
    return load_probes()


def run_demo(spec: str, **scan_overrides) -> RunReport:
    cfg = load_config(spec)
    scan = cfg.scan.model_copy(update={"seed": 1, **scan_overrides})
    return asyncio.run(run_scan(ScanRequest(cfg.target, scan)))


@pytest.fixture(scope="session")
def weak_report() -> RunReport:
    return run_demo("demo:weak")


@pytest.fixture(scope="session")
def hardened_report() -> RunReport:
    return run_demo("demo:hardened")


@pytest.fixture(scope="session")
def small_report() -> RunReport:
    """A fast report with mutators, used by the exporter tests."""
    return run_demo("demo:medium", mutators=["base64", "roleplay"], max_probes=25)


def _port_open(host: str, port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    """URL of a Redis server for integration tests (skips when none is available)."""
    import os

    url = os.environ.get("REDIS_URL")
    if url:
        yield url  # a generator fixture: `return url` here would end it without yielding
        return
    exe = shutil.which("redis-server") or os.environ.get("REDIS_SERVER_BIN")
    if not exe:
        pytest.skip("no Redis available (set REDIS_URL or install redis-server)")
    import subprocess
    import time

    port = 6390
    proc = subprocess.Popen(
        [exe, "--port", str(port), "--save", "", "--appendonly", "no"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        if _port_open("127.0.0.1", port):
            break
        time.sleep(0.1)
    yield f"redis://127.0.0.1:{port}/0"
    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture(scope="session")
def pg_server_url():
    """A PostgreSQL server for integration tests.

    Uses ``TEST_POSTGRES_URL`` (CI service container) if set, otherwise a throw-away server from the
    optional ``pgserver`` package, otherwise skips.
    """
    import os

    url = os.environ.get("TEST_POSTGRES_URL")
    if url:
        yield url
        return
    try:
        import pgserver  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip("no PostgreSQL available (set TEST_POSTGRES_URL or `pip install pgserver`)")
    import tempfile

    data = Path(tempfile.mkdtemp(prefix="llmscan-pg-"))
    server = pgserver.get_server(data, cleanup_mode="delete")
    yield server.get_uri()
    server.cleanup()


@pytest.fixture()
def pg_database(pg_server_url):
    """A fresh, empty database per test (dropped afterwards); yields its URL."""
    import uuid

    import psycopg
    from sqlalchemy.engine import make_url

    admin = make_url(pg_server_url.replace("postgresql://", "postgresql+psycopg://", 1))
    name = f"llmscan_{uuid.uuid4().hex[:12]}"
    dsn = admin.set(drivername="postgresql").render_as_string(hide_password=False)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    yield admin.set(database=name, drivername="postgresql").render_as_string(hide_password=False)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
