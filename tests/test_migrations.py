"""Migrations CI: the baseline must bootstrap a fresh database end-to-end."""

import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parent.parent
ADMIN_URL = os.environ.get("BARAQ_TEST_ADMIN_URL")
if not ADMIN_URL:
    _test_url = os.environ.get(
        "BARAQ_TEST_DATABASE_URL",
        "postgresql+psycopg://postgres:password@127.0.0.1:55432/baraq_test",
    )
    ADMIN_URL = make_url(_test_url).set(database="postgres").render_as_string(
        hide_password=False
    )


def _fresh_db_name() -> str:
    return f"baraq_test_migrate_{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def scratch_db():
    """Create and drop a throwaway PostgreSQL database for the migration."""
    name = _fresh_db_name()
    admin = create_engine(ADMIN_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    admin.dispose()
    # ``str(URL)`` masks the password as ``***``; the subprocess needs the real
    # DSN to connect to the scratch database.
    url = make_url(ADMIN_URL).set(database=name).render_as_string(hide_password=False)
    yield url, name
    admin = create_engine(ADMIN_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    admin.dispose()


def test_migrations_baseline_bootstraps_fresh_postgres(scratch_db):
    url, _name = scratch_db
    env = dict(os.environ)  # keep SystemRoot etc. or winsock breaks (WinError 10106)
    env.update(
        {
            "BARAQ_DATABASE_URL": url,
            "BARAQ_SKIP_SECRET_GEN": "1",
        }
    )
    run = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "migrate_db.py")],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        cwd=ROOT,
    )
    assert run.returncode == 0, run.stderr[-1500:]
    engine = create_engine(url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
    finally:
        engine.dispose()
    for expected in (
        "users",
        "alerts",
        "events",
        "entity_nodes",
        "entity_edges",
        "threat_intel_records",
        "audit_log",
        "alembic_version",
    ):
        assert expected in tables, f"missing table after upgrade: {expected}"


def test_baseline_revision_exists():
    versions = ROOT / "alembic" / "versions"
    baselines = list(versions.glob("*baseline*.py"))
    assert baselines, "no baseline migration"
    text_ = baselines[0].read_text(encoding="utf-8")
    assert "down_revision = None" in text_
    assert "def upgrade" in text_
