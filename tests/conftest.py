"""Shared test fixtures - isolated database per test session.

Set the database URL BEFORE importing any backend module so tests never
touch the production database.

Isolation uses the dedicated ``baraq_test`` database on the local
PostgreSQL cluster (service ``BARAQ-PostgreSQL``). Every table is
truncated (with identity restart) before each test, so primary keys stay
deterministic and the suite is fully isolated from ``baraq``.
"""

from __future__ import annotations

import os
import tempfile
import urllib.parse

_test_database_url = os.environ.get("BARAQ_TEST_DATABASE_URL") or os.environ.get(
    "BARAQ_DATABASE_URL",
    "postgresql+psycopg://postgres:password@127.0.0.1:55432/baraq_test",
)
_test_db_name = urllib.parse.urlsplit(_test_database_url).path.lstrip("/")
if not _test_db_name or "test" not in _test_db_name.lower():
    raise RuntimeError(
        "Refusing to run the test suite against database "
        f"{_test_db_name!r}: the suite truncates every table. Set "
        "BARAQ_TEST_DATABASE_URL to a dedicated database whose name contains "
        "'test' (for example baraq_test)."
    )
os.environ["BARAQ_TEST_DATABASE_URL"] = _test_database_url
os.environ["BARAQ_DATABASE_URL"] = _test_database_url
print(f"[conftest] test DB URL -> {os.environ['BARAQ_DATABASE_URL']}")
# The v2 telemetry/detection stack is fully enabled in the isolated test
# database (never enabled for the production DB name - config gate).
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_ALERTS_V2"] = "1"
os.environ["BARAQ_BEHAVIOR_GROUPS"] = "1"
os.environ["BARAQ_CORRELATION"] = "1"
os.environ["BARAQ_RISK"] = "1"
os.environ["BARAQ_INTERVAL"] = "60"
# Isolate ML model persistence from the production database folder.
_test_tmp = os.path.join(tempfile.gettempdir(), "baraq_test_meta")
os.makedirs(_test_tmp, exist_ok=True)
os.environ["BARAQ_ML_META_FILE"] = os.path.join(_test_tmp, "model_meta.json")
# Never let first-run secret generation write to / modify the real project .env.
os.environ["BARAQ_SKIP_SECRET_GEN"] = "1"
# Override the project .env credentials so tests always run with the dev keys
# (the config loader is non-overriding, so these take precedence over .env).
os.environ["BARAQ_API_KEYS"] = (
    '{"baraq-dev-admin": "admin", "baraq-dev-analyst": "analyst"}'
)
os.environ["BARAQ_ADMIN_PASSWORD"] = "baraq-test-admin"
os.environ["BARAQ_TOKEN_SECRET"] = "baraq-test-token-secret"
# Pin agent keys too: _secret() falls back to the real DPAPI vault, which
# still holds the pre-rename agent keys - tests must never depend on them.
os.environ["BARAQ_AGENT_KEYS"] = (
    '{"baraq-agent-dev": "agent-dev", "baraq-agent-laptop2": "laptop2"}'
)
# Deterministic test runs: never spawn the background scheduler thread and use
# the fully-local assistant engine (no dependence on a live AI endpoint).
os.environ["BARAQ_NO_SCHEDULER"] = "1"
os.environ["BARAQ_AI_API_URL"] = ""
os.environ["BARAQ_SCHEDULER_ENABLED"] = "0"  # no background collector in tests
# Deterministic alert aggregation: the 30s re-trigger cooldown is a production
# anti-flood guard, but tests loop the same finding and must see every trigger.
os.environ["BARAQ_ALERT_RETRIGGER_COOLDOWN_SECONDS"] = "0"
# Never spam Windows toasts / webhooks / email from synthetic test alerts.
os.environ["BARAQ_TOAST_ENABLED"] = "0"
# SOAR tests must never run live-fire response actions: with the project .env
# enabling BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED=1, playbook runs would call
# real netsh/taskkill against this workstation (firewall rules accumulate on
# every suite run). The config loader is non-overriding, so this wins over .env.
os.environ["BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED"] = "0"
# Cap sklearn/BLAS threads: IsolationForest grid search + CV oversubscribe
# 8 cores otherwise and multi-minute wall times on small test fixtures.
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")
# Disable CSRF for tests so cookie-session tests work without tokens.
os.environ["BARAQ_CSRF_ENABLED"] = "0"
os.environ.setdefault("BARAQ_TEST_MODE", "0")
os.environ.setdefault("BARAQ_ALLOW_DEV_KEYS", "1")
# Never run the suite under the production profile, even when the project
# .env (non-overriding loader) configures BARAQ_ENV=production: the
# production profile rejects the conftest dev API keys at import time.
os.environ["BARAQ_ENV"] = "test"
# Production .env raises the retrain gates (so hourly age-gate training
# dominates); tests keep the historical low thresholds so staleness fixtures
# stay small. setdefault wins because .env loads non-overriding later.
os.environ.setdefault("BARAQ_ML_RETRAIN_MIN_NEW_EVENTS", "200")
os.environ.setdefault("BARAQ_ML_RETRAIN_MIN_NEW_VERDICTS", "5")
os.environ["BARAQ_ENCRYPT_AT_REST"] = "0"
os.environ["BARAQ_TLS"] = "0"
os.environ["BARAQ_COOKIE_SECURE"] = "0"
os.environ["BARAQ_DATASET_ENABLED"] = "1"
os.environ["BARAQ_DATASET_ANONYMIZE"] = "0"
# Point the Sigma engine at an empty scratch dir: the full community rule set
# (2,400+ YAML) takes ~25s to parse and would slow every RulesEngine test.
os.environ["SIGMA_RULES_DIR"] = os.path.join(
    tempfile.gettempdir(), "baraq_test_sigma_rules_empty"
)
# Fixture/lab traffic uses TEST-NET IPs; keep them "external" for rules that
# gate on BARAQ_TESTNET_EXTERNAL (production defaults to off).
os.environ["BARAQ_TESTNET_EXTERNAL"] = "1"
# Robustness eval is hundreds of IF predict calls (~50ms each) — skip in tests.
os.environ["BARAQ_ML_SKIP_ROBUSTNESS"] = "1"

import pytest
from sqlalchemy import text

from backend.database.connection import SessionLocal, engine, init_db
from backend.database.models import Base

_TABLE_NAMES = list(Base.metadata.tables.keys())


def _table_names() -> list[str]:
    """All registered tables, including ones imported after conftest loads
    (e.g. the v2 telemetry models) so every test starts from a clean DB."""
    return sorted(Base.metadata.tables.keys())


@pytest.fixture(scope="session", autouse=True)
def _init_database():
    init_db()
    yield


@pytest.fixture(autouse=True)
def _reset_compliance_assessments():
    """Compliance templates are process-wide mutable state - reset per test.

    Without this, an assessment recorded by one test leaks into the next and
    gap-analysis assertions depend on test order.
    """
    from backend.compliance.frameworks import reset_assessments

    reset_assessments()
    yield


def _reset_database(terminate_stragglers: bool = False):
    """Truncate every table (identity restart) from a fresh session.

    ``terminate_stragglers`` kills idle-in-transaction sessions first - used
    only as a fallback when the TRUNCATE stalls on a leaked connection.
    """
    session = SessionLocal()
    try:
        session.execute(text("SET LOCAL lock_timeout = '10s'"))
        # Defense in depth: conftest validates BARAQ_TEST_DATABASE_URL at
        # import, but re-check the database we are actually connected to
        # before issuing a destructive TRUNCATE. The catalog lookup is
        # PostgreSQL-specific; SQLite installs are covered by the URL guard.
        bind = session.get_bind()
        if bind is not None and bind.dialect.name == "postgresql":
            db_name = session.scalar(text("SELECT current_database()")) or ""
            if "test" not in str(db_name).lower():
                raise RuntimeError(
                    f"Refusing to truncate non-test database {db_name!r}. "
                    "Set BARAQ_TEST_DATABASE_URL to a dedicated test database."
                )
        if terminate_stragglers:
            session.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = current_database() "
                    "AND pid <> pg_backend_pid() AND state = 'idle in transaction'"
                )
            )
            session.commit()
        tables = ", ".join(f'"{t}"' for t in _table_names())
        session.execute(text(f"TRUNCATE TABLE {tables} RESTART IDENTITY CASCADE"))
        session.commit()
    finally:
        session.close()


@pytest.fixture(autouse=True)
def _clean_database():
    """Reset every table before each test for full isolation.

    All tables are truncated in ONE statement (a single lock-acquisition
    order). Pooled connections left in an open transaction by the previous
    test are closed via ``engine.dispose()`` first; if the TRUNCATE still
    stalls on a leaked session, idle-in-transaction stragglers are
    terminated and the truncate retried. The happy path never kills a
    connection - killing is the loud fallback, never the norm.
    """
    engine.dispose()
    try:
        _reset_database()
    except Exception:
        engine.dispose()
        import time
        time.sleep(0.5)
        try:
            _reset_database(terminate_stragglers=True)
        except Exception:
            engine.dispose()
            _reset_database(terminate_stragglers=True)
    yield


@pytest.fixture()
def db():
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


def run_simulation(db, scenario: str | None = None) -> dict:
    """Execute a fixture-driven pipeline run inside a test database."""
    from backend.api.system import run_pipeline
    from tests.fixtures import full_suite

    return run_pipeline(db, full_suite() if scenario is None else _scenario(scenario))


def _scenario(name: str) -> list[dict]:
    from tests import fixtures

    mapping = {
        "brute_force": fixtures.brute_force,
        "powershell": fixtures.suspicious_powershell,
        "privilege_escalation": fixtures.privilege_escalation,
        "persistence": fixtures.persistence,
        "port_scan": fixtures.port_scan,
        "lateral_movement": fixtures.lateral_movement,
        "data_staging": fixtures.data_staging,
        "baseline": fixtures.benign_baseline,
    }
    if name not in mapping:
        raise KeyError(f"Unknown fixture scenario: {name}")
    return mapping[name]()
