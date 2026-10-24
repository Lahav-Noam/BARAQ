"""Multi-tenant ("org") scoping tests.

An analyst may only read/act on records tagged with their organization;
admins (and API keys) see everything. The ingest channel attaches the
organization configured for the reporting agent.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.api.system import run_pipeline
from backend.auth import create_token, hash_password
from backend.database.connection import SessionLocal
from backend.database.models import (
    Alert,
    DnsQuery,
    Endpoint,
    HttpRequest,
    NetworkConnection,
    NormalizedEvent,
    ProcessRecord,
    User,
)
from tests.fixtures import brute_force

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_user(db, username: str, role: str = "analyst", org: str = "") -> User:
    user = User(
        username=username,
        password_hash=hash_password("baraq-test-password"),
        role=role,
        full_name=username,
        org=org,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _token(user: User) -> str:
    return create_token(user.id, user.username, user.role, user.org)


def _headers(user: User) -> dict:
    return {"Authorization": f"Bearer {_token(user)}"}


@pytest.fixture(scope="module")
def admin_client():
    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as c:
        yield c


# ---------------------------------------------------------------------------
# pipeline attribution
# ---------------------------------------------------------------------------


def test_pipeline_attaches_org_to_events_and_alerts(db):
    run_pipeline(db, brute_force(), org="univ-a")
    assert db.scalar(select(func.count(NormalizedEvent.id))) > 0
    assert db.scalar(
        select(func.count(NormalizedEvent.id)).where(NormalizedEvent.org == "univ-a")
    ) == db.scalar(select(func.count(NormalizedEvent.id)))
    assert db.scalar(select(func.count(Alert.id))) > 0
    assert db.scalar(
        select(func.count(Alert.id)).where(Alert.org == "univ-a")
    ) == db.scalar(select(func.count(Alert.id)))


def test_pipeline_default_org_is_empty(db):
    run_pipeline(db, brute_force(), org="")
    assert db.scalar(select(func.count(Alert.id))) > 0
    assert db.scalar(select(func.count(Alert.id)).where(Alert.org == "")) == db.scalar(
        select(func.count(Alert.id))
    )


# ---------------------------------------------------------------------------
# ingest attribution via BARAQ_AGENT_ORGS mapping
# ---------------------------------------------------------------------------


def test_ingest_attributes_org_from_agent_mapping(admin_client, monkeypatch):
    from backend import config

    monkeypatch.setitem(config.AGENT_ORGS, "agent-dev", "univ-a")
    body = {
        "records": brute_force(8),
        "host": "pc-1",
    }
    resp = admin_client.post(
        "/api/ingest",
        json=body,
        headers={"X-Agent-Key": "baraq-agent-dev"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["org"] == "univ-a"

    with SessionLocal() as s:
        events = s.scalars(
            select(NormalizedEvent).where(NormalizedEvent.org == "univ-a")
        ).all()
        assert events, "ingested events must carry the agent org"
        ep = s.get(Endpoint, "agent-dev")
        assert ep is not None and ep.org == "univ-a"
        alerts = s.scalars(select(Alert).where(Alert.org == "univ-a")).all()
        assert alerts, "ingested events should have produced org-scoped alerts"


# ---------------------------------------------------------------------------
# API enforcement
# ---------------------------------------------------------------------------


@pytest.fixture()
def seeded(db):
    """One alert per tenant so scoping is observable."""
    run_pipeline(db, brute_force(8), org="univ-a")
    run_pipeline(db, brute_force(8), org="univ-b")
    run_pipeline(db, brute_force(8), org="")
    return db


def test_alerts_are_scoped_per_org(seeded, admin_client):
    admin = admin_client.get("/api/alerts")
    assert admin.status_code == 200
    total = admin.json()["total"]
    assert total > 0, "admin should see alerts"

    analyst_a = _make_user(seeded, "analyst-a", org="univ-a")
    analyst_b = _make_user(seeded, "analyst-b", org="univ-b")

    resp_a = admin_client.get("/api/alerts", headers=_headers(analyst_a))
    assert resp_a.status_code == 200
    items_a = resp_a.json()["items"]
    assert items_a, "analyst should see their own org's alerts"
    assert all(a["org"] == "univ-a" for a in items_a)

    resp_b = admin_client.get("/api/alerts", headers=_headers(analyst_b))
    assert all(a["org"] == "univ-b" for a in resp_b.json()["items"])
    # identical seeded scenarios -> identical per-org totals (two-phase
    # detection completes correlation chains within the same pass, so each
    # org has a base alert plus its chain alert - never merged across orgs).
    assert resp_b.json()["total"] == resp_a.json()["total"]

    # admin sees the union of every org's alerts
    univ_c_count = db_scalar(select(func.count(Alert.id)).where(Alert.org == ""))
    assert total == resp_a.json()["total"] + resp_b.json()["total"] + univ_c_count


def test_alert_detail_is_404_across_orgs(seeded, admin_client):
    org_a_alert = db_scalar(select(Alert).where(Alert.org == "univ-a"))
    analyst_b = _make_user(seeded, "analyst-bb", org="univ-b")
    resp = admin_client.get(
        f"/api/alerts/{org_a_alert.id}", headers=_headers(analyst_b)
    )
    assert resp.status_code == 404
    own = admin_client.get(
        f"/api/alerts/{org_a_alert.id}",
        headers=_headers(_make_user(seeded, "analyst-aa", org="univ-a")),
    )
    assert own.status_code == 200


def test_alert_queries_are_scoped_by_org(seeded, db):
    _make_user(db, "analyst-count", org="univ-a")
    total_a = db.scalar(select(func.count(Alert.id)).where(Alert.org == "univ-a"))
    total_all = db.scalar(select(func.count(Alert.id)))
    from backend.analyzers import dashboard

    with SessionLocal() as s:
        assert dashboard.dashboard_summary(s, org="univ-a")["active_alerts"] == total_a
        assert dashboard.dashboard_summary(s)["active_alerts"] == total_all


def db_scalar(select_stmt):
    with SessionLocal() as s:
        return s.scalar(select_stmt)


# ---------------------------------------------------------------------------
# fleet (endpoints) scoping
# ---------------------------------------------------------------------------


def test_endpoints_are_scoped_per_org(seeded, db, admin_client):
    with SessionLocal() as s:
        s.add(
            Endpoint(
                agent_id="ep-a",
                host="host-a",
                org="univ-a",
                records_total=1,
                events_total=1,
                alerts_total=0,
            )
        )
        s.add(
            Endpoint(
                agent_id="ep-b",
                host="host-b",
                org="univ-b",
                records_total=1,
                events_total=1,
                alerts_total=0,
            )
        )
        s.commit()

    analyst_a = _make_user(db, "endpoint-analyst", org="univ-a")
    resp = admin_client.get("/api/endpoints", headers=_headers(analyst_a))
    assert resp.status_code == 200
    ids = [ep["agent_id"] for ep in resp.json()["items"]]
    assert "ep-a" in ids and "ep-b" not in ids


def test_telemetry_endpoints_are_scoped_per_org(seeded, db, admin_client):
    """Raw process/network/DNS/HTTP feeds must honour the caller's org."""
    now = datetime.now(UTC)
    with SessionLocal() as s:
        s.add_all(
            [
                ProcessRecord(pid=101, name="proc-a", observed_at=now, org="univ-a"),
                ProcessRecord(pid=202, name="proc-b", observed_at=now, org="univ-b"),
                NetworkConnection(
                    remote_ip="10.10.0.1",
                    remote_port=443,
                    observed_at=now,
                    org="univ-a",
                ),
                NetworkConnection(
                    remote_ip="10.10.0.2",
                    remote_port=443,
                    observed_at=now,
                    org="univ-b",
                ),
                DnsQuery(query="a.telemetry.test", observed_at=now, org="univ-a"),
                DnsQuery(query="b.telemetry.test", observed_at=now, org="univ-b"),
                HttpRequest(
                    host="a.telemetry.test",
                    url="http://a.telemetry.test/",
                    observed_at=now,
                    org="univ-a",
                ),
                HttpRequest(
                    host="b.telemetry.test",
                    url="http://b.telemetry.test/",
                    observed_at=now,
                    org="univ-b",
                ),
            ]
        )
        s.commit()

    analyst_a = _make_user(db, "telemetry-analyst", org="univ-a")
    headers = _headers(analyst_a)

    processes = admin_client.get("/api/processes", headers=headers)
    assert processes.status_code == 200, processes.text
    assert {p["name"] for p in processes.json()["items"]} == {"proc-a"}

    network = admin_client.get("/api/network", headers=headers)
    assert network.status_code == 200, network.text
    assert {r["remote_ip"] for r in network.json()["items"]} == {"10.10.0.1"}

    dns = admin_client.get("/api/dns", headers=headers)
    assert dns.status_code == 200, dns.text
    assert {r["query"] for r in dns.json()["items"]} == {"a.telemetry.test"}

    http = admin_client.get("/api/http", headers=headers)
    assert http.status_code == 200, http.text
    assert {r["host"] for r in http.json()["items"]} == {"a.telemetry.test"}

    stats = admin_client.get("/api/network/stats", headers=headers)
    assert stats.status_code == 200, stats.text
    body = stats.json()
    assert body["counts"] == {"connections": 1, "dns": 1, "http": 1}
    assert [r["ip"] for r in body["top_ips"]] == ["10.10.0.1"]
    assert {r["query"] for r in body["top_dns"]} == {"a.telemetry.test"}
    assert {r["host"] for r in body["top_hosts"]} == {"a.telemetry.test"}


def test_ml_explanations_are_404_across_orgs(seeded, db, admin_client):
    org_a_alert = db.scalar(select(Alert).where(Alert.org == "univ-a"))
    org_a_event = db.scalar(
        select(NormalizedEvent).where(NormalizedEvent.org == "univ-a")
    )
    assert org_a_alert is not None and org_a_event is not None

    analyst_b = _make_user(db, "explain-analyst", org="univ-b")
    headers = _headers(analyst_b)

    alert_resp = admin_client.get(
        f"/api/system/ml/explain/alert/{org_a_alert.id}", headers=headers
    )
    assert alert_resp.status_code == 404
    assert alert_resp.json()["detail"] == "Alert not found"

    event_resp = admin_client.get(
        f"/api/system/ml/explain/event/{org_a_event.id}", headers=headers
    )
    assert event_resp.status_code == 404
    assert event_resp.json()["detail"] == "Event not found"


def test_admin_can_narrow_scope_via_header(seeded, admin_client):
    univ_a_count = db_scalar(select(func.count(Alert.id)).where(Alert.org == "univ-a"))
    resp = admin_client.get("/api/alerts", headers={"X-Org": "univ-a"})
    assert resp.status_code == 200
    assert resp.json()["total"] == univ_a_count
    assert resp.json()["total"] > 0
    assert all(a["org"] == "univ-a" for a in resp.json()["items"])


def test_tenant_scope_helper():
    """Direct checks of the security helper's three branches."""
    from fastapi import Request

    def req(**extra):
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "scheme": "http",
            "query_string": b"",
            "headers": [(b"host", b"test")],
        }
        for k, v in extra.items():
            scope[k] = v
        return Request(scope)

    from backend.security import tenant_scope

    assert tenant_scope(req(state={"api_role": "admin"})) is None
    assert (
        tenant_scope(
            req(
                state={
                    "api_role": "analyst",
                    "token_user": {"role": "analyst", "org": "univ-a"},
                }
            )
        )
        == "univ-a"
    )
    assert tenant_scope(req(state={"api_role": "analyst"})) == ""
    # Admins can narrow via X-Org; nobody else can widen.
    scoped = req(state={"api_role": "admin"})
    scoped.scope["headers"] = [(b"host", b"test"), (b"x-org", b"univ-a")]
    assert tenant_scope(scoped) == "univ-a"
    wide = req(
        state={
            "api_role": "analyst",
            "token_user": {"role": "analyst", "org": "univ-b"},
        }
    )
    wide.scope["headers"] = [(b"host", b"test"), (b"x-org", b"univ-a")]
    assert tenant_scope(wide) == "univ-b"
