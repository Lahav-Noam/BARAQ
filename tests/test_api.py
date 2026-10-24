"""Test the FastAPI application routes with TestClient."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as test_client:
        yield test_client


def seed(client) -> None:
    """Populate the test database with the fixture-based attack suite."""
    from backend.api.system import run_pipeline
    from backend.database.connection import SessionLocal
    from tests.fixtures import full_suite

    db = SessionLocal()
    try:
        result = run_pipeline(db, full_suite())
    finally:
        db.close()
    return result


def test_root(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    # A fresh test database has no trained ML model, so the readiness endpoint
    # legitimately reports "warning" while still being usable.
    assert data["status"] in {"ok", "warning"}
    assert data["checks"]["database"]["status"] == "ok"


def test_dashboard_summary(client):
    seed(client)
    resp = client.get("/api/dashboard/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "security_score" in data
    assert "active_alerts" in data
    assert data["active_alerts"] >= 4


def test_alerts_listing(client):
    seed(client)
    resp = client.get("/api/alerts", params={"page_size": 10})
    assert resp.status_code == 200
    assert resp.json()["total"] >= 4


def test_alert_detail_and_status(client):
    seed(client)
    alerts = client.get("/api/alerts", params={"page_size": 1}).json()["items"]
    alert_id = alerts[0]["id"]
    resp = client.get(f"/api/alerts/{alert_id}")
    assert resp.status_code == 200
    assert resp.json()["mitre_id"]
    update = client.patch(
        f"/api/alerts/{alert_id}/status", json={"status": "in_progress"}
    )
    assert update.json()["status"] == "investigating"
    resolved = client.patch(
        f"/api/alerts/{alert_id}/status", json={"status": "resolved"}
    )
    assert resolved.json()["status"] == "resolved"
    closed = client.patch(f"/api/alerts/{alert_id}/status", json={"status": "closed"})
    assert closed.json()["status"] == "closed"
    bad = client.patch(
        f"/api/alerts/{alert_id}/status", json={"status": "investigating"}
    )
    assert bad.status_code == 409  # closed -> investigating is an illegal transition


def test_investigation(client):
    seed(client)
    alerts = client.get("/api/alerts", params={"page_size": 1}).json()["items"]
    resp = client.get(f"/api/investigation/alert/{alerts[0]['id']}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["attack_chain"]
    assert data["summary"]


def test_assistant_chat(client):
    seed(client)
    resp = client.post("/api/assistant/chat", json={"message": "explain alert 1"})
    assert resp.status_code == 200
    assert resp.json()["reply"]


def test_reports_endpoint(client):
    seed(client)
    resp = client.post(
        "/api/reports/generate", json={"report_type": "executive", "format": "json"}
    )
    assert resp.status_code == 200
    assert resp.json()["format"] == "json"
    listing = client.get("/api/reports/list")
    assert listing.json()["items"]


def test_events_endpoint(client):
    seed(client)
    resp = client.get("/api/events", params={"page_size": 5})
    assert resp.status_code == 200
    assert resp.json()["total"] > 0


def test_events_category_and_user_substring_filters(client):
    seed(client)
    items = client.get("/api/events", params={"page_size": 5}).json()["items"]
    assert items
    category = items[0]["category"]
    user = items[0].get("user") or ""
    by_category = client.get("/api/events", params={"category": category[:5]}).json()
    assert by_category["total"] > 0
    assert all(category.lower() in i["category"].lower() for i in by_category["items"])
    if user:
        by_user = client.get("/api/events", params={"user": user[:4]}).json()
        assert by_user["total"] > 0
