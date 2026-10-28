"""Deployment-gate and shadow-mode tests.

These tests pin the safety contract for the ML layer:

* unknown deployment modes fall back to shadow;
* a missing or non-validated manifest never permits enforcement;
* every scored network bucket is persisted for monitoring;
* ``shadow`` mode does not mutate event ``ml_score`` / ``is_anomaly``;
* ``off`` mode writes nothing.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from backend.database.models import MLShadowScore, NetworkConnection, NormalizedEvent
from backend.ml.anomaly import MLAnomalyDetector
from backend.ml.deployment import (
    DeploymentManifest,
    configured_mode,
    deployment_status,
    enforcement_allowed,
    load_manifest,
)


@pytest.fixture()
def session():
    from backend.database.connection import SessionLocal

    db = SessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


def _network_detector() -> MLAnomalyDetector:
    """A tiny, deterministic detector with a network stream and no labels."""
    detector = MLAnomalyDetector(load_persisted=False)
    model = IsolationForest(n_estimators=10, random_state=0)
    model.fit(np.zeros((20, 29), dtype=float))
    detector.models["network"] = model
    detector.baselines["network"] = np.array([0.0, 0.1, 0.2], dtype=float)
    detector.thresholds["network"] = -0.1  # deliberately flag the test bucket

    # A login stream lets the shadow-mode test prove that an event which is
    # actually scored still does not receive ml_score/is_anomaly.
    login = IsolationForest(n_estimators=10, random_state=0)
    login.fit(np.zeros((20, 37), dtype=float))
    detector.models["login"] = login
    detector.baselines["login"] = np.array([0.0, 0.1, 0.2], dtype=float)
    detector.thresholds["login"] = 2.0
    detector.version = 121
    return detector


def _network_row(remote_ip: str = "203.0.113.77") -> NetworkConnection:
    return NetworkConnection(
        pid=4242,
        process="curl",
        local_ip="10.0.0.5",
        local_port=50000,
        remote_ip=remote_ip,
        remote_port=443,
        state="Established",
        bytes_sent=100,
        bytes_recv=200,
        duration_seconds=1.0,
        observed_at=datetime.now(UTC) - timedelta(seconds=10),
        org="test-org",
    )


def _event_row() -> NormalizedEvent:
    from backend.analyzers.normalizer import Normalizer
    from tests.fixtures import benign_baseline

    return NormalizedEvent(**Normalizer().normalize(benign_baseline(1)[0]))


def test_unknown_mode_falls_back_to_shadow(monkeypatch):
    monkeypatch.setenv("BARAQ_ML_DEPLOYMENT_MODE", "enforce")
    assert configured_mode() == "shadow"
    monkeypatch.setenv("BARAQ_ML_DEPLOYMENT_MODE", " SHADOW ")
    assert configured_mode() == "shadow"
    monkeypatch.setenv("BARAQ_ML_DEPLOYMENT_MODE", "advisory")
    assert configured_mode() == "advisory"


def test_missing_manifest_is_shadow_only(tmp_path):
    manifest = load_manifest(tmp_path / "does-not-exist.json")
    assert manifest.status == "missing"
    assert enforcement_allowed(manifest) is False
    assert manifest.blocking_reasons


def test_blocked_manifest_downgrades_advisory_to_shadow(monkeypatch, tmp_path):
    import backend.ml.deployment as deployment

    path = tmp_path / "manifest.json"
    path.write_text("{not valid json")
    monkeypatch.setattr(deployment, "ML_MANIFEST_FILE", path)
    monkeypatch.setenv("BARAQ_ML_DEPLOYMENT_MODE", "advisory")

    assert deployment.load_manifest().status == "blocked"
    assert deployment.configured_mode() == "shadow"


def test_manifest_validation_controls_enforcement(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "status": "shadow",
                "mode": "shadow",
                "model_version": 121,
                "feature_version": 7,
                "blocking_reasons": ["campaign holdout missing"],
            }
        )
    )
    shadow = load_manifest(path)
    assert shadow.status == "shadow"
    assert enforcement_allowed(shadow) is False

    path.write_text(
        json.dumps(
            {
                "status": "validated",
                "mode": "advisory",
                "model_version": 121,
                "feature_version": 7,
            }
        )
    )
    validated = load_manifest(path)
    assert validated.status == "validated"
    assert enforcement_allowed(validated) is True


def test_deployment_status_exposes_mode_and_manifest(monkeypatch, tmp_path):
    monkeypatch.setenv("BARAQ_ML_DEPLOYMENT_MODE", "shadow")
    manifest = DeploymentManifest(
        status="shadow",
        mode="shadow",
        model_version=121,
        feature_version=7,
        blocking_reasons=["unvalidated"],
    )
    status = deployment_status(manifest)
    assert status["mode"] == "shadow"
    assert status["manifest"]["status"] == "shadow"
    assert status["enforcement_allowed"] is False
    assert status["feature_version"] == 7


def test_shadow_score_serializes():
    row = MLShadowScore(
        stream="network",
        model_version=121,
        feature_version=7,
        entity="203.0.113.77",
        score=0.75,
        threshold=0.6,
        flagged=True,
        observed_at=datetime.now(UTC),
        org="test-org",
        detail={"count": 3},
    )
    data = row.to_dict()
    assert data["stream"] == "network"
    assert data["score"] == 0.75
    assert data["flagged"] is True
    assert data["detail"] == {"count": 3}


def test_shadow_mode_persists_network_score_without_event_flags(
    monkeypatch, session
):
    monkeypatch.setenv("BARAQ_ML_DEPLOYMENT_MODE", "shadow")
    session.add(_network_row())
    event = _event_row()
    session.add(event)
    session.commit()

    detector = _network_detector()
    result = detector.analyze_events(session, hours=1)

    assert result["status"] == "ok"
    assert result["mode"] == "shadow"
    assert result["scored"] >= 1  # the login event was scored
    assert result["shadow_scores"] == 1
    assert result["shadow_flagged"] == 1
    assert result["flagged"] == 0

    scores = session.query(MLShadowScore).all()
    assert len(scores) == 1
    score = scores[0]
    assert score.entity == "203.0.113.77"
    assert score.model_version == 121
    assert score.feature_version == 7
    assert score.org == "test-org"
    assert score.flagged is True
    assert score.detail["mode"] == "shadow"

    # Shadow mode must not promote the score onto the event.
    session.refresh(event)
    assert event.ml_score is None
    assert event.is_anomaly in (False, None)


def test_advisory_mode_still_records_shadow_rows(monkeypatch, session):
    monkeypatch.setenv("BARAQ_ML_DEPLOYMENT_MODE", "advisory")
    session.add(_network_row())
    event = _event_row()
    session.add(event)
    session.commit()

    detector = _network_detector()
    result = detector.analyze_events(session, hours=1)

    assert result["status"] == "ok"
    assert result["mode"] == "advisory"
    assert result["shadow_scores"] == 1
    # Advisory may count the network bucket as flagged, but still creates no alert.
    assert result["flagged"] >= 1
    session.refresh(event)
    assert event.ml_score is not None
    assert session.query(MLShadowScore).count() == 1


def test_off_mode_does_not_score_or_write(monkeypatch, session):
    monkeypatch.setenv("BARAQ_ML_DEPLOYMENT_MODE", "off")
    session.add(_network_row())
    session.commit()

    detector = _network_detector()
    result = detector.analyze_events(session, hours=1)

    assert result["status"] == "disabled"
    assert result["mode"] == "off"
    assert result["scored"] == 0
    assert session.query(MLShadowScore).count() == 0


def test_deployment_endpoint_returns_gate_and_distribution(monkeypatch, session):
    from fastapi.testclient import TestClient

    from backend.main import app

    monkeypatch.setenv("BARAQ_ML_DEPLOYMENT_MODE", "shadow")
    session.add(
        MLShadowScore(
            stream="network",
            model_version=121,
            feature_version=7,
            entity="203.0.113.77",
            score=0.91,
            threshold=0.60,
            flagged=True,
            observed_at=datetime.now(UTC),
            org="test-org",
            detail={"count": 2},
        )
    )
    session.commit()

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        response = client.get("/api/system/ml/deployment?hours=24")
    assert response.status_code == 200
    body = response.json()
    assert body["deployment"]["mode"] == "shadow"
    assert body["deployment"]["manifest"]["status"] in {
        "missing",
        "shadow",
        "blocked",
        "validated",
    }
    assert body["shadow_scores"] == 1
    assert body["shadow_flagged"] == 1
    assert body["score_distribution"]["max"] == 0.91
    assert body["top_flagged"][0]["entity"] == "203.0.113.77"
