"""Regression tests for per-stream stacking and out-of-fold thresholds.

These cover the production failure mode where one pooled meta-learner emitted
the pooled prior for every ordinary event in a rare stream: benign process
events all scored exactly ``0.000539``, so recall/FPR looked perfect while the
score carried no per-event ranking at all.
"""

from __future__ import annotations

import numpy as np
import pytest

from backend.ml.anomaly import MLAnomalyDetector
from backend.ml.ensemble import EnsembleStacker, PerStreamStacker


def _separable(n: int = 400, pos_rate: float = 0.06, seed: int = 7):
    """Base-model outputs with real separation between classes."""
    rng = np.random.RandomState(seed)
    y = (rng.random(n) < pos_rate).astype(int)
    if_scores = np.where(y, rng.normal(0.85, 0.07, n), rng.normal(0.25, 0.18, n))
    p = np.where(y, rng.normal(0.80, 0.10, n), rng.normal(0.05, 0.05, n))
    return np.clip(if_scores, 0, 1), np.clip(p, 0, 1), y


def _point_mass(n: int = 400, pos_rate: float = 0.06, seed: int = 11):
    """Base-model outputs identical for every benign row (the old bug)."""
    rng = np.random.RandomState(seed)
    y = (rng.random(n) < pos_rate).astype(int)
    if_scores = np.where(y, 0.9, 0.5)
    p = np.where(y, 0.9, 0.00044)
    return if_scores, p, y


# ---------------------------------------------------------------------------
# PerStreamStacker
# ---------------------------------------------------------------------------
def test_untrained_stream_falls_back_to_blend():
    stacker = PerStreamStacker()
    # 0.6*0.9 + 0.4*0.8
    assert stacker.predict("process", 0.9, 0.8) == pytest.approx(0.86)
    assert not stacker.trained_for("process")


def test_fit_stream_accepts_separable_stream():
    if_scores, p, y = _separable()
    stacker = PerStreamStacker()
    decision = stacker.fit_stream("login", if_scores, p, y)

    assert decision["status"] == "accepted"
    assert stacker.trained_for("login")
    # The meta must return a genuine ranking, not one value for everything.
    benign = [stacker.predict("login", float(a), float(b))
              for a, b in zip(if_scores[y == 0], p[y == 0])]
    assert len(set(np.round(benign, 9))) > 10


def test_fit_stream_rejects_point_mass():
    if_scores, p, y = _point_mass()
    stacker = PerStreamStacker()
    decision = stacker.fit_stream("process", if_scores, p, y)

    assert decision["trained"] is False
    assert "point mass" in decision["reason"]
    assert not stacker.trained_for("process")
    # Rejected learner must not change serving behaviour.
    assert stacker.predict("process", 0.5, 0.00044) == pytest.approx(0.6 * 0.5 + 0.4 * 0.00044)


def test_fit_stream_requires_enough_labels():
    stacker = PerStreamStacker()
    y = np.array([0] * 40 + [1] * 2)
    decision = stacker.fit_stream(
        "network", np.linspace(0, 1, 42), np.zeros(42), y
    )
    assert decision["status"] == "insufficient-labels"
    assert not stacker.trained_for("network")


def test_predict_batch_matches_predict_per_row():
    if_scores, p, y = _separable(seed=13)
    stacker = PerStreamStacker()
    stacker.fit_stream("login", if_scores, p, y)

    batch = stacker.predict_batch("login", if_scores[:20], p[:20])
    single = np.array([stacker.predict("login", a, b)
                       for a, b in zip(if_scores[:20], p[:20])])
    np.testing.assert_allclose(batch, single, rtol=1e-9)


def test_status_reports_per_stream_decisions():
    if_scores, p, y = _separable()
    stacker = PerStreamStacker()
    stacker.fit_stream("login", if_scores, p, y)

    status = stacker.status()
    assert status["is_trained"] is True
    assert "login" in status["streams"]
    assert status["streams"]["login"]["decision"]["status"] == "accepted"
    assert status["streams"]["process"]["decision"] is None


# ---------------------------------------------------------------------------
# Legacy EnsembleStacker still behaves, but selection is CV-based
# ---------------------------------------------------------------------------
def test_stacker_reports_cv_auc_not_train_accuracy():
    if_scores, p, y = _separable(seed=3)
    stacker = EnsembleStacker()
    result = stacker.train_meta(if_scores, p, None, y)

    assert result["status"] == "ok"
    assert "cv_auc" in result
    assert 0.0 <= result["cv_auc"] <= 1.0
    assert "train_accuracy" not in result


def test_stacker_refuses_single_class():
    y = np.zeros(100, dtype=int)
    stacker = EnsembleStacker()
    result = stacker.train_meta(np.linspace(0, 1, 100), np.zeros(100), None, y)
    assert result["trained"] is False
    assert result["status"] == "single-class"


# ---------------------------------------------------------------------------
# Out-of-fold thresholding
# ---------------------------------------------------------------------------
def test_threshold_from_scores_honours_fpr_budget():
    rng = np.random.RandomState(5)
    scores = np.concatenate([rng.normal(0.2, 0.05, 400), rng.normal(0.9, 0.03, 20)])
    labels = np.array([0] * 400 + [1] * 20)

    threshold, info = MLAnomalyDetector._threshold_from_scores(scores, labels, 0.10)

    assert info["source"] == "out-of-fold"
    assert info["fpr"] <= 0.10
    assert info["recall"] >= 0.9
    assert 0.2 < threshold < 0.9


def test_threshold_from_scores_handles_missing_labels():
    scores = np.linspace(0, 1, 50)
    threshold, info = MLAnomalyDetector._threshold_from_scores(
        scores, np.zeros(50, dtype=int), 0.05
    )
    assert info["source"] == "cfar-only"
    assert 0.9 <= threshold <= 1.0


def test_threshold_refuses_to_split_identical_scores():
    """No candidate threshold may claim recall from a single score value."""
    scores = np.full(100, 0.00044)
    labels = np.array([1] * 10 + [0] * 90)

    threshold, info = MLAnomalyDetector._threshold_from_scores(scores, labels, 0.05)
    # Every event shares one score: the only honest operating point is "no
    # separation", i.e. nothing is flagged above the mass.
    assert threshold >= 0.00044
    assert info["fpr"] == 0.0


# ---------------------------------------------------------------------------
# Calibration must stay monotone at realistic positive counts
# ---------------------------------------------------------------------------
def test_small_imbalanced_head_uses_platt_not_isotonic():
    rng = np.random.RandomState(2)
    X = rng.normal(size=(120, 6))
    y = np.zeros(120, dtype=int)
    X[y == 1] += 2.0
    y[:8] = 1
    X[:8] += 2.0

    model, name = MLAnomalyDetector._build_classifier(X, y)
    assert name.endswith("+platt"), name
    # Platt scaling is strictly monotone, so ranking is preserved.
    proba = model.predict_proba(X)[:, 1]
    assert len(np.unique(np.round(proba, 10))) > 50


# ---------------------------------------------------------------------------
# Vector routing
# ---------------------------------------------------------------------------
class _SpyModel:
    """Minimal stream model that records how many rows it was asked to score."""

    def __init__(self, width: int, decision: float = -0.3):
        self.n_features_in_ = width
        self.decision = decision
        self.rows_scored = 0

    def decision_function(self, X):
        self.rows_scored += len(X)
        return np.full(len(X), self.decision)


def test_logon_type_10_routes_to_login_not_process():
    """A 37-dim login vector must never enter the 48-dim process model.

    ``10`` is both a logon type (RDP) and a process-stream event id, and login
    vectors start with ``logon_type`` rather than an event id. Routing on
    ``features[0]`` alone sent real login events into the process model, which
    answered with a silent ``0.0``.
    """
    det = MLAnomalyDetector()
    login_model, process_model = _SpyModel(37), _SpyModel(48)
    det.models = {"login": login_model, "process": process_model}

    login_vec = [10.0] + [0.0] * 36
    assert det._behavior_for_vector(login_vec) == "login"
    assert det.score_event(login_vec) > 0.0
    assert login_model.rows_scored == 1
    assert process_model.rows_scored == 0

    batch = det.score_events([login_vec])
    assert batch[0] > 0.0
    assert login_model.rows_scored == 2
    assert process_model.rows_scored == 0


def test_process_event_id_10_still_routes_to_process():
    det = MLAnomalyDetector()
    det.models = {"login": _SpyModel(37), "process": _SpyModel(48)}

    process_vec = [10.0] + [0.0] * 47
    assert det._behavior_for_vector(process_vec) == "process"
    assert det.score_events([process_vec])[0] > 0.0


# ---------------------------------------------------------------------------
# Ensemble persistence
# ---------------------------------------------------------------------------
def test_bundle_roundtrip_keeps_per_stream_meta(tmp_path, monkeypatch):
    from sklearn.ensemble import IsolationForest

    if_scores, p, y = _separable(seed=21)
    X = np.random.RandomState(1).normal(size=(50, 4))

    det = MLAnomalyDetector()
    det.models = {"login": IsolationForest(random_state=42).fit(X)}
    det.ensemble = PerStreamStacker()
    det.ensemble.fit_stream("login", if_scores, p, y)
    assert det.ensemble.trained_for("login")

    bundle = tmp_path / "model.joblib"
    monkeypatch.setattr(det, "_bundle_path", lambda: bundle)
    monkeypatch.setattr(det, "_prev_bundle_path", lambda: tmp_path / "prev.joblib")
    det._save_bundle()
    assert bundle.exists()

    restored = MLAnomalyDetector()
    monkeypatch.setattr(restored, "_bundle_path", lambda: bundle)
    assert restored._load_bundle() is True
    assert isinstance(restored.ensemble, PerStreamStacker)
    assert restored.ensemble.trained_for("login")


def test_rollback_drops_meta_fitted_for_the_newer_model(tmp_path, monkeypatch):
    """Rolling back the base models must not keep the newer stacker.

    The stack was fitted in the newer model's score space; keeping it while
    restoring older base models silently changes what serving emits.
    """
    import joblib

    from sklearn.ensemble import IsolationForest

    from backend.ml.anomaly import ML_FEATURE_VERSION

    X = np.random.RandomState(3).normal(size=(40, 4))
    det = MLAnomalyDetector()
    det.models = {"login": IsolationForest(random_state=0).fit(X)}
    det.ensemble = PerStreamStacker()
    if_scores, p, y = _separable(seed=33)
    det.ensemble.fit_stream("login", if_scores, p, y)
    assert det.ensemble.trained_for("login")

    prev = tmp_path / "prev.joblib"
    joblib.dump(
        {
            "feature_version": ML_FEATURE_VERSION,
            "models": det.models,
            "thresholds": {"login": 0.5},
            "baselines": {},
            "version": 1,
        },
        prev,
    )
    monkeypatch.setattr(det, "_prev_bundle_path", lambda: prev)
    monkeypatch.setattr(det, "_save_meta", lambda: None)

    assert det.rollback() is True
    assert isinstance(det.ensemble, PerStreamStacker)
    assert det.ensemble.trained_for("login") is False
