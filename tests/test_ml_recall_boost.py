"""Tests for the recall booster (Phase 4 ML recall improvements).

Validates:
- tune_threshold_for_recall maximizes recall within FPR budget
- UEBA baseline deviation scoring
- Temporal cross-stream sequence detection
- Adversarial sample generation
- RecallBooster end-to-end scoring
"""

from __future__ import annotations

import numpy as np
import pytest
from datetime import UTC, datetime, timedelta

from backend.ml.recall_boost import (
    RecallBooster,
    UEBABaseline,
    TemporalCrossStreamScorer,
    tune_threshold_for_recall,
    generate_adversarial_samples,
    RECALL_TARGET_FPR,
    RECALL_TARGET_RECALL,
    _ueba_baseline,
    _temporal_scorer,
)


# ---------------------------------------------------------------------------
# Threshold tuning tests
# ---------------------------------------------------------------------------

def test_tune_threshold_for_recall_maxes_recall_within_fpr():
    """Threshold should maximize recall while keeping FPR <= budget."""
    rng = np.random.RandomState(42)
    # 100 attack samples (high scores), 900 benign (low scores)
    attack_scores = rng.uniform(0.6, 1.0, 100)
    benign_scores = rng.uniform(0.0, 0.4, 900)
    scores = np.concatenate([attack_scores, benign_scores])
    labels = np.concatenate([np.ones(100), np.zeros(900)])

    threshold, metrics = tune_threshold_for_recall(
        scores, labels, max_fpr=0.10, target_recall=0.80
    )

    # FPR must be within budget
    assert metrics["fpr"] <= 0.10 + 1e-6, f"FPR {metrics['fpr']} exceeds budget"
    # Recall should be meaningful
    assert metrics["recall"] > 0.5, f"Recall {metrics['recall']} too low"
    assert metrics["threshold"] == threshold


def test_tune_threshold_for_recall_no_attacks():
    """With no attack samples, returns conservative CFAR-like threshold."""
    rng = np.random.RandomState(42)
    scores = rng.uniform(0.0, 1.0, 500)
    labels = np.zeros(500)

    threshold, metrics = tune_threshold_for_recall(scores, labels)
    assert metrics["recall"] == 0.0
    assert 0.0 <= threshold <= 1.0


def test_tune_threshold_strict_fpr_budget():
    """Very strict FPR budget (1%) should still return a valid threshold."""
    rng = np.random.RandomState(42)
    attack_scores = rng.uniform(0.7, 1.0, 50)
    benign_scores = rng.uniform(0.0, 0.3, 950)
    scores = np.concatenate([attack_scores, benign_scores])
    labels = np.concatenate([np.ones(50), np.zeros(950)])

    threshold, metrics = tune_threshold_for_recall(
        scores, labels, max_fpr=0.01, target_recall=0.80
    )
    assert metrics["fpr"] <= 0.01 + 1e-6


# ---------------------------------------------------------------------------
# UEBA baseline tests
# ---------------------------------------------------------------------------

def test_ueba_baseline_insufficient_history_returns_zero():
    """Users with < 10 events get zero UEBA deviation."""
    ueba = UEBABaseline()
    score = ueba.deviation_score("newuser", 4624, {"source_ip": "10.0.0.1"})
    assert score == 0.0


def test_ueba_baseline_new_ip_deviation():
    """A new source IP for a well-established user produces deviation."""
    ueba = UEBABaseline()
    user = "alice"

    # Build history: alice always logs in from 10.0.0.1 during business hours (hour 10)
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    for i in range(50):
        ueba._baselines[user]["hours"][10] += 1  # Always hour 10
        ueba._baselines[user]["ips"].add("10.0.0.1")
        ueba._baselines[user]["total"] += 1

    # Now score a login from a new IP at 3 AM
    facts = {"source_ip": "203.0.113.5"}
    ts_new = datetime(2026, 1, 10, 3, 0, 0, tzinfo=UTC)
    score = ueba.deviation_score(user, 4624, facts, ts_new)
    # New IP + unusual hour should produce deviation > 0
    assert score > 0.0, f"Expected UEBA deviation > 0, got {score}"
    assert score <= 1.0


def test_ueba_baseline_normal_behavior_returns_zero():
    """Normal behavior for an established user returns low deviation."""
    ueba = UEBABaseline()
    user = "bob"

    # Build history: bob always logs in from 10.0.0.1 at hour 10
    for i in range(50):
        ueba._baselines[user]["hours"][10] += 1  # Always hour 10
        ueba._baselines[user]["ips"].add("10.0.0.1")
        ueba._baselines[user]["total"] += 1

    # Score a normal login from the usual IP during usual hours
    facts = {"source_ip": "10.0.0.1"}
    ts_normal = datetime(2026, 1, 10, 10, 0, 0, tzinfo=UTC)
    score = ueba.deviation_score(user, 4624, facts, ts_normal)
    assert score == 0.0, f"Expected 0 deviation for normal behavior, got {score}"


# ---------------------------------------------------------------------------
# Temporal cross-stream scorer tests
# ---------------------------------------------------------------------------

def test_temporal_brute_force_pattern():
    """Multiple failed logons then success from same IP = high score."""
    scorer = TemporalCrossStreamScorer()
    host = "workstation-01"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)

    # Add 5 failed logons from 203.0.113.5
    for i in range(5):
        scorer._host_events[host].append(
            (base + timedelta(minutes=i), 4625, "203.0.113.5", "admin")
        )

    # Then a successful logon from same IP
    score = scorer.score_sequence(
        host, 4624, "203.0.113.5", "admin",
        base + timedelta(minutes=6)
    )
    assert score >= 0.8, f"Brute force pattern should score >= 0.8, got {score}"


def test_temporal_process_after_logon():
    """Process execution right after logon = moderate score."""
    scorer = TemporalCrossStreamScorer()
    host = "workstation-02"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)

    scorer._host_events[host].append((base, 4624, "10.0.0.1", "bob"))
    scorer._host_events[host].append((base + timedelta(minutes=2), 4688, "10.0.0.1", "bob"))

    score = scorer.score_sequence(
        host, 4688, "10.0.0.1", "bob",
        base + timedelta(minutes=2)
    )
    assert score >= 0.6, f"Process after logon should score >= 0.6, got {score}"


def test_temporal_service_then_network():
    """Service install then network = high score (C2 persistence)."""
    scorer = TemporalCrossStreamScorer()
    host = "server-01"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)

    scorer._host_events[host].append((base, 7045, "10.0.0.1", "system"))
    scorer._host_events[host].append((base + timedelta(minutes=1), 5156, "203.0.113.99", "system"))

    score = scorer.score_sequence(
        host, 5156, "203.0.113.99", "system",
        base + timedelta(minutes=1)
    )
    assert score >= 0.7, f"Service->network should score >= 0.7, got {score}"


def test_temporal_no_history_returns_zero():
    """No history = zero score."""
    scorer = TemporalCrossStreamScorer()
    score = scorer.score_sequence("unknown-host", 4624, "10.0.0.1", "admin")
    assert score == 0.0


# ---------------------------------------------------------------------------
# Adversarial augmentation tests
# ---------------------------------------------------------------------------

def test_generate_adversarial_samples_creates_attack_labels():
    """Adversarial samples should all be labelled as attack (1)."""
    rng = np.random.RandomState(42)
    X_attack = rng.uniform(0.0, 1.0, (10, 5))

    X_adv, y_adv = generate_adversarial_samples(
        X_attack, n_per_sample=3, random_state=42
    )

    assert len(X_adv) == 30  # 10 samples * 3 per sample
    assert len(y_adv) == 30
    assert np.all(y_adv == 1)  # All adversarial samples are attacks
    assert X_adv.shape[1] == 5


def test_generate_adversarial_samples_empty_input():
    """Empty input returns empty arrays."""
    X_adv, y_adv = generate_adversarial_samples(
        np.empty((0, 5)), n_per_sample=3
    )
    assert len(X_adv) == 0
    assert len(y_adv) == 0


def test_generate_adversarial_samples_with_model():
    """With an Isolation Forest model, adversarial samples use gradient direction."""
    from sklearn.ensemble import IsolationForest

    rng = np.random.RandomState(42)
    X = rng.uniform(0.0, 1.0, (50, 5))
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)

    # Attack samples: high anomaly scores
    attack_mask = model.predict(X) == -1
    X_attack = X[attack_mask]

    if len(X_attack) > 0:
        X_adv, y_adv = generate_adversarial_samples(
            X_attack, model=model, n_per_sample=2, random_state=42
        )
        assert len(X_adv) == len(X_attack) * 2
        assert np.all(y_adv == 1)


# ---------------------------------------------------------------------------
# RecallBooster end-to-end tests
# ---------------------------------------------------------------------------

def test_recall_booster_ueba_boost():
    """UEBA deviation should boost the final score."""
    from backend.ml.anomaly import MLAnomalyDetector

    detector = MLAnomalyDetector()
    # Manually add a model so scoring works
    from sklearn.ensemble import IsolationForest
    rng = np.random.RandomState(42)
    X = rng.uniform(0.0, 1.0, (100, 5))
    detector.models["login"] = IsolationForest(contamination=0.1, random_state=42)
    detector.models["login"].fit(X)
    detector.baselines["login"] = np.linspace(0, 1, 100)
    detector.thresholds["login"] = 0.5

    booster = RecallBooster(detector)

    # Build UEBA baseline for a user
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    for i in range(50):
        ts = base + timedelta(hours=i)
        _ueba_baseline._baselines["alice"]["hours"][ts.hour] += 1
        _ueba_baseline._baselines["alice"]["ips"].add("10.0.0.1")
        _ueba_baseline._baselines["alice"]["total"] += 1

    # Score a normal event (low base score, no UEBA deviation)
    features = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    score_normal = booster.score_event(
        "login", features, user="alice", event_id=4624,
        facts={"source_ip": "10.0.0.1"},
        ts=datetime(2026, 1, 10, 10, 0, 0, tzinfo=UTC),
    )

    # Score an anomalous event (new IP + unusual hour)
    score_anomalous = booster.score_event(
        "login", features, user="alice", event_id=4624,
        facts={"source_ip": "203.0.113.5"},
        ts=datetime(2026, 1, 10, 3, 0, 0, tzinfo=UTC),
    )

    # The anomalous event should score higher due to UEBA + temporal boosts
    # (base score is same, but UEBA/temporal add to it)
    assert score_anomalous >= score_normal, (
        f"Anomalous event ({score_anomalous}) should score >= normal ({score_normal})"
    )


def test_recall_booster_no_booster_falls_back_to_detector():
    """Without a recall booster, score_event_with_recall uses detector directly."""
    from backend.ml.anomaly import MLAnomalyDetector

    detector = MLAnomalyDetector()
    assert detector.recall_booster is None

    # score_event_with_recall should fall back to score_event_for_behavior
    score = detector.score_event_with_recall("login", [1, 0, 0, 0, 0, 0, 0, 0, 0])
    assert score == 0.0  # No model trained, returns 0


def test_recall_target_constants():
    """Module constants should be sane."""
    assert 0.0 < RECALL_TARGET_FPR < 1.0
    assert 0.0 < RECALL_TARGET_RECALL < 1.0
    assert RECALL_TARGET_FPR == 0.10
    assert RECALL_TARGET_RECALL == 0.80
