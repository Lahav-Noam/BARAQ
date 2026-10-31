"""Regression tests for the validation harness's honesty checks.

The harness used to report "100 % recall / 0 % FPR" twice over: once because
tied scores were sorted positives-first, and once because a threshold was
recommended even when a stream emitted only a handful of distinct benign
scores (so any cut lands in a gap, not in a ranking).
"""

from __future__ import annotations

import numpy as np
import pytest

from scripts.validate_ml import (
    DEGENERATE_MIN_DISTINCT,
    _recall_at_fpr,
    _recommended_threshold,
    _score_health,
)


def test_recall_at_fpr_cannot_split_tied_scores():
    """A single score value must never fabricate recall at low FPR."""
    labels = [1] * 10 + [0] * 90
    scores = [0.5] * 100

    out = _recall_at_fpr(labels, scores, 0.05)

    assert out["recall"] == 0.0
    assert out["distinct_scores"] == 1


def test_recall_at_fpr_handles_mixed_ties():
    """Positives and negatives sharing a score are added to the same bucket."""
    labels = [1, 0] + [1] * 9 + [0] * 5 + [0] * 84
    scores = [0.9, 0.9] + [0.2] * 9 + [0.2] * 5 + [0.1] * 84

    out = _recall_at_fpr(labels, scores, 0.05)

    # 0.9: 1 TP + 1 FP -> 1.1 % FPR, 10 % recall (admissible).
    # 0.2: adds 9 TP but also 5 FP -> 6/90 = 6.7 % FPR, over budget, so the
    # threshold cannot be lowered to "split" the tie.
    assert out["recall"] == pytest.approx(0.1, abs=1e-4)
    assert out["threshold"] == pytest.approx(0.9)


def test_score_health_flags_four_value_benign_stream():
    labels = [0] * 195 + [1] * 20
    benign = [0.28, 0.28451, 0.28452, 0.28453]
    scores = [benign[i % 4] for i in range(195)] + [0.960902] * 20

    health = _score_health(labels, scores)

    assert health["distinct_benign_scores"] == 4
    assert health["degenerate"] is True


def test_score_health_accepts_ranked_stream():
    rng = np.random.RandomState(4)
    labels = [0] * 200 + [1] * 20
    scores = list(rng.normal(0.2, 0.05, 200)) + list(rng.normal(0.9, 0.02, 20))

    health = _score_health(labels, scores)

    assert health["distinct_benign_scores"] >= DEGENERATE_MIN_DISTINCT
    assert health["degenerate"] is False


def test_recommended_threshold_refuses_degenerate_stream():
    """Four benign values plus a separated attack mass is a gap, not a ranking."""
    labels = [0] * 195 + [1] * 20
    benign = [0.28, 0.28451, 0.28452, 0.28453]
    scores = [benign[i % 4] for i in range(195)] + [0.960902] * 20

    # A naive midpoint search reports 100 % recall at 0 % FPR here.
    assert _recommended_threshold(labels, scores, 0.10) is None


def test_recommended_threshold_returns_budgeted_point_on_ranked_stream():
    rng = np.random.RandomState(9)
    labels = [0] * 400 + [1] * 40
    scores = list(rng.normal(0.2, 0.05, 400)) + list(rng.normal(0.9, 0.03, 40))

    rec = _recommended_threshold(labels, scores, 0.10)

    assert rec is not None
    assert rec["fpr"] <= 0.10
    assert rec["recall"] >= 0.75
    assert "optimistic" in rec["fitted_on"]


def test_recommended_threshold_needs_both_classes():
    assert _recommended_threshold([0] * 50, [0.1] * 50, 0.1) is None
    assert _recommended_threshold([1] * 50, [0.1] * 50, 0.1) is None


def test_recommended_threshold_needs_both_classes():
    assert _recommended_threshold([0] * 50, [0.1] * 50, 0.1) is None
    assert _recommended_threshold([1] * 50, [0.1] * 50, 0.1) is None
