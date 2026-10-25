"""Tests for the conservative ML deployment gate."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "ml_deployment_gate", ROOT / "scripts" / "ml_deployment_gate.py"
)
assert _SPEC is not None and _SPEC.loader is not None
_GATE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_GATE)


def _evidence(**overrides):
    evidence = {
        "model_version": 121,
        "feature_version": 7,
        "local_fpr": 0.005,
        "background_fpr": 0.005,
        "s2_b_recall": 0.80,
        "s3_a_recall": 0.60,
        "s4_b_recall": 0.90,
        "independent_campaign": True,
        "contemporaneous_benign": True,
        "strict_temporal_split": True,
        "causal_features": True,
        "local_attack_positives": 1,
        "feature_availability_audit": True,
        "single_feature_baseline_check": True,
        "feature_artifact_audit": True,
        "model_f1": 0.80,
        "best_single_feature_f1": 0.50,
    }
    evidence.update(overrides)
    return evidence


def _bundle(tmp_path):
    bundle = tmp_path / "model.bundle.joblib"
    bundle.write_bytes(b"not-a-real-bundle")
    return bundle


def test_missing_evidence_stays_shadow(tmp_path):
    manifest = _GATE.evaluate({}, {"version": 121, "feature_version": 7}, _bundle(tmp_path))
    assert manifest["status"] == "shadow"
    assert manifest["mode"] == "shadow"
    assert "No deployment evidence" in manifest["blocking_reasons"][0]


def test_complete_evidence_can_validate(tmp_path):
    manifest = _GATE.evaluate(
        _evidence(), {"version": 121, "feature_version": 7}, _bundle(tmp_path)
    )
    assert manifest["status"] == "validated"
    assert manifest["blocking_reasons"] == []


def test_single_feature_rule_blocks_promotion(tmp_path):
    manifest = _GATE.evaluate(
        _evidence(best_single_feature_f1=0.95),
        {"version": 121, "feature_version": 7},
        _bundle(tmp_path),
    )
    assert manifest["status"] == "shadow"
    assert any("single-feature" in reason for reason in manifest["blocking_reasons"])


def test_model_or_feature_version_mismatch_blocks_promotion(tmp_path):
    manifest = _GATE.evaluate(
        _evidence(model_version=122, feature_version=8),
        {"version": 121, "feature_version": 7},
        _bundle(tmp_path),
    )
    assert manifest["status"] == "shadow"
    joined = "\n".join(manifest["blocking_reasons"])
    assert "model v122" in joined
    assert "feature v8" in joined


def test_feature_artifact_audit_is_required(tmp_path):
    manifest = _GATE.evaluate(
        _evidence(feature_artifact_audit=False),
        {"version": 121, "feature_version": 7},
        _bundle(tmp_path),
    )
    assert manifest["status"] == "shadow"
    assert any("artifact" in reason for reason in manifest["blocking_reasons"])
