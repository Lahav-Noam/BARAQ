#!/usr/bin/env python3
"""Build the ML deployment manifest from explicit evaluation evidence.

The gate is intentionally conservative.  A missing or incomplete evidence
file produces a ``shadow`` manifest, not a promotion.  Only evidence that
explicitly covers a genuinely independent campaign, contemporaneous benign
traffic, a local false-positive estimate, and a single-feature baseline can
reach ``status: validated``.

Usage::

    PYTHONPATH=. .venv/bin/python scripts/ml_deployment_gate.py
    PYTHONPATH=. .venv/bin/python scripts/ml_deployment_gate.py \
        --evidence datasets/botsv1_bench/results/deployment_evidence.json --write

The output defaults to ``database/model_manifest.json``.  The live model
bundle and metadata are never modified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE = ROOT / "database" / "model.bundle.joblib"
DEFAULT_META = ROOT / "database" / "model_meta.json"
DEFAULT_OUT = ROOT / "database" / "model_manifest.json"

#: Minimum evidence before a model may leave shadow mode.  These are
#: deliberately not "best effort" thresholds.
CRITERIA: dict[str, Any] = {
    "max_local_fpr": 0.01,
    "max_background_fpr": 0.01,
    "min_cross_campaign_recall": 0.50,
    "required_scenarios": ["S2", "S3", "S4"],
    "required_local_attack_positives": 1,
    "require_independent_campaign": True,
    "require_contemporaneous_benign": True,
    "require_strict_temporal_split": True,
    "require_causal_features": True,
    "require_single_feature_baseline_check": True,
    "require_feature_availability_audit": True,
    "require_feature_artifact_audit": True,
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def _load_json(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text())
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def _num(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def evaluate(evidence: dict, meta: dict, bundle: Path) -> dict:
    blockers: list[str] = []
    notes: list[str] = []
    model_version = int(meta.get("version", 0) or 0)
    feature_version = int(meta.get("feature_version", 0) or 0)
    ev_version = int(evidence.get("model_version", model_version) or 0)
    ev_feature = int(evidence.get("feature_version", feature_version) or 0)

    if ev_version != model_version:
        blockers.append(
            f"Evidence is for model v{ev_version}, loaded metadata is v{model_version}."
        )
    if ev_feature != feature_version:
        blockers.append(
            f"Evidence uses feature v{ev_feature}, loaded model uses v{feature_version}."
        )
    if not evidence:
        blockers.append(
            "No deployment evidence file was supplied; the loaded model has no "
            "campaign-held-out validation in this repository."
        )
        notes.append("Default status is shadow-only. This is the current v121 state.")

    local_fpr = _num(evidence.get("local_fpr"))
    background_fpr = _num(evidence.get("background_fpr"))
    s2_recall = _num(evidence.get("s2_b_recall"))
    s3_recall = _num(evidence.get("s3_a_recall"))
    s4_recall = _num(evidence.get("s4_b_recall"))

    if local_fpr is None:
        blockers.append("Missing local benign false-positive rate.")
    elif local_fpr > CRITERIA["max_local_fpr"]:
        blockers.append(
            f"Local FPR {local_fpr:.4f} exceeds {CRITERIA['max_local_fpr']:.4f}."
        )
    if background_fpr is None:
        blockers.append("Missing BOTSv1 background false-positive rate.")
    elif background_fpr > CRITERIA["max_background_fpr"]:
        blockers.append(
            f"Background FPR {background_fpr:.4f} exceeds "
            f"{CRITERIA['max_background_fpr']:.4f}."
        )
    for name, value, label in [
        ("S2", s2_recall, "S2 A->B recall"),
        ("S3", s3_recall, "S3 B->A recall"),
    ]:
        if value is None:
            blockers.append(f"Missing {label}.")
        elif value < CRITERIA["min_cross_campaign_recall"]:
            blockers.append(
                f"{label} {value:.4f} is below "
                f"{CRITERIA['min_cross_campaign_recall']:.4f}."
            )
    if s4_recall is None:
        blockers.append("Missing S4 time-forward recall.")
    elif s4_recall < CRITERIA["min_cross_campaign_recall"]:
        blockers.append(
            f"S4 time-forward recall {s4_recall:.4f} is below "
            f"{CRITERIA['min_cross_campaign_recall']:.4f}."
        )

    if evidence.get("independent_campaign") is not True:
        blockers.append(
            "No genuinely independent campaign was supplied; BOTSv1 A/B alone "
            "cannot establish zero-shot generalization."
        )
    if evidence.get("contemporaneous_benign") is not True:
        blockers.append(
            "No contemporaneous benign traffic from the same hosts/time window."
        )
    if evidence.get("strict_temporal_split") is not True:
        blockers.append("Strict time-forward/campaign-held-out split is missing.")
    if evidence.get("causal_features") is not True:
        blockers.append("Causal feature audit is missing.")
    if int(evidence.get("local_attack_positives", 0) or 0) < CRITERIA[
        "required_local_attack_positives"
    ]:
        blockers.append(
            "No local attack positives; local recall is unproven."
        )
    if evidence.get("feature_availability_audit") is not True:
        blockers.append(
            "Feature-availability audit missing; benchmark features may not exist "
            "in the live network path."
        )
    if evidence.get("single_feature_baseline_check") is not True:
        blockers.append(
            "Single-feature baseline check missing; a trivial rule may explain the score."
        )
    else:
        model_f1 = _num(evidence.get("model_f1"))
        best_rule_f1 = _num(evidence.get("best_single_feature_f1"))
        if model_f1 is None or best_rule_f1 is None:
            blockers.append(
                "Single-feature baseline check is marked complete but model_f1/"
                "best_single_feature_f1 values are missing."
            )
        elif best_rule_f1 >= model_f1:
            blockers.append(
                "A single-feature rule matches or beats the model; the model "
                "adds no defensible signal."
            )

    if evidence.get("feature_artifact_audit") is not True:
        blockers.append(
            "Feature-artifact audit missing or failed (path/missing-value shortcut)."
        )

    status = "validated" if not blockers else "shadow"
    mode = "advisory" if status == "validated" else "shadow"
    return {
        "schema_version": 1,
        "status": status,
        "mode": mode,
        "generated_at": datetime.now(UTC).isoformat(),
        "model_version": model_version,
        "feature_version": feature_version,
        "bundle_sha256": _sha256(bundle),
        "evidence_source": str(evidence.get("_source", "")),
        "criteria": CRITERIA,
        "evaluation": {
            "local_fpr": local_fpr,
            "background_fpr": background_fpr,
            "s2_b_recall": s2_recall,
            "s3_a_recall": s3_recall,
            "s4_b_recall": s4_recall,
            "independent_campaign": bool(evidence.get("independent_campaign")),
            "contemporaneous_benign": bool(
                evidence.get("contemporaneous_benign")
            ),
            "strict_temporal_split": bool(
                evidence.get("strict_temporal_split")
            ),
            "causal_features": bool(evidence.get("causal_features")),
            "local_attack_positives": int(
                evidence.get("local_attack_positives", 0) or 0
            ),
            "single_feature_baseline_check": bool(
                evidence.get("single_feature_baseline_check")
            ),
            "feature_availability_audit": bool(
                evidence.get("feature_availability_audit")
            ),
            "feature_artifact_audit": bool(
                evidence.get("feature_artifact_audit")
            ),
        },
        "blocking_reasons": blockers,
        "notes": notes,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", type=Path, default=None)
    ap.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    ap.add_argument("--meta", type=Path, default=DEFAULT_META)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    meta = _load_json(args.meta)
    evidence = _load_json(args.evidence) if args.evidence else {}
    if args.evidence:
        evidence["_source"] = str(args.evidence)
    manifest = evaluate(evidence, meta, args.bundle)
    text = json.dumps(manifest, indent=2)
    print(text)
    if args.write:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(
            "(dry run; pass --write to update the deployment manifest)",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
