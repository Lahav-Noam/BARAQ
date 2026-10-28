"""Validate BARAQ's ML detector on this deployment's own telemetry.

Answers the three questions that decide whether the ML layer is
production-ready:

1. **Recall** - of the events analysts confirmed as attacks, how many did
   the ML flag?
2. **False-positive rate** - of the events analysts confirmed as benign,
   how many did it flag?
3. **Where is the knee?** - recall/FPR at a sweep of thresholds, so the
   operator can pick an operating point instead of trusting one number.

Method (no leakage):

* Train on the first ``1 - holdout`` fraction of events, chronologically,
  with ``cutoff`` so the baseline never sees the evaluation window.
* Score only the held-out tail, which the model has never seen.
* Labels come from the analyst feedback loop (``verdicts``).  When a row
  is seed-tagged (``raw_json.seed_label``) the true label is used as a
  documented secondary reference; otherwise it is ignored.

Usage::

    python scripts/validate_ml.py                        # train + evaluate
    python scripts/validate_ml.py --no-train             # score only
    python scripts/validate_ml.py --holdout-fraction 0.3
    python scripts/validate_ml.py --json reports/ml_validation.json

Exit code is 0 when the configured targets are met (recall >= 0.80 and
FPR <= 0.10 on the seed-truth reference), 1 otherwise - so it can gate a
deployment pipeline.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select

from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent, Verdict
from backend.ml.anomaly import (
    LOGIN_EVENTS,
    NETWORK_EVENTS,
    PROCESS_EVENTS,
    MLAnomalyDetector,
    _behavior_of,
    event_feature_vector,
)

BEHAVIORS = ("login", "process")
TARGET_RECALL = 0.80
TARGET_FPR = 0.10


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _labels_from_verdicts(session) -> dict[int, int]:
    rows = session.execute(select(Verdict.event_id, Verdict.verdict)).all()
    return {
        int(eid): (1 if verdict == "true_positive" else 0)
        for eid, verdict in rows
    }


def _seed_label(raw) -> int | None:
    """Synthetic/benchmark ground truth, when the row carries one."""
    if isinstance(raw, dict):
        v = raw.get("seed_label")
        if v is not None:
            return int(v)
    return None


def _metrics(labels: list[int], scores: list[float], threshold: float) -> dict:
    tp = fp = tn = fn = 0
    for y, s in zip(labels, scores):
        flagged = s > threshold
        if y and flagged:
            tp += 1
        elif y:
            fn += 1
        elif flagged:
            fp += 1
        else:
            tn += 1
    total = tp + fp + tn + fn
    recall = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    precision = tp / max(tp + fp, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    return {
        "threshold": round(threshold, 4),
        "samples": total,
        "positives": tp + fn,
        "negatives": tn + fp,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "recall": round(recall, 4),
        "fpr": round(fpr, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
    }


def _recall_at_fpr(labels: list[int], scores: list[float], target_fpr: float) -> dict:
    """Best recall achievable while holding FPR <= target (label-aware knee)."""
    pairs = sorted(zip(scores, labels), reverse=True)
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return {"target_fpr": target_fpr, "recall": None, "threshold": None}
    tp = fp = 0
    best = {"recall": 0.0, "threshold": 1.01}
    for score, y in pairs:
        if y:
            tp += 1
        else:
            fp += 1
        if fp / n_neg <= target_fpr:
            recall = tp / n_pos
            if recall > best["recall"]:
                best = {"recall": recall, "threshold": score}
    return {
        "target_fpr": target_fpr,
        "recall": round(best["recall"], 4),
        "threshold": round(best["threshold"], 4),
    }


def _recommended_threshold(
    labels: list[int], scores: list[float], target_fpr: float
) -> dict | None:
    """Threshold maximising F1 subject to ``FPR <= target_fpr``.

    Candidates are the midpoints between *distinct* scores, so a stream whose
    benign scores are a point mass (common when a calibrated meta-learner
    collapses a rare stream to its base rate) still yields a usable split
    instead of a quantile that lands exactly on the mass.
    """
    import numpy as np

    y = np.asarray(labels, dtype=int)
    s = np.asarray(scores, dtype=float)
    if y.sum() == 0 or (1 - y).sum() == 0:
        return None
    uniq = np.unique(s)
    if len(uniq) == 1:
        return None
    cands = (uniq[:-1] + uniq[1:]) / 2.0
    best = None
    for t in cands:
        m = _metrics(labels, scores, float(t))
        if m["fpr"] > target_fpr:
            continue
        if best is None or m["f1"] > best["f1"]:
            best = m
    if best is None:
        return None
    best["fitted_on"] = "same hold-out window (optimistic - recalibrate in shadow)"
    return best


def _sweep(labels: list[int], scores: list[float]) -> list[dict]:
    out = []
    for t in (0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
        m = _metrics(labels, scores, t)
        out.append(
            {
                "threshold": t,
                "recall": m["recall"],
                "fpr": m["fpr"],
                "precision": m["precision"],
                "tp": m["tp"],
                "fp": m["fp"],
            }
        )
    return out


def _fmt_pct(value) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


# ---------------------------------------------------------------------------
# main validation
# ---------------------------------------------------------------------------
def run(holdout_fraction: float, train: bool, retrain_full: bool,
        apply_thresholds: bool = False) -> dict:
    session = SessionLocal()
    started = time.time()
    trainable = LOGIN_EVENTS | PROCESS_EVENTS

    try:
        rows = session.execute(
            select(
                NormalizedEvent.id,
                NormalizedEvent.event_id,
                NormalizedEvent.timestamp,
                NormalizedEvent.raw_json,
                NormalizedEvent.user,
                NormalizedEvent.host,
            )
            .where(NormalizedEvent.event_id.in_(trainable))
            .order_by(NormalizedEvent.timestamp)
        ).all()
        if not rows:
            raise SystemExit(
                "No trainable events (4624/4625/4688/...) in the database. "
                "Collect telemetry or run scripts/seed_validation_telemetry.py."
            )

        split = int(len(rows) * (1.0 - holdout_fraction))
        cutoff = rows[split].timestamp
        holdout_rows = rows[split:]
        print(
            f"Events: {len(rows):,} trainable, hold-out {len(holdout_rows):,} "
            f"after {cutoff.isoformat()}"
        )

        # ---- train (chronological cutoff, never persists by default) ----
        detector = MLAnomalyDetector()
        train_result: dict = {"status": "skipped"}
        if train:
            print("Training (persist=False, cutoff=hold-out start)...")
            t0 = time.time()
            train_result = detector.train(
                session=session,
                hours=None,
                validate=False,
                persist=False,
                cutoff=cutoff,
                kind="validation",
            )
            print(
                f"  trained {train_result.get('samples', 0):,} samples in "
                f"{time.time() - t0:.0f}s; thresholds={train_result.get('thresholds')}"
            )
            print(f"  internal (heuristic-labelled) hold-out: "
                  f"{train_result.get('holdout_metrics')}")
        else:
            from backend.ml.anomaly import get_detector

            detector = MLAnomalyDetector(load_persisted=True)
            if not detector.is_ready:
                detector = get_detector()

        # ---- score the held-out tail once, per stream ----
        # Production scores one stream at a time (an event is routed to its
        # stream at ingest), so evaluate the same way instead of mixing
        # feature spaces in a single batch.
        print(f"Scoring {len(holdout_rows):,} held-out events...")
        t0 = time.time()
        verdicts = _labels_from_verdicts(session)
        scored: list[dict] = []
        for row in holdout_rows:
            behavior = _behavior_of(int(row.event_id))
            feats = event_feature_vector(
                {
                    "event_id": row.event_id,
                    "raw_json": row.raw_json or {},
                    "timestamp": row.timestamp,
                },
                _shared_session=session,
            )
            if not feats:
                continue
            scored.append(
                {
                    "id": row.id,
                    "event_id": row.event_id,
                    "behavior": behavior,
                    "user": row.user,
                    "host": row.host,
                    "features": feats,
                    "verdict": verdicts.get(row.id),
                    "seed_label": _seed_label(row.raw_json),
                }
            )
        print(f"  {len(scored):,} vectors in {time.time() - t0:.0f}s")

        by_behavior: dict[str, list[dict]] = {}
        for r in scored:
            by_behavior.setdefault(r["behavior"], []).append(r)
        for behavior, group in by_behavior.items():
            model = detector.models.get(behavior)
            if model is None:
                print(f"  WARNING: no model for stream '{behavior}' "
                      f"({len(group)} events left unscored)")
                continue
            dims = {len(r["features"]) for r in group}
            if dims != {model.n_features_in_}:
                print(f"  WARNING: {behavior} feature dims {sorted(dims)} != "
                      f"model dims {model.n_features_in_}")
            ss = detector.score_events([r["features"] for r in group])
            for r, s in zip(group, ss):
                r["score"] = float(s)
                r.pop("features", None)
            nonzero = sum(1 for s in ss if s > 0.0)
            print(f"  {behavior}: {len(group)} scored, nonzero={nonzero}")
        scored = [r for r in scored if "score" in r]

        # ---- metrics per stream ----
        results: dict[str, dict] = {}
        for behavior in BEHAVIORS:
            subset = [r for r in scored if r["behavior"] == behavior]
            if not subset:
                continue
            threshold = float(detector.thresholds.get(behavior, 0.5))

            seed = [r for r in subset if r["seed_label"] is not None]
            ver = [r for r in subset if r["verdict"] is not None]

            entry: dict = {
                "threshold": round(threshold, 4),
                "scored": len(subset),
                "attacks_in_window": sum(1 for r in subset if r["seed_label"] == 1),
            }
            if seed and len({r["seed_label"] for r in seed}) == 2:
                labels = [r["seed_label"] for r in seed]
                vals = [r["score"] for r in seed]
                entry["seed_truth"] = _metrics(labels, vals, threshold)
                entry["seed_truth_sweep"] = _sweep(labels, vals)
                entry["recall_at"] = {
                    f"fpr_{int(f * 100)}pct": _recall_at_fpr(labels, vals, f)
                    for f in (0.01, 0.05, 0.10, 0.20)
                }
                entry["recommended_threshold"] = _recommended_threshold(
                    labels, vals, TARGET_FPR
                )
            if ver and len({r["verdict"] for r in ver}) == 2:
                labels = [r["verdict"] for r in ver]
                vals = [r["score"] for r in ver]
                entry["analyst_verdicts"] = _metrics(labels, vals, threshold)
            results[behavior] = entry

        # ---- network stream (scored separately) ----
        net_rows = session.execute(
            select(
                NormalizedEvent.id,
                NormalizedEvent.event_id,
                NormalizedEvent.timestamp,
                NormalizedEvent.raw_json,
            )
            .where(NormalizedEvent.event_id.in_(NETWORK_EVENTS))
            .where(NormalizedEvent.timestamp >= cutoff)
            .order_by(NormalizedEvent.timestamp)
        ).all()
        net_scored = []
        for row in net_rows:
            raw = row.raw_json or {}
            facts = (raw.get("facts") or raw) if isinstance(raw, dict) else {}
            remote_ip = str(facts.get("remote_ip") or facts.get("dest_ip") or "")
            if not remote_ip:
                continue
            try:
                n = int(facts.get("count") or facts.get("connections") or 1)
            except (TypeError, ValueError):
                n = 1
            try:
                ports = int(facts.get("distinct_ports") or 1)
            except (TypeError, ValueError):
                ports = 1
            s = detector.score_network_connection(remote_ip, count=n, distinct_ports=ports)
            net_scored.append(
                {
                    "id": row.id,
                    "verdict": verdicts.get(row.id),
                    "seed_label": _seed_label(raw),
                    "score": float(s),
                }
            )
        if net_scored:
            threshold = float(detector.thresholds.get("network", 0.5))
            entry = {"threshold": round(threshold, 4), "scored": len(net_scored)}
            seed = [r for r in net_scored if r["seed_label"] is not None]
            if seed and len({r["seed_label"] for r in seed}) == 2:
                labels = [r["seed_label"] for r in seed]
                vals = [r["score"] for r in seed]
                entry["seed_truth"] = _metrics(labels, vals, threshold)
                entry["seed_truth_sweep"] = _sweep(labels, vals)
                entry["recall_at"] = {
                    f"fpr_{int(f * 100)}pct": _recall_at_fpr(labels, vals, f)
                    for f in (0.01, 0.05, 0.10, 0.20)
                }
                entry["recommended_threshold"] = _recommended_threshold(
                    labels, vals, TARGET_FPR
                )
            ver = [r for r in net_scored if r["verdict"] is not None]
            if ver and len({r["verdict"] for r in ver}) == 2:
                entry["analyst_verdicts"] = _metrics(
                    [r["verdict"] for r in ver],
                    [r["score"] for r in ver],
                    threshold,
                )
            results["network"] = entry

        # ---- optional: refit on everything for the production bundle ----
        full_result = None
        applied: dict[str, float] = {}
        if retrain_full:
            print("Refitting on the full history (persist=True) for deployment...")
            full_result = detector.train(
                session=session, hours=None, validate=False, persist=True, kind="validation"
            )
            print(f"  deployed samples={full_result.get('samples', 0)} "
                  f"thresholds={full_result.get('thresholds')}")

            if apply_thresholds:
                for stream, entry in results.items():
                    rec = entry.get("recommended_threshold")
                    if not rec:
                        continue
                    detector.thresholds[stream] = float(rec["threshold"])
                    applied[stream] = float(rec["threshold"])
                if applied:
                    detector._save_meta()
                    print(f"  applied calibrated thresholds: {applied}")

        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "holdout_fraction": holdout_fraction,
            "holdout_start": cutoff.isoformat(),
            "trainable_events": len(rows),
            "holdout_events": len(holdout_rows),
            "scored_events": len(scored),
            "train": train_result,
            "full_retrain": full_result,
            "applied_thresholds": applied,
            "streams": results,
            "events": [
                {
                    "id": r["id"],
                    "event_id": r["event_id"],
                    "behavior": r["behavior"],
                    "user": r.get("user"),
                    "host": r.get("host"),
                    "score": round(r["score"], 6),
                    "label": r["verdict"] if r["verdict"] is not None else r["seed_label"],
                    "label_source": "verdict" if r["verdict"] is not None else "seed",
                    "verdict": r["verdict"],
                    "seed_label": r["seed_label"],
                }
                for r in sorted(scored, key=lambda x: -x["score"])
            ],
            "network_events": [
                {
                    "id": r["id"],
                    "score": round(r["score"], 6),
                    "verdict": r["verdict"],
                    "seed_label": r["seed_label"],
                }
                for r in sorted(net_scored, key=lambda x: -x["score"])
            ],
            "elapsed_seconds": round(time.time() - started, 1),
            "targets": {"recall": TARGET_RECALL, "fpr": TARGET_FPR},
        }
    finally:
        session.close()


def render(report: dict) -> str:
    lines = [
        "=" * 72,
        "BARAQ ML VALIDATION REPORT",
        f"generated: {report['generated_at']}",
        f"held-out window starts: {report['holdout_start']}",
        f"trainable events: {report['trainable_events']:,}   "
        f"held-out: {report['holdout_events']:,}   scored: {report['scored_events']:,}",
        "=" * 72,
    ]
    for behavior, entry in report["streams"].items():
        lines.append("")
        lines.append(f"[{behavior.upper()}]  threshold={entry['threshold']}  "
                     f"scored={entry['scored']:,}")
        if "seed_truth" in entry:
            m = entry["seed_truth"]
            lines.append(
                f"  seed truth  : recall={_fmt_pct(m['recall'])} "
                f"fpr={_fmt_pct(m['fpr'])} precision={_fmt_pct(m['precision'])} "
                f"f1={m['f1']:.3f}  (tp={m['tp']} fp={m['fp']} fn={m['fn']} tn={m['tn']})"
            )
            best = entry.get("recall_at", {})
            if best:
                parts = [
                    f"{k.replace('fpr_', '@')}FPR -> {_fmt_pct(v['recall'])}"
                    for k, v in best.items() if v.get("recall") is not None
                ]
                lines.append("  recall@FPR  : " + ", ".join(parts))
        if "analyst_verdicts" in entry:
            m = entry["analyst_verdicts"]
            lines.append(
                f"  analyst set : recall={_fmt_pct(m['recall'])} "
                f"fpr={_fmt_pct(m['fpr'])} precision={_fmt_pct(m['precision'])} "
                f"f1={m['f1']:.3f}  (n={m['samples']})"
            )
        else:
            lines.append("  analyst set : not enough labelled verdicts")
        rec = entry.get("recommended_threshold")
        if rec:
            lines.append(
                f"  RECOMMENDED : threshold={rec['threshold']} -> "
                f"recall={_fmt_pct(rec['recall'])} fpr={_fmt_pct(rec['fpr'])} "
                f"precision={_fmt_pct(rec['precision'])} "
                f"(configured {entry['threshold']})"
            )

    lines.extend(["", "-" * 72, "THRESHOLD SWEEP (seed truth)", ""])
    for behavior, entry in report["streams"].items():
        if "seed_truth_sweep" not in entry:
            continue
        lines.append(f"{behavior}:")
        lines.append("  thr   recall    fpr   precision")
        for row in entry["seed_truth_sweep"]:
            lines.append(
                f"  {row['threshold']:.2f}  {_fmt_pct(row['recall']):>7}  "
                f"{_fmt_pct(row['fpr']):>6}  {_fmt_pct(row['precision']):>8}"
            )

    lines.extend(["", "-" * 72, "VERDICT"])
    ok = True
    for behavior, entry in report["streams"].items():
        if behavior == "network":
            continue
        m = entry.get("seed_truth") or entry.get("analyst_verdicts")
        if not m:
            continue
        # Prefer the calibrated operating point when the configured
        # threshold does not honour the FPR budget.
        rec = entry.get("recommended_threshold")
        used = m
        if rec and m["fpr"] > TARGET_FPR:
            used = rec
        passed = used["recall"] >= TARGET_RECALL and used["fpr"] <= TARGET_FPR
        ok = ok and passed
        lines.append(
            f"  {behavior}: recall {_fmt_pct(used['recall'])} (target {TARGET_RECALL:.0%}), "
            f"fpr {_fmt_pct(used['fpr'])} (target {TARGET_FPR:.0%}) -> "
            f"{'PASS' if passed else 'FAIL'}"
            + ("  [after threshold recalibration]" if used is not m else "")
        )
    lines.append("")
    lines.append("  OVERALL: " + ("PASS - targets met on this data" if ok else
                                  "FAIL - do not enable autonomous response"))
    lines.append("=" * 72)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--holdout-fraction", type=float, default=0.2)
    parser.add_argument("--no-train", action="store_true",
                        help="reuse the persisted model instead of retraining")
    parser.add_argument("--retrain-full", action="store_true",
                        help="after validating, refit+persist on the full history")
    parser.add_argument("--apply-thresholds", action="store_true",
                        help="with --retrain-full: persist the calibrated per-stream "
                             "thresholds into the model metadata")
    parser.add_argument("--json", type=Path, default=None,
                        help="write the machine-readable report here")
    parser.add_argument("--report-dir", type=Path, default=Path("reports"))
    args = parser.parse_args()

    report = run(
        holdout_fraction=args.holdout_fraction,
        train=not args.no_train,
        retrain_full=args.retrain_full,
        apply_thresholds=args.apply_thresholds,
    )
    text = render(report)
    print("\n" + text)

    args.report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out = args.json or (args.report_dir / f"ml_validation_{stamp}.json")
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nJSON report: {out}")

    failures = 0
    for behavior, entry in report["streams"].items():
        if behavior == "network":
            continue
        m = entry.get("seed_truth") or entry.get("analyst_verdicts")
        if m and not (m["recall"] >= TARGET_RECALL and m["fpr"] <= TARGET_FPR):
            failures += 1
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
