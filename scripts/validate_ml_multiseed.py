"""Run the ML validation harness over several corpus seeds and aggregate.

A single synthetic draw cannot tell you whether a recall number is a property
of the detector or of that one campaign ordering. This driver re-seeds the
corpus, reruns the chronological train/score harness, and reports the spread
plus a pooled Wilson interval for every stream.

Example::

    python scripts/validate_ml_multiseed.py --seeds 1,2,3 --hard-mode

The corpus is *synthetic*. A tight interval here means "the detector behaves
consistently on this generator", not "the detector generalises to your estate";
real labelled telemetry remains mandatory before trusting the numbers.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # allow `python scripts/...` from the repo root
    sys.path.insert(0, str(ROOT))

from scripts.seed_validation_telemetry import build_dataset, insert  # noqa: E402
from scripts.validate_ml import run as run_validation  # noqa: E402

STREAMS = ("login", "process", "network")


def wilson_interval(successes: int, trials: int, z: float = 1.96) -> list[float]:
    """95 % Wilson score interval for a proportion (better than normal approx.)."""
    if trials <= 0:
        return [0.0, 0.0]
    phat = successes / trials
    denom = 1.0 + z * z / trials
    centre = (phat + z * z / (2 * trials)) / denom
    margin = (
        z * math.sqrt(phat * (1 - phat) / trials + z * z / (4 * trials * trials)) / denom
    )
    return [round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4)]


def _summary(values: list[float]) -> dict:
    if not values:
        return {"n": 0, "mean": None, "min": None, "max": None}
    return {
        "n": len(values),
        "mean": round(sum(values) / len(values), 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
    }


def aggregate(per_seed: list[dict]) -> dict:
    agg: dict = {}
    for stream in STREAMS:
        entries = [s["streams"].get(stream) for s in per_seed]
        entries = [e for e in entries if e]
        if not entries:
            continue
        block: dict = {"seeds": len(entries)}

        truth = [e.get("seed_truth") for e in entries if e.get("seed_truth")]
        if truth:
            tp = sum(m["tp"] for m in truth)
            fp = sum(m["fp"] for m in truth)
            fn = sum(m["fn"] for m in truth)
            tn = sum(m["tn"] for m in truth)
            block["configured"] = {
                "recall": _summary([m["recall"] for m in truth]),
                "fpr": _summary([m["fpr"] for m in truth]),
                "pooled_recall": round(tp / max(tp + fn, 1), 4),
                "pooled_recall_ci95": wilson_interval(tp, tp + fn),
                "pooled_fpr": round(fp / max(fp + tn, 1), 4),
                "pooled_fpr_ci95": wilson_interval(fp, fp + tn),
            }

        recs = [e["recommended_threshold"] for e in entries if e.get("recommended_threshold")]
        if recs:
            tp = sum(m["tp"] for m in recs)
            fp = sum(m["fp"] for m in recs)
            fn = sum(m["fn"] for m in recs)
            tn = sum(m["tn"] for m in recs)
            block["recommended"] = {
                "recall": _summary([m["recall"] for m in recs]),
                "fpr": _summary([m["fpr"] for m in recs]),
                "pooled_recall": round(tp / max(tp + fn, 1), 4),
                "pooled_recall_ci95": wilson_interval(tp, tp + fn),
                "pooled_fpr": round(fp / max(fp + tn, 1), 4),
                "pooled_fpr_ci95": wilson_interval(fp, fp + tn),
            }

        health = [e["score_health"] for e in entries if e.get("score_health")]
        if health:
            block["degenerate_seeds"] = sum(1 for h in health if h["degenerate"])
            block["distinct_benign_scores"] = _summary(
                [float(h["distinct_benign_scores"]) for h in health]
            )
        agg[stream] = block
    return agg


def render(report: dict) -> str:
    lines = [
        "=" * 72,
        "BARAQ ML MULTI-SEED VALIDATION",
        f"seeds: {report['seeds']}   hard_mode: {report['hard_mode']}",
        f"hold-out fraction: {report['holdout_fraction']:.0%}   "
        f"elapsed: {report['elapsed_seconds']:.0f}s",
        "=" * 72,
    ]
    for stream, block in report["aggregated"].items():
        lines.append("")
        lines.append(f"[{stream.upper()}] across {block['seeds']} seed(s)")
        cfg = block.get("configured")
        rec = block.get("recommended")
        if cfg:
            lines.append(
                f"  configured threshold : recall {cfg['pooled_recall']:.1%}"
                f" {cfg['pooled_recall_ci95']}  fpr {cfg['pooled_fpr']:.1%}"
                f" {cfg['pooled_fpr_ci95']}"
            )
            lines.append(
                f"    per-seed recall {cfg['recall']['min']:.1%}-"
                f"{cfg['recall']['max']:.1%} (mean {cfg['recall']['mean']:.1%})"
            )
        if rec:
            lines.append(
                f"  recalibrated         : recall {rec['pooled_recall']:.1%}"
                f" {rec['pooled_recall_ci95']}  fpr {rec['pooled_fpr']:.1%}"
                f" {rec['pooled_fpr_ci95']}"
            )
            lines.append(
                f"    per-seed recall {rec['recall']['min']:.1%}-"
                f"{rec['recall']['max']:.1%} (mean {rec['recall']['mean']:.1%})"
            )
        elif block.get("degenerate_seeds") == block.get("seeds"):
            lines.append(
                "  recalibrated         : none - degenerate scores, no usable "
                "operating point"
            )
        if "degenerate_seeds" in block:
            lines.append(
                f"  score health         : {block['degenerate_seeds']}/{block['seeds']} "
                f"seeds degenerate (benign point mass), "
                f"distinct benign scores {block['distinct_benign_scores']['min']:.0f}-"
                f"{block['distinct_benign_scores']['max']:.0f}"
            )
    lines.extend(
        [
            "",
            "-" * 72,
            "Synthetic corpus only. Tight intervals mean the detector is",
            "consistent on this generator; they are not evidence about real",
            "telemetry.",
            "=" * 72,
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", default="1,2,3")
    parser.add_argument("--days", type=int, default=35)
    parser.add_argument("--users", type=int, default=20)
    parser.add_argument("--holdout-fraction", type=float, default=0.2)
    parser.add_argument("--hard-mode", action="store_true")
    parser.add_argument("--out", type=Path, default=Path("reports/ml_multiseed.json"))
    args = parser.parse_args()

    seeds = [int(s) for s in args.seeds.split(",") if s.strip()]
    started = time.time()
    per_seed: list[dict] = []

    for seed in seeds:
        print(f"\n=== seed {seed} ===")
        events, attack_ids, _ = build_dataset(
            days=args.days, users=args.users, seed=seed, hard_mode=args.hard_mode
        )
        insert(events, seed=seed)
        print(f"  corpus: {len(events):,} events, {len(attack_ids):,} attacks")
        report = run_validation(args.holdout_fraction, train=True, retrain_full=False)
        report["seed"] = seed
        per_seed.append(report)

    finished = time.time()
    report = {
        "seeds": seeds,
        "hard_mode": bool(args.hard_mode),
        "days": args.days,
        "users": args.users,
        "holdout_fraction": args.holdout_fraction,
        "elapsed_seconds": round(finished - started, 1),
        "aggregated": aggregate(per_seed),
        "per_seed": [
            {
                "seed": r["seed"],
                "streams": {
                    name: {
                        "seed_truth": r["streams"][name].get("seed_truth"),
                        "recommended_threshold": r["streams"][name].get("recommended_threshold"),
                        "score_health": r["streams"][name].get("score_health"),
                    }
                    for name in STREAMS
                    if name in r["streams"]
                },
            }
            for r in per_seed
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\n" + render(report))
    print(f"\nJSON report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
