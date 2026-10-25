#!/usr/bin/env python3
"""Build a separate candidate bundle from a BOTSv1 benchmark run.

This never overwrites the live bundle. Promotion is a deliberate, separate
copy step after the holdout report is reviewed.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path('datasets/botsv1_bench')
RESULTS = ROOT / 'results'
sys.path.insert(0, 'scripts')
from bench_botsv1_splits import split_cross, split_s1  # noqa: E402
from backend.ml.anomaly import ML_FEATURE_VERSION, MLAnomalyDetector  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--scenario', required=True, choices=['S1', 'S2', 'S3'])
    ap.add_argument('--tag', required=True, help='e.g. S1_v1')
    ap.add_argument('--threshold', type=float, required=True)
    ap.add_argument('--supervised-name', default='xgboost+platt')
    ap.add_argument('--out', default='database/model.bundle.botsv1_bench.joblib')
    ap.add_argument('--meta-out', default='database/model_meta.botsv1_bench.json')
    args = ap.parse_args()

    d = np.load(ROOT / 'features.npz', allow_pickle=True)
    X = d['X']
    meta = pd.read_pickle(ROOT / 'meta.pkl')
    y = (meta.label == 1).to_numpy().astype(int)
    split = split_s1(meta) if args.scenario == 'S1' else split_cross(
        meta, 'A_to_B' if args.scenario == 'S2' else 'B_to_A')
    meta = meta.copy()
    meta['split'] = split
    tr = (meta.split == 'train').to_numpy()

    if_model = joblib.load(RESULTS / f'{args.tag}_if.joblib')
    sup = joblib.load(RESULTS / f'{args.tag}_sup.joblib')

    btr = np.where(tr & (y == 0))[0]
    loc = np.where(tr & (y == 0) & (meta.dataset == 'local').to_numpy())[0]
    if len(loc):
        btr = np.concatenate([btr, np.tile(loc, 9)])
    rawb = np.clip(0.5 - if_model.decision_function(X[btr]), 0.0, 1.0)
    baseline = np.sort(rawb)

    bundle = {
        'feature_version': ML_FEATURE_VERSION,
        'models': {'network': if_model},
        'encoders': {},
        'supervised': sup,
        'supervised_name': args.supervised_name,
        'supervised_by_stream': {'network': sup},
        'supervised_name_by_stream': {'network': args.supervised_name},
        'thresholds': {'login': 0.5, 'process': 0.5, 'network': float(args.threshold)},
        'baselines': {'network': baseline.tolist()},
        'version': 1,
        'feedback_weights': {},
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out)

    meta_out = {
        'trained_at': datetime.now(timezone.utc).isoformat(),
        'n_samples': int(len(btr)),
        'events_at_train': 0,
        'supervised': args.supervised_name,
        'thresholds': bundle['thresholds'],
        'feature_version': ML_FEATURE_VERSION,
        'version': 1,
        'train_kind': 'botsv1_bench',
        'train_scenario': args.scenario,
        'train_tag': args.tag,
        'benchmark_db': 'baraq_ml_bench',
        'dataset': 'BOTSv1 Sysmon + local benign hard negatives',
        'feedback_weights': {},
    }
    Path(args.meta_out).write_text(json.dumps(meta_out, indent=2))

    # Sanity check: the candidate bundle must reproduce the saved blend scores.
    scores_path = RESULTS / f'{args.tag}_scores.npz'
    if scores_path.exists():
        saved = np.load(scores_path)
        te = (meta.split == 'test').to_numpy()
        det = MLAnomalyDetector()
        det.models = bundle['models']
        det.supervised = bundle['supervised']
        det.supervised_by_stream = bundle['supervised_by_stream']
        det.thresholds = bundle['thresholds']
        det.baselines = {'network': baseline}
        det.ensembles = {}
        det.ensemble = None
        actual = np.asarray(det._combined_score_batch(
            'network', if_model, X[te].tolist()))
        expected = saved['blend_test']
        diff = float(np.max(np.abs(actual - expected)))
        print(f'bundle -> {out}')
        print(f'metadata -> {args.meta_out}')
        print(f'baseline length {len(baseline):,}')
        print(f'max |bundle - saved blend_test| = {diff:.3e}')
        if diff > 1e-6:
            raise SystemExit('candidate bundle does not reproduce saved scores')
    else:
        print(f'bundle -> {out}')
        print(f'metadata -> {args.meta_out}')


if __name__ == '__main__':
    main()
