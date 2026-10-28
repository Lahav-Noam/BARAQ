#!/usr/bin/env python3
"""Score a candidate BOTSv1 bundle over the full benchmark and report metrics."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path('datasets/botsv1_bench')


def metrics(y, s, thr):
    y = np.asarray(y).astype(int)
    s = np.asarray(s, dtype=float)
    pred = s >= thr
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    tn = int((~pred & (y == 0)).sum())
    p = tp / max(tp + fp, 1)
    r = tp / max(tp + fn, 1)
    return {
        'n': int(len(y)), 'pos': int(y.sum()), 'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'precision': float(p), 'recall': float(r),
        'f1': float(2 * p * r / max(p + r, 1e-12)),
        'fpr': float(fp / max(fp + tn, 1)), 'threshold': float(thr),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bundle', default='database/model.bundle.botsv1_bench.joblib')
    ap.add_argument('--threshold', type=float, required=True)
    ap.add_argument('--out', default=str(ROOT / 'candidate_scores.npy'))
    args = ap.parse_args()

    d = np.load(ROOT / 'features.npz', allow_pickle=True)
    X = d['X']
    meta = pd.read_pickle(ROOT / 'meta.pkl')
    bundle = joblib.load(args.bundle)
    from backend.ml.anomaly import MLAnomalyDetector
    det = MLAnomalyDetector()
    det.models = bundle['models']
    det.supervised = bundle.get('supervised')
    det.supervised_by_stream = bundle.get('supervised_by_stream') or {}
    det.thresholds = bundle.get('thresholds') or {}
    det.baselines = {k: np.asarray(v, dtype=float) for k, v in (bundle.get('baselines') or {}).items()}
    det.ensembles = {}
    det.ensemble = None
    model = det.models['network']
    scores = np.empty(len(X), dtype=float)
    for i in range(0, len(X), 50000):
        scores[i:i + 50000] = det._combined_score_batch(
            'network', model, X[i:i + 50000].tolist())
    np.save(args.out, scores)

    y = (meta.label == 1).to_numpy()
    slices = {
        'all': np.ones(len(meta), bool),
        'botsv1': (meta.dataset == 'botsv1').to_numpy(),
        'botsv1_bg': ((meta.dataset == 'botsv1') & (y == 0)),
        'local': (meta.dataset == 'local').to_numpy(),
        'A': ((meta.dataset == 'botsv1') & (meta.campaign == 'A')).to_numpy(),
        'B': ((meta.dataset == 'botsv1') & (meta.campaign == 'B')).to_numpy(),
        'hardneg_A': ((meta.dataset == 'botsv1') & (y == 0) & (meta.window == 'A')).to_numpy(),
        'hardneg_B': ((meta.dataset == 'botsv1') & (y == 0) & (meta.window == 'B')).to_numpy(),
    }
    out = {'bundle': args.bundle, 'threshold': args.threshold, 'slices': {}}
    for name, mask in slices.items():
        m = metrics(y[mask], scores[mask], args.threshold)
        out['slices'][name] = m
        print(f'{name:12s} n={m["n"]:7d} pos={m["pos"]:6d} TP={m["tp"]:6d} '
              f'FP={m["fp"]:7d} FN={m["fn"]:6d} P={m["precision"]:.5f} '
              f'R={m["recall"]:.5f} F1={m["f1"]:.5f} FPR={m["fpr"]:.6f}')
    Path(args.out).with_suffix('.json').write_text(json.dumps(out, indent=2))


if __name__ == '__main__':
    main()
