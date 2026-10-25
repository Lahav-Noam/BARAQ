#!/usr/bin/env python3
"""Score the current live bundle on the BOTSv1 benchmark features."""
from __future__ import annotations
import json, time
from pathlib import Path
import joblib, numpy as np
from backend.ml.anomaly import MLAnomalyDetector

ROOT = Path('datasets/botsv1_bench')
def main():
    d = np.load(ROOT / 'features.npz', allow_pickle=True)
    X = d['X']
    b = joblib.load('database/model.bundle.joblib')
    det = MLAnomalyDetector()
    det.models = b['models']; det.supervised = b.get('supervised')
    det.supervised_by_stream = b.get('supervised_by_stream') or {}
    det.thresholds = b.get('thresholds') or {}; det.baselines = b.get('baselines') or {}
    det.ensembles = {}; det.ensemble = None
    m = det.models['network']; thr = float(det.thresholds.get('network', 0.5))
    print('features', m.n_features_in_, 'threshold', thr)
    scores = np.empty(len(X)); t = time.time()
    for i in range(0, len(X), 50000):
        scores[i:i + 50000] = det._combined_score_batch(
            'network', m, X[i:i + 50000].tolist())
    np.save(ROOT / 'live_scores.npy', scores)
    meta = json.load(open('database/model_meta.json'))
    (ROOT / 'live_model_meta.json').write_text(json.dumps(meta, indent=2))
    print('scored in', round(time.time() - t, 1), 's; version', meta.get('version'),
          'threshold', meta.get('thresholds', {}).get('network'))
    print('quantiles', np.quantile(scores, [0, .5, .9, .99, 1]))
if __name__ == '__main__':
    main()
