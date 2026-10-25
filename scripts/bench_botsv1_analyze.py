#!/usr/bin/env python3
"""Threshold-budget analysis for a trained BOTSv1 benchmark run.

Reports test metrics at several validation-only local false-positive budgets.
The validation split chooses the threshold; the test split is never used to
choose it.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path('datasets/botsv1_bench')
RESULTS = ROOT / 'results'
sys.path.insert(0, 'scripts')
from bench_botsv1_splits import split_cross, split_s1  # noqa: E402


def metrics(y: np.ndarray, s: np.ndarray, thr: float) -> dict:
    y = np.asarray(y).astype(int)
    s = np.asarray(s, dtype=float)
    pred = s >= thr
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    tn = int((~pred & (y == 0)).sum())
    p = tp / max(tp + fp, 1)
    r = tp / max(tp + fn, 1)
    f1 = 2 * p * r / max(p + r, 1e-12)
    out = dict(n=int(len(y)), pos=int(y.sum()), tp=tp, fp=fp, fn=fn, tn=tn,
               precision=float(p), recall=float(r), f1=float(f1),
               fpr=float(fp / max(fp + tn, 1)), threshold=float(thr))
    if len(set(y)) > 1:
        out['roc_auc'] = float(roc_auc_score(y, s))
        out['pr_auc'] = float(average_precision_score(y, s))
    else:
        out['roc_auc'] = None
        out['pr_auc'] = None
    return out


def choose_threshold(s_val, y_val, local_val, budget):
    """Maximize global validation F1 subject to local validation FPR <= budget."""
    vals = np.unique(np.concatenate([
        np.quantile(s_val, np.linspace(0.5, 0.9999, 800)),
        np.quantile(s_val[local_val], np.linspace(0.0, 1.0, 300)),
    ]))
    best = None
    for t in vals:
        lfp = int((s_val[local_val] >= t).sum())
        lfpr = lfp / max(int(local_val.sum()), 1)
        if lfpr > budget + 1e-12:
            continue
        m = metrics(y_val, s_val, t)
        # Tie-break toward a higher threshold (fewer local flags).
        key = (m['f1'], t)
        if best is None or key > best[0]:
            best = (key, float(t), m, lfpr)
    if best is not None:
        return best[1], best[2], best[3]
    t = float(s_val[local_val].max()) + 1e-9
    if t > 1.0:
        t = 1.0 + 1e-9
    return t, metrics(y_val, s_val, t), 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--scenario', required=True, choices=['S1', 'S2', 'S3'])
    ap.add_argument('--tag', required=True)
    ap.add_argument('--budgets', default='0,0.002,0.005,0.01,0.02,0.05')
    args = ap.parse_args()

    meta = pd.read_pickle(ROOT / 'meta.pkl')
    split = split_s1(meta) if args.scenario == 'S1' else split_cross(
        meta, 'A_to_B' if args.scenario == 'S2' else 'B_to_A')
    meta = meta.copy()
    meta['split'] = split
    y = (meta.label == 1).to_numpy().astype(int)
    val = (meta.split == 'val').to_numpy()
    test = (meta.split == 'test').to_numpy()
    local = (meta.dataset == 'local').to_numpy()
    bots = (meta.dataset == 'botsv1').to_numpy()
    local_val_full = val & local
    local_val = local_val_full[val]

    test_meta = meta.loc[test].reset_index(drop=True)
    y_test = y[test]
    bots_t = (test_meta.dataset == 'botsv1').to_numpy()
    local_t = (test_meta.dataset == 'local').to_numpy()
    bg_t = bots_t & (y_test == 0)
    A_t = (test_meta.campaign == 'A').to_numpy()
    B_t = (test_meta.campaign == 'B').to_numpy()
    hardneg_A_t = bg_t & (test_meta.window == 'A').to_numpy()
    hardneg_B_t = bg_t & (test_meta.window == 'B').to_numpy()

    d = np.load(RESULTS / f'{args.tag}_scores.npz')
    candidates = {
        'if': (d['if_val'], d['if_test']),
        'sup': (d['p_val'], d['p_test']),
        'blend': (d['blend_val'], d['blend_test']),
    }
    budgets = [float(x) for x in args.budgets.split(',') if x.strip()]
    report = {'scenario': args.scenario, 'tag': args.tag,
              'val_negatives': int((~y[val]).sum()),
              'val_local': int(local_val.sum()),
              'test_local': int(local_t.sum()), 'budgets': budgets}

    for name, (s_val, s_test) in candidates.items():
        entry = {'budget_results': {}}
        for budget in budgets:
            t, vm, vfpr = choose_threshold(s_val, y[val], local_val, budget)
            tm = {
                'all': metrics(y_test, s_test, t),
                'botsv1': metrics(y_test[bots_t], s_test[bots_t], t),
                'botsv1_bg': metrics(y_test[bg_t], s_test[bg_t], t),
                'local': metrics(y_test[local_t], s_test[local_t], t),
                'A': metrics(y_test[A_t], s_test[A_t], t),
                'B': metrics(y_test[B_t], s_test[B_t], t),
                'hardneg_A': metrics(y_test[hardneg_A_t], s_test[hardneg_A_t], t),
                'hardneg_B': metrics(y_test[hardneg_B_t], s_test[hardneg_B_t], t),
            }
            for k in ('A', 'B'):
                m = tm[k]
                if m['n']:
                    m['detected'] = bool(m['tp'] > 0)
            entry['budget_results'][str(budget)] = {
                'threshold': t, 'val_f1': vm['f1'], 'val_local_fpr': vfpr,
                'test': tm,
            }
            b = tm['B']
            l = tm['local']
            print(f'{args.tag} {name:5s} local_val_FPR<={budget:<6g} thr={t:.6f} '
                  f'val_F1={vm["f1"]:.4f} | test B recall={b["recall"]:.4f} '
                  f'B flagged={b["tp"]}/{b["pos"]} A recall={tm["A"]["recall"]:.4f} '
                  f'localFP={l["fp"]}/{l["n"]} bgFP={tm["botsv1_bg"]["fp"]} '
                  f'all_F1={tm["all"]["f1"]:.4f}')
        report[name] = entry

    out = RESULTS / f'{args.tag}_analysis.json'
    out.write_text(json.dumps(report, indent=2, default=str))
    print('wrote', out)

    # Flagged local test flows at the 1% local-FPR budget for the blend.
    if 'blend' in candidates:
        t, _, _ = choose_threshold(candidates['blend'][0], y[val], local_val, 0.01)
        s_test = candidates['blend'][1]
        flagged = test_meta.loc[local_t & (s_test >= t)].copy()
        flagged['score'] = s_test[local_t & (s_test >= t)]
        cols = [c for c in ['ts', 'host', 'image', 'dst_ip', 'dst_port', 'score'] if c in flagged.columns]
        flagged[cols].to_csv(RESULTS / f'{args.tag}_local_flags_fpr1.csv', index=False)
        print('local flags at 1% budget ->', RESULTS / f'{args.tag}_local_flags_fpr1.csv')


if __name__ == '__main__':
    main()
