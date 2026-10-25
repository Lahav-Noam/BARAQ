#!/usr/bin/env python3
"""Train and evaluate improved BARAQ network models on the BOTSv1 benchmark.

Scenarios
---------
S1 : within-campaign holdout. Campaign B is held out by unseen destination IP;
     campaign A is held out by future time. Benign background is held out by
     time buckets; local live flows are held out by time.
S2 : leave-one-campaign-out A -> B (train on campaign A, test on campaign B).
S3 : leave-one-campaign-out B -> A (train on campaign B, test on campaign A).
"""
from __future__ import annotations
import argparse, json, sys, time
from pathlib import Path
import numpy as np, pandas as pd, joblib
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, average_precision_score, precision_recall_curve

ROOT = Path('datasets/botsv1_bench')
RESULTS = ROOT / 'results'
RESULTS.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, 'scripts')
from bench_botsv1_splits import split_s1, split_cross
from backend.ml.anomaly import MLAnomalyDetector

def rank_scores(raw, baseline):
    raw = np.asarray(raw, dtype=float)
    if baseline is None or len(baseline) == 0:
        return np.clip(raw, 0, 1)
    return np.clip(np.interp(raw, np.sort(baseline),
                             np.linspace(0, 1, len(baseline))), 0, 1)

def metrics(y, s, thr):
    y = np.asarray(y).astype(int); s = np.asarray(s, dtype=float)
    pred = s >= thr
    tp = int(((pred) & (y == 1)).sum()); fp = int(((pred) & (y == 0)).sum())
    fn = int(((~pred) & (y == 1)).sum()); tn = int(((~pred) & (y == 0)).sum())
    p = tp / max(tp + fp, 1); r = tp / max(tp + fn, 1)
    f1 = 2 * p * r / max(p + r, 1e-12); fpr = fp / max(fp + tn, 1)
    out = dict(n=int(len(y)), pos=int(y.sum()), tp=tp, fp=fp, fn=fn, tn=tn,
               precision=float(p), recall=float(r), f1=float(f1),
               fpr=float(fpr), threshold=float(thr))
    if len(set(y)) > 1:
        out['roc_auc'] = float(roc_auc_score(y, s))
        out['pr_auc'] = float(average_precision_score(y, s))
    else:
        out['roc_auc'] = None; out['pr_auc'] = None
    return out

def best_f1(y, s):
    prec, rec, ths = precision_recall_curve(y, s)
    f1 = 2 * prec * rec / np.maximum(prec + rec, 1e-12)
    i = int(np.nanargmax(f1[:-1])) if len(ths) else 0
    t = float(ths[i]) if len(ths) else 0.5
    return t, metrics(y, s, t)

def _fast_f1(y, s, t):
    """F1 and FPR support without re-sorting for AUC on every candidate."""
    pred = s >= t
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    tn = int((~pred & (y == 0)).sum())
    p = tp / max(tp + fp, 1)
    r = tp / max(tp + fn, 1)
    return 2 * p * r / max(p + r, 1e-12), fp / max(fp + tn, 1)


def best_with_local_fpr(y, s, local_mask, max_fpr=0.01):
    qs = np.unique(np.concatenate([
        np.quantile(s, np.linspace(0.50, 0.999, 600)),
        np.quantile(s[local_mask], np.linspace(0.0, 1.0, 300)),
        [float(s[local_mask].max()) + 1e-9],
    ]))
    qs = np.unique(np.clip(qs, 0, 1.0 + 1e-9))
    best = None
    for t in qs:
        f1, _ = _fast_f1(y, s, t)
        _, local_fpr = _fast_f1(y[local_mask], s[local_mask], t)
        if local_fpr <= max_fpr:
            if best is None or f1 > best[1]:
                best = (float(t), f1)
    if best is None:
        t, m = best_f1(y, s)
        return t, m, metrics(y[local_mask], s[local_mask], t)
    t = best[0]
    return t, metrics(y, s, t), metrics(y[local_mask], s[local_mask], t)

def evaluate_scores(name, scores, thr, meta, test_index=None):
    test = (meta.split == 'test').to_numpy()
    bots = (meta.dataset == 'botsv1').to_numpy()
    loc = (meta.dataset == 'local').to_numpy()
    y = (meta.label == 1).to_numpy()
    if test_index is not None:
        full = np.full(len(meta), -1.0)
        full[test_index] = np.asarray(scores)
        scores = full
    masks = {
        'test_all': test,
        'botsv1_all': test & bots,
        'botsv1_pos': test & bots & y,
        'botsv1_bg': test & bots & (~y),
        'local': test & loc,
        'A': test & (meta.campaign == 'A').to_numpy(),
        'B': test & (meta.campaign == 'B').to_numpy(),
        'hardneg_A': test & bots & (~y) & (meta.window == 'A').to_numpy(),
        'hardneg_B': test & bots & (~y) & (meta.window == 'B').to_numpy(),
    }
    res = {k: metrics(y[m], scores[m], thr) for k, m in masks.items() if m.any()}
    for c in ['A', 'B']:
        m = masks[c]
        if m.any():
            res[c]['detected'] = bool((scores[m] >= thr).any())
            res[c]['flagged'] = int((scores[m] >= thr).sum())
    return res

def build_train_indices(meta, train_a_dup=20, train_local_dup=10):
    tr = (meta.split == 'train').to_numpy()
    loc = (meta.dataset == 'local').to_numpy()
    a = (meta.campaign == 'A').to_numpy()
    parts = [np.where(tr)[0]]
    ai = np.where(tr & a)[0]
    if train_a_dup > 1 and len(ai):
        parts.append(np.tile(ai, train_a_dup - 1))
    li = np.where(tr & loc)[0]
    if train_local_dup > 1 and len(li):
        parts.append(np.tile(li, train_local_dup - 1))
    return np.concatenate(parts)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--scenario', default='S1', choices=['S1', 'S2', 'S3'])
    ap.add_argument('--tag', default='')
    ap.add_argument('--no-local-aug', action='store_true')
    ap.add_argument('--no-ti', action='store_true')
    ap.add_argument('--zero-cols', default='', help='comma-separated feature indices to zero')
    args = ap.parse_args()

    d = np.load(ROOT / 'features.npz', allow_pickle=True)
    X = d['X']; meta = pd.read_pickle(ROOT / 'meta.pkl')
    y = (meta.label == 1).to_numpy().astype(int)
    split = split_s1(meta) if args.scenario == 'S1' else split_cross(
        meta, 'A_to_B' if args.scenario == 'S2' else 'B_to_A')
    meta = meta.copy(); meta['split'] = split
    tr = (meta.split == 'train').to_numpy(); va = (meta.split == 'val').to_numpy()
    te = (meta.split == 'test').to_numpy()
    print(f'{args.scenario}: train={tr.sum():,} val={va.sum():,} test={te.sum():,} '
          f'pos={int(y[tr].sum()):,}/{int(y[va].sum()):,}/{int(y[te].sum()):,}', flush=True)
    print('train campaigns', meta.loc[tr & (y == 1), 'campaign'].value_counts().to_dict(),
          'test', meta.loc[te & (y == 1), 'campaign'].value_counts().to_dict(), flush=True)

    Xuse = X.copy()
    if args.no_ti:
        Xuse[:, [21, 22]] = 0.0
    if args.zero_cols:
        Xuse[:, [int(x) for x in args.zero_cols.split(',') if x.strip()]] = 0.0

    # Isolation Forest on benign training rows, local hard negatives up-weighted.
    btr = np.where(tr & (y == 0))[0]
    if not args.no_local_aug:
        loc = np.where(tr & (y == 0) & (meta.dataset == 'local').to_numpy())[0]
        if len(loc):
            btr = np.concatenate([btr, np.tile(loc, 9)])
    print('IF fit on', len(btr), 'benign rows', flush=True)
    t = time.time()
    if_model = IsolationForest(n_estimators=300, max_samples=256,
                               contamination='auto', random_state=42, n_jobs=-1)
    if_model.fit(Xuse[btr])
    print('IF fitted in', round(time.time() - t, 1), 's', flush=True)
    rawb = np.clip(0.5 - if_model.decision_function(Xuse[btr]), 0, 1)
    baseline = np.sort(rawb)
    base_val = rank_scores(np.clip(0.5 - if_model.decision_function(Xuse[va]), 0, 1), baseline)
    base_te = rank_scores(np.clip(0.5 - if_model.decision_function(Xuse[te]), 0, 1), baseline)

    # Supervised model: BARAQ's calibrated XGBoost/RF builder.
    idx = build_train_indices(meta, train_a_dup=20,
                              train_local_dup=(1 if args.no_local_aug else 10))
    print('supervised train rows', len(idx), 'pos', int(y[idx].sum()),
          'neg', int((1 - y[idx]).sum()), flush=True)
    t = time.time()
    sup, name = MLAnomalyDetector._build_classifier(Xuse[idx], y[idx])
    print('supervised', name, 'fitted in', round(time.time() - t, 1), 's', flush=True)
    p_val = sup.predict_proba(Xuse[va])[:, 1]
    p_te = sup.predict_proba(Xuse[te])[:, 1]

    # Persist fitted models and raw scores before threshold evaluation so a
    # downstream reporting error does not force a refit.
    tag = f'{args.scenario}{args.tag}'
    np.savez_compressed(RESULTS / f'{tag}_partial_scores.npz',
                        if_baseline=baseline,
                        if_val=base_val, if_test=base_te,
                        p_val=p_val, p_test=p_te)
    joblib.dump(if_model, RESULTS / f'{tag}_if.joblib')
    joblib.dump(sup, RESULTS / f'{tag}_sup.joblib')

    live_scores = np.load(ROOT / 'live_scores.npy')
    live_meta = json.load(open(ROOT / 'live_model_meta.json'))
    live_thr = float(live_meta['thresholds']['network'])
    report = {
        'scenario': args.scenario, 'tag': args.tag,
        'split_counts': {'train': int(tr.sum()), 'val': int(va.sum()), 'test': int(te.sum())},
        'train_pos': int(y[tr].sum()), 'val_pos': int(y[va].sum()), 'test_pos': int(y[te].sum()),
        'supervised_name': name, 'live_version': live_meta.get('version'),
        'live_threshold': live_thr,
        'baseline_live': evaluate_scores('live', live_scores, live_thr, meta),
    }

    locva_full = (meta.dataset == 'local').to_numpy() & va
    locva = locva_full[va]
    # IF
    tif, mif = best_f1(y[va], base_val)
    tif2, mif2, lmif = best_with_local_fpr(y[va], base_val, locva)
    report['if'] = {
        'thr_f1': tif, 'metrics_val': mif, 'thr_local1': tif2,
        'metrics_val_local1': mif2, 'local_val': lmif,
        'test_at_f1': evaluate_scores('if', base_te, mif['threshold'], meta, te),
        'test_at_local1': evaluate_scores('if', base_te, mif2['threshold'], meta, te),
    }
    # Supervised
    tsup, msup = best_f1(y[va], p_val)
    tsup2, msup2, lmsup = best_with_local_fpr(y[va], p_val, locva)
    report['sup'] = {
        'thr_f1': tsup, 'metrics_val': msup, 'thr_local1': tsup2,
        'metrics_val_local1': msup2, 'local_val': lmsup,
        'test_at_f1': evaluate_scores('sup', p_te, msup['threshold'], meta, te),
        'test_at_local1': evaluate_scores('sup', p_te, msup2['threshold'], meta, te),
    }
    # Blend
    blend_val = 0.6 * base_val + 0.4 * p_val
    blend_te = 0.6 * base_te + 0.4 * p_te
    tbl, mbl = best_f1(y[va], blend_val)
    tbl2, mbl2, lmbl = best_with_local_fpr(y[va], blend_val, locva)
    report['blend'] = {
        'thr_f1': tbl, 'metrics_val': mbl, 'thr_local1': tbl2,
        'metrics_val_local1': mbl2, 'local_val': lmbl,
        'test_at_f1': evaluate_scores('blend', blend_te, mbl['threshold'], meta, te),
        'test_at_local1': evaluate_scores('blend', blend_te, mbl2['threshold'], meta, te),
    }

    tag = f'{args.scenario}{args.tag}'
    np.savez_compressed(RESULTS / f'{tag}_scores.npz',
                        if_baseline=baseline,
                        if_val=base_val, if_test=base_te,
                        p_val=p_val, p_test=p_te,
                        blend_val=blend_val, blend_test=blend_te)
    joblib.dump(if_model, RESULTS / f'{tag}_if.joblib')
    joblib.dump(sup, RESULTS / f'{tag}_sup.joblib')
    (RESULTS / f'{tag}_report.json').write_text(json.dumps(report, indent=2, default=str))
    (RESULTS / f'{tag}_baseline.joblib').write_text('') if False else None
    print('wrote', RESULTS / f'{tag}_report.json')
    for k in ['baseline_live', 'if', 'sup', 'blend']:
        r = report[k]
        if 'test_at_f1' in r:
            for mode in ['test_at_f1', 'test_at_local1']:
                mm = r[mode]['test_all']
                print(f'{k:14s} {mode:14s} F1={mm["f1"]:.4f} P={mm["precision"]:.4f} '
                      f'R={mm["recall"]:.4f} FP={mm["fp"]} FN={mm["fn"]} '
                      f'thr={mm["threshold"]:.4f}')
            print('  local test', r['test_at_f1'].get('local'))
            print('  B test', r['test_at_f1'].get('B'))
            print('  A test', r['test_at_f1'].get('A'))
        else:
            print(f'{k} test_all', r.get('test_all'))
            print('  local test', r.get('local'), 'B', r.get('B'), 'A', r.get('A'))

if __name__ == '__main__':
    main()
