#!/usr/bin/env python3
"""Diagnose why the S1 BOTSv1 result is near-perfect.

This is deliberately a *negative* analysis.  It computes one-feature
baselines, split-composition checks, and ablations that show how much of S1's
headline score is explained by Campaign B's static infrastructure fingerprint.
It does not train a model and does not touch the live database.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path('datasets/botsv1_bench')
RESULTS = ROOT / 'results'
sys.path.insert(0, 'scripts')
from bench_botsv1_splits import split_s1, split_s4  # noqa: E402

FEATURE_NAMES = [
    'net_event_type', 'is_network_event', 'is_login_event', 'is_process_event',
    'hour_sin', 'hour_cos', 'is_night', 'is_weekend', 'src_ip_num', 'dst_ip_num',
    'is_private_src', 'is_private_dst', 'is_link_local_dst', 'is_multicast_dst',
    'is_loopback_src', 'dst_port_norm', 'port_category', 'time_since_dst',
    'time_since_src', 'conn_count_100', 'src_count_100', 'is_attack_ip',
    'is_attack_src', 'time_since_scaled', 'rapid_repeat', 'conn_count_50',
    'src_count_50', 'same_src_dst', 'dst_without_src',
]


def metrics(y, scores, thr):
    y = np.asarray(y).astype(int)
    pred = np.asarray(scores) >= thr
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    tn = int((~pred & (y == 0)).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    return {
        'n': int(len(y)), 'pos': int(y.sum()), 'tp': tp, 'fp': fp, 'fn': fn,
        'tn': tn, 'precision': precision, 'recall': recall,
        'f1': 2 * precision * recall / max(precision + recall, 1e-12),
        'fpr': fp / max(fp + tn, 1),
    }


def rule_metrics(frame, mask, name):
    y = (frame.label == 1).to_numpy()
    out = {'rule': name, 'all': metrics(y, mask, 0.5)}
    for camp in ['A', 'B']:
        m = (frame.campaign == camp).to_numpy()
        if m.any():
            out[camp] = metrics(y[m], mask[m], 0.5)
    for label, m in [('local', (frame.dataset == 'local').to_numpy()),
                     ('botsv1_bg', ((frame.dataset == 'botsv1') & (frame.label == 0)).to_numpy())]:
        if m.any():
            out[label] = metrics(y[m], mask[m], 0.5)
    return out


def feature_importances(model_path):
    if not model_path.exists():
        return {}
    model = joblib.load(model_path)
    estimators = getattr(model, 'calibrated_classifiers_', None)
    if not estimators:
        return {}
    gains = np.mean([c.estimator.feature_importances_ for c in estimators], axis=0)
    return {FEATURE_NAMES[i]: float(g) for i, g in sorted(
        enumerate(gains), key=lambda x: -x[1]) if g > 0}


def split_summary(meta, split, scenario):
    frame = meta.copy()
    frame['split'] = split
    out = {'scenario': scenario, 'counts': {}, 'positives': {}}
    for name in ['train', 'val', 'test']:
        sub = frame[frame.split == name]
        out['counts'][name] = int(len(sub))
        out['positives'][name] = int((sub.label == 1).sum())
    test = frame[frame.split == 'test']
    out['test_composition'] = {
        'total': int(len(test)),
        'positives': int((test.label == 1).sum()),
        'negatives': int((test.label == 0).sum()),
        'campaign_A': int((test.campaign == 'A').sum()),
        'campaign_B': int((test.campaign == 'B').sum()),
        'local': int((test.dataset == 'local').sum()),
        'botsv1_bg': int(((test.dataset == 'botsv1') & (test.label == 0)).sum()),
    }
    return frame, out


def main():
    meta = pd.read_pickle(ROOT / 'meta.pkl')
    meta['ts'] = pd.to_datetime(meta.ts, utc=True)
    report = {'status': 'S1 is a within-campaign shortcut diagnostic, not a holdout'}

    # --- S1: single-feature baselines and split composition -----------------
    s1_frame, s1_summary = split_summary(meta, split_s1(meta), 'S1')
    test = s1_frame[s1_frame.split == 'test'].copy()
    port_rule = (test.dst_port == 6892).to_numpy()
    ip_rule = test.dst_ip.astype(str).str.startswith('85.93.').to_numpy()
    s1_summary['single_feature_rules'] = {
        'dst_port_6892': rule_metrics(test, port_rule, 'dst_port == 6892'),
        'dst_ip_85_93': rule_metrics(test, ip_rule, 'dst_ip startswith 85.93.'),
    }

    b = s1_frame[s1_frame.campaign == 'B']
    b_train = b[b.split == 'train']
    b_test = b[b.split == 'test']
    b_window = s1_frame[(s1_frame.dataset == 'botsv1') & (s1_frame.label == 0)
                        & (s1_frame.window == 'B')]
    benign_b_window = s1_frame[(s1_frame.dataset == 'botsv1') & (s1_frame.label == 0)
                               & (s1_frame.ts >= b.ts.min()) & (s1_frame.ts <= b.ts.max())]
    s1_summary['s1_leakage_checks'] = {
        'b_train_test_dst_ip_overlap': len(set(b_train.dst_ip) & set(b_test.dst_ip)),
        'b_train_hosts': sorted(b_train.host.unique().tolist()),
        'b_test_hosts': sorted(b_test.host.unique().tolist()),
        'b_train_time': [b_train.ts.min().isoformat(), b_train.ts.max().isoformat()],
        'b_test_time': [b_test.ts.min().isoformat(), b_test.ts.max().isoformat()],
        'b_train_ports': {str(k): int(v) for k, v in b_train.dst_port.value_counts().items()},
        'b_test_ports': {str(k): int(v) for k, v in b_test.dst_port.value_counts().items()},
        'b_bursts': {str(k): int(v) for k, v in b.ts.dt.floor('1min').value_counts().sort_index().items()},
        'benign_in_b_attack_window_total': int(len(benign_b_window)),
        'benign_in_b_attack_window_by_split': {
            str(k): int(v) for k, v in benign_b_window.split.value_counts().items()},
        'same_host_benign_in_b_attack_window_by_split': {
            str(k): int(v) for k, v in benign_b_window[
                benign_b_window.host == 'we8105desk'].split.value_counts().items()},
        'hardneg_B_test': {
            'n': int(len(b_window[b_window.split == 'test'])),
            'time': [b_window[b_window.split == 'test'].ts.min().isoformat(),
                     b_window[b_window.split == 'test'].ts.max().isoformat()],
            'note': '18:00-18:23 bucket, after the 16:49/16:50/17:15 bursts',
        },
    }
    s1_summary['feature_importances'] = feature_importances(RESULTS / 'S1_v1_sup.joblib')

    # Existing model report and ablations, if present.
    def grab(tag):
        path = RESULTS / f'{tag}_report.json'
        if not path.exists():
            return None
        r = json.load(open(path))
        out = {}
        for component in ['if', 'sup', 'blend']:
            c = r.get(component, {})
            t = c.get('test_at_f1', {})
            out[component] = {
                'threshold': c.get('thr_f1'),
                'test_all': t.get('test_all'),
                'B': t.get('B'),
                'A': t.get('A'),
                'local': t.get('local'),
                'background': t.get('botsv1_bg'),
            }
        return out

    s1_summary['models'] = {
        'full': grab('S1_v1'),
        'no_raw_ip': grab('S1_noip'),
        'no_port': grab('S1_noport'),
        'no_raw_ip_no_port': grab('S1_noipport'),
    }
    report['S1'] = s1_summary

    # --- S4: time-forward burst holdout ------------------------------------
    s4_frame, s4_summary = split_summary(meta, split_s4(meta), 'S4')
    s4_test = s4_frame[s4_frame.split == 'test']
    s4_summary['single_feature_rules'] = {
        'dst_port_6892': rule_metrics(
            s4_test, (s4_test.dst_port == 6892).to_numpy(), 'dst_port == 6892'),
    }
    s4_summary['models'] = {'full': grab('S4_v1')}
    b4 = s4_frame[s4_frame.campaign == 'B']
    s4_summary['s4_checks'] = {
        'b_train_ips': int(b4[b4.split == 'train'].dst_ip.nunique()),
        'b_test_ips': int(b4[b4.split == 'test'].dst_ip.nunique()),
        'b_train_test_ip_overlap': len(
            set(b4[b4.split == 'train'].dst_ip) & set(b4[b4.split == 'test'].dst_ip)),
    }
    report['S4'] = s4_summary

    # --- S2/S3: clean cross-campaign failure --------------------------------
    cross = {}
    for name, direction in [('S2_AtoB', 'A_to_B'), ('S3_BtoA', 'B_to_A')]:
        scores_path = RESULTS / ('S2_v1_partial_scores.npz' if name.startswith('S2')
                                 else 'S3_v1_scores.npz')
        if not scores_path.exists():
            continue
        from bench_botsv1_splits import split_cross
        split = split_cross(meta, direction)
        te = meta[split == 'test'].copy()
        data = np.load(scores_path)
        key = 'p_test' if 'p_test' in data else None
        if key is None or len(data[key]) != len(te):
            continue
        te['sup_score'] = data[key]
        # Threshold from the held-out validation split, not test.
        val = meta[split == 'val']
        yv = (val.label == 1).to_numpy()
        pv = data['p_val']
        from sklearn.metrics import precision_recall_curve
        prec, rec, ths = precision_recall_curve(yv, pv)
        f1 = 2 * prec * rec / np.maximum(prec + rec, 1e-12)
        thr = float(ths[int(np.nanargmax(f1[:-1]))])
        cross[name] = {
            'supervised_threshold': thr,
            'A_recall': float(((te.campaign == 'A') & (te.sup_score >= thr)).sum()
                              / max((te.campaign == 'A').sum(), 1)),
            'B_recall': float(((te.campaign == 'B') & (te.sup_score >= thr)).sum()
                              / max((te.campaign == 'B').sum(), 1)),
            'B_max_score': float(te.loc[te.campaign == 'B', 'sup_score'].max()),
        }
    report['cross_campaign'] = cross

    out = RESULTS / 'S1_diagnostics.json'
    out.write_text(json.dumps(report, indent=2, default=str))
    print(f'wrote {out}')
    print('\nS1 test: port-6892 rule')
    print(json.dumps(report['S1']['single_feature_rules']['dst_port_6892'], indent=2))
    print('\nS1 leakage checks')
    print(json.dumps(report['S1']['s1_leakage_checks'], indent=2))
    print('\nS4 test: port-6892 rule')
    print(json.dumps(report['S4']['single_feature_rules']['dst_port_6892'], indent=2))
    print('\nS2/S3 supervised cross-campaign')
    print(json.dumps(report['cross_campaign'], indent=2))


if __name__ == '__main__':
    main()
