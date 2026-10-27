#!/usr/bin/env python3
"""
High-level network detector benchmark runner.

Runs S2 (A→B), S3 (B→A), S4 (time-forward) evaluations with full
ablation and single-feature baseline reporting.
"""
from __future__ import annotations
import argparse
import json
import logging
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import roc_auc_score, average_precision_score

# Add backend to path
sys.path.insert(0, '/home/haaraphel/BARAQ')

from backend.ml.high_level import (
    HighLevelDetector, Profiler, FEATURES, FEATURE_VERSION,
    rule_scores, build_feature_matrix, build_local_matrix
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

RESULTS_DIR = Path('/home/haaraphel/BARAQ/datasets/botsv1_bench/results_hl')
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Split definitions (matching bench_botsv1_splits.py)
def make_splits(meta: pd.DataFrame, scenario: str, seed: int = 42):
    """Create train/val/test splits for the given scenario."""
    from scripts.bench_botsv1_splits import split_s1, split_s4, split_cross
    
    if scenario == 'S2':
        # A→B: train on campaign A, test on campaign B
        sp = split_cross(meta, direction='A_to_B', seed=seed)
    elif scenario == 'S3':
        # B→A: train on campaign B, test on campaign A
        sp = split_cross(meta, direction='B_to_A', seed=seed)
    elif scenario == 'S4':
        # Time-forward: train on early data, test on late data
        sp = split_s4(meta)
    else:
        raise ValueError(f"Unknown scenario: {scenario}")
    
    return {
        'train': (sp == 'train'),
        'val': (sp == 'val'),
        'test': (sp == 'test')
    }


def evaluate_split(detector: HighLevelDetector, X: np.ndarray, meta: pd.DataFrame, 
                   split_name: str, mask: np.ndarray) -> dict:
    """Evaluate detector on a split."""
    X_split = X[mask]
    meta_split = meta[mask]
    
    # Get predictions
    scores = detector.fused_score(X_split)
    preds = (scores >= detector.threshold).astype(int)
    
    # Ground truth
    y_true = (meta_split.label == 1).astype(int) if 'label' in meta_split.columns else np.zeros(len(meta_split))
    
    # Per-campaign metrics
    results = {
        'split': split_name,
        'n_samples': len(X_split),
        'n_positive': int(y_true.sum()),
        'threshold': detector.threshold,
        'campaigns': {}
    }
    
    for camp in ['A', 'B']:
        camp_mask = (meta_split.campaign == camp).to_numpy()
        if camp_mask.sum() == 0:
            continue
        y_c = y_true[camp_mask]
        s_c = scores[camp_mask]
        p_c = preds[camp_mask]
        
        tp = int(((p_c == 1) & (y_c == 1)).sum())
        fp = int(((p_c == 1) & (y_c == 0)).sum())
        fn = int(((p_c == 0) & (y_c == 1)).sum())
        tn = int(((p_c == 0) & (y_c == 0)).sum())
        
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        
        # AUC
        try:
            auc = roc_auc_score(y_c, s_c)
            ap = average_precision_score(y_c, s_c)
        except Exception:
            auc = 0.5
            ap = 0.0
        
        results['campaigns'][camp] = {
            'n': int(camp_mask.sum()),
            'positives': int(y_c.sum()),
            'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'precision': prec, 'recall': rec, 'f1': f1,
            'roc_auc': auc, 'pr_auc': ap,
            'score_quantiles': np.quantile(s_c, [0, .25, .5, .75, .9, .99, 1]).tolist()
        }
    
    # Local benign FPR
    local_mask = (meta_split.dataset == 'local').to_numpy()
    if local_mask.sum() > 0:
        s_local = scores[local_mask]
        fpr = (s_local >= detector.threshold).mean()
        results['local_fpr'] = float(fpr)
        results['local_score_quantiles'] = np.quantile(s_local, [0, .25, .5, .75, .9, .99, 1]).tolist()
    
    return results


def run_scenario(scenario: str, X: np.ndarray, meta: pd.DataFrame, 
                 X_local: np.ndarray, tag: str = '') -> dict:
    """Run a full scenario evaluation."""
    logger.info(f"Running {scenario} evaluation...")
    
    # Get splits
    splits = make_splits(meta, scenario)
    
    # Training data: benign background (for IF)
    bg_mask = splits['train'] & ((meta.dataset == 'botsv1') & (meta.label == 0)).to_numpy()
    X_train = X[bg_mask]
    
    # Subsample for IF training
    rng = np.random.default_rng(42)
    if len(X_train) > 60000:
        idx = rng.choice(len(X_train), 60000, replace=False)
        X_train = X_train[idx]
    
    logger.info(f"Training IF on {len(X_train)} benign samples")
    
    # Train detector
    det = HighLevelDetector()
    det.fit(X_train, X_local)
    
    # Evaluate on val and test
    results = {
        'scenario': scenario,
        'detector': {
            'threshold': det.threshold,
            'threshold_quantile': det.threshold_quantile,
            'feature_version': det.feature_version,
            'training_manifest': det.training_manifest
        },
        'splits': {}
    }
    
    for split_name in ['val', 'test']:
        if split_name in splits:
            mask = splits[split_name]
            res = evaluate_split(det, X, meta, split_name, mask)
            results['splits'][split_name] = res
            logger.info(f"  {split_name}: {res}")
    
    # Save detector
    det_path = RESULTS_DIR / f'{scenario}{tag}_detector.joblib'
    det.save(det_path)
    logger.info(f"Saved detector to {det_path}")
    
    return results


def single_feature_baselines(X: np.ndarray, meta: pd.DataFrame, feature_names: list) -> dict:
    """Compute AUC for each feature individually."""
    logger.info("Computing single-feature baselines...")
    
    bg_mask = ((meta.dataset == 'botsv1') & (meta.label == 0)).to_numpy()
    results = {}
    
    # Sample for speed
    rng = np.random.default_rng(42)
    bg_idx = np.where(bg_mask)[0]
    rng.shuffle(bg_idx)
    bg_sample = bg_idx[:50000]
    
    for camp in ['A', 'B']:
        camp_mask = (meta.campaign == camp).to_numpy()
        camp_idx = np.where(camp_mask)[0]
        
        idx = np.concatenate([camp_idx, bg_sample])
        y = np.concatenate([np.ones(len(camp_idx)), np.zeros(len(bg_sample))])
        
        camp_results = {}
        for i, name in enumerate(feature_names):
            try:
                auc = roc_auc_score(y, X[idx, i])
                auc = max(auc, 1 - auc)
                camp_results[name] = float(auc)
            except Exception:
                camp_results[name] = 0.5
        
        results[camp] = camp_results
    
    return results


def ablation_study(X: np.ndarray, meta: pd.DataFrame, X_local: np.ndarray, 
                   feature_names: list) -> dict:
    """Run ablation experiments."""
    logger.info("Running ablation study...")
    
    # Define ablation groups
    ablations = {
        'full': list(range(len(feature_names))),
        'no_temporal': [i for i, n in enumerate(feature_names) 
                        if not any(k in n for k in ['hour', 'is_night', 'is_weekend', 'pair_interval', 'pair_time', 'pair_regular', 'host_rate'])],
        'no_process': [i for i, n in enumerate(feature_names) 
                       if not n.startswith('process_')],
        'no_fanin': [i for i, n in enumerate(feature_names) 
                     if not any(k in n for k in ['dst_host_fanout', 'dst_count', 'ext_dst_host', 'ext_dst_count', 'ext_dst_fanin'])],
        'no_rules': [i for i, n in enumerate(feature_names) 
                     if not n.startswith('ext_')],  # All external/interaction features
        'no_domain': [i for i, n in enumerate(feature_names) 
                      if not n.startswith('domain_')],
    }
    
    bg_mask = ((meta.dataset == 'botsv1') & (meta.label == 0)).to_numpy()
    rng = np.random.default_rng(42)
    bg_idx = np.where(bg_mask)[0]
    rng.shuffle(bg_idx)
    bg_sample = bg_idx[:60000]
    
    results = {}
    
    for name, feat_idx in ablations.items():
        logger.info(f"  Ablation: {name} ({len(feat_idx)} features)")
        
        # Train IF on subset
        X_train = X[bg_sample][:, feat_idx]
        iforest = IsolationForest(n_estimators=200, max_samples=4096, 
                                   contamination='auto', random_state=42, n_jobs=4)
        iforest.fit(X_train)
        
        # Evaluate
        for camp in ['A', 'B']:
            camp_mask = (meta.campaign == camp).to_numpy()
            X_camp = X[camp_mask][:, feat_idx]
            y_camp = np.ones(len(X_camp))
            y_bg = np.zeros(len(bg_sample))
            
            s_camp = -iforest.decision_function(X_camp)
            s_bg = -iforest.decision_function(X[bg_sample][:, feat_idx])
            
            try:
                auc = roc_auc_score(np.concatenate([y_camp, y_bg]), 
                                    np.concatenate([s_camp, s_bg]))
                auc = max(auc, 1 - auc)
            except Exception:
                auc = 0.5
            
            key = f'{camp}_{name}'
            results[key] = {'auc': float(auc), 'n_features': len(feat_idx)}
    
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', choices=['S2', 'S3', 'S4', 'all'], default='all')
    parser.add_argument('--tag', default='')
    parser.add_argument('--skip-ablation', action='store_true')
    parser.add_argument('--skip-single-feature', action='store_true')
    args = parser.parse_args()
    
    # Load data
    logger.info("Loading data...")
    meta = pd.read_pickle('/home/haaraphel/BARAQ/datasets/botsv1_bench/meta.pkl')
    X = np.load('/home/haaraphel/BARAQ/datasets/botsv1_bench/X_hl.npy')
    X_local = np.load('/home/haaraphel/BARAQ/datasets/botsv1_bench/local_X_hl.npy')
    
    logger.info(f"Data loaded: X={X.shape}, meta={len(meta)}, X_local={X_local.shape}")
    
    all_results = {}
    
    # Single-feature baselines
    if not args.skip_single_feature:
        sf_results = single_feature_baselines(X, meta, FEATURES)
        all_results['single_feature'] = sf_results
        with open(RESULTS_DIR / f'single_feature{args.tag}.json', 'w') as f:
            json.dump(sf_results, f, indent=2)
    
    # Ablation study
    if not args.skip_ablation:
        abl_results = ablation_study(X, meta, X_local, FEATURES)
        all_results['ablation'] = abl_results
        with open(RESULTS_DIR / f'ablation{args.tag}.json', 'w') as f:
            json.dump(abl_results, f, indent=2)
    
    # Scenario evaluations
    scenarios = ['S2', 'S3', 'S4'] if args.scenario == 'all' else [args.scenario]
    
    for sc in scenarios:
        res = run_scenario(sc, X, meta, X_local, args.tag)
        all_results[sc] = res
        with open(RESULTS_DIR / f'{sc}{args.tag}_results.json', 'w') as f:
            json.dump(res, f, indent=2, default=str)
    
    # Summary
    logger.info("\n=== SUMMARY ===")
    for sc in scenarios:
        if sc in all_results:
            for split_name, split_res in all_results[sc].get('splits', {}).items():
                for camp, camp_res in split_res.get('campaigns', {}).items():
                    logger.info(f"  {sc} {split_name} {camp}: recall={camp_res['recall']:.4f}, "
                               f"precision={camp_res['precision']:.4f}, f1={camp_res['f1']:.4f}, "
                               f"auc={camp_res['roc_auc']:.4f}")
            if 'local_fpr' in all_results[sc].get('splits', {}).get('test', {}):
                logger.info(f"  {sc} test local FPR: {all_results[sc]['splits']['test']['local_fpr']:.4f}")
    
    # Save all results
    with open(RESULTS_DIR / f'all_results{args.tag}.json', 'w') as f:
        json.dump(all_results, f, indent=2, default=str)
    
    logger.info(f"All results saved to {RESULTS_DIR}")


if __name__ == '__main__':
    main()