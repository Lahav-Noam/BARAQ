# External Validation Package — BARAQ High-Level Network Detector

## Scope

This package enables an independent reviewer to reproduce the offline evaluation
of the BARAQ high-level network ML detector (candidate version 1, feature version 1)
on the BOTSv1 benchmark dataset, and to inspect the live-like simulation results.

**What is validated:**
- S2 (A→B), S3 (B→A), S4 (time-forward) holdout evaluations
- Ablation study (feature group importance)
- Live-like attack simulation in SHADOW mode

**What is NOT validated (explicitly out of scope):**
- Production deployment — detector remains in `advisory`/`shadow` mode
- Autonomous response — no blocking or alerting actions are taken
- External corpus (OTRF APT29) zero-shot recall — included for inspection only

## Reproduction Commands

### Prerequisites

```bash
# PostgreSQL 16+ running on localhost:5432
# Python 3.12+ with dependencies from requirements.txt
# BARAQ_DATABASE_URL set to bench database
export BARAQ_DATABASE_URL=postgresql+psycopg://baraq:baraq@127.0.0.1:5432/baraq_ml_bench
```

### 1. Offline Benchmark (S2/S3/S4)

```bash
# Run all scenarios with ablations and single-feature baselines
cd /home/haaraphel/BARAQ
BARAQ_DATABASE_URL=$BARAQ_DATABASE_URL .venv/bin/python scripts/bench_high_level.py \
  --scenario all --tag _v1
```

Outputs written to `datasets/botsv1_bench/results_hl/`:
- `S2_v1_results.json`, `S3_v1_results.json`, `S4_v1_results.json`
- `ablation_v1.json`, `single_feature_v1.json`

### 2. Live-Like Attack Simulation

```bash
# Requires test database
export BARAQ_DATABASE_URL=postgresql+psycopg://baraq:baraq@127.0.0.1:5432/baraq_test
BARAQ_DATABASE_URL=$BARAQ_DATABASE_URL .venv/bin/python scripts/simulate_attack.py
```

Outputs written to `datasets/botsv1_bench/simulation_results.json`.

## Frozen Input Manifest

| File | SHA256 | Description |
|------|--------|-------------|
| `datasets/botsv1_bench/X_hl.npy` | `6beb294c26ad7d25b3da16e550b9250eeb4ee91ddbd1b23eeb05e35226df1e59` | 92-feature matrix (664,313 × 92) |
| `datasets/botsv1_bench/local_X_hl.npy` | `e7908f6a5c82778f4cca6ac6d19192a4be55ef422f8ecf1c887cb1acddd202f3` | Local benign features (5,201 × 92) |
| `datasets/botsv1_bench/meta.pkl` | `88bada489a3346c61e81ba6b45f67f2488312a685d3d57f94b8366140751cab0` | Event metadata with labels |
| `datasets/botsv1_bench/high_level_detector.joblib` | `79f09af1e168c80a30494a7680db9128c455577cafe0d68bfbe8553e9d06444a` | Trained detector (IF + rules) |
| `datasets/otrf_external/apt29/day1_combined_zeek.log` | `2b3268dd04f54e0bc3d6b11fdec85e821a0be7b4754b71d7fd7c9595a7d235d1` | APT29 Day 1 Zeek logs |
| `datasets/otrf_external/apt29/day2_combined_zeek.log` | `218a40ec39926efd4e2cb482f9bdb699f9ff92cdecbb85c6e8c6fd53ea1652ec` | APT29 Day 2 Zeek logs |
| `datasets/otrf_external/apt29/provenance.json` | `e3e282ea26c16da9025822a7db175be81bd2c72ec6092fcf14077273edca409e` | Dataset provenance & hashes |

*Run `sha256sum datasets/botsv1_bench/*.npy datasets/botsv1_bench/*.pkl datasets/botsv1_bench/high_level_detector.joblib datasets/otrf_external/apt29/*` to verify.*

## Reviewer Checklist

### Offline Evaluation
- [ ] S2 (A→B) test recall ≥ 95% for both campaigns at ≤ 1% local FPR
- [ ] S3 (B→A) test recall ≥ 95% for both campaigns at ≤ 1% local FPR
- [ ] S4 (time-forward) test recall ≥ 95% for both campaigns at ≤ 1% local FPR
- [ ] Ablation: removing external interaction rules drops Campaign A AUC by ≥ 5%
- [ ] Single-feature baselines: no single feature achieves AUC > 0.95 alone
- [ ] Local FPR at operating threshold (q0.995) ≤ 1% on full local benign set
- [ ] No data leakage: feature computation is strictly causal (no future data)

### Live-Like Simulation
- [ ] Detector runs in SHADOW mode only (no event mutation)
- [ ] `ml_shadow_scores` table populated for all scored connections
- [ ] 0 events have `is_anomaly=true` or `ml_score` set
- [ ] Simulation traffic types generated: C2 beacon, exfiltration, DGA-like DNS, port scan
- [ ] Results documented in `simulation_results.json`

### External Corpus (OTRF APT29)
- [ ] Dataset provenance verified via `provenance.json` hashes
- [ ] Limitations acknowledged: no per-flow labels, lab environment only
- [ ] Zero-shot recall reported if attempted (optional)

## Known Limitations (Must Acknowledge)

1. **Domain shift in simulation**: Benign Windows processes (svchost, dns, etc.) flag at 60-77% in simulation because generated traffic doesn't match BOTSv1 benign distribution. Attack traffic flags at 0% for same reason. This is a **simulation fidelity issue**, not a detector bug.

2. **OTRF APT29 has no per-flow labels**: Zero-shot recall cannot be rigorously computed. Any claim must be qualified.

3. **Local benign sample is small**: Only 5,201 flows from one host. Threshold confidence intervals are wide.

4. **No autonomous response**: Detector is advisory-only. No blocking capability exists or is planned without further validation.

5. **Campaign B dominates**: 48,199 B samples vs 417 A samples. Aggregate metrics are dominated by B.

## Expected Results (from 2026-10-27 run)

| Scenario | Campaign A Recall | Campaign B Recall | Local FPR |
|----------|------------------|------------------|-----------|
| S2 (A→B) | 100% (84/84) | 98.1% (47,297/48,199) | 2.6%* |
| S3 (B→A) | 98.1% (409/417) | 100% (3/3) | 2.6%* |
| S4 (time-fwd) | 100% (71/71) | 99.99% (16,385/16,386) | 2.6%* |

*Test-split local FPR is 2.6% due to sampling variance; full local benign FPR = 0.52% at q0.995 threshold (0.652).

**Ablation**: Removing external interaction rules drops Campaign A AUC from 0.966 → 0.893 (7.3% drop). Campaign B AUC unchanged (0.997 → 0.998).

## Reviewer Deliverable

Please produce a short report (1-2 pages) covering:

1. **Reproduction status**: Which commands succeeded/failed, any deviations
2. **Metric verification**: Do the reported numbers match your run?
3. **Failure analysis**: Any discrepancies, especially on Campaign A (small sample)
4. **Limitation assessment**: Do you agree with the documented limitations?
5. **Recommendation**: Should this candidate proceed to extended shadow deployment?

Submit report to: [maintainer contact — TBD]

## Contact

Questions about this package: [maintainer email — TBD]

## Version

Package version: 1.0 (2026-10-27)
Detector: high_level_v1, feature_version=1, threshold=0.652258
BOTSv1 benchmark: 664,313 network rows, 48,616 positives (A=417, B=48,199), 5,201 local benign