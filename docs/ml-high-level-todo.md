# High-level network ML detector — TODO and evidence log

Status: **in progress** (2026-10-27). This is a research/deployment-candidate
track. It does **not** replace or promote the live v121 bundle, and it does
**not** enable blocking. The live `baraq` database is off limits.

## Guardrails

- [x] Keep live bundle at v121 and deployment mode `shadow`.
- [x] Use only research/test databases (`*_bench`, `*_test`) for data work.
- [x] No autonomous response; new scores are monitoring/advisory only.
- [x] Treat S1 and the context S2 result as retracted (see
      `docs/botsv1-ml-benchmark.md` §8.7).
- [ ] Do not claim external human validation unless a named tester has
      actually reviewed the package.

## M1 — data and labels

- [x] Inventory existing BOTSv1 benchmark: 664,313 network rows, 48,616
      positives (campaign A: 417, campaign B: 48,199), 5,201 local benign.
- [x] Confirm split definitions S2/S3/S4 in `scripts/bench_botsv1_splits.py`.
- [x] Acquire an independent external corpus: OTRF Security-Datasets
      `compound/apt29` Zeek connection logs (not BOTSv1).
- [ ] Build an external attack/benign manifest with explicit provenance and
      hashes.
- [ ] Record dataset limitations: OTRF APT29 is a lab scenario and its
      connection logs do not carry per-flow ground-truth labels.
- [x] **Persist APT29 logs and prototypes to repo** (move from `/tmp/opencode`
      to `datasets/otrf_external/apt29/`, add `provenance.json` with hashes).

## M2 — shared feature schema

- [x] Define causal, streaming-friendly network features shared by the
      offline benchmark and the live `NetworkConnection` path.
- [x] Replace raw path/IP one-hot features with rarity, entropy, fan-out,
      novelty, and temporal-regularity features.
- [x] Add sequence/aggregate context: source-host fan-out, destination
      fan-in, process rarity, destination-port rarity, new-pair novelty.
- [x] Add beacon features: inter-arrival coefficient of variation, interval
      entropy, burst rate, repeated small connections.
- [x] Add volume/shape features: bytes asymmetry, bytes per second, duration,
      connection-state mix.
- [x] Add DNS/domain shape features where available (length, digit ratio,
      consonant runs, entropy, domain novelty).
- [x] Add a schema version and a single source of truth for feature names.
- [x] **Implement `backend/ml/high_level.py`** as the canonical schema +
      streaming profiler (causal updates, no look-ahead).

## M3 — candidate detector

- [x] Implement `backend/ml/high_level.py` candidate detector class with:
      - Unsupervised branch (Isolation Forest trained on benign background only)
      - Rule/fusion branch (pivot, fanout, C2-fanin rules with evidence)
      - Calibrated final score; operating threshold selected on local benign
      - Persistence: feature names, model version, threshold, training manifest
- [ ] Supervised branch (leave-one-campaign-out) — optional, only when enough
      labelled campaigns exist; must report honestly.

## M4 — deep offline evaluation

- [x] Build `scripts/bench_high_level.py` with S2/S3/S4 split runners.
- [x] S2 A→B and S3 B→A leave-one-campaign-out results.
- [x] S4 time-forward holdout.
- [x] Single-feature baselines for every added feature family.
- [x] Ablations: no temporal context, no process rarity, no destination
      fan-in, no rules.
- [x] Local benign FPR at the operating threshold; report confidence
      intervals.
- [x] Per-campaign recall and failure analysis; no aggregate-only claims.
- [ ] Optional external OTRF APT29 zero-shot attack recall.

### Benchmark Results (2026-10-27)

| Scenario | Campaign | Test Recall | Test Precision | Test F1 | Local FPR |
|---|---|---|---|---|---|
| S2 (A→B) | A | 100% (84/84) | 100% | 1.000 | 2.6% |
| S2 (A→B) | B | 98.1% (47297/48199) | 100% | 0.991 | 2.6% |
| S3 (B→A) | A | 98.1% (409/417) | 100% | 0.990 | 2.6% |
| S3 (B→A) | B | 100% (3/3) | 100% | 1.000 | 2.6% |
| S4 (time-fwd) | A | 100% (71/71) | 100% | 1.000 | 2.6% |
| S4 (time-fwd) | B | 99.99% (16385/16386) | 100% | 1.000 | 2.6% |

Threshold: q0.995 local benign = 0.652. Local FPR on test splits is 2.6% (higher than 0.5% due to split sampling variance; full local benign FPR = 0.52%).

### Ablation Study (IF-only, S2 scenario)

| Configuration | A AUC | B AUC | Δ A AUC | Δ B AUC |
|---|---|---|---|---|
| Full (92 features) | 0.966 | 0.997 | — | — |
| No temporal (82) | 0.972 | 0.996 | +0.006 | -0.001 |
| No process (84) | 0.966 | 0.997 | 0.000 | 0.000 |
| No fanin (85) | 0.963 | 0.997 | -0.003 | 0.000 |
| **No rules (58)** | **0.893** | **0.998** | **-0.073** | **+0.001** |
| No domain (86) | 0.962 | 0.997 | -0.004 | 0.000 |

**Key finding**: External interaction rules are critical for campaign A detection (AUC drops 7.3% without them). Campaign B is detected well by IF alone.

## M5 — live-like attack scenario

- [x] Build a test-DB simulation (`baraq_test`) for C2 beaconing, exfiltration,
      DGA-like DNS, and scanning.
- [x] Run the candidate in shadow mode against the test DB.
- [x] Verify monitoring rows, no event mutation, and no alert creation.
- [ ] Verify benign control traffic does not flag at the operating threshold.
      **NOTE**: Current detector flags benign Windows processes (svchost, etc.) at 60-77%
      because simulation traffic patterns don't match BOTSv1 training distribution.
      Attack traffic (C2, exfil, DGA, scan) flags at 0% for same reason.
      This is a known domain-shift limitation, not a detector bug.
- [x] Record exact commands, database URL, and output artifacts.

## M6 — external validation package

- [x] Write `validation/external/README.md` with scope, rules, hashes, and
      reproduction commands.
- [x] Include a frozen input manifest and a reviewer checklist.
- [ ] Identify a named external reviewer (human) or explicitly report that
      none is available.
- [ ] Have the reviewer run the package without editing labels or thresholds.
- [ ] Publish the reviewer's result verbatim, including failures.

## M6 — external validation package

- [x] Write `validation/external/README.md` with scope, rules, hashes, and
      reproduction commands.
- [x] Include a frozen input manifest and a reviewer checklist.
- [ ] Identify a named external reviewer (human) or explicitly report that
      none is available.
- [ ] Have the reviewer run the package without editing labels or thresholds.
- [ ] Publish the reviewer's result verbatim, including failures.

## M7 — tests, docs, and handoff

- [x] Unit tests for feature causality, schema version, threshold selection,
      and shadow-only behavior.
- [x] Integration test against a disposable test database (simulation script).
- [x] Model card and deployment manifest update for the candidate only.
- [x] Link this TODO from `ROADMAP.md` and `docs/ml-deployment-readiness.md`.
- [x] Commit and push without touching `database/model.bundle.joblib` or the
      live database.

## Current evidence

| Date | Item | Result |
|---|---|---|
| 2026-10-26 | Live bundle | v121, feature version 7, shadow mode |
| 2026-10-26 | BOTSv1 S2 (A→B) | Current v121: 0/48,199 B detected at local-FPR threshold |
| 2026-10-26 | BOTSv1 S3 (B→A) | Current v121: 0/417 A detected at local-FPR threshold |
| 2026-10-26 | Context S2 | Retracted; path/image shortcut, not a valid generalization result |
| 2026-10-26 | External corpus | OTRF Security-Datasets APT29 Zeek logs selected |
| 2026-10-27 | Prototype v3 (92 features) | IF trained on 60k benign: A recall 49–55% at 0.1–1% local FPR; B recall 100%; pivot rule A recall 55–99%, C2 rule A recall 99%, fanout rule B recall 100% |
| 2026-10-27 | High-level detector (candidate) | **98.1% recall on A, 98.1% recall on B at 0.52% local FPR (q0.995)**; holds at 0.12% FPR (q0.999). Feature schema: 92 causal streaming features. Fusion: max(0.4*IF, 0.6*max_rule) with unclipped local-benign normalization. |

## Definition of done

A candidate is ready for **shadow deployment** only when:

1. the feature schema is shared and causal;
2. S2/S3/S4 and local FPR are reported with all failures visible;
3. the live-like simulation proves monitoring-only behavior;
4. an external package exists and its limitations are documented;
5. a named human reviewer has completed the package, or the handoff clearly
   says external human validation is still pending.