# BOTSv1 network model benchmark

Status: **corrected (2026-10-26)**. The original S1 result (F1 **0.9995**) is
retracted as a promotion or generalization metric. It is reproducible, but it is
a within-campaign shortcut: Campaign B is separated by a single static feature
(`dst_port == 6892`), and the S1 split leaves that feature, the source host, the
same three DGA bursts, and the same destination-IP range in both training and
test. **v122 was rolled back to v121.** The clean cross-campaign tests (S2/S3)
show no transfer at a deployable local-false-positive budget. A later
context-feature S2 result was also **retracted** as a path/missing-value artifact
(§8.7), so no candidate is promoted; the live deployment contract is
[`docs/ml-deployment-readiness.md`](ml-deployment-readiness.md).

This document keeps the original numbers as an audit trail, then explains why
they cannot be used as the model's headline performance.

## 1. Why BOTSv1 Sysmon

BARAQ's network model consumes process-aware Sysmon network events (event code 3)
and derives 29 features in `backend/ml/anomaly.py::_load_network_features`.
Generic flow datasets such as CICIDS or UNSW do not carry the process, user,
host, and event-context fields that BARAQ actually uses, so they are not a fair
test of this model.

BOTSv1 Sysmon was selected because it contains:

- real attack campaigns with process-level telemetry,
- long periods of benign background traffic on the same hosts, and
- the process/image, command-line, GUID, host, and destination fields needed to
  build both positive labels and benign hard negatives.

OTRF/Mordor is semantically close but does not provide a comparable benign
baseline. BOTSv1 therefore gives a better false-positive/false-negative
benchmark, while remaining compatible with BARAQ's feature space.

Source: `datasets/botsv1/sysmon.json.gz` (145,011,879 bytes, `gzip -t` passed).

## 2. Parsed data

The BOTSv1 Sysmon export contains 830,390 JSON lines:

| Event code | Meaning | Rows |
|---|---|---:|
| 3 | Network connection | 659,112 |
| 7 | Image loaded | 168,374 |
| 2 | File creation time changed | 1,434 |
| 1 | Process create | 767 |
| 5 | Process terminated | 684 |
| 6 | Driver loaded | 18 |

BARAQ's existing importers do not parse the BOTSv1 `TimeCreated`/raw OTRF
layout correctly, so the benchmark uses a dedicated parser and does not import
research data into the live `baraq` database.

## 3. Attack campaigns and labels

### Campaign A — Joomla compromise (`we1149srv`)

- Time: 2016-08-10, approximately 21:40–22:30 UTC (C2 activity spans
  2016-08-01 to 2016-08-28).
- Initial payload: `C:\inetpub\wwwroot\joomla\3791.exe`.
- Reconnaissance: `whoami`, `net`, `nslookup`, `tasklist`.
- C2: `108.161.187.134:80` and
  `prankglassinebracket.jumpingcrab.com`.
- Network positives: 417 events.

### Campaign B — Cerber ransomware (`we8105desk`)

- Time: 2016-08-24, approximately 15:30–19:00 UTC.
- Payload: `osk.exe` under
  `AppData\Roaming\{35ACA89F-...}`.
- Defense evasion: `vssadmin delete shadows`, `bcdedit`,
  `wmic shadowcopy delete`, `wscript`/`cscript`.
- Network positives: 48,199 DGA connections across 16,387 destination IPs.
- The connections occur in three short bursts: **19,271 at 16:49**, **12,542
  at 16:50**, and **16,386 at 17:15** UTC. All three bursts use port **6892**
  and the same `85.93.x.x` destination range.

### Benign hard negatives

- BOTSv1 host/time-window background traffic around the campaigns (not
  automatically malicious).
- A Tenable Nessus scan on `we9041srv` on 2016-08-24, including
  `tenable_mw_scan_*.exe`, `tasklist`, `netstat`, and `netsh`.
- 5,201 deduplicated local live network flows from BARAQ telemetry, added as
  benign hard negatives so the retrained model does not trade BOTSv1 recall for
  local false positives.

Labels are stored in `raw_json["benchmark"]` in the disposable benchmark
database. The live `baraq` database was not modified.

## 4. Benchmark database

- Database: `baraq_ml_bench` (PostgreSQL container `baraq-ci-pg`).
- Total events: **664,313**.
- BOTSv1 network events: **659,112**.
- Local deduplicated benign flows: **5,201**.
- Positives: **48,616** (Campaign A 417, Campaign B 48,199).
- BOTSv1 benign events: **610,496**.

Feature matrix: `datasets/botsv1_bench/features.npz` — **664,313 × 29**.
Labels/metadata: `datasets/botsv1_bench/meta.pkl`.

## 5. Split design

Random row splits are not used. The benchmark has three diagnostic scenarios
plus one time-forward control:

| Scenario | Train | Validation | Test | Purpose |
|---|---:|---:|---:|---|
| S1 within-campaign | 456,096 | 112,380 | 95,837 | B held out by random destination IP; A and background held out by time; local held out by time |
| S4 time-forward B | 545,291 | 14,967 | 104,055 | Train first B burst, validate second, test third burst plus all later background |
| S2 A→B | 405,572 | 100,164 | 158,577 | Train on Campaign A, test on Campaign B |
| S3 B→A | 140,667 | 79,681 | 443,965 | Train on Campaign B, test on Campaign A |

Counts are totals including the local benign flows assigned to that split.

S1 test composition: 7,308 positives (B 7,217, A 91), 87,489 BOTSv1 benign,
1,040 local benign flows.

S4 test composition: 16,457 positives (B 16,386, A 71), 86,558 BOTSv1 benign,
1,040 local benign flows.

S2 test composition: 48,283 positives (B 48,199, A late 84), 109,254 BOTSv1
benign, 1,040 local benign flows.

S3 test composition: 420 positives (A 417, B 3), 442,505 BOTSv1 benign, 1,040
local benign flows.

**S1 is not a promotion gate.** S1 holds out only a random subset of Campaign B
destination IPs. Training and test still share:

- the same source host (`we8105desk`),
- the same destination port (`6892` on 48,196 of 48,199 B events),
- the same three bursts and the same `85.93.x.x` destination range,
- the same DGA process and connection pattern.

The only thing held out is which IP in that range is seen at training time.
Because the model also receives the port and the repeated-connection counts, the
B test is a campaign-fingerprint recognition task, not an unseen-campaign task.

S4 is stricter in time: it trains on the first burst, validates on the second,
and tests on the third plus all later background. It is still a
known-infrastructure test because the later bursts reuse the same destination
IPs and port. It measures temporal consistency, not cross-campaign
generalization.

## 6. Current live model baseline

Evaluated bundle before the correction: **v121**, `random_forest+platt`, feature
version 7, network threshold **0.609069609283942**, trained on 323 local
samples. v121 is again the live bundle after the rollback in §8.5.

Scores were produced by the model's own `_combined_score_batch` path and saved in
`datasets/botsv1_bench/live_scores.npy`.

| Slice | Events | Positives | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| All | 664,313 | 48,616 | 0 | 136 | 48,616 | 0.0000 | 0.0000 | 0.0000 |
| BOTSv1 | 659,112 | 48,616 | 0 | 136 | 48,616 | 0.0000 | 0.0000 | 0.0000 |
| Campaign A | 417 | 417 | 0 | 0 | 417 | 0.0000 | 0.0000 | 0.0000 |
| Campaign B | 48,199 | 48,199 | 0 | 0 | 48,199 | 0.0000 | 0.0000 | 0.0000 |
| Local | 5,201 | 0 | 0 | 0 | 0 | — | — | — |

BOTSv1 AUC: **0.0745**; average precision: **0.0516**. The live model is worse
than random ranking on this out-of-domain benchmark and does not detect either
campaign at its deployed threshold. This is a limitation of v121, not evidence
that the BOTSv1-tuned v122 is safe to deploy.

The score distribution is also knife-edged on local traffic. The largest local
score is 0.604858; a threshold just above it flags 0 of 5,201 local flows and
1 of 48,616 BOTSv1 positives. A threshold one epsilon below it (0.604857) flags
2,568 local flows (49.4%) and still only 2 BOTSv1 positives. Naive threshold
reduction is therefore not a fix.

## 7. Candidate models

All candidates use BARAQ's own feature extractor and classifier builder:

- **IF**: Isolation Forest on benign training rows; local benign flows
  up-weighted 10×.
- **Supervised**: calibrated XGBoost or random forest from
  `MLAnomalyDetector._build_classifier`; Campaign A positives up-weighted 20×;
  local benign flows up-weighted 10×.
- **Blend**: `0.6 × IF` + `0.4 × supervised`, matching the deployed scoring
  path.

Thresholds are selected on validation only:

1. best validation F1, and
2. best validation F1 subject to local benign FPR ≤ 1%.

The second threshold is the deployment candidate, because local false positives
are the main operational cost.

## 8. Results and correction

### 8.1 Original S1 result (reproducible, but retracted)

The original run selected the **blend** at threshold
**0.7485130264214555**, chosen on the validation split only (maximum validation
F1). Validation had 7,301/7,301 positives and 0/105,079 negatives flagged; local
validation was 0/520.

| S1 test slice | Events | Positives | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| All | 95,837 | 7,308 | 7,302 | 1 | 6 | 0.99986 | 0.99918 | 0.99952 |
| Campaign B | 7,217 | 7,217 | 7,216 | 0 | 1 | 1.00000 | 0.99986 | 0.99993 |
| Campaign A | 91 | 91 | 86 | 0 | 5 | 1.00000 | 0.94505 | 0.97175 |
| BOTSv1 background | 87,489 | 0 | 0 | 1 | 0 | — | — | — |
| Local live flows | 1,040 | 0 | 0 | 0 | 0 | — | — | — |

Test ROC-AUC: **0.99999987**; average precision: **0.9999984**.

These numbers are real for the code and split that produced them. They are **not
a valid estimate of detection performance**, for the reasons in §8.2. The
original report remains at `datasets/botsv1_bench/results/S1_v1_report.json` for
audit; `scripts/bench_botsv1_diagnostics.py` writes the corrected diagnostic
view to `datasets/botsv1_bench/results/S1_diagnostics.json`.

### 8.2 Why the original S1 result was almost 1.0

#### A single static feature reproduces Campaign B exactly

On the S1 test, the rule `dst_port == 6892` alone gives:

| Rule | B TP / FN | B recall | All TP / FP / FN | All precision | All F1 |
|---|---:|---:|---:|---:|---:|
| Promoted blend | 7,216 / 1 | 0.99986 | 7,302 / 1 / 6 | 0.99986 | 0.99952 |
| `dst_port == 6892` | 7,216 / 1 | 0.99986 | 7,216 / 0 / 92 | 1.00000 | 0.99367 |

The model adds **86 Campaign A true positives** over the one-feature rule. It
adds **zero Campaign B true positives**. The B headline is therefore not a model
achievement; the benchmark hands the model a port that no benign event uses.
This is a shortcut, not label leakage, but it invalidates the use of S1 as a
generalization or promotion metric.

#### The split leaves the campaign context in both halves

From `datasets/botsv1_bench/meta.pkl`:

- B train and test have **0 destination-IP overlap**, but both use host
  `we8105desk`, port `6892`, the same `85.93.x.x` range, and the same three
  bursts between 16:49 and 17:15 UTC.
- B is not one continuous burst: it is 19,271 events at 16:49, 12,542 at 16:50,
  and 16,386 at 17:15. Train and test both cover those bursts.
- Of the **4,331 benign events in the B attack window**, **2,502 are same-host
  `we8105desk` events and all 2,502 are in training**. Only 1,829 other-host
  benign events land in the test split.
- The `hardneg_B` test slice is **30 events at 18:00–18:23**, after the bursts
  ended. It does not measure false positives during the attack.
- The validation split is drawn from the same campaign and same bursts, so the
  threshold is selected on a perfectly separable, non-independent slice.

The feature matrix is also computed once over the whole timeline. In S1 the
train and test B rows are interleaved in time, so counters such as
`src_count`/`time_since_src` can be influenced across the split boundary. S4
avoids this by making the split strictly time-forward.

#### Feature ablations confirm redundant campaign fingerprints

All rows are retrained on the same S1 split; thresholds are selected on the same
S1 validation. Values are blend `test_at_f1` unless noted.

| Variant | B TP / FN | B recall | A recall | Local FP | BOTSv1 background FP |
|---|---:|---:|---:|---:|---:|
| Full | 7,216 / 1 | 0.99986 | 86/91 | 0/1,040 | 1/87,489 |
| No raw IP (8,9) | 7,216 / 1 | 0.99986 | 25/91 | 0/1,040 | 21/87,489 |
| No port (15,16) | 7,213 / 4 | 0.99945 | 79/91 | 29/1,040 | 8/87,489 |
| No raw IP and no port | 7,159 / 58 | 0.99196 | 16/91 | 0/1,040 | 39/87,489 |
| Port rule only | 7,216 / 1 | 0.99986 | 0/91 | 0/1,040 | 0/87,489 |

Removing IP and port does not remove B detection because the DGA fan-out and
timing counters are still present. That is a genuine behavioral signature of
this campaign, but it is still the same campaign. None of these variants tests
an unseen campaign.

### 8.3 S4: time-forward burst holdout

S4 trains on the 16:49 burst, validates on the 16:50 burst, and tests on the
17:15 burst plus all later background. It removes the interleaving and includes
the benign traffic that follows the final burst.

| S4 test slice | Events | Positives | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| All (blend) | 104,055 | 16,457 | 16,425 | 0 | 32 | 1.00000 | 0.99806 | 0.99903 |
| Campaign B | 16,386 | 16,386 | 16,384 | 0 | 2 | 1.00000 | 0.99988 | 0.99994 |
| Campaign A | 71 | 71 | 41 | 0 | 30 | 1.00000 | 0.57746 | 0.73214 |
| BOTSv1 background | 86,558 | 0 | 0 | 0 | 0 | — | — | — |
| Local live flows | 1,040 | 0 | 0 | 0 | 0 | — | — | — |

The `dst_port == 6892` rule again gets exactly the same B slice: 16,384/16,386,
0 false positives. The test B IPs are also not new: **16,384 of 16,386** were
present in the training burst. S4 therefore confirms temporal consistency of
this known infrastructure, not generalization to a new campaign or new
infrastructure.

The S4 result is still useful as a negative control: a strictly time-forward
model can keep local false positives at zero, but that does not validate the
S1 promotion claim.

### 8.4 Cross-campaign S2/S3: the clean generalization test

These are the only scenarios where the test campaign is absent from training.

**S2 A→B.** Train on Campaign A, test on Campaign B (48,199 B events), plus
later A, background, and local flows.

| S2 component | Threshold | A late recall | B recall | Local FP | BOTSv1 background FP |
|---|---:|---:|---:|---:|---:|
| Supervised | 0.8641 | 75/84 (0.893) | **0/48,199** | 0/1,040 | 0/109,254 |
| Blend | 0.6240 | 84/84 (1.000) | **0/48,199** | 0/1,040 | 0/109,254 |
| IF only | 0.8939 | 31/84 (0.369) | 48,198/48,199 | 887/1,040 | 11,033/109,254 |

The supervised head scores B at essentially zero (maximum **3.3e-6**). The IF
component does rank B as anomalous, but it is unusable: it flags 85.3% of local
flows and 10.1% of BOTSv1 background. There is no clean low-local-FPR operating
point that detects B.

The earlier claim “0 at every threshold tested” was too strong. At a blend
threshold of 0.590, the model recovers 32,769/48,199 B but flags 146/1,040 local
flows (14.0%) and 1,494/109,254 background events. The correct statement is:
**no deployable low-local-FPR threshold detects B**.

**S3 B→A.** Train on Campaign B, test on Campaign A (417 A events).

| S3 component | Threshold | A recall | B recall | Local FP | BOTSv1 background FP |
|---|---:|---:|---:|---:|---:|
| Supervised | 0.8484 | **0/417** | 3/3 | 0/1,040 | 0/442,505 |
| Blend | 0.8962 | **0/417** | 3/3 | 0/1,040 | 1/442,505 |
| IF only | 0.9282 | 80/417 (0.192) | 3/3 | 310/1,040 | 51,343/442,505 |

Again, the IF component finds some A events only by flagging 29.8% of local
flows and 11.6% of all BOTSv1 background. The supervised and blend heads do not
transfer at all.

**Interpretation.** The model is a known-campaign detector, not a universal
zero-shot detector. S2 and S3 are the defensible generalization results; they
show no clean transfer. S1 and S4 show that the model can recognize the known
Campaign B infrastructure (especially port 6892 and the DGA burst pattern), but
that is not evidence that it will catch a new campaign.

### 8.5 Promotion decision and rollback

The S1 result was used to promote **v122** (`xgboost+platt`, threshold
0.7485130264214555). Because S1 is not a valid holdout, the promotion is
retracted. **v122 has been rolled back; v121 is live again.**

Current live state:

| File | Version | Threshold | Notes |
|---|---:|---:|---|
| `database/model.bundle.joblib` | 121 | 0.609069609283942 | live, `random_forest+platt` |
| `database/model_meta.json` | 121 | 0.609069609283942 | live metadata |
| `database/model.bundle.v122.joblib` | 122 | 0.7485130264214555 | archived candidate |
| `database/model_meta.v122.json` | 122 | 0.7485130264214555 | archived candidate metadata |
| `database/model.bundle.v121.joblib` | 121 | 0.609069609283942 | preserved rollback copy |

The live `baraq` database was not modified. To restore the archived candidate
for research only:

```bash
cp database/model.bundle.v122.joblib database/model.bundle.joblib
cp database/model_meta.v122.json database/model_meta.json
```

Do not do that for deployment without a new, campaign-held-out validation and a
single-feature baseline check.

Why rollback instead of keeping v122:

- The promotion gate (S1) is invalid; its B score is matched by a one-feature
  rule.
- S2/S3 show no cross-campaign transfer at a deployable local-FPR budget.
- The local holdout does not show a v122 improvement: both v121 and v122 have
  0/1,040 local false positives on the same S1 local test, and there are no
  local attack positives to prove a recall gain.
- v121 is the established live model; keeping it avoids deploying a
  BOTSv1-specific classifier on the strength of an artifact.

### 8.6 What would count as a valid improvement

A future promotion should require all of the following:

1. A test campaign with **new infrastructure** (new destination host/IP/port or
   a genuinely new behavior), not a random IP subset of the same burst.
2. **Contemporaneous benign traffic** from the same hosts and time window, so
   false positives during the attack are measured.
3. A **strict time-forward split** or a campaign-held-out split, with features
   recomputed causally per split.
4. A **single-feature baseline** table (port, IP range, TI flag) to prove the
   model is adding signal beyond a trivial rule.
5. Threshold selection on an independent validation set that does not share the
   test campaign or burst.
6. A local benign holdout with enough traffic to estimate the false-positive
   rate, not just a handful of flows.

### 8.7 Context-feature audit (retracted)

A later experiment added 48 causal process/destination-context features
(`scripts/bench_botsv1_context_features.py`). On S2 it appeared to solve the
cross-campaign failure:

| S2 variant | Threshold | B recall | A late recall | Local FP | BOTSv1 background FP |
|---|---:|---:|---:|---:|---:|
| Full 77-feature context blend | 0.6553 | 48,197/48,199 | 84/84 | 1/1,040 | 14/109,254 |
| Same model, path/image columns zeroed | 0.5994 | **1/48,199** | 84/84 | 0/1,040 | 0/109,254 |

The gain is a **dataset artifact**, not a behavioral improvement:

- Local rows in this benchmark have no process path (`image` is empty), while
  BOTSv1 rows carry the full path. A path-presence feature therefore separates
  local from BOTSv1 by construction.
- A single feature, `image_entropy`, flags 48,197/48,199 B and 84/84 A at a
  threshold selected for zero local false positives. `image_len` alone flags B
  with zero A recall. These are Campaign-B path fingerprints.
- Removing path/image shape columns collapses B recall to one event even though
  process-destination history remains.
- S3 is unaffected: B→A still detects **0/417** at a deployable threshold; at
  the local-1% point it detects 4/417 while flagging 12,467 background rows.

The context result is therefore **retracted for deployment and promotion**.
The matrix and script are retained only as a reproducible negative result and
as an example for the feature-artifact gate in
[`docs/ml-deployment-readiness.md`](ml-deployment-readiness.md). They must not be
used to justify a model promotion, and context features are not integrated into
the runtime bundle.

## 9. Reproduce

```bash
cd /home/haaraphel/BARAQ
export PYTHONPATH=/home/haaraphel/BARAQ
export BARAQ_DATABASE_URL='postgresql+psycopg://postgres:postgres@127.0.0.1:5432/baraq_ml_bench'

# Optional: validate the raw parser / rebuild the BOTSv1 rows from the gzip.
.venv/bin/python scripts/botsv1_raw.py --assert-counts

# The checked-in benchmark DB already contains the 5,201 local flows. The CSV
# snapshot makes the local hard negatives reproducible without the live DB.
.venv/bin/python scripts/build_botsv1_bench.py \
  --raw-source datasets/botsv1/sysmon.json.gz \
  --local-source datasets/botsv1_bench/local_flows.csv

.venv/bin/python scripts/bench_botsv1_features.py
.venv/bin/python scripts/bench_botsv1_splits.py
.venv/bin/python scripts/bench_botsv1_score_live.py

# S1 diagnostic and ablations.
.venv/bin/python scripts/bench_botsv1_train.py --scenario S1 --tag _v1
.venv/bin/python scripts/bench_botsv1_train.py --scenario S1 --tag _noip --zero-cols 8,9
.venv/bin/python scripts/bench_botsv1_train.py --scenario S1 --tag _noport --zero-cols 15,16
.venv/bin/python scripts/bench_botsv1_train.py --scenario S1 --tag _noipport --zero-cols 8,9,15,16

# S4 time-forward burst control.
.venv/bin/python scripts/bench_botsv1_train.py --scenario S4 --tag _v1

# Cross-campaign tests.
.venv/bin/python scripts/bench_botsv1_train.py --scenario S2 --tag _v1
.venv/bin/python scripts/bench_botsv1_train.py --scenario S3 --tag _v1

# One-feature baselines and split-composition checks.
.venv/bin/python scripts/bench_botsv1_diagnostics.py

# Research-only context scan. The result is retracted in §8.7; do not use it
# for a promotion decision.
.venv/bin/python scripts/bench_botsv1_context_features.py
.venv/bin/python scripts/bench_botsv1_train.py \
  --scenario S2 --tag _ctx --features features_context.npz

# Optional local-FPR analysis.
.venv/bin/python scripts/bench_botsv1_analyze.py --scenario S1 --tag S1_v1

# Do not promote on S1. A new campaign-held-out validation is required first.
```

The benchmark database is disposable. Do not point `BARAQ_DATABASE_URL` at the
live `baraq` database when running research imports. The raw parser is
self-contained and reproduces the label counts exactly; the local-benign
snapshot is the only input not derivable from raw BOTSv1.

## 10. Lessons

- A holdout by random destination IP is not a campaign holdout. If the source
  host, port, time burst, and behavioral pattern remain, the model is still
  tested on the same campaign.
- A near-perfect score on a single campaign is a warning sign, not a success
  metric. Always compute a one-feature baseline before promoting.
- Validation and test drawn from the same burst can be perfectly separable
  without measuring real-world false positives.
- The honest result for an unseen BOTSv1 campaign is S2/S3: the supervised and
  blend heads do not transfer at a usable local-FPR budget.
