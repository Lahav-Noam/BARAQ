# BOTSv1 network model benchmark (draft)

Status: **final**. The benchmark data, labels, splits, S1/S2/S3 runs, ablations,
and live-baseline comparison are complete. The S1 candidate was promoted to the
live bundle as **v122**; the v121 bundle and metadata are preserved for
rollback. The main caveat is that this is a known-campaign detector, not a
universal zero-shot detector: S2 and S3 show no cross-campaign transfer.

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
- Network positives: 48,199 DGA connections across 16,387 destination IPs in
  approximately 26 minutes (16:49–17:15 UTC).

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

Random row splits are not used. They would let the model memorize destination
IPs or host/time context. Three grouped/time-based scenarios are evaluated.

| Scenario | Train | Validation | Test | Purpose |
|---|---:|---:|---:|---|
| S1 within-campaign | 456,096 | 112,380 | 95,837 | B held out by unseen destination IP; A and background held out by time; local held out by time |
| S2 A→B | 405,572 | 100,164 | 158,577 | Train on Campaign A, test on Campaign B |
| S3 B→A | 140,667 | 79,681 | 443,965 | Train on Campaign B, test on Campaign A |

Counts are totals including the local benign flows assigned to that split.

S1 test composition: 7,308 positives (B 7,217, A 91), 87,489 BOTSv1 benign,
1,040 local benign flows.

S2 test composition: 48,283 positives (B 48,199, A late 84), 109,254 BOTSv1
benign, 1,040 local benign flows.

S3 test composition: 420 positives (A 417, B 3), 442,505 BOTSv1 benign, 1,040
local benign flows.

S1 is the primary promotion gate because it contains both campaigns, real benign
background, and local hard negatives. S2/S3 measure cross-campaign
generalization and expose reliance on campaign-specific indicators such as the
Campaign A C2 IP.

## 6. Current live model baseline

Evaluated bundle: **v121**, `random_forest+platt`, feature version 7, network
threshold **0.609069609283942**, trained on 323 local samples.

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
campaign at its deployed threshold.

The score distribution is also knife-edged on local traffic. The largest local
score is 0.604858; a threshold just above it flags 0 of 5,201 local flows and
1 of 48,616 BOTSv1 positives. A threshold one epsilon below it (0.604857) flags
2,568 local flows (49.4%) and still only 2 BOTSv1 positives. Naive threshold
reduction is therefore not a fix.

Implication: the comparison is not “can we beat 0.609?” but “can a retrained
model detect BOTSv1 campaigns while keeping local false positives at or near
zero?” The live bundle must remain in place unless the holdout shows that
improvement.

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

## 8. Results

### 8.1 S1 primary holdout

Selected candidate: **blend**, threshold **0.7485130264214555**, selected on the
validation split only (maximum validation F1; the lowest threshold on the
perfect-validation plateau). The threshold is 0.0763 above the largest local
validation score (0.6722), so it is not sitting on a local tie.

| S1 test slice | Events | Positives | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| All | 95,837 | 7,308 | 7,302 | 1 | 6 | 0.99986 | 0.99918 | 0.99952 |
| Campaign B | 7,217 | 7,217 | 7,216 | 0 | 1 | 1.00000 | 0.99986 | 0.99993 |
| Campaign A | 91 | 91 | 86 | 0 | 5 | 1.00000 | 0.94505 | 0.97175 |
| BOTSv1 background | 87,489 | 0 | 0 | 1 | 0 | — | — | — |
| Local live flows | 1,040 | 0 | 0 | 0 | 0 | — | — | — |

Test ROC-AUC: **0.99999987**; average precision: **0.9999984**.

Validation (threshold selection) had 7,301/7,301 positives and 0/105,079
negatives flagged; local validation was 0/520. The perfect validation
separation is a warning sign, not a success by itself, so S2/S3 are used to
check cross-campaign generalization.

The six missed test positives were five `php-cgi.exe` connections to
`108.161.187.134:80` on 2016-08-23/26 and one `osk.exe` DGA connection to
`54.148.194.58:80`. The single false positive was benign `svchost.exe` LLMNR
traffic from `we1149srv` (`e000:fc:0:0:0:0:0:0:5355`).

Component comparison at their validation-selected thresholds:

| Component | S1 test F1 | B recall | A recall | Local FP | BOTSv1 background FP |
|---|---:|---:|---:|---:|---:|
| IF only | 0.8188 | 0.9988 | 0.0110 | 336/1,040 | 3,091 |
| Supervised only | 0.99986 | 1.0000 | 0.9890 | 0/1,040 | 0 |
| Blend | 0.99952 | 0.99986 | 0.9451 | 0/1,040 | 1 |

The IF-only model is unusable for local traffic (32.3% local FPR). The
supervised head carries the result; the blend is selected because it matches
the deployed `0.6*IF + 0.4*supervised` scoring path and keeps local FPR at zero
on the holdout.

### 8.2 S2 A→B and S3 B→A

These are zero-shot cross-campaign checks: S2 trains on Campaign A and tests on
Campaign B; S3 trains on Campaign B and tests on Campaign A.

**S2 A→B (completed).** The model trained on Campaign A detects **0 of 48,199
Campaign B events** at every threshold tested. It does detect held-out later
Campaign A traffic, so this is a campaign-generalization failure rather than a
broken split:

| S2 component | Threshold | A late recall | B recall | Local FP | BOTSv1 background FP |
|---|---:|---:|---:|---:|---:|
| Supervised only | 0.8643 | 71/84 (0.845) | 0/48,199 | 0/1,040 | 0/109,254 |
| Blend | 0.7869 | 60/84 (0.714) | 0/48,199 | 0/1,040 | 0/109,254 |
| Blend, aggressive | 0.5991 | 84/84 (1.000) | 0/48,199 | 4/1,040 | 65/109,254 |

The aggressive threshold is the 1% local-FPR validation budget. It proves the
model can recover all later A events, but still cannot see B at all. Campaign A
and Campaign B have structurally different network behavior (single-IP C2
versus high-volume DGA fan-out), and a model trained on one does not
automatically transfer to the other. The promoted S1 model is trained on both
known campaigns; this result is the reason it must be treated as a
known-campaign detector, not as universal coverage.

**S3 B→A (completed).** The model trained on Campaign B detects **0 of 417
Campaign A events** at the validation-selected supervised/blend thresholds. It
does detect the 3 Campaign B events that leaked into the test window, so the
model is not broken; it simply does not transfer to the A campaign.

| S3 component | Threshold | A recall | B recall | Local FP | BOTSv1 background FP |
|---|---:|---:|---:|---:|---:|
| Supervised only | 0.8484 | 0/417 (0.000) | 3/3 (1.000) | 0/1,040 | 0/442,505 |
| Blend | 0.8962 | 0/417 (0.000) | 3/3 (1.000) | 0/1,040 | 1/442,505 |
| IF only | 0.9282 | 80/417 (0.192) | 3/3 (1.000) | 310/1,040 | 51,653/442,505 |

The IF-only row is not a usable detector; it buys a small amount of A recall by
flagging 11.7% of all BOTSv1 benign background and 29.8% of local flows.

**Interpretation.** S1 demonstrates that a model trained on both campaigns can
detect both known campaigns with zero local false positives. S2 and S3
demonstrate that this is *within-campaign* generalization, not universal
zero-shot detection. A model trained on Campaign A detects none of B; a model
trained on B detects none of A. The S1 A holdout is time-based, not IP-based,
so its 94.5% A recall may be assisted by the recurring C2 IP. The B holdout is
by unseen destination IP but still shares the source host and DGA burst; it is
not a fully unseen campaign. The ablation in §8.4 shows that the B signal
survives removal of raw IP features, so it is behavioral rather than pure IP
memorization, but S2 remains the cleaner cross-campaign test.

### 8.3 Feature-importance and leakage checks

The S1 supervised head's top features (mean XGBoost gain across the calibration
folds) are:

| Feature | Importance |
|---|---:|
| `conn_count` (destination connection count) | 0.394 |
| `dst_ip_num` (raw destination IP as a number) | 0.253 |
| `conn_count50` (capped connection count) | 0.199 |
| `time_since_dst` (time since previous connection to IP) | 0.110 |
| `dst_port_norm` | 0.013 |
| `src_ip_num` | 0.013 |

The threat-intel flags `is_atk` and `is_atk_src` (features 21–22) have **zero**
gain, so the S1 A result is not driven by the C2 IP being present in the TI
feed. The high `dst_ip_num` importance is still a memorization risk; this is
exactly what the S2/S3 cross-campaign checks and the `--zero-cols 8,9` ablation
are intended to expose. Campaign B's unseen-IP holdout is the strongest
behavioral evidence: it keeps 99.99% recall even though every test destination
IP is new.

### 8.4 Raw-IP ablation

To separate behavior from IP memorization, the S1 model was retrained with
features 8 and 9 (`src_ip_num`, `dst_ip_num`) zeroed. Everything else was held
constant.

| S1 variant | Threshold | B recall | A recall | Local FP | BOTSv1 background FP |
|---|---:|---:|---:|---:|---:|
| With raw IPs (promoted blend) | 0.7485 | 7,216/7,217 (0.99986) | 86/91 (0.945) | 0/1,040 | 1/87,489 |
| No raw IPs (blend) | 0.8766 | 7,216/7,217 (0.99986) | 25/91 (0.275) | 0/1,040 | 1/87,489 |

Removing the raw IP features leaves Campaign B recall unchanged, so the B
result is behavioral (repeated connections and timing), not destination-IP
memorization. Campaign A recall falls from 94.5% to 27.5%, confirming that the
A result is substantially assisted by the recurring C2 IP. The no-IP model is
an ablation only; it is not deployable through the current feature pipeline
without a transform that zeros those columns at inference.

The threat-intel flags (`is_atk`, `is_atk_src`) already have zero gain in the
full model, so a separate no-TI run was not needed.

### 8.5 Full-benchmark sanity check and promotion

At the promoted threshold, scoring the full benchmark (including training rows;
this is a sanity check, not a holdout) gives:

| Slice | TP | FP | FN | Recall | Notes |
|---|---:|---:|---:|---:|---|
| All | 48,602 | 1 | 14 | 0.99971 | 664,313 events |
| Campaign B | 48,196 | 0 | 3 | 0.99994 | 48,199 positives |
| Campaign A | 406 | 0 | 11 | 0.97362 | 417 positives |
| Local flows | 0 | 0 | 0 | — | 0/5,201 flagged |
| BOTSv1 background | 0 | 1 | 0 | — | one `svchost.exe` LLMNR event |

The defensible holdout numbers remain the S1 test figures in §8.1: 7,302/7,308
positives, 1 FP, 6 FN, 0 local FP. The full-benchmark figures merely confirm
that the saved bundle reproduces the same behavior across the whole corpus.

**Promotion.** The S1 blend was promoted to the live bundle as **v122**,
threshold **0.7485130264214555**. The v121 bundle and metadata are preserved:

- `database/model.bundle.v121.joblib`
- `database/model_meta.v121.json`
- promoted copies: `database/model.bundle.v122.joblib`,
  `database/model_meta.v122.json`

Rollback:

```bash
cp database/model.bundle.v121.joblib database/model.bundle.joblib
cp database/model_meta.v121.json database/model_meta.json
```

The promoted model detects the two known BOTSv1 campaigns with zero local
false positives, but S2/S3 show that it does not generalize to a structurally
new campaign. Keep threat intelligence and local labeled retraining in the
loop; do not treat v122 as universal coverage. The live `baraq` database was
not modified, and no `main`/security-batch code was rewritten.

## 9. Reproduce

```bash
cd /home/haaraphel/BARAQ
export PYTHONPATH=/home/haaraphel/BARAQ
export BARAQ_DATABASE_URL='postgresql+psycopg://postgres:postgres@127.0.0.1:5432/baraq_ml_bench'

# Optional: validate the raw parser / rebuild the BOTSv1 rows from the gzip.
.venv/bin/python scripts/botsv1_raw.py --assert-counts

# The checked-in benchmark DB already contains the 5,201 local flows.  The CSV
# snapshot makes the local hard negatives reproducible without the live DB.
.venv/bin/python scripts/build_botsv1_bench.py \
  --raw-source datasets/botsv1/sysmon.json.gz \
  --local-source datasets/botsv1_bench/local_flows.csv

.venv/bin/python scripts/bench_botsv1_features.py
.venv/bin/python scripts/bench_botsv1_splits.py
.venv/bin/python scripts/bench_botsv1_score_live.py
.venv/bin/python scripts/bench_botsv1_train.py --scenario S1 --tag _v1
.venv/bin/python scripts/bench_botsv1_train.py --scenario S2 --tag _v1
.venv/bin/python scripts/bench_botsv1_train.py --scenario S3 --tag _v1
.venv/bin/python scripts/bench_botsv1_train.py --scenario S1 --tag _noip --zero-cols 8,9
.venv/bin/python scripts/bench_botsv1_analyze.py --scenario S1 --tag S1_v1
.venv/bin/python scripts/bench_botsv1_score_candidate.py --threshold 0.7485130264214555
.venv/bin/python scripts/bench_botsv1_promote.py --scenario S1 --tag S1_v1 \
  --threshold 0.7485130264214555 --supervised-name xgboost+platt
```

The benchmark database is disposable. Do not point `BARAQ_DATABASE_URL` at the
live `baraq` database when running research imports. The raw parser is
self-contained and reproduces the label counts exactly; the local-benign
snapshot is the only input not derivable from raw BOTSv1.
