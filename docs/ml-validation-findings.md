# ML validation findings — from point-mass scores to a measurable operating point

Status: **not production-ready for autonomous response.** The scoring collapse
that produced the earlier "100 % recall / 0 % FPR" headlines is fixed and the
detector now emits a genuine per-event ranking on login and process. What is
still missing is evidence from real labelled telemetry, a usable network
stream, and a threshold that transfers from calibration to a future window — the
configured login boundary flags 17.6 % of benign logins (95 % CI 15.0–20.6)
against a 5 % budget.

Headline numbers are pooled over three corpus seeds with Wilson intervals
(`reports/ml_multiseed_hard.json`); a single-seed table is included for detail.


This document records the method, the measured numbers before and after the
fix, and the exact blockers that remain.

## Method

`scripts/validate_ml.py` is the reproducible harness:

1. Load every login/process event, chronologically.
2. Train on the first 80 % with an explicit `cutoff`, in-memory
   (`persist=False`), so the evaluation window is never seen during fitting.
3. Score the held-out tail through the deployed path
   (`event_feature_vector` → `score_events`), one stream at a time, exactly as
   ingest does.
4. Label with the analyst feedback loop (`verdicts`), with
   `raw_json.seed_label` as a documented secondary reference for synthetic
   corpora.
5. Report recall / FPR / precision at the configured threshold, a threshold
   sweep, the best recall achievable inside 1 / 5 / 10 / 20 % FPR, the
   recommended calibrated threshold, and **score health** (how many distinct
   scores the stream actually emits). A stream with fewer than 10 distinct
   benign scores gets **no recommendation** — a midpoint between four values
   would otherwise report "100 % recall at 0 % FPR" that means nothing.

`scripts/validate_ml_multiseed.py` repeats the whole run over several corpus
seeds and pools the counts with Wilson 95 % intervals, because one synthetic
draw cannot distinguish a detector property from a campaign-ordering artefact.

`scripts/seed_validation_telemetry.py` produces the corpus used here when no
real telemetry exists: 35 days, 5 578 events, **1.76 % attack prevalence**,
chronological campaigns (password spray → credential access → execution,
persistence, night lateral movement, C2 beaconing, account-lockout sweep),
stable per-user work hours/hosts/process mixes, and 926 analyst verdicts
(98 confirmed attacks + 828 benign closed as false positives).

`--hard-mode` removes the indicators that the offline labeler hardcodes
(TEST-NET `203.0.113.*` / `198.51.100.*` / `192.0.2.*` / `45.*` source IPs) and
the well-known tool names in `_is_attack_sample` (`mimikatz`, `procdump`,
`nc.exe`, ...). Behaviour is unchanged; only the giveaway strings are gone, so
a detection that survives hard mode cannot be explained by threat-intel
lookup.

Reproduce with:

```bash
# easy corpus (labeler shortcuts present - optimistic ceiling)
python scripts/seed_validation_telemetry.py --days 35 --users 20
python scripts/validate_ml.py --holdout-fraction 0.2

# hard corpus (shortcuts removed - the honest number)
python scripts/seed_validation_telemetry.py --days 35 --users 20 --hard-mode
python scripts/validate_ml.py --holdout-fraction 0.2

# several seeds, pooled with confidence intervals
python scripts/validate_ml_multiseed.py --seeds 1,2,3 --hard-mode
```

## Results — hard mode, 3 corpus seeds (pooled)

Configured FPR budgets are per stream (`ML_STREAM_FPR`): login 5 %, process
15 %, network 10 %. The harness gate is deliberately a flat 10 % for every
stream, which is stricter than the process budget. Counts are pooled across
seeds; brackets are Wilson 95 % intervals.

| Stream  | Events (pos/neg) | Configured thr: recall | FPR | Recalibrated (≤10 % gate) | Score health |
|---------|------------------|------------------------|-----|---------------------------|--------------|
| login   | 66 / 715         | 100 % [94.5, 100]      | **17.6 % [15.0, 20.6]** | 100 % @ 5.6 % [4.1, 7.5] | 65–70 distinct benign scores, 0/3 degenerate |
| process | 21 / 1 954       | 90.5 % [71.1, 97.4]    | 0 % [0, 0.2]            | 95.2 % [77.3, 99.2] @ 0 % | 310–344 distinct benign scores, 0/3 degenerate |
| network | 60 / 608         | **0 % [0, 6.0]**       | 0 % [0, 0.6]            | **none — degenerate** | 4 distinct benign scores, 3/3 degenerate |

Reading that table honestly:

* **Re-running the same three seeds moved the login FPR from 18.3 % to 17.6 %**
  and shifted individual thresholds (seed 2 login: 0.537 → 0.503). The
  supervised stage is not bit-reproducible under multithreading, so the
  intervals above are sampling intervals over held-out events only; they do not
  include training variance. Treat differences under ~2 points as noise.
* **Login ranks, but the configured threshold over-alerts by design.** All 66
  held-out attacks are found, and 17.6 % of benign logins are flagged — about
  3.5× the 5 % budget. This is consistent across three independent draws
  (15.0–20.6 %), so it is a systematic property of fitting the boundary before
  the campaigns happen, not seed luck. Recalibrating *on the scored window*
  lands at 5.6 %, but that number is optimistic by construction: it fits the
  window it measures. Treat 5.6 % as a floor and 17.6 % as what the shipped
  model actually did on the next week.
* **Process is real but small-n.** 21 positives across three seeds → 90.5 %
  recall, interval 71–97 %. Zero false positives in 1 954 benign events only
  bounds FPR at ≤ 0.2 %. The stream is no longer degenerate (310–344 distinct
  benign scores), which is the part the fix guarantees; the recall figure needs
  more positives before it means anything precise.
* **Network still has no operating point.** 0 % recall at the configured
  threshold across all three seeds, and only **4 distinct benign scores**. The
  harness now refuses to recommend a threshold below 10 distinct benign scores,
  so this stream is reported `UNVALIDATED` instead of headlining a fictitious
  "100 % @ 0 %" that a midpoint between four values would produce.

### Single-seed detail (seed 1, 911 held-out events, 29 attacks)

| Stream  | Configured thr | Recall @ thr | FPR @ thr | Recalibrated | Score health |
|---------|---------------|--------------|-----------|--------------|--------------|
| login   | 0.5397        | 100 %        | 12.8 %    | 100 % @ 5.6 % | 65 distinct benign scores |
| process | 0.6056        | 100 %        | 0.0 %     | 100 % @ 0.0 % | 310 distinct benign scores |
| network | 0.9556        | 0 %          | 0.0 %     | not measurable | 4 distinct benign scores |

The threshold *values* are not comparable between seeds (seed 3 calibrated
login to 0.188 and still found every attack), which is why the report leads
with pooled rates rather than a threshold number.

Reading that table honestly:

* **Login now ranks.** Before the fix the 22 held-out logins collapsed into
  three score values and topped out at 31.8 % recall at a 10 % FPR budget.
  Now the whole attack set sits above the 94th percentile of benign logins.
  The gain came from removing the isotonic collapse (which had flattened the
  benign class) and from calibrating the boundary on out-of-fold scores; the
  per-stream meta itself was rejected on this corpus because it did not beat
  the blend (AUC 0.973 vs 0.981), which is the gate doing its job.
* **The configured threshold does not transfer.** Calibration on out-of-fold
  predictions measured 4.7 % FPR at the 5 % budget; the following week
  realised 12.8–20.5 % depending on the draw. The model is fitted before the
  campaigns happen, so this is distribution shift, not a tuning bug. Production
  needs a shadow window to re-fit the boundary (see the deployment section).
* **Process still looks perfect, but n = 7.** 7/7 positives gives a Wilson
  95 % interval of roughly 65–100 %; 0/648 false positives only bounds FPR at
  ≤ 0.5 %. The stream is no longer degenerate (317 distinct benign scores),
  so this is a real ranking rather than a point mass — it is simply too few
  positives to claim more.
* **The network stream is not validated.** It has no labelled attacks inside
  the training window (all C2 beacons fall after the cutoff), and the per-IP
  aggregate vector emits only 4 distinct values across 195 benign held-out
  events. A threshold on 4 values is a coin flip. Until it is trained on
  `NetworkConnection` rows with labelled history, network alerts should be
  treated as unmeasured.

### Before / after (before = 1 seed, pre-fix; after = 3 seeds, pooled)

| Stream  | Before recall @ FPR | After recall @ FPR | What changed |
|---------|---------------------|--------------------|--------------|
| login   | 31.8 % @ 9.5 %      | **100 % @ 17.6 %** configured, 5.6 % after recalibration | monotone (Platt) calibration restored ranking; out-of-fold threshold replaced the in-sample one. The per-stream meta was *rejected* by its AUC gate (0.973 vs 0.981 for the blend), so the improvement is calibration + thresholding, not a new model. |
| process | 100 % @ 0.0 % (degenerate) | **90.5 % @ 0.0 %** (real ranking) | honest recall replaces a point-mass artefact; the score now varies per event (310–344 vs 1 distinct benign value) |
| network | 0 % @ 0.0 % (degenerate)   | 0 % (still unvalidated) | unchanged; needs labelled history |

The trade is deliberate: the fix turned a silent failure into an honest
over-alert. Ranking is solved; choosing an operating point that respects the
budget is not, and that is now visible instead of hidden behind a 0 % FPR.


## Why the earlier "100 % recall / 0 % FPR" was not real

Measured on the held-out tail of the pre-fix easy-mode run:

| stream | benign scores | attack scores |
|---|---|---|
| process | 648 events, **all exactly 0.000539** (1 distinct value) | 7 events, 3 distinct values, min 0.156 |
| network | 191 events, **all exactly 0.284519** | 20 events, **all exactly 0.960902** |
| login | 231 events, 28 distinct values, mode 0.000539 | 22 events, 3 distinct values, min 0.527 |

Two mechanisms produced that:

1. **Isotonic calibration on a tiny positive count.** `CalibratedClassifierCV`
   with `method="isotonic"` is piecewise constant. With a handful of
   positives it maps the entire benign region to one probability, throwing
   away the classifier's ranking. Every benign process event then received
   exactly `0.000539`.
2. **A single pooled meta-learner fitted on in-sample predictions.** All
   streams were concatenated, so the pooled positive rate dominated the rare
   stream and the learner emitted its prior for ordinary events. Model
   selection used *training accuracy*, which a depth-3 gradient booster always
   wins by memorising its leaves.

"100 % recall / 0 % FPR" was a threshold sitting in the empty gap between two
point masses. It said nothing about which event to look at first.

The report itself also lied: `_recall_at_fpr` sorted `(score, label)`
descending, so on tied scores the positives were counted before the negatives
and a stream with identical scores for everything reported "100 % recall at
0 % FPR". Ties are now handled as score buckets.

## Bugs found and fixed

### 1. Per-stream meta-learners trained on out-of-fold predictions
`backend/ml/ensemble.py` — new `PerStreamStacker` holds one learner per
behaviour. Each is trained on predictions from a throwaway copy of the base
models fitted on the first 75 % of the stream, evaluated on the last 25 %, so
the meta never sees its own training rows. A learner is only **accepted** if it
beats the plain `0.6*rank + 0.4*proba` blend on hold-out AUC *and* emits more
than one distinct benign score; otherwise the stream stays on the blend and the
decision is recorded in `stream_health` / the ensemble status.

### 2. Model selection by cross-validated AUC, not training accuracy
`EnsembleStacker.train_meta` now selects between logistic regression and
gradient boosting with `_cv_auc` (stratified, time-ordered) and only considers
boosting when there are ≥ 30 positives. The previous selection could never
pick anything but the booster, which is how the pooled learner collapsed.

### 3. Isotonic calibration only with enough data
`_build_classifier` keeps isotonic (≥ 200 positives and ≥ 2 000 negatives) and
uses Platt scaling otherwise. Platt is strictly monotone, so per-event ranking
survives calibration.

### 4. Thresholds come from out-of-fold scores
`_threshold_from_scores` picks the operating point from the deployed scoring
path on rows the fold models never saw, instead of the in-sample CFAR quantile.
That is what makes a configured FPR budget meaningful. The provenance
(`out-of-fold` vs `cfar-only`, positives/negatives, measured recall/FPR) is
returned by `train()` and written into the model metadata.

### 5. The meta-learner is persisted
The bundle never contained the ensemble, so every restart silently downgraded
scoring to the plain blend and live scores stopped matching the validated
model. `_save_bundle` / `_load_bundle` / `rollback` now carry the per-stream
learners.

### 6. Degenerate streams are reported, not hidden
`_stream_score_health` samples the most recent training rows and records how
many distinct scores a stream emits. `status()` exposes it, and
`validate_ml.py` prints a `WARNING: DEGENERATE STREAM` line plus a report-level
caveat.

### 7. Silent failures in evaluation
* `train()`'s hold-out block called `detector.score_events(...)` inside a
  method — `NameError`, swallowed, so `holdout_metrics` was always `{}`. It now
  calls `self.score_events(...)` and reports real numbers.
* `_tune_threshold` clamped the CFAR boundary to `[0.05, 0.98]`, unreachable
  for probability scores around `1e-3`, silently disabling two streams. The
  clamp now follows the observed score range instead of assuming `[0, 1]`
  uniformity.
* `score_events` swallowed feature-dimension mismatches as `0.0` scores. It
  logs the mismatch and falls back to per-row routing, which reports the real
  failure instead of a silent zero.
* `_recall_at_fpr` sorted `(score, label)` descending, so on ties positives were
  consumed before negatives and a single-score stream reported "100 % recall at
  0 % FPR". Ties are now handled as score buckets, and the threshold is rounded
  before comparison.


### 8. Login vectors were scored by the process model
`score_event` / `score_events` routed on `features[0]`, assuming it was the
event id. That is true for process vectors but **false for login vectors**,
which start with `logon_type` (`event_feature_vector` deliberately omits the
event id for login to avoid label leakage). Because the process stream contains
event ids `10` and `11` — which are also the RDP and cached logon types — a
real 37-dim login vector beginning with `logon_type=10` was handed to the 48-dim
process model. The mismatch path logged
`score_events: process feature dim 37 != model dim 48` and returned `0.0`, so
a subset of logins silently scored zero and could never alert.

Routing is now `_behavior_for_vector`: feature width decides first (37/38 for
login vs 48 for process), and the event id is only consulted when two streams
share a width. The fallback also logs instead of failing silently, and there is
a regression test asserting that a vector starting with `10.0` and 37 features
reaches the login model and never the process one.


## Remaining blockers

1. **No real labelled telemetry.** Every number here comes from a generator
   that I wrote. It can prove the pipeline is internally consistent and that
   the fixes work; it cannot prove detection quality on your estate.
2. **The labeler still shares signals with the features.** Hard mode removes
   the obvious indicator shortcuts, but rules such as "Office parent spawning
   an interpreter" and "writable-path binary" are both labels *and* features.
   A clean test needs analyst verdicts on real campaigns.
3. **Threshold transfer.** Out-of-fold calibration realised 4.7 % FPR, the
   next windows realised 12.8–20.5 % (pooled 17.6 %). Two things make the OOF
   estimate fragile: the hold-out slice is attack-enriched (73 positives / 263
   rows, versus 1.76 % in production), so the 95th percentile of the benign
   tail is estimated from only ~190 rows, and the campaigns themselves are what
   changed between the two windows. Re-fit the boundary on a shadow window
   before trusting the budget; a percentile from 190 benign rows is a point
   estimate with a wide interval, not a contract.
4. **Network stream.** No labelled attacks in the training window and 4
   distinct benign scores across three seeds. The harness now reports it as
   `UNVALIDATED` and refuses to recommend a threshold below 10 distinct benign
   scores. It needs per-connection features and labelled history before it can
   alert.
5. **Login still lacks sequence context.** A spray is a pattern (many failures
   per user/IP in minutes), not a single event. Per-event features cannot fully
   separate "one typo" from "attempt 9 of 40". The current detection relies on
   the surrounding fields (`sub_status`, lockout flags, night logon type), which
   is why it holds up on this corpus and may not on a quieter one.
6. **Small positive counts.** Process has 7 positives per seed (21 pooled),
   network 20 per seed. Intervals are wide by construction, and the process
   90.5 % recall is not evidence of a stable 90 %.
7. **The operating point, not the ranking, is the open problem.** Login ranks
   correctly (100 % recall at every threshold that admits the attacks) but the
   calibrated boundary flags ~18 % of benign logins on the next week. Fixing
   that is a calibration/monitoring problem: shadow scoring, re-fit on recent
   benign traffic, and alert on the budget rather than on a stored constant.

## Deployment recommendation

Do **not** set `BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED=1`.

1. `BARAQ_ML_DEPLOYMENT_MODE=shadow` — score without alerting.
2. Run `scripts/validate_ml.py --retrain-full --apply-thresholds` against a
   real shadow window to replace the out-of-fold thresholds with ones measured
   on production traffic.
3. Watch `stream_health` in `/api/ml/status`: a stream with fewer than 10
   distinct benign scores must not be thresholded, let alone actioned.
4. Only after a real-data run reports ≥ 80 % recall at ≤ 10 % FPR on login and
   process, with a non-degenerate score distribution, should destructive
   actions be considered.
