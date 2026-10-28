# ML validation findings — operating-point honesty and three detector bugs

Status: **not production-ready.** The detector ranks attacks very well on the
validation corpus, but its *deployed thresholds* were broken, and the login
stream cannot reach the 80 % recall target at a 10 % false-positive budget.

This document records how the numbers were produced, what was fixed, and what
still blocks an autonomous-response deployment.

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
   sweep, the best recall achievable inside 1 / 5 / 10 / 20 % FPR, and a
   recommended calibrated threshold.

`scripts/seed_validation_telemetry.py` produces the corpus used here when no
real telemetry exists: 35 days, 5 578 events, **1.76 % attack prevalence**,
chronological campaigns (password spray → credential access → execution,
persistence, night lateral movement, C2 beaconing, account-lockout sweep),
stable per-user work hours/hosts/process mixes, and 926 analyst verdicts
(98 confirmed attacks + 828 benign closed as false positives).

Reproduce with:

```bash
python scripts/seed_validation_telemetry.py --days 35 --users 20
python scripts/validate_ml.py --holdout-fraction 0.2
```

## Results (held-out tail: 908 scored events, 29 attacks)

Configured thresholds are what `train()` persisted. "Recommended" maximises F1
subject to `FPR <= 10 %` on the same window (therefore optimistic; recalibrate
on a shadow window in production).

| Stream  | Configured thr | Recommended thr | Recall | FPR  | Precision |
|---------|---------------|-----------------|--------|------|-----------|
| login   | 0.2561        | 0.9551          | 72.7 % | 2.6 %| 72.7 %    |
| process | 0.0005        | 0.0784          | 100 %  | 0.0 %| 100 %     |
| network | 0.0005        | 0.6227          | 100 %  | 0.0 %| 100 %     |

Recall inside an FPR budget (seed truth):

| Stream  | @1 % FPR | @5 % FPR | @10 % FPR | @20 % FPR |
|---------|----------|----------|-----------|-----------|
| login   | 0.0 %    | 72.7 %   | 72.7 %    | 100 %     |
| process | 100 %    | 100 %    | 100 %     | 100 %     |
| network | 100 %    | 100 %    | 100 %     | 100 %     |

### Interpretation

* **Process and network detection is genuinely strong** on this corpus: every
  injected execution/persistence/C2 event scores in the top cluster with no
  benign false positives, once the threshold is sane.
* **Login tops out at 72.7 % recall @ ≤10 % FPR.** The 6 missed attacks are the
  low-and-slow night lateral-movement `4624` type-3 logons (score 0.5268),
  which sit *below* the benign false-positive tail (single bad-password
  `4625` events score higher). Per-event features cannot separate "one failed
  logon" from "start of a spray"; this needs sequence/velocity context at
  scoring time.
* **Precision on this corpus is not representative.** Attack prevalence is
  1.76 %; a real estate is closer to 0.01–0.1 %, so live precision will be far
  lower for the same recall/FPR. Treat recall/FPR as the portable numbers.

## Bugs found and fixed

### 1. Hold-out evaluation never ran (`backend/ml/anomaly.py`)

```python
_scores = detector.score_events(...)   # NameError: 'detector' is not defined
```

The block is inside `train()`, so `detector` does not exist. The exception was
swallowed by `except Exception: logger.exception("Hold-out evaluation failed")`,
so every training run reported `holdout_metrics: {}` and the "honest hold-out
evaluation" feature never produced a number. Fixed to use `self`.

**Impact:** any claim of validated recall from `train()`'s `holdout_metrics`
was unsupported.

### 2. Threshold clamp produced unreachable thresholds (`_tune_threshold`)

```python
cfar = float(np.clip(cfar, 0.05, 0.98))
```

The clamp assumed the deployed score is roughly uniform over `[0, 1]` (true for
IsolationForest ranks). Once the probability-calibrated ensemble meta-learner
is active, a rare stream emits probabilities around `1e-3`, so the CFAR
quantile was clamped up to `0.05` — a value no event could exceed. The process
and network streams stopped alerting entirely while the dashboard still
reported "trained, thresholds present".

Fixed by clamping inside the observed score range. Measured effect: process
threshold `0.05 → 0.0006`, network `0.05 → 0.0006`, restoring the streams.

**Impact:** silent total loss of detection on two of three streams.

### 3. Batched scoring swallowed feature-space mismatches (`score_events`)

Both failure modes (`np.array` on ragged rows, `X.shape[1] !=
model.n_features_in_`) did a bare `continue`, leaving `0.0` scores. A schema
drift therefore looked like "no anomalies" rather than an error.

Fixed to log a warning and fall back to per-row scoring.

**Impact:** observability; a broken stream was indistinguishable from a quiet
one.

## Known issue still open — pooled, in-sample meta-learner

`_train_ensemble_meta()` concatenates **all streams** into one
gradient-boosted meta-learner and fits it on **in-sample** base predictions.
Two consequences:

1. Base rates are pooled, so a rare stream (process ≈ 0.1 % positives) is
   collapsed toward the pooled rate. In this corpus every benign process event
   receives the *identical* score `0.000567…`, i.e. the meta-learner emits its
   global base rate for that stream and only the attack tail escapes.
2. Thresholds are tuned on those in-sample scores, so the realised FPR does
   not match the configured budget (login: configured for 5 %, realised 15.2 %).

A constant benign score is still separable from an attack cluster, which is why
calibrated thresholds recover perfect process/network separation. But the
score is not a trustworthy probability, and the FPR budget is not honoured.

**Recommended fix:** one meta-learner per stream, trained on out-of-fold base
predictions (chronological split, not `RandomState` sampling), then tune
thresholds on a held-out calibration slice. Until then, treat the ensemble
output as an ordinal score and calibrate thresholds empirically.

## Deployment recommendation

Do **not** set `BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED=1`.

1. `BARAQ_ML_DEPLOYMENT_MODE=shadow` — score without alerting.
2. Run `scripts/validate_ml.py --retrain-full --apply-thresholds` against a
   real shadow window to replace the unreachable thresholds.
3. Watch login-stream recall; it is the limiting stream (72.7 % @ 10 % FPR).
4. Only after a real-data run reports ≥80 % recall at ≤10 % FPR on login and
   process should destructive actions be considered.
