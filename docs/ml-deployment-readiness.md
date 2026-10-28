# ML deployment readiness

Status: **shadow/advisory only (2026-10-27)**. The live bundle remains **v121**.
No ML-driven response action is enabled, and no model is promoted as a
general-purpose detector.

**High-level network detector (candidate track)**: See [`docs/ml-high-level-todo.md`](docs/ml-high-level-todo.md) for a separate research/deployment-candidate track with a 92-feature causal detector achieving 98-100% recall on BOTSv1 at 0.52% local FPR. This candidate is **not** a replacement for v121 and does not enable blocking.

This document is the operational contract for the ML layer. It exists because
the BOTSv1 benchmark produced a near-perfect result that did **not** survive an
independent audit. The fix is not a better headline number; it is a gate that
prevents the same class of result from reaching production again.

## 1. Current state

| Item | Value |
|---|---|
| Live bundle | `database/model.bundle.joblib`, version **121** |
| Live metadata | `database/model_meta.json`, feature version **7** |
| Training corpus | 323 local network samples; no local attack positives |
| Manifest | `database/model_manifest.json`, status **shadow** |
| ML mode default | `advisory` (event scores can inform analyst risk; no action) |
| Recommended rollout mode | `shadow` until local telemetry is reviewed |
| Enforcement | disabled; there is no `enforce` mode in the runtime |

v121 is a **local baseline**, not a proven attack classifier. BARAQ's rule and
correlation layers remain the primary detection path. The ML layer contributes
an anomaly opinion and monitoring data.

## 2. Modes

`BARAQ_ML_DEPLOYMENT_MODE` accepts:

| Mode | Event `ml_score` / `is_anomaly` | Network shadow rows | Risk contribution | Alerts/actions |
|---|---|---|---|---|
| `off` | not written | no | no | no |
| `shadow` | not written | yes | no | no |
| `advisory` | written | yes | analyst-facing risk only | no autonomous action |

Any unknown value falls back to `shadow`. There is deliberately no `enforce`
mode: a model cannot trigger a containment action through this layer.

The manifest status is separate from the runtime mode:

| Manifest status | Meaning |
|---|---|
| `validated` | Evidence passed the gate; advisory promotion is allowed. Enforcement still requires a separate response-action review. |
| `shadow` | Monitoring only. This is the current state. |
| `blocked` | The manifest is unreadable or internally inconsistent; runtime scoring is downgraded to `shadow`. |
| `missing` | No manifest was generated; enforcement is impossible, and scoring follows `BARAQ_ML_DEPLOYMENT_MODE` (default `advisory`). |

`GET /api/system/ml/deployment` returns the mode, manifest, recent shadow-score
distribution, and the highest-scoring flagged buckets. `GET /api/system/ml/status`
includes the same mode/manifest fields.

## 3. Promotion gate

A model may leave `shadow` only when **all** of the following are supplied to
`scripts/ml_deployment_gate.py`:

1. A genuinely independent campaign, not another IP subset of BOTSv1 A/B.
2. Contemporaneous benign traffic from the same hosts and time window.
3. A strict time-forward or campaign-held-out split with causally computed
   features.
4. Local benign false-positive rate **≤ 1%**.
5. BOTSv1 background false-positive rate **≤ 1%**.
6. Cross-campaign recall **≥ 50%** on S2 (A→B) and S3 (B→A), at the local-FPR
   threshold.
7. At least one local attack positive, so local recall is not unproven.
8. A single-feature baseline check showing the model beats port/IP/path rules.
9. A feature-availability audit: every feature must exist in the live scoring
   path, including process path/hostname if the model depends on it.
10. A feature-artifact audit: no missing-value or dataset-origin shortcut
    (see §5).

The gate writes `database/model_manifest.json`; it never modifies the bundle or
`model_meta.json`. Passing the gate is necessary but still does not enable
enforcement.

## 4. Shadow rollout procedure

```bash
cd /home/haaraphel/BARAQ
export PYTHONPATH="$PWD"
export BARAQ_ML_DEPLOYMENT_MODE=shadow

# Generate/refresh the manifest from explicit evidence (none currently).
.venv/bin/python scripts/ml_deployment_gate.py --write

# Confirm the runtime view.
curl -s -H "X-API-Key: $BARAQ_API_KEY" \
  http://127.0.0.1:8001/api/system/ml/deployment | jq

# Inspect recent scores.
curl -s -H "X-API-Key: $BARAQ_API_KEY" \
  "http://127.0.0.1:8001/api/system/ml/deployment?hours=24" | jq
```

Operational checks for the first 24–72 hours:

- `shadow_scores` should be non-zero after an `analyze_events` pass.
- `score_distribution.p95` should be below the operating threshold; a p95 above
  the threshold means the local baseline and the live traffic disagree.
- Review `top_flagged` buckets with the process/host owner. A remote IP alone is
  not evidence of compromise.
- Compare rule alerts to shadow-flagged buckets. If the same benign service
  appears repeatedly, fix the feature or add an allowlist; do not lower the
  threshold to make the queue look busy.

## 5. Why the context result is not deployed

A 77-feature process/destination context model appeared to fix S2:

| S2 context variant | B recall | A recall | Local FP | Background FP |
|---|---:|---:|---:|---:|
| Full context | 48,197/48,199 | 84/84 | 1/1,040 | 14/109,254 |
| Zero path/image features | **1/48,199** | 84/84 | 0/1,040 | 0/109,254 |

The gain was a **dataset artifact**, not a behavioral improvement:

- The local rows have no process path; BOTSv1 rows do. Any path-presence feature
  separates local from BOTSv1.
- A single feature, `image_entropy`, flags 48,197/48,199 B and 84/84 A with zero
  local false positives.
- B's path is a long GUID-style path in `AppData`; `image_len` alone learns that
  path and gets B with zero A recall. That is a Campaign-B fingerprint, not
  cross-campaign generalization.
- Removing the path/image columns collapses B recall to one event. The S3
  B→A result is still 0/417 at a deployable threshold.

The context matrix and script remain in the repository as a reproducible
negative result. They are research-only and must not be wired into the live
feature builder.

## 6. Remaining blockers

- No independent third campaign; BOTSv1 A/B cannot prove zero-shot transfer.
- No local attack telemetry; local recall is unknown.
- The live network feature path is not identical to the benchmark path:
  `NetworkConnection` carries process basename, not full process path or
  destination hostname, and `_network_features` still derives `port_category`
  from the number of distinct ports. A future promoted model must use a shared
  feature builder.
- The local benign snapshot is 5,201 flows and spans one host; a 1% FPR estimate
  from it has wide uncertainty.

## 7. Rollback

The bundle and metadata are separate from the manifest. To restore the known
live state:

```bash
cp database/model.bundle.v121.joblib database/model.bundle.joblib
cp database/model_meta.v121.json database/model_meta.json
```

Then regenerate/clear the manifest with `scripts/ml_deployment_gate.py` and
restart the API. A **shadow** manifest can stay in place after a rollback; it is
a record that the loaded model has not passed the promotion gate, not a
configuration that changes scoring.

## 8. Commands run

```bash
# Unit coverage for the deployment gate/shadow mode.
.venv/bin/python -m pytest tests/test_ml_deployment.py -q

# Gate only (dry run).
PYTHONPATH=. .venv/bin/python scripts/ml_deployment_gate.py

# Write the conservative v121 manifest.
PYTHONPATH=. .venv/bin/python scripts/ml_deployment_gate.py --write
```
