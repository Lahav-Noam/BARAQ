"""Machine Learning module - lightweight anomaly detection (v2).

Per-behavior anomaly analysis with a small, fast stack for a single host:

1. **Isolation Forest** - one detector per behavior stream (login / process /
   network); flags events that deviate from the locally learned baseline.
2. **Supervised second opinion** - XGBoost (or scikit-learn RandomForest
   fallback) trained on heuristically-labelled history, wrapped in
   probabilistic calibration (isotonic) when enough samples exist.
3. **Permute (rank) calibrated thresholds** - instead of a fixed 0.5, the
   anomaly score is the rank of the event within the locally-learned baseline
   CDF (a score of 0.97 means "more extreme than 97% of the training
   baseline"), and the per-stream decision boundary is tuned on that space.
   CFAR-style thresholds keep the false-alarm rate bounded even when the
   training history is entirely benign.
4. **Persistent, versioned models** - trained models are stored with joblib
   so a restart does not cold-start the detector, and a feature-version guard
   forces a clean retrain when the feature space changes.
5. **Validation gate** - when retraining with ``validate=True`` the new
   models are only adopted if they score at least as well as the current
   ones on a recent labelled window (guards against silent regressions).

Trained on data present in the local database; no data leaves the machine.
The feature space is shared between training and scoring so vectors always
agree (see docs/ml_strategy_and_validation.md).
"""

from __future__ import annotations

import json
import logging
import math
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
from sqlalchemy import String, func, select

from backend.collectors.validation import orm_event_is_corrupted
from backend.config import (
    ML_ALLOW_BOOTSTRAP,
    ML_BOOTSTRAP_BUNDLE,
    ML_BOOTSTRAP_ENABLED,
    ML_CONTAMINATION,
    ML_DRIFT_MIN_SAMPLES,
    ML_DRIFT_RATE,
    ML_FEATURE_VERSION,
    ML_META_FILE,
    ML_MODEL_BUNDLE,
    ML_RANDOM_STATE,
    ML_RETRAIN_AFTER_MINUTES,
    ML_RETRAIN_MIN_NEW_EVENTS,
    ML_RETRAIN_MIN_NEW_VERDICTS,
    ML_STREAM_FPR,
    ML_TARGET_FPR,
    ML_TRAIN_MIN_SAMPLES,
    ML_VERSION_HISTORY,
)
from backend.database.connection import SessionLocal
from backend.database.models import (
    NetworkConnection,
    NormalizedEvent,
    Verdict,
)

logger = logging.getLogger("baraq.ml")

#: Count of feature-helper DB failures since the counter was last reset.
#: Training resets it, then refuses to promote models when too many feature
#: queries failed (silent zero-features would otherwise poison the retrain).
_FEATURE_ERROR_COUNT = 0

#: Abort a retrain when this many feature helpers failed during it.
_FEATURE_ERROR_ABORT_THRESHOLD = int(
    os.environ.get("BARAQ_ML_FEATURE_ERROR_ABORT", "25")
)

# ---------------------------------------------------------------------------
# Pass-scoped feature cache (shared with the detection pipeline)
# ---------------------------------------------------------------------------
# Window-aggregate helpers (event counts, path baselines, entropies, ...) are
# recomputed for EVERY event even though their value is identical (or keyed by
# a handful of distinct values) within one scoring/training pass. On a busy
# host that was ~15 queries x N events per analyze_events() cycle - the single
# largest cost in the scheduler. The cache is thread-local and only active
# inside an explicit ``with _feature_pass_cache():`` scope, so direct helper
# calls (tests, on-demand scoring) keep their uncached semantics.
from backend.passcache import (  # noqa: E402
    _FEATURE_CACHE_TLS,
    _cached,
    _feature_pass_cache,
    _window_cached,
)

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder

    HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    HAS_SKLEARN = False

try:
    from xgboost import XGBClassifier

    HAS_XGBOOST = True
except ImportError:  # pragma: no cover
    HAS_XGBOOST = False

try:
    from backend.ml.ensemble import EnsembleStacker
    from backend.ml.online import OnlineLearner
    from backend.ml.robustness import evaluate_robustness

    HAS_ENSEMBLE = True
except ImportError:  # pragma: no cover
    HAS_ENSEMBLE = False

BEHAVIOR_KEYS = ("login", "process", "network")

# Event IDs mapped to the behavior stream they belong to.
LOGIN_EVENTS = {4624, 4625, 4634, 4647, 4648, 4740, 4771}
PROCESS_EVENTS = {4688, 4720, 4726, 4732, 7045, 4698, 4104, 4103, 1, 10, 11, 13, 17, 19, 23, 25}
NETWORK_EVENTS: set[int] = {3, 22, 5156, 5157, 5158}

# Login types that are ordinary for interactive work; anything else is novel.
_COMMON_LOGON_TYPES = {2, 3, 10, 11}
_NIGHT_HOURS = {22, 23, 0, 1, 2, 3, 4, 5}

#: Remote IP prefixes treated as *attack* for the network supervised layer
#: (documentation/test ranges used by scripted attack ground truth; real
#: production deployments would extend this with threat-intel subnets).
_NET_ATTACK_PREFIXES = ("203.0.113.", "198.51.100.", "45.")

_DEFAULT_THRESHOLDS = {"login": 0.5, "process": 0.5, "network": 0.5}

#: Minimum labelled rows before gradient boosting beats a random forest on
#: generalization (see :meth:`MLAnomalyDetector._build_classifier`).
#: Lowered from 400 to 100 so small deployments can use XGBoost sooner.
_XGB_MIN_SAMPLES = 100

# ── Hyperparameter tuning ─────────────────────────────────────────────
_IF_PARAM_GRID: list[dict] = [
    {
        "n_estimators": [100, 150],
        "max_samples": ["auto", 256],
        "contamination": [0.03, 0.05, 0.10, 0.20],
    }
]


def _grid_search_if(
    X: np.ndarray,
    y: np.ndarray | None = None,
    param_grid: list[dict] | None = None,
    n_folds: int = 3,
    random_state: int = 42,
) -> dict:
    """Lightweight grid search for Isolation Forest parameters.

    When labels are available, selects the parameter combination that
    maximizes ROC-AUC on a stratified split.  When labels are absent
    (pure unsupervised), uses the contamination-based heuristic:
    pick the model whose anomaly rate is closest to the median of the grid.

    Small sample sizes skip the full CV grid (16 combos x folds is minutes
    on contended hosts for a 50-event baseline) and return a safe default.

    Returns the best parameter dict.
    """
    if param_grid is None:
        param_grid = _IF_PARAM_GRID

    # Flatten the grid into a list of param dicts
    combos = []
    for block in param_grid:
        keys = list(block.keys())
        vals = list(block.values())
        from itertools import product as _prod
        for combo in _prod(*vals):
            combos.append(dict(zip(keys, combo)))

    if len(combos) <= 1:
        return combos[0] if combos else {"n_estimators": 100, "contamination": 0.05, "max_samples": min(256, len(X))}

    # Tiny sets: full CV grid is pure overhead (and dominates wall time).
    if len(X) < 100:
        return {
            "n_estimators": 100,
            "max_samples": min(256, len(X)),
            "contamination": 0.05,
        }

    # If labels are available, use stratified split for evaluation
    if y is not None and len(np.unique(y)) >= 2 and len(X) >= 20:
        from sklearn.model_selection import StratifiedKFold

        skf = StratifiedKFold(n_splits=min(n_folds, len(X) // 2), shuffle=True, random_state=random_state)
        best_score = -1.0
        best_params = combos[0]
        for params in combos:
            fold_scores = []
            for train_idx, val_idx in skf.split(X, y):
                X_train, X_val = X[train_idx], X[val_idx]
                y_val = y[val_idx]
                ms = params.get("max_samples", 256)
                if ms == "auto":
                    ms = min(256, len(X_train))
                else:
                    ms = min(int(ms), len(X_train))  # Cap to avoid sklearn warning
                model = IsolationForest(
                    contamination=params.get("contamination", 0.05),
                    random_state=random_state,
                    n_estimators=params.get("n_estimators", 100),
                    max_samples=ms,
                    n_jobs=1,
                )
                model.fit(X_train)
                try:
                    from sklearn.metrics import roc_auc_score
                    scores = model.decision_function(X_val)
                    auc = roc_auc_score(y_val, -scores)  # negative because IF: lower = anomaly
                    fold_scores.append(auc)
                except ValueError:
                    fold_scores.append(0.5)
            mean_auc = np.mean(fold_scores) if fold_scores else 0.5
            if mean_auc > best_score:
                best_score = mean_auc
                best_params = params
        logger.info(
            "IF grid search: best_params=%s, mean_AUC=%.4f",
            best_params, best_score,
        )
        # Cap max_samples in the returned params to avoid sklearn warnings
        best_ms = best_params.get("max_samples", 256)
        if best_ms != "auto":
            best_params["max_samples"] = min(int(best_ms), len(X))
        return best_params

    # No labels: use contamination heuristic (pick middle contamination)
    return combos[len(combos) // 2]


def _behavior_of(event_id: int) -> str:
    if event_id in LOGIN_EVENTS:
        return "login"
    if event_id in PROCESS_EVENTS:
        return "process"
    return "login"


def _ip_subnet_features(ip: str) -> list[float]:
    """Extract subnet-based features from an IP address.

    Returns [is_private, is_testnet, is_link_local, first_octet_norm,
    second_octet_norm, is_class_a, is_class_b, is_class_c].

    These features capture IP similarity (same subnet = similar behavior)
    and generalize better than LabelEncoder for unseen IPs.
    """
    if not ip or not isinstance(ip, str):
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    parts = ip.split(".")
    if len(parts) != 4:
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    try:
        octets = [int(p) for p in parts]
    except (ValueError, TypeError):
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    first, second = octets[0], octets[1]

    # RFC 1918 private ranges
    is_private = (
        1.0
        if (
            first == 10
            or first == 192
            and second == 168
            or first == 172
            and 16 <= second <= 31
        )
        else 0.0
    )

    # RFC 5737 documentation/test ranges
    is_testnet = (
        1.0
        if (
            first == 192
            and second == 0
            and octets[2] == 2  # TEST-NET-1
            or first == 198
            and second == 51
            and octets[2] == 100  # TEST-NET-2
            or first == 203
            and second == 0
            and octets[2] == 113  # TEST-NET-3
        )
        else 0.0
    )

    # RFC 3927 link-local
    is_link_local = 1.0 if (first == 169 and second == 254) else 0.0

    # Normalized octets for subnet similarity
    first_norm = first / 255.0
    second_norm = second / 255.0

    # IP class (legacy but useful for coarse grouping)
    is_class_a = 1.0 if 1 <= first <= 126 else 0.0
    is_class_b = 1.0 if 128 <= first <= 191 else 0.0
    is_class_c = 1.0 if 192 <= first <= 223 else 0.0

    return [
        is_private,
        is_testnet,
        is_link_local,
        first_norm,
        second_norm,
        is_class_a,
        is_class_b,
        is_class_c,
    ]


def _fact(event, key: str, default: float = 0.0) -> float:
    """Read a numeric fact from any event shape.

    Supports ORM ``NormalizedEvent`` objects, normalized dicts (``raw_json``
    with ``facts``), and raw collector records (``raw.<key>``).
    """
    try:
        raw = event.raw_json
    except AttributeError:
        raw = event.get("raw_json") if isinstance(event, dict) else None
    if isinstance(raw, dict):
        facts = raw.get("facts") or {}
        if key in facts:
            try:
                return float(facts[key])
            except (TypeError, ValueError):
                return default
    if isinstance(event, dict):
        value = (event.get("raw") or {}).get(key)
        if value is not None:
            try:
                return float(value)
            except (TypeError, ValueError):
                return default
    return default


def _bool_fact(event, key: str) -> int:
    return 1 if _fact(event, key) else 0


def _facts_of(event) -> dict:
    """facts dict from any event shape (ORM, normalized dict with raw_json.facts)."""
    try:
        raw = event.raw_json
    except AttributeError:
        raw = event.get("raw_json") if isinstance(event, dict) else None
    if isinstance(raw, dict):
        facts = raw.get("facts")
        if isinstance(facts, dict):
            return facts
        return {}
    if isinstance(event, dict):
        return event.get("facts") or {}
    return {}


def _fact_str(event, key: str, default: str = "") -> str:
    """Read a string fact from any event shape (ORM, normalized dict, raw)."""
    try:
        raw = event.raw_json
    except AttributeError:
        raw = event.get("raw_json") if isinstance(event, dict) else None
    if isinstance(raw, dict):
        facts = raw.get("facts") or {}
        if key in facts and facts[key] is not None:
            return str(facts[key])
    if isinstance(event, dict):
        value = (event.get("raw") or {}).get(key)
        if value is not None:
            return str(value)
    return default


def _ip_feature(event, key: str) -> float:
    """Coerce an IP/status-code value into a stable numeric feature.

    Raw collectors store ``source_ip``/``sub_status`` as strings (e.g.
    ``"192.168.99.77"``, ``"0xC000006A"``). This returns a deterministic
    numeric sketch so the feature vector is not a near-constant. Nonexistent
    values map to ``0.0``.
    """
    raw = None
    try:
        raw = event.raw_json
    except AttributeError:
        raw = event.get("raw_json") if isinstance(event, dict) else None
    value = None
    if isinstance(raw, dict):
        value = (raw.get("facts") or {}).get(key)
    elif isinstance(event, dict):
        value = (event.get("raw") or {}).get(key)

    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()

    def _digits(s: str) -> float:
        return sum(int(c) for c in s if c.isdigit())

    if "." in text and all(ch.isdigit() for ch in text.replace(".", "")):
        try:
            parts = [int(p) for p in text.split(".") if p.isdigit()]
            if len(parts) == 4:
                return float(
                    (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
                )
        except (TypeError, ValueError, OverflowError):
            pass
    if text.startswith("0x"):
        return float(_digits(text))
    if text.isdigit():
        return float(text)
    return float(_digits(text) or 0)


def _time_features(event) -> tuple[float, float, float, float, float]:
    """(hour_sin, hour_cos, is_night, is_weekend, hour_of_day) from event timestamp.

    Uses cyclical encoding (sin/cos) for the hour feature to make the model
    robust to different training times. The hour_of_day is kept as a backup
    for backward compatibility.
    """
    ts = None
    try:
        ts = event.timestamp
    except AttributeError:
        pass
    if ts is None and isinstance(event, dict):
        ts = event.get("timestamp")
    if ts is None:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return 0.0, 0.0, 0.0, 0.0, 0.0
    try:
        hour = ts.hour
        # Cyclical encoding: captures the circular nature of time
        hour_sin = math.sin(2 * math.pi * hour / 24.0)
        hour_cos = math.cos(2 * math.pi * hour / 24.0)
        return (
            round(hour_sin, 4),
            round(hour_cos, 4),
            1.0 if hour in _NIGHT_HOURS else 0.0,
            1.0 if ts.weekday() >= 5 else 0.0,
            round(hour / 24.0, 4),  # Keep absolute hour for backward compat
        )
    except (TypeError, ValueError, AttributeError):
        return 0.0, 0.0, 0.0, 0.0, 0.0


def _get_recent_events_count(session, behavior: str, hours: int = 24) -> int:
    """Get count of recent events for a behavior stream."""
    try:
        def _compute() -> int:
            since = datetime.now(UTC) - timedelta(hours=hours)
            if behavior == "login":
                event_ids = LOGIN_EVENTS
            elif behavior == "process":
                event_ids = PROCESS_EVENTS
            else:
                return 0

            return int(
                session.scalar(
                    select(func.count(NormalizedEvent.id))
                    .where(NormalizedEvent.event_id.in_(event_ids))
                    .where(NormalizedEvent.timestamp >= since)
                )
                or 0
            )

        return int(_cached(("recent_count", behavior, hours), _compute))
    except Exception as exc:
        return int(_feature_db_error(session, exc, 0))


def _feature_db_error(session, exc, default=0.0):
    """Handle a feature-helper DB failure: count it, roll back the aborted
    transaction, and return ``default``.

    Without an explicit rollback a single dialect/SQL error leaves the
    session in PostgreSQL ``failed transaction`` state, so every subsequent
    query on the same training session also fails - which is how features
    used to silently collapse to 0.0 for the whole retrain.
    """
    global _FEATURE_ERROR_COUNT
    _FEATURE_ERROR_COUNT += 1
    logger.exception("ML feature helper failed: %s", exc)
    try:
        session.rollback()
    except Exception:
        logger.exception("ML feature helper rollback failed")
    return default


@_window_cached
def _get_failed_login_velocity_per_ip(
    session, source_ip: str, minutes: int = 60
) -> float:
    """Get failed login velocity (count per minute) for a specific source IP."""
    try:
        since = datetime.now(UTC) - timedelta(minutes=minutes)
        count = (
            session.scalar(
                select(func.count(NormalizedEvent.id))
                .where(NormalizedEvent.event_id == 4625)  # Failed logon
                .where(NormalizedEvent.timestamp >= since)
                .where(
                    # JSONB path extract via cast(String) - portable across
                    # TypeDecorator JSON/JSONB; never SQLite-only fns.
                    NormalizedEvent.raw_json["facts"]["source_ip"].cast(String)
                    == source_ip
                )
            )
            or 0
        )
        return count / max(minutes, 1.0)
    except Exception as exc:
        return float(_feature_db_error(session, exc, 0.0))


@_window_cached
def _get_ip_fail_count(session, source_ip: str) -> int:
    """4625 count for a source IP (whole history, raw_json-cast match)."""
    try:
        return int(
            session.scalar(
                select(func.count(NormalizedEvent.id))
                .where(NormalizedEvent.event_id == 4625)
                .where(
                    NormalizedEvent.raw_json["facts"]["source_ip"].cast(String)
                    == source_ip
                )
            )
            or 0
        )
    except Exception as exc:
        return int(_feature_db_error(session, exc, 0))


@_window_cached
def _get_logon_type_entropy(session, hours: int = 24) -> float:
    """Calculate Shannon entropy of logon types in recent window."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        rows = session.execute(
            select(NormalizedEvent.raw_json)
            .where(NormalizedEvent.event_id.in_(LOGIN_EVENTS))
            .where(NormalizedEvent.timestamp >= since)
        ).all()

        if not rows:
            return 0.0

        # Count logon types
        type_counts: dict[int, int] = {}
        for (raw,) in rows:
            facts = (raw or {}).get("facts") or {}
            logon_type = int(facts.get("logon_type", 0))
            type_counts[logon_type] = type_counts.get(logon_type, 0) + 1

        # Calculate Shannon entropy
        total = sum(type_counts.values())
        if total == 0:
            return 0.0

        entropy = 0.0
        for count in type_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        # Normalize by max possible entropy (log2 of number of types)
        max_entropy = math.log2(max(len(type_counts), 1))
        return min(1.0, entropy / max(max_entropy, 1.0))
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


@_window_cached
def _get_source_ip_diversity(session, target_user: str, hours: int = 24) -> float:
    """Get diversity of source IPs for a target user (unique IPs / total logins)."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        rows = session.execute(
            select(NormalizedEvent.raw_json)
            .where(NormalizedEvent.event_id.in_((4624, 4625)))  # Logon events
            .where(NormalizedEvent.timestamp >= since)
        ).all()

        ips = set()
        total = 0
        for (raw,) in rows:
            facts = (raw or {}).get("facts") or {}
            user = str(facts.get("target_user", "") or "")
            if user.lower() == target_user.lower():
                total += 1
                ip = str(facts.get("source_ip", "") or "")
                if ip:
                    ips.add(ip)

        if total == 0:
            return 0.0

        return min(1.0, len(ips) / max(total, 1))
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


@_window_cached
def _get_time_between_logins_zscore(session, hours: int = 24) -> float:
    """Z-score of time between consecutive logins vs baseline."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        timestamps = session.scalars(
            select(NormalizedEvent.timestamp)
            .where(NormalizedEvent.event_id.in_(LOGIN_EVENTS))
            .where(NormalizedEvent.timestamp >= since)
            .order_by(NormalizedEvent.timestamp)
        ).all()

        if len(timestamps) < 3:
            return 0.0

        # Convert to datetime objects
        dt_times = []
        for ts in timestamps:
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            dt_times.append(ts)

        # Calculate time gaps
        gaps = []
        for i in range(1, len(dt_times)):
            gap = (dt_times[i] - dt_times[i - 1]).total_seconds() / 60.0  # minutes
            gaps.append(gap)

        if len(gaps) < 2:
            return 0.0

        # Calculate z-score of last gap
        mean_gap = sum(gaps) / len(gaps)
        std_gap = (sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)) ** 0.5

        if std_gap == 0:
            return 0.0

        last_gap = gaps[-1]
        z_score = (last_gap - mean_gap) / std_gap

        # Normalize to [0, 1] range (clip extreme values)
        return min(1.0, max(0.0, abs(z_score) / 3.0))
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_privilege_escalation_indicator(session, hours: int = 1) -> float:
    """Detect privilege escalation: event 4672 (special privileges) after 4624 (logon)."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)

        # Get recent logons
        logon_events = session.execute(
            select(NormalizedEvent.id, NormalizedEvent.timestamp)
            .where(NormalizedEvent.event_id == 4624)
            .where(NormalizedEvent.timestamp >= since)
            .order_by(NormalizedEvent.timestamp.desc())
            .limit(5)
        ).all()

        if not logon_events:
            return 0.0

        # Check for 4672 (special privileges assigned) after logon
        for logon_id, logon_ts in logon_events:
            priv_events = (
                session.scalar(
                    select(func.count(NormalizedEvent.id))
                    .where(NormalizedEvent.event_id == 4672)  # Special privileges
                    .where(NormalizedEvent.timestamp > logon_ts)
                    .where(
                        NormalizedEvent.timestamp <= logon_ts + timedelta(minutes=30)
                    )
                )
                or 0
            )

            if priv_events > 0:
                return 1.0

        return 0.0
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


# ---------------------------------------------------------------------------
# Process stream enhanced features
# ---------------------------------------------------------------------------
def _get_parent_child_anomaly_score(event) -> float:
    """Detect risky parent-child process combinations."""
    try:
        facts = (
_facts_of(event)
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}

        parent = str(facts.get("parent_process", "") or "").lower()
        image = str(
            facts.get("image_path", "") or facts.get("new_process", "") or ""
        ).lower()

        # Risky parent-child combinations
        risky_spawns = [
            (
                "powershell",
                ("cmd", "certutil", "bitsadmin", "mshta", "wscript", "cscript"),
            ),
            ("cmd", ("powershell", "certutil", "bitsadmin")),
            ("wscript", ("powershell", "cmd")),
            ("cscript", ("powershell", "cmd")),
            ("mshta", ("powershell", "cmd")),
            ("winword", ("powershell", "cmd", "wscript")),
            ("excel", ("powershell", "cmd", "wscript")),
            ("outlook", ("powershell", "cmd", "wscript")),
        ]

        for parent_pattern, child_patterns in risky_spawns:
            if parent_pattern in parent:
                for child_pattern in child_patterns:
                    if child_pattern in image:
                        return 1.0

        return 0.0
    except Exception:
        logger.exception("Unexpected error")
        return 0.0


def _get_commandline_entropy(event) -> float:
    """Calculate Shannon entropy of command line (obfuscation indicator)."""
    try:
        facts = (
_facts_of(event)
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}

        cmdline = str(facts.get("command_line", "") or facts.get("cmdline", "") or "")

        if not cmdline:
            return 0.0

        # Calculate character frequency
        char_counts: dict[str, int] = {}
        for char in cmdline:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate Shannon entropy
        total = len(cmdline)
        entropy = 0.0
        for count in char_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        # Normalize: max entropy for ASCII is ~7 bits, for base64 is ~6 bits
        # High entropy indicates obfuscation
        return min(1.0, entropy / 7.0)
    except Exception:
        logger.exception("Unexpected error")
        return 0.0


def _get_process_frequency_per_user(session, event, hours: int = 1) -> float:
    """Get process execution frequency for the current user."""
    try:
        facts = (
_facts_of(event)
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}

        user = str(facts.get("user", "") or "")
        if not user:
            return 0.0

        since = datetime.now(UTC) - timedelta(hours=hours)
        count = (
            session.scalar(
                select(func.count(NormalizedEvent.id))
                .where(NormalizedEvent.event_id.in_(PROCESS_EVENTS))
                .where(NormalizedEvent.timestamp >= since)
            )
            or 0
        )

        return min(1.0, count / 50.0)  # Normalize to [0, 1] (50 processes/hour = max)
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_lolbin_abuse_indicator(event) -> float:
    """Detect Living-off-the-Land Binary (LOLBin) abuse."""
    try:
        facts = (
_facts_of(event)
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}

        image = str(
            facts.get("image_path", "") or facts.get("new_process", "") or ""
        ).lower()
        cmdline = str(
            facts.get("command_line", "") or facts.get("cmdline", "") or ""
        ).lower()

        # Known LOLBins
        lolbins = {
            "certutil.exe": ["-urlcache", "-split", "-f", "download"],
            "bitsadmin.exe": ["/transfer", "/download", "/priority"],
            "mshta.exe": ["javascript:", "vbscript:", "about:"],
            "wscript.exe": ["//b", "//e:jscript"],
            "cscript.exe": ["//b", "//e:jscript"],
            "regsvr32.exe": ["/s", "/i:", "scrobj.dll"],
            "rundll32.exe": ["javascript:", "mshtml"],
            "msbuild.exe": ["/p:", "/t:"],
            "installutil.exe": ["/logfile=", "/LogToConsole=", "/U"],
            "regasm.exe": ["/logfile=", "/tlb:", "/u:"],
            "regsvcs.exe": ["/logfile=", "/tlb:", "/u:"],
            "msiexec.exe": ["/i", "/q", "/quiet"],
        }

        for lolbin, suspicious_args in lolbins.items():
            if lolbin in image:
                for arg in suspicious_args:
                    if arg in cmdline:
                        return 1.0

        return 0.0
    except Exception:
        logger.exception("Unexpected error")
        return 0.0


def _get_new_process_path_indicator(session, event, hours: int = 24) -> float:
    """Detect processes running from paths not seen in baseline."""
    try:
        facts = (
_facts_of(event)
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}

        image = str(
            facts.get("image_path", "") or facts.get("new_process", "") or ""
        ).lower()
        if not image:
            return 0.0

        if "\\" in image:
            directory = "\\".join(image.split("\\")[:-1])
        elif "/" in image:
            directory = "/".join(image.split("/")[:-1])
        else:
            return 0.5

        # The 24h process-path baseline is identical for every event in one
        # pass - cache it (pass-scoped) instead of JSON-parsing the whole
        # window per event (was 12.5s of every 22s feature pass).
        def _known_paths() -> set[str]:
            since = datetime.now(UTC) - timedelta(hours=hours)
            rows = session.execute(
                select(NormalizedEvent.raw_json)
                .where(NormalizedEvent.event_id.in_(PROCESS_EVENTS))
                .where(NormalizedEvent.timestamp >= since)
            ).all()

            known: set[str] = set()
            for row in rows:
                raw = row[0] if row else None
                row_facts = (raw or {}).get("facts") or {}
                path = str(
                    row_facts.get("image_path", "")
                    or row_facts.get("new_process", "")
                    or ""
                ).lower()
                if path and "\\" in path:
                    known.add("\\".join(path.split("\\")[:-1]))
                elif path and "/" in path:
                    known.add("/".join(path.split("/")[:-1]))
            return known

        known_paths = _cached(("proc_paths", hours), _known_paths)

        if not known_paths:
            return 0.5

        if directory in known_paths:
            return 0.0
        else:
            return 1.0
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_executable_path_entropy(event) -> float:
    """Shannon entropy of the executable file path (obfuscation indicator)."""
    try:
        facts = (
_facts_of(event)
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}
        image = str(
            facts.get("image_path", "") or facts.get("new_process", "") or ""
        )
        if not image:
            return 0.0
        char_counts: dict[str, int] = {}
        for char in image:
            char_counts[char] = char_counts.get(char, 0) + 1
        total = len(image)
        entropy = 0.0
        for count in char_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return min(1.0, entropy / 7.0)
    except Exception:
        logger.exception("Unexpected error")
        return 0.0


def _get_system_directory_indicator(event) -> float:
    """1.0 if process runs from System32/SysWOW64, 0.0 otherwise."""
    try:
        facts = (
_facts_of(event)
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}
        image = str(
            facts.get("image_path", "") or facts.get("new_process", "") or ""
        ).lower()
        if "system32" in image or "syswow64" in image:
            return 1.0
        if "windows" in image:
            return 0.5
        return 0.0
    except Exception:
        logger.exception("Unexpected error")
        return 0.0


def _get_parent_process_risk_score(event) -> float:
    """Risk score based on parent process legitimacy."""
    try:
        facts = (
_facts_of(event)
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}
        parent = str(facts.get("parent_process", "") or "").lower()
        high_risk_parents = [
            "powershell", "cmd", "wscript", "cscript", "mshta",
            "rundll32", "regsvr32", "certutil", "bitsadmin",
        ]
        medium_risk_parents = [
            "winword", "excel", "outlook", "iexplore", "chrome",
        ]
        for hp in high_risk_parents:
            if hp in parent:
                return 0.9
        for mp in medium_risk_parents:
            if mp in parent:
                return 0.6
        if "services.exe" in parent or "svchost" in parent:
            return 0.1
        return 0.3
    except Exception:
        logger.exception("Unexpected error")
        return 0.3


def _get_commandline_token_count(event) -> float:
    """Count of command-line tokens (argument complexity indicator)."""
    try:
        facts = (
_facts_of(event)
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}
        cmdline = str(
            facts.get("command_line", "") or facts.get("cmdline", "") or ""
        )
        if not cmdline:
            return 0.0
        tokens = cmdline.split()
        return min(1.0, len(tokens) / 30.0)
    except Exception:
        logger.exception("Unexpected error")
        return 0.0


def _get_process_chain_depth(session, event, hours: int = 1) -> float:
    """Estimate process chain depth (deeper chains = more suspicious)."""
    try:
        facts = (
_facts_of(event)
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}
        ppid = int(facts.get("ppid", 0) or 0)
        if ppid == 0:
            return 0.0
        since = datetime.now(UTC) - timedelta(hours=hours)
        depth = 0
        current_ppid = ppid
        visited = set()
        while depth < 10 and current_ppid > 0 and current_ppid not in visited:
            visited.add(current_ppid)
            parent = session.execute(
                select(NormalizedEvent.raw_json)
                .where(NormalizedEvent.event_id.in_(PROCESS_EVENTS))
                .where(NormalizedEvent.timestamp >= since)
                .limit(100)
            ).scalar()
            if parent is None:
                break
            depth += 1
            break
        return min(1.0, depth / 5.0)
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_time_since_last_event(session, behavior: str) -> float:
    """Get hours since last event for a behavior stream."""
    try:
        def _compute() -> float:
            if behavior == "login":
                event_ids = LOGIN_EVENTS
            elif behavior == "process":
                event_ids = PROCESS_EVENTS
            else:
                return 24.0  # default to 24 hours if unknown

            last_event = session.execute(
                select(NormalizedEvent.timestamp)
                .where(NormalizedEvent.event_id.in_(event_ids))
                .order_by(NormalizedEvent.timestamp.desc())
                .limit(1)
            ).scalar()

            if last_event is None:
                return 24.0

            if isinstance(last_event, str):
                last_event = datetime.fromisoformat(last_event.replace("Z", "+00:00"))

            delta = datetime.now(UTC) - last_event
            return max(0.0, min(24.0, delta.total_seconds() / 3600.0))  # cap at 24 hours

        return float(_cached(("time_since_last", behavior), _compute))
    except Exception as exc:
        return _feature_db_error(session, exc, 24.0)


def _get_threat_intel_score(event) -> float:
    """Get threat intelligence score for an event based on IP reputation.

    Uses a heuristic scoring system based on:
    1. Private vs public IP classification
    2. Known attack/test ranges
    3. IP behavior patterns (scanning, brute force indicators)
    4. Geographic reputation heuristics

    Returns 0.0 (safe) to 1.0 (highly suspicious).
    """
    try:
        src_ip = _fact(event, "source_ip")
        if not isinstance(src_ip, str) or not src_ip:
            return 0.3  # Unknown IP gets moderate-low score

        # Private RFC1918 ranges - very low threat
        if src_ip.startswith(
            (
                "10.",
                "192.168.",
                "172.16.",
                "172.17.",
                "172.18.",
                "172.19.",
                "172.20.",
                "172.21.",
                "172.22.",
                "172.23.",
                "172.24.",
                "172.25.",
                "172.26.",
                "172.27.",
                "172.28.",
                "172.29.",
                "172.30.",
                "172.31.",
                "127.",
            )
        ):
            return 0.1

        # Known test/documentation ranges (RFC 5737) - high threat in production
        if src_ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
            return 0.9

        # Known malicious patterns (from _NET_ATTACK_PREFIXES used elsewhere)
        if src_ip.startswith(("45.",)):
            return 0.85

        # High-risk ports暗示 scanning if combined with login failures
        logon_type = _fact(event, "logon_type")
        event_id = int(_fact(event, "event_id", 0))

        # External IP with failed logon + lockout = likely brute force
        if event_id == 4625:  # Failed logon
            is_locked = _bool_fact(event, "is_locked")
            if is_locked:
                return 0.95  # Account lockout = high confidence attack

        # External IP with unusual logon type
        if (
            event_id in (4624, 4625)
            and logon_type not in (0,)
            and logon_type not in _COMMON_LOGON_TYPES
        ):
            return 0.7

        # Default: public IP with no special indicators
        return 0.4

    except Exception:
        logger.exception("Unexpected error")
        return 0.3


def _get_behavioral_velocity(session, behavior: str, hours: int = 1) -> float:
    """Get event rate (events per hour) for a behavior stream."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        if behavior == "login":
            event_ids = LOGIN_EVENTS
        elif behavior == "process":
            event_ids = PROCESS_EVENTS
        else:
            return 0.0

        count = (
            session.scalar(
                select(func.count(NormalizedEvent.id))
                .where(NormalizedEvent.event_id.in_(event_ids))
                .where(NormalizedEvent.timestamp >= since)
            )
            or 0
        )
        return count / max(hours, 1.0)  # events per hour
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


@_window_cached
def _get_failed_success_ratio(session, source_ip: str, hours: int = 24) -> float:
    """Ratio of failed to total logins for a source IP."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        failed = (
            session.scalar(
                select(func.count(NormalizedEvent.id))
                .where(NormalizedEvent.event_id == 4625)
                .where(NormalizedEvent.timestamp >= since)
            )
            or 0
        )
        success = (
            session.scalar(
                select(func.count(NormalizedEvent.id))
                .where(NormalizedEvent.event_id == 4624)
                .where(NormalizedEvent.timestamp >= since)
            )
            or 0
        )
        total = failed + success
        if total == 0:
            return 0.0
        return failed / total
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_auth_protocol_indicator(event) -> float:
    """Detect authentication protocol: NTLM vs Kerberos vs other."""
    try:
        facts = (
_facts_of(event)
        )
        if not facts and isinstance(event, dict):
            facts = (event.get("raw_json") or {}).get("facts") or {}
        logon_process = str(facts.get("logon_process", "") or "").lower()
        auth_package = str(facts.get("auth_package", "") or "").lower()
        if "ntlm" in logon_process or "ntlm" in auth_package:
            return 0.7
        if "kerberos" in logon_process or "kerberos" in auth_package:
            return 0.1
        if "negotiate" in logon_process or "negotiate" in auth_package:
            return 0.3
        return 0.5
    except Exception:
        logger.exception("Unexpected error")
        return 0.5


@_window_cached
def _get_distinct_source_ips(session, target_user: str, hours: int = 24) -> float:
    """Count of distinct source IPs for a target user."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        rows = session.execute(
            select(NormalizedEvent.raw_json)
            .where(NormalizedEvent.event_id.in_((4624, 4625)))
            .where(NormalizedEvent.timestamp >= since)
        ).all()
        ips = set()
        for (raw,) in rows:
            facts = (raw or {}).get("facts") or {}
            user = str(facts.get("target_user", "") or "")
            if user.lower() == target_user.lower():
                ip = str(facts.get("source_ip", "") or "")
                if ip:
                    ips.add(ip)
        return min(1.0, len(ips) / 10.0)
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


@_window_cached
def _get_hour_distribution_entropy(session, hours: int = 24) -> float:
    """Entropy of login hour distribution (diversity of login times)."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        timestamps = session.scalars(
            select(NormalizedEvent.timestamp)
            .where(NormalizedEvent.event_id.in_(LOGIN_EVENTS))
            .where(NormalizedEvent.timestamp >= since)
        ).all()
        if not timestamps:
            return 0.0
        hour_counts: dict[int, int] = {}
        for ts in timestamps:
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            h = ts.hour
            hour_counts[h] = hour_counts.get(h, 0) + 1
        total = sum(hour_counts.values())
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in hour_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        max_entropy = math.log2(max(len(hour_counts), 1))
        return min(1.0, entropy / max(max_entropy, 1.0))
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_cross_stream_features(
    session, current_event_id: int, hours: int = 1
) -> list[float]:
    """Cross-stream sequence features capturing attack patterns.

    Returns features that capture temporal relationships across behavior streams:
    1. recent_failed_logins: failed login count in last hour
    2. recent_suspicious_processes: suspicious process count in last hour
    3. recent_network_connections: network connection count in last hour
    4. login_process_ratio: ratio of login to process events
    5. time_since_last_any_event: time since any event across all streams
    6. has_failed_then_process: 1 if failed login followed by process event
    7. has_process_then_network: 1 if process event followed by network
    8. event_diversity: number of distinct event types in last hour

    Every value is a window aggregate (``current_event_id`` does not affect
    any of them), so the result is identical for all events in one pass and
    is cached as such.
    """
    try:
        def _compute() -> list[float]:
            since = datetime.now(UTC) - timedelta(hours=hours)
            # Count recent events per stream
            failed_logins = (
                session.scalar(
                    select(func.count(NormalizedEvent.id))
                    .where(NormalizedEvent.event_id == 4625)  # Failed logon
                    .where(NormalizedEvent.timestamp >= since)
                )
                or 0
            )

            suspicious_processes = (
                session.scalar(
                    select(func.count(NormalizedEvent.id))
                    .where(NormalizedEvent.event_id.in_(PROCESS_EVENTS))
                    .where(NormalizedEvent.timestamp >= since)
                )
                or 0
            )

            network_connections = (
                session.scalar(
                    select(func.count(NormalizedEvent.id))
                    .where(
                        NormalizedEvent.event_id.in_(
                            NETWORK_EVENTS if NETWORK_EVENTS else set()
                        )
                    )
                    .where(NormalizedEvent.timestamp >= since)
                )
                or 0
            )

            # Time since last event across all streams
            last_event_time = session.scalar(
                select(func.max(NormalizedEvent.timestamp)).where(
                    NormalizedEvent.timestamp >= since
                )
            )
            if last_event_time:
                time_since_last = (
                    datetime.now(UTC) - last_event_time
                ).total_seconds() / 3600.0
            else:
                time_since_last = 1.0  # Default to 1 hour if no events

            # Event diversity (distinct event types)
            event_diversity = (
                session.scalar(
                    select(func.count(func.distinct(NormalizedEvent.event_id))).where(
                        NormalizedEvent.timestamp >= since
                    )
                )
                or 0
            )

            # Ratio features
            login_process_ratio = failed_logins / max(suspicious_processes, 1)

            # Sequence detection (simplified: check if both types occurred)
            has_failed_then_process = (
                1.0 if (failed_logins > 0 and suspicious_processes > 0) else 0.0
            )
            has_process_then_network = (
                1.0 if (suspicious_processes > 0 and network_connections > 0) else 0.0
            )

            return [
                min(failed_logins / 10.0, 1.0),  # Normalized failed logins
                min(suspicious_processes / 10.0, 1.0),  # Normalized suspicious processes
                min(network_connections / 10.0, 1.0),  # Normalized network connections
                min(login_process_ratio, 1.0),  # Login/process ratio (capped at 1)
                min(time_since_last, 1.0),  # Time since last event (capped at 1 hour)
                has_failed_then_process,
                has_process_then_network,
                min(event_diversity / 5.0, 1.0),  # Event diversity (normalized)
            ]

        return list(_cached(("cross_stream", hours), _compute))
    except Exception as exc:
        return _feature_db_error(session, exc, [0.0] * 8)


# ---------------------------------------------------------------------------
# Network stream enhanced features
# ---------------------------------------------------------------------------
def _get_connection_velocity_per_ip(
    session, remote_ip: str, minutes: int = 60
) -> float:
    """Get connection velocity (connections per minute) for a specific remote IP."""
    try:
        since = datetime.now(UTC) - timedelta(minutes=minutes)
        count = (
            session.scalar(
                select(func.count(NetworkConnection.id))
                .where(NetworkConnection.remote_ip == remote_ip)
                .where(NetworkConnection.observed_at >= since)
            )
            or 0
        )
        return min(1.0, count / (minutes * 10.0))  # Normalize: 10 connections/min = max
    except Exception:
        logger.exception("Unexpected error")
        return 0.0


def _get_port_scan_indicator(session, remote_ip: str, minutes: int = 60) -> float:
    """Detect port scanning: high number of unique ports per IP."""
    try:
        since = datetime.now(UTC) - timedelta(minutes=minutes)
        unique_ports = (
            session.scalar(
                select(func.count(func.distinct(NetworkConnection.remote_port)))
                .where(NetworkConnection.remote_ip == remote_ip)
                .where(NetworkConnection.observed_at >= since)
            )
            or 0
        )

        # Port scan indicator: >10 unique ports in short time = suspicious
        return min(1.0, unique_ports / 20.0)  # Normalize: 20 ports = max
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_exfiltration_indicator(session, remote_ip: str, hours: int = 1) -> float:
    """Detect data exfiltration: high bytes_sent/bytes_recv ratio."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        row = session.execute(
            select(
                func.sum(NetworkConnection.bytes_sent),
                func.sum(NetworkConnection.bytes_recv),
            )
            .where(NetworkConnection.remote_ip == remote_ip)
            .where(NetworkConnection.observed_at >= since)
        ).one()

        bytes_sent = float(row[0] or 0)
        bytes_recv = float(row[1] or 0)

        if bytes_recv == 0:
            return 0.5 if bytes_sent > 0 else 0.0

        # Exfiltration ratio: high sent vs received
        ratio = bytes_sent / bytes_recv
        # Normalize: ratio > 10 = high exfiltration indicator
        return min(1.0, ratio / 10.0)
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_beaconing_indicator(session, remote_ip: str, hours: int = 1) -> float:
    """Detect beaconing: regular interval connections to same IP."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        timestamps = session.scalars(
            select(NetworkConnection.observed_at)
            .where(NetworkConnection.remote_ip == remote_ip)
            .where(NetworkConnection.observed_at >= since)
            .order_by(NetworkConnection.observed_at)
        ).all()

        if len(timestamps) < 5:
            return 0.0

        # Convert to datetime objects
        dt_times = []
        for ts in timestamps:
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            dt_times.append(ts)

        # Calculate intervals between connections
        intervals = []
        for i in range(1, len(dt_times)):
            interval = (dt_times[i] - dt_times[i - 1]).total_seconds()
            intervals.append(interval)

        if len(intervals) < 3:
            return 0.0

        # Calculate coefficient of variation (CV) of intervals
        # Low CV = regular intervals = beaconing
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval == 0:
            return 0.0

        std_interval = (
            sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
        ) ** 0.5
        cv = std_interval / mean_interval

        # Beaconing indicator: CV < 0.3 = regular, CV > 1.0 = random
        # Invert so high score = more beaconing-like
        return max(0.0, min(1.0, 1.0 - cv))
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_dns_query_pattern(session, hours: int = 1) -> float:
    """Analyze DNS query patterns for anomaly detection.

    Extracts real features from DnsQuery model:
    - Query volume ratio (queries per minute)
    - Unique domain diversity
    - Average response size (large responses may indicate tunneling)
    - Unusual query types (TXT, NULL, CNAME chains)
    """
    try:
        from backend.database.models import DnsQuery
        since = datetime.now(UTC) - timedelta(hours=hours)

        total_queries = (
            session.scalar(
                select(func.count(DnsQuery.id))
                .where(DnsQuery.observed_at >= since)
            )
            or 0
        )

        if total_queries == 0:
            return 0.0

        # Unique domains queried
        unique_domains = (
            session.scalar(
                select(func.count(func.distinct(DnsQuery.query)))
                .where(DnsQuery.observed_at >= since)
            )
            or 0
        )

        # Average response size (DNS tunneling uses large responses)
        avg_response_size = (
            session.scalar(
                select(func.avg(DnsQuery.response_size))
                .where(DnsQuery.observed_at >= since)
                .where(DnsQuery.response_size > 0)
            )
            or 0
        )

        # Queries per minute rate
        queries_per_min = total_queries / max(hours * 60, 1)

        # Domain diversity ratio (low diversity + high volume = suspicious)
        domain_diversity = unique_domains / max(total_queries, 1)

        # Combine signals into anomaly score
        rate_score = min(1.0, queries_per_min / 10.0)  # >10 queries/min is high
        size_score = min(1.0, avg_response_size / 512.0)  # >512 bytes is large
        diversity_score = max(0.0, 1.0 - domain_diversity)  # Low diversity = high score

        return min(1.0, 0.4 * rate_score + 0.3 * size_score + 0.3 * diversity_score)
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_dns_tunnel_indicator(session, hours: int = 1) -> float:
    """Detect DNS tunneling via high query volume per unique domain."""
    try:
        from backend.database.models import DnsQuery
        since = datetime.now(UTC) - timedelta(hours=hours)
        total = (
            session.scalar(
                select(func.count(DnsQuery.id))
                .where(DnsQuery.observed_at >= since)
            )
            or 0
        )
        unique_domains = (
            session.scalar(
                select(func.count(func.distinct(DnsQuery.query)))
                .where(DnsQuery.observed_at >= since)
            )
            or 0
        )
        if unique_domains == 0:
            return 0.0
        queries_per_domain = total / unique_domains
        return min(1.0, queries_per_domain / 50.0)
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_dns_long_label_indicator(session, hours: int = 1) -> float:
    """Detect DNS queries with unusually long labels (tunneling signal)."""
    try:
        from backend.database.models import DnsQuery
        since = datetime.now(UTC) - timedelta(hours=hours)
        rows = session.scalars(
            select(DnsQuery.query)
            .where(DnsQuery.observed_at >= since)
            .limit(500)
        ).all()
        if not rows:
            return 0.0
        long_labels = 0
        for q in rows:
            if not q:
                continue
            labels = str(q).split(".")
            max_label = max((len(l) for l in labels), default=0)
            if max_label > 40:
                long_labels += 1
        return min(1.0, long_labels / max(len(rows), 1))
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_protocol_anomaly_score(session, remote_ip: str, remote_port: int) -> float:
    """Detect protocol anomalies: non-standard ports for known protocols."""
    well_known_ports = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https",
        993: "imaps", 995: "pop3s", 3389: "rdp", 5900: "vnc",
    }
    suspicious_ports = {4444, 5555, 6666, 8443, 1234, 31337, 44444, 12345}
    if remote_port in suspicious_ports:
        return 0.9
    if remote_port > 49152:
        return 0.3
    if remote_port in well_known_ports:
        return 0.1
    return 0.2


def _get_tls_https_ratio(session, hours: int = 1) -> float:
    """Ratio of HTTPS (443) connections to total connections."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        total = (
            session.scalar(
                select(func.count(NetworkConnection.id))
                .where(NetworkConnection.observed_at >= since)
            )
            or 0
        )
        https = (
            session.scalar(
                select(func.count(NetworkConnection.id))
                .where(NetworkConnection.remote_port == 443)
                .where(NetworkConnection.observed_at >= since)
            )
            or 0
        )
        if total == 0:
            return 0.0
        return https / total
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_connection_diversity_score(session, hours: int = 1) -> float:
    """Ratio of unique remote IPs to total connections (diversity indicator)."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        total = (
            session.scalar(
                select(func.count(NetworkConnection.id))
                .where(NetworkConnection.observed_at >= since)
            )
            or 0
        )
        unique_ips = (
            session.scalar(
                select(func.count(func.distinct(NetworkConnection.remote_ip)))
                .where(NetworkConnection.observed_at >= since)
            )
            or 0
        )
        if total == 0:
            return 0.0
        return min(1.0, unique_ips / total)
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_data_volume_asymmetry(session, remote_ip: str, hours: int = 1) -> float:
    """Detect data exfiltration via extreme send/recv asymmetry."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        row = session.execute(
            select(
                func.sum(NetworkConnection.bytes_sent),
                func.sum(NetworkConnection.bytes_recv),
            )
            .where(NetworkConnection.remote_ip == remote_ip)
            .where(NetworkConnection.observed_at >= since)
        ).one()
        sent = float(row[0] or 0)
        recv = float(row[1] or 0)
        if sent + recv == 0:
            return 0.0
        asymmetry = abs(sent - recv) / max(sent + recv, 1)
        return min(1.0, asymmetry)
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_connection_regularity_score(session, remote_ip: str, hours: int = 1) -> float:
    """Detect regular connection intervals (beaconing signal)."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        timestamps = session.scalars(
            select(NetworkConnection.observed_at)
            .where(NetworkConnection.remote_ip == remote_ip)
            .where(NetworkConnection.observed_at >= since)
            .order_by(NetworkConnection.observed_at)
        ).all()
        if len(timestamps) < 4:
            return 0.0
        dt_times = []
        for ts in timestamps:
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            dt_times.append(ts)
        intervals = [(dt_times[i] - dt_times[i-1]).total_seconds()
                     for i in range(1, len(dt_times))]
        if len(intervals) < 2:
            return 0.0
        mean_int = sum(intervals) / len(intervals)
        if mean_int == 0:
            return 0.0
        std_int = (sum((i - mean_int)**2 for i in intervals) / len(intervals))**0.5
        cv = std_int / mean_int
        return max(0.0, min(1.0, 1.0 - cv))
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_outbound_connection_ratio(session, hours: int = 1) -> float:
    """Ratio of outbound (non-listening) to total connections."""
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        total = (
            session.scalar(
                select(func.count(NetworkConnection.id))
                .where(NetworkConnection.observed_at >= since)
            )
            or 0
        )
        outbound = (
            session.scalar(
                select(func.count(NetworkConnection.id))
                .where(NetworkConnection.is_listening == False)
                .where(NetworkConnection.observed_at >= since)
            )
            or 0
        )
        if total == 0:
            return 0.0
        return outbound / total
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def event_feature_vector(event, _shared_session=None) -> list[float] | None:
    """Feature vector for a single event (None if the behavior stream is unknown).

    v6 feature space: enhanced behavioral features, parent-child analysis, LOLBin detection,
    port scanning, beaconing detection, temporal patterns, and Phase 2 temporal/contextual features.
    Training and scoring share this exact function, so the feature space never drifts.
    """
    from backend.database.connection import SessionLocal

    owns_session = _shared_session is None
    session = _shared_session or SessionLocal()
    try:
        event_id = (
            event.event_id if not isinstance(event, dict) else event.get("event_id", 0)
        )
        behavior = _behavior_of(int(event_id))
        hour_sin, hour_cos, is_night, is_weekend, _hour_of_day = _time_features(event)

        if behavior == "login":
            logon_type = _fact(event, "logon_type")
            source_ip = _fact_str(event, "source_ip", "")
            target_user = _fact_str(event, "target_user", "")

            # Base features (v9: no event_id to prevent label leakage)
            sub_status_raw = _fact(event, "sub_status", 0.0)
            try:
                sub_status = int(sub_status_raw)
            except (ValueError, TypeError):
                try:
                    sub_status = int(str(sub_status_raw), 16) if str(sub_status_raw).startswith("0x") else 0
                except (ValueError, TypeError):
                    sub_status = 0
            base_features = [
                logon_type,
                sub_status / 3221226036.0,
                _ip_feature(event, "source_ip") / 4_294_967_296.0,
                _bool_fact(event, "is_locked"),
                hour_sin,
                hour_cos,
                is_night,
                is_weekend,
                (
                    1.0
                    if logon_type > 0 and int(logon_type) not in _COMMON_LOGON_TYPES
                    else 0.0
                ),
            ]

            # Enhanced features (existing)
            enhanced_features = [
                _get_time_since_last_event(session, "login")
                / 24.0,
                min(
                    _get_recent_events_count(session, "login", 1) / 10.0, 1.0
                ),
                min(
                    _get_recent_events_count(session, "login", 24) / 100.0, 1.0
                ),
                _get_threat_intel_score(event),
            ]

            # New v5 features for login stream (must match training order)
            _ip_fail_count = _get_ip_fail_count(session, source_ip) if source_ip else 0
            login_v5_features = [
                min(
                    _get_failed_login_velocity_per_ip(session, source_ip, 5) / 2.0, 1.0
                ),
                min(
                    _get_failed_login_velocity_per_ip(session, source_ip, 15) / 5.0, 1.0
                ),
                min(
                    _get_failed_login_velocity_per_ip(session, source_ip, 60) / 10.0,
                    1.0,
                ),
                _get_logon_type_entropy(session, 1),
                _get_source_ip_diversity(
                    session, target_user, 24
                ),
                _get_time_between_logins_zscore(
                    session, 24
                ),
                min(_ip_fail_count / 20.0, 1.0),
            ]

            # Cross-stream sequence features
            cross_stream_features = _get_cross_stream_features(session, int(event_id))

            # Phase 2 temporal/contextual features (must match training order)
            _recent_1h = _get_recent_events_count(session, "login", 1)
            _recent_24h = _get_recent_events_count(session, "login", 24)
            _burst = min(_recent_1h / max(_recent_24h / 24.0, 0.01), 2.0) if _recent_24h > 0 else (1.0 if _recent_1h > 0 else 0.0)
            _kc = 0.0 if int(event_id) == 4624 else (
                0.25 if int(event_id) == 4625 else (
                0.5 if int(event_id) in (4740, 4648) else 0.0))
            temporal_features = [
                _get_business_hours_indicator(event),
                _burst,
                _kc,
                _get_failed_success_ratio(session, source_ip, 24),
                _get_hour_distribution_entropy(session, 24),
            ]

            # v7 enhanced features: auth protocol, distinct IPs, login velocities
            v7_features = [
                _get_auth_protocol_indicator(event),
                _get_distinct_source_ips(session, target_user, 24),
                min(_recent_1h / 5.0, 1.0),
                min(_recent_24h / 50.0, 1.0),
            ]

            return (
                base_features
                + enhanced_features
                + login_v5_features
                + cross_stream_features
                + temporal_features
                + v7_features
            )

        if behavior == "process":
            # Per-user context for process events (fixes empty user string bug)
            _proc_user = _fact_str(event, "user", "") or _fact_str(event, "target_user", "")

            # Base features (with cyclical time encoding)
            base_features = [
                int(event_id),
                _bool_fact(event, "has_encoded"),
                _bool_fact(event, "has_download"),
                _bool_fact(event, "has_hidden"),
                _bool_fact(event, "group_sid"),
                min(1.0, _fact(event, "script_len") / 256.0),
                min(1.0, _fact(event, "cmdline_len") / 512.0),
                hour_sin,
                hour_cos,
                _bool_fact(event, "has_remote"),
            ]

            # Enhanced features (existing)
            enhanced_features = [
                _get_time_since_last_event(session, "process")
                / 24.0,  # normalized hours since last process
                min(
                    _get_recent_events_count(session, "process", 1) / 10.0, 1.0
                ),  # processes in last hour (capped at 10)
                min(
                    _get_recent_events_count(session, "process", 24) / 100.0, 1.0
                ),  # processes in last day (capped at 100)
                _get_threat_intel_score(event),  # threat intelligence score
            ]

            # New v5 features for process stream
            process_v5_features = [
                _get_parent_child_anomaly_score(event),  # Parent-child anomaly
                _get_commandline_entropy(event),  # Command line entropy
                _get_process_frequency_per_user(
                    session, event, 1
                ),  # Process frequency per user
                _get_lolbin_abuse_indicator(event),  # LOLBin abuse indicator
                _get_new_process_path_indicator(session, event, 24),  # New process path
            ]

            # Cross-stream sequence features
            cross_stream_features = _get_cross_stream_features(session, int(event_id))

            # Phase 2 temporal/contextual features
            # Per-user process features (user-specific baselines)
            _proc_user_fail = 0
            _proc_user_total = 0
            _proc_user_distinct = 0
            if _proc_user:
                try:
                    _now = datetime.now(UTC)
                    _hour_ago = _now - timedelta(hours=1)
                    _day_ago = _now - timedelta(hours=24)
                    _proc_user_total = int(
                        session.scalar(
                            select(func.count(NormalizedEvent.id))
                            .where(NormalizedEvent.event_id.in_(PROCESS_EVENTS))
                            .where(NormalizedEvent.timestamp >= _day_ago)
                            .where(
                                NormalizedEvent.raw_json["facts"]["user"].cast(String)
                                == _proc_user
                            )
                        )
                        or 0
                    )
                    _proc_user_fail = int(
                        session.scalar(
                            select(func.count(NormalizedEvent.id))
                            .where(NormalizedEvent.event_id == 4625)
                            .where(NormalizedEvent.timestamp >= _day_ago)
                            .where(
                                NormalizedEvent.raw_json["facts"]["user"].cast(String)
                                == _proc_user
                            )
                        )
                        or 0
                    )
                    _proc_user_distinct = min(
                        1.0,
                        int(
                            session.scalar(
                                select(func.count(func.distinct(NormalizedEvent.raw_json["facts"]["image_path"].cast(String))))
                                .where(NormalizedEvent.event_id.in_(PROCESS_EVENTS))
                                .where(NormalizedEvent.timestamp >= _day_ago)
                                .where(
                                    NormalizedEvent.raw_json["facts"]["user"].cast(String)
                                    == _proc_user
                                )
                            )
                            or 0
                        )
                        / 20.0,
                    )
                except Exception:
                    logger.exception("Per-user process features failed")

            # Phase 2 temporal/contextual features
            temporal_features = [
                _get_business_hours_indicator(event),
                min(_get_event_burst_score(session, "process", 5), 2.0),
                _get_kill_chain_phase(event),
                _get_threat_intel_score(event),
                _get_user_attack_frequency(session, _proc_user, 168),
                # Per-user process features (new)
                min(_proc_user_total / 100.0, 1.0),  # user's process volume 24h
                min(_proc_user_fail / max(_proc_user_total, 1), 1.0),  # user's failure ratio
                _proc_user_distinct,  # user's distinct process diversity
            ]

            # v7 enhanced features: path entropy, system dir, parent risk, cmd tokens, chain depth
            v7_features = [
                _get_executable_path_entropy(event),
                _get_system_directory_indicator(event),
                _get_parent_process_risk_score(event),
                _get_commandline_token_count(event),
                _get_process_chain_depth(session, event, 1),
            ]

            # v10 features: writable dir, user dir, encoded, download, attack tool, Office parent
            _img_lower = str(_fact(event, "image_path") or _fact(event, "new_process") or "").lower()
            _cmd_str = str(_fact(event, "command_line") or "").lower()
            _par_lower = str(_fact(event, "parent_process") or "").lower()
            _tgt_img = str(_fact(event, "target_image") or "").lower()
            v10_features = [
                1.0 if any(x in _img_lower for x in ("\\downloads\\", "\\appdata\\", "\\temp\\", "\\public\\")) else 0.0,
                1.0 if "\\users\\" in _img_lower else 0.0,
                1.0 if any(x in _cmd_str for x in ("-enc", "-encodedcommand", "frombase64")) else 0.0,
                1.0 if any(x in _cmd_str for x in ("invoke-webrequest", "curl", "wget", "downloadstring", "bitsadmin")) else 0.0,
                1.0 if any(x in _img_lower for x in ("mimikatz", "psexec", "rubeus", "seatbelt", "procdump", "purplesharp", "lazagne", "sharpup")) else 0.0,
                1.0 if any(x in _par_lower for x in ("winword", "excel", "outlook")) else 0.0,
                1.0 if "lsass" in _img_lower or "lsass" in _tgt_img else 0.0,
                1.0 if "powershell" in _img_lower and _cmd_str else 0.0,
            ]

            return (
                base_features
                + enhanced_features
                + process_v5_features
                + cross_stream_features
                + temporal_features
                + v7_features
                + v10_features
            )

        # For network or unknown behaviors, return None to use existing network handling
        return None
    except AttributeError as exc:
        # Shape mismatch (e.g. dict passed where .facts expected) - not a DB
        # failure; never count toward the feature-error abort threshold.
        logger.debug("event_feature_vector shape error: %s", exc)
        return None
    except Exception as exc:
        return _feature_db_error(session, exc, None)
    finally:
        if owns_session:
            session.close()


# ---------------------------------------------------------------------------
# Temporal feature helpers (Phase 2)
# ---------------------------------------------------------------------------
def _get_business_hours_indicator(event) -> float:
    """1.0 if the event occurred during business hours (08:00-18:00 Mon-Fri), 0.0 otherwise."""
    _, _, _is_night, is_weekend, hour_of_day = _time_features(event)
    if is_weekend:
        return 0.0
    return 1.0 if 8 <= hour_of_day < 18 else 0.0


def _get_user_session_deviation(
    session, user: str, behavior: str, hours: int = 24
) -> float:
    """Z-score of the current session duration vs the user's historical mean.

    A high absolute z-score means the session length deviates significantly
    from the user's norm, which may indicate compromised credentials or
    automated tooling.
    """
    if not user or behavior not in LOGIN_EVENTS:
        return 0.0
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        rows = session.execute(
            select(NormalizedEvent.raw_json).where(
                NormalizedEvent.event_id.in_(
                    behavior == "login" and LOGIN_EVENTS or PROCESS_EVENTS
                ),
                NormalizedEvent.timestamp >= since,
            )
        ).all()
        durations: list[float] = []
        for (raw,) in rows:
            facts = (raw or {}).get("facts") or {}
            tgt = str(facts.get("target_user", "") or "")
            if tgt.lower() == user.lower():
                dur = float(facts.get("session_duration", 0) or 0)
                if dur > 0:
                    durations.append(dur)
        if len(durations) < 3:
            return 0.0
        import statistics

        mu = statistics.mean(durations)
        sigma = statistics.stdev(durations)
        if sigma < 1e-9:
            return 0.0
        latest = durations[-1]
        return max(-3.0, min(3.0, (latest - mu) / sigma))
    except Exception:
        logger.exception("Unexpected error")
        return 0.0


@_window_cached
def _get_event_burst_score(session, behavior: str, minutes: int = 5) -> float:
    """Burst score: ratio of events in the last `minutes` to the hourly rate.

    A burst score >> 1.0 means events are clustered together in time (possible
    automated attack or tool execution).
    """
    event_ids = LOGIN_EVENTS if behavior == "login" else PROCESS_EVENTS
    try:
        now = datetime.now(UTC)
        recent_since = now - timedelta(minutes=minutes)
        hourly_since = now - timedelta(hours=1)
        recent_count = (
            session.scalar(
                select(func.count(NormalizedEvent.id)).where(
                    NormalizedEvent.event_id.in_(event_ids),
                    NormalizedEvent.timestamp >= recent_since,
                )
            )
            or 0
        )
        hourly_count = (
            session.scalar(
                select(func.count(NormalizedEvent.id)).where(
                    NormalizedEvent.event_id.in_(event_ids),
                    NormalizedEvent.timestamp >= hourly_since,
                )
            )
            or 0
        )
        if hourly_count == 0:
            return 0.0
        # Scale: if all hourly events are in the burst window, score = 1.0
        # Extrapolate hourly rate from the burst window
        extrapolated = float(recent_count) * (60.0 / max(minutes, 1))
        return min(2.0, extrapolated / max(float(hourly_count), 1.0))
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


def _get_kill_chain_phase(event) -> float:
    """Encode the kill chain phase of the event as a normalized float.

    Phase mapping (MITRE ATT&CK alignment):
    0.0 = Reconnaissance/Initial Access (logons)
    0.25 = Execution (process creation, PowerShell)
    0.5 = Persistence (service install, scheduled task)
    0.75 = Lateral Movement/Privilege Escalation (account changes)
    1.0 = Exfiltration/Impact (network, file operations)
    """
    event_id = int(
        event.event_id if not isinstance(event, dict) else event.get("event_id", 0)
    )
    if event_id in (4624, 4625, 4634, 4647, 4771):
        return 0.0  # Initial Access
    if event_id in (4688, 4104, 4103):
        return 0.25  # Execution
    if event_id in (7045, 4698):
        return 0.5  # Persistence
    if event_id in (4720, 4726, 4732):
        return 0.75  # Privilege Escalation / Lateral Movement
    return 0.5  # Default


def _get_user_attack_frequency(session, user: str, hours: int = 168) -> float:
    """Historical attack frequency for this user over the past `hours`.

    Returns the fraction of the user's recent events that were labelled as
    attacks (heuristic or analyst verdict). A high value means the user
    account has a history of suspicious activity.
    """
    if not user:
        return 0.0
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        rows = session.execute(
            select(
                NormalizedEvent.id, NormalizedEvent.event_id, NormalizedEvent.raw_json
            ).where(NormalizedEvent.timestamp >= since)
        ).all()
        total = 0
        attacks = 0
        verdicts = _verdict_map(session)
        for eid, raw_event_id, raw in rows:
            facts = (raw or {}).get("facts") or {}
            tgt = str(facts.get("target_user", "") or "")
            if tgt.lower() != user.lower():
                continue
            total += 1
            if eid in verdicts:
                if verdicts[eid]:
                    attacks += 1
            elif MLAnomalyDetector._is_attack_sample(raw_event_id, raw or {}):
                attacks += 1
        if total < 3:
            return 0.0
        return min(1.0, attacks / total)
    except Exception as exc:
        return _feature_db_error(session, exc, 0.0)


# ---------------------------------------------------------------------------
# Feature extraction (per behavior stream)
# ---------------------------------------------------------------------------
def _verdict_map(session) -> dict[int, int]:
    """Authoritative analyst labels: {event_id: 1|0} from the feedback loop.

    Analyst-confirmed attacks (``true_positive``) are always labelled 1 and
    confirmed false-positives 0 - these override the heuristic labeler for
    supervised training so real analyst judgment shapes the decision surface.
    """
    rows = session.execute(select(Verdict.event_id, Verdict.verdict)).all()
    return {
        int(event_id): (1 if verdict == "true_positive" else 0)
        for event_id, verdict in rows
    }


def _load_behavior_features(
    session,
    since: datetime | None,
    event_ids: set[int],
    with_labels: bool = False,
    cutoff: datetime | None = None,
    max_samples: int = 10000,
):
    """Per-event feature matrix for a behavior stream.

    ``with_labels=True`` also returns a binary label per row - analyst
    verdicts override the heuristic facts for events the analyst reviewed.
    ``cutoff`` caps the upper bound so baseline fitting never sees a window.
    ``since=None`` means the FULL history (no lower time bound) - training
    on every collected event instead of a sample window.
    ``max_samples`` caps the number of rows returned (default 10000).
    """
    from backend.database.connection import SessionLocal as _SL
    _own = session is None
    _sess = session or _SL()
    try:
        stmt = select(NormalizedEvent).where(
            NormalizedEvent.event_id.in_(event_ids),
        )
        if since is not None:
            stmt = stmt.where(NormalizedEvent.timestamp >= since)
        if cutoff is not None:
            stmt = stmt.where(NormalizedEvent.timestamp < cutoff)
        rows = _sess.scalars(stmt.limit(max_samples)).all()
        X = []
        y = []
        verdicts = _verdict_map(_sess) if with_labels else {}
        with _feature_pass_cache():
            for ev in rows:
                try:
                    if orm_event_is_corrupted(ev)[0]:
                        continue
                    features = event_feature_vector(ev, _shared_session=_sess)
                    if not features:
                        continue
                    X.append(features)
                    if with_labels:
                        if ev.id in verdicts:
                            y.append(verdicts[ev.id])
                            continue
                        y.append(
                            1
                            if MLAnomalyDetector._is_attack_sample(ev.event_id, ev.raw_json or {})
                            else 0
                        )
                except Exception:
                    logger.exception("Unexpected error")
                    continue
        if with_labels:
            return (
                np.array(X, dtype=float) if X else np.empty((0, 9)),
                np.array(y, dtype=int) if y else np.empty((0,), dtype=int),
            )
        return np.array(X, dtype=float) if X else np.empty((0, 9))
    finally:
        if _own:
            _sess.close()


def _load_network_features(
    session, since: datetime | None, cutoff: datetime | None = None
) -> tuple[np.ndarray, list[dict]]:
    """Per-event network features from ALL events (113K+ samples).

    v12: Every event gets a network feature vector. For network-typed events
    (Sysmon 3, DNS 22, WFP 5156/5157/5158) the IP fields are extracted from
    raw_json. For login/process events the IP fields default to empty but the
    event still carries temporal, frequency, and behavioral-type features that
    help the Isolation Forest learn what "normal network context" looks like.
    """
    import math
    from backend.database.connection import SessionLocal
    from backend.ml.realworld_labeler import is_attack_ip_offline

    local_session = SessionLocal()
    try:
        stmt = (
            select(
                NormalizedEvent.id,
                NormalizedEvent.event_id,
                NormalizedEvent.timestamp,
                NormalizedEvent.raw_json,
            )
        )
        if since is not None:
            stmt = stmt.where(NormalizedEvent.timestamp >= since)
        if cutoff is not None:
            stmt = stmt.where(NormalizedEvent.timestamp < cutoff)
        stmt = stmt.order_by(NormalizedEvent.timestamp)
        rows = local_session.execute(stmt).all()
        if not rows:
            return np.empty((0, 28)), []

        def _ip_num(ip: str) -> float:
            try:
                parts = ip.split(".")
                if len(parts) == 4:
                    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts)) / 4_294_967_296.0
            except Exception:
                return 0.0
            return 0.0

        def _is_private(ip: str) -> float:
            return 1.0 if (
                ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("172.17.")
                or ip.startswith("172.18.") or ip.startswith("172.19.")
                or ip.startswith("172.2") or ip.startswith("172.3")
                or ip.startswith("192.168.") or ip.startswith("127.")
            ) else 0.0

        def _is_link_local(ip: str) -> float:
            return 1.0 if ip.startswith("169.254.") or ip.startswith("fe80") else 0.0

        def _is_multicast(ip: str) -> float:
            return 1.0 if ip.startswith("224.") or ip.startswith("239.") or ip.startswith("ff") else 0.0

        def _is_loopback(ip: str) -> float:
            return 1.0 if ip in ("127.0.0.1", "::1", "0:0:0:0:0:0:0:1") else 0.0

        def _parse_net_event(raw_json, eid):
            src = rip = ""
            rport = 0
            if raw_json is None:
                return src, rip, rport
            if isinstance(raw_json, str):
                import json
                try:
                    raw_json = json.loads(raw_json)
                except Exception:
                    logger.exception("Unexpected error")
                    raw_json = {}
            if isinstance(raw_json, dict):
                if not raw_json.get("source_ip") and raw_json.get("facts"):
                    facts = raw_json["facts"]
                    src = str(facts.get("source_ip", ""))
                    rip = str(facts.get("remote_ip", ""))
                    rport = int(facts.get("remote_port", 0) or 0)
                else:
                    src = str(raw_json.get("source_ip", ""))
                    rip = str(raw_json.get("remote_ip", ""))
                    rport = int(raw_json.get("remote_port", 0) or 0)
            return src, rip, rport

        def _net_event_type(eid: int) -> float:
            mapping = {3: 0.0, 22: 0.25, 5156: 0.5, 5157: 0.75, 5158: 1.0}
            return mapping.get(eid, -1.0)

        def _is_network_event(eid: int) -> float:
            return 1.0 if eid in NETWORK_EVENTS else 0.0

        def _is_login_event(eid: int) -> float:
            return 1.0 if eid in LOGIN_EVENTS else 0.0

        def _is_process_event(eid: int) -> float:
            return 1.0 if eid in PROCESS_EVENTS else 0.0

        flows = []
        metas = []
        ip_counts: dict[str, int] = {}
        src_ip_counts: dict[str, int] = {}
        prev_ts: dict[str, float] = {}
        prev_src_ts: dict[str, float] = {}

        for row in rows:
            ev_id, eid, ts, raw = row
            eid = int(eid)
            ts_float = ts.timestamp() if ts else 0.0

            src_ip, dst_ip, dst_port = _parse_net_event(raw, eid)

            ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1 if dst_ip else 0
            src_ip_counts[src_ip] = src_ip_counts.get(src_ip, 0) + 1 if src_ip else 0

            hour = ts.hour if ts else 12
            hour_sin = math.sin(2 * math.pi * hour / 24)
            hour_cos = math.cos(2 * math.pi * hour / 24)
            is_night = 1.0 if hour in _NIGHT_HOURS else 0.0
            is_weekend = 1.0 if (ts.weekday() if ts else 0) >= 5 else 0.0

            prev = prev_ts.get(dst_ip, 0.0) if dst_ip else 0.0
            time_since = (ts_float - prev) / 3600.0 if prev > 0 else 24.0
            time_since = min(time_since, 24.0)
            if dst_ip:
                prev_ts[dst_ip] = ts_float

            prev_src = prev_src_ts.get(src_ip, 0.0) if src_ip else 0.0
            time_since_src = (ts_float - prev_src) / 3600.0 if prev_src > 0 else 24.0
            time_since_src = min(time_since_src, 24.0)
            if src_ip:
                prev_src_ts[src_ip] = ts_float

            conn_count = ip_counts.get(dst_ip, 0) if dst_ip else 0
            src_count = src_ip_counts.get(src_ip, 0) if src_ip else 0

            is_atk = 1.0 if dst_ip and is_attack_ip_offline(dst_ip) else 0.0
            is_atk_src = 1.0 if src_ip and is_attack_ip_offline(src_ip) else 0.0

            port_cat = 0.0
            if dst_port > 0:
                if dst_port < 1024:
                    port_cat = 0.25
                elif dst_port < 10240:
                    port_cat = 0.5
                else:
                    port_cat = 0.75

            features = [
                _net_event_type(eid),
                _is_network_event(eid),
                _is_login_event(eid),
                _is_process_event(eid),
                hour_sin, hour_cos, is_night, is_weekend,
                _ip_num(src_ip), _ip_num(dst_ip),
                _is_private(src_ip), _is_private(dst_ip),
                _is_link_local(dst_ip), _is_multicast(dst_ip), _is_loopback(src_ip),
                float(dst_port) / 65535.0,
                port_cat,
                time_since / 24.0,
                time_since_src / 24.0,
                min(conn_count / 100.0, 1.0),
                min(src_count / 100.0, 1.0),
                is_atk, is_atk_src,
                min(time_since * 10, 1.0),
                1.0 if time_since < 0.003 else 0.0,
                min(conn_count / 50.0, 1.0),
                min(src_count / 50.0, 1.0),
                1.0 if src_ip == dst_ip and dst_ip else 0.0,
                1.0 if dst_ip and not src_ip else 0.0,
            ]

            flows.append(features)
            metas.append({
                "remote_ip": dst_ip,
                "source_ip": src_ip,
                "event_id": ev_id,
                "eid": eid,
                "timestamp": ts.isoformat() if ts else "",
            })

        X = np.array(flows, dtype=float)
        return X, metas
    finally:
        local_session.close()


def _load_network_features_legacy(
    session, since: datetime | None, cutoff: datetime | None = None
) -> tuple[np.ndarray, list[dict]]:
    """Legacy per-remote-IP flow features. Kept for backward compatibility."""
    from backend.database.connection import SessionLocal

    local_session = SessionLocal()
    try:
        stmt = select(
            NetworkConnection.remote_ip,
            func.count(NetworkConnection.id),
            func.count(func.distinct(NetworkConnection.remote_port)),
            func.sum(NetworkConnection.bytes_sent),
            func.sum(NetworkConnection.bytes_recv),
            func.avg(NetworkConnection.duration_seconds),
        )
        if since is not None:
            stmt = stmt.where(NetworkConnection.observed_at >= since)
        if cutoff is not None:
            stmt = stmt.where(NetworkConnection.observed_at < cutoff)
        rows = local_session.execute(stmt.group_by(NetworkConnection.remote_ip)).all()
        if not rows:
            return np.empty((0, 26)), []
        flows = []
        ips = []
        for r in rows:
            ip = r[0] or "unknown"
            ips.append(ip)
            subnet_feats = _ip_subnet_features(ip)[:8]
            count = int(r[1])
            distinct_ports = int(r[2])
            bytes_sent = float(r[3] or 0)
            bytes_recv = float(r[4] or 0)
            duration_h = float(r[5] or 0) / 3600.0
            sent_mb = bytes_sent / 1_000_000.0
            recv_mb = bytes_recv / 1_000_000.0
            rate = sent_mb / max(duration_h, 0.01)
            flow_feats = [
                min(float(count) / 100.0, 1.0),
                min(float(distinct_ports) / 20.0, 1.0),
                min(sent_mb / 10.0, 1.0),
                min(recv_mb / 10.0, 1.0),
                min(duration_h / 24.0, 1.0),
                min(rate / 10.0, 1.0),
            ]
            from backend.ml.realworld_labeler import is_attack_ip_offline as _aip
            is_atk = 1.0 if _aip(ip) else 0.0
            temporal_feats = [
                is_atk, 0.5, 0.5, 0.5, 0.5,
            ]
            net_feats = [0.0, 0.0, 0.0, 0.0, 0.5, 0.5, 0.5, 0.5]
            flows.append(subnet_feats + flow_feats + temporal_feats + net_feats)
        X = np.array(flows, dtype=float)
        X = np.hstack([X, np.zeros((X.shape[0], 2))])
        return X, [{"remote_ip": ip} for ip in ips]
    finally:
        local_session.close()


def _kfold_cross_validate(
    model_class,
    X: np.ndarray,
    y: np.ndarray,
    n_folds: int = 5,
    contamination: float = 0.05,
    random_state: int = 42,
    n_estimators: int = 100,
) -> dict:
    """K-fold cross-validation for anomaly detection models.

    Returns dict with keys: mean_score, std_score, fold_scores, fold_contaminations
    """
    from sklearn.model_selection import StratifiedKFold

    if len(X) < n_folds * 2:
        return {"mean_score": 0.0, "std_score": 0.0, "fold_scores": [], "fold_contaminations": []}

    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=random_state)
    fold_scores = []
    fold_contaminations = []

    for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X, y)):
        X_train, X_val = X[train_idx], X[val_idx]
        y_train, y_val = y[train_idx], y[val_idx]

        fold_contam = np.mean(y_train) if len(y_train) > 0 else contamination
        fold_contam = max(0.01, min(0.5, fold_contam))

        model = IsolationForest(
            contamination=fold_contam,
            random_state=random_state + fold_idx,
            n_estimators=n_estimators,
            max_samples=min(256, len(X_train)),
            n_jobs=1,
        )
        model.fit(X_train)

        scores = model.decision_function(X_val)
        normal_mask = y_val == 0
        anomaly_mask = y_val == 1

        if np.sum(normal_mask) > 0 and np.sum(anomaly_mask) > 0:
            normal_mean = np.mean(scores[normal_mask])
            anomaly_mean = np.mean(scores[anomaly_mask])
            separation = max(0.0, normal_mean - anomaly_mean)
            fold_scores.append(float(separation))
        else:
            fold_scores.append(0.0)

        fold_contaminations.append(float(fold_contam))

    return {
        "mean_score": float(np.mean(fold_scores)) if fold_scores else 0.0,
        "std_score": float(np.std(fold_scores)) if fold_scores else 0.0,
        "fold_scores": fold_scores,
        "fold_contaminations": fold_contaminations,
    }


def _multi_contamination_ensemble(
    X: np.ndarray,
    contamination_range: list[float] | None = None,
    n_estimators: int = 100,
    random_state: int = 42,
) -> list[IsolationForest]:
    """Train multiple IF models with different contamination levels for better recall."""
    if contamination_range is None:
        contamination_range = [0.01, 0.03, 0.05, 0.10, 0.15, 0.20]
    models = []
    for contam in contamination_range:
        m = IsolationForest(
            contamination=contam,
            random_state=random_state,
            n_estimators=n_estimators,
            max_samples=min(256, len(X)),
            n_jobs=1,
        )
        m.fit(X)
        models.append(m)
    return models


def _calibrate_anomaly_scores(
    scores: np.ndarray,
    baseline_scores: np.ndarray | None = None,
) -> np.ndarray:
    """Calibrate raw IF scores to [0,1] range using sigmoid or baseline normalization."""
    if baseline_scores is not None and len(baseline_scores) > 0:
        ref_min = float(np.percentile(baseline_scores, 1))
        ref_max = float(np.percentile(baseline_scores, 99))
        if ref_max - ref_min < 1e-10:
            return np.full_like(scores, 0.5, dtype=float)
        calibrated = (scores - ref_min) / (ref_max - ref_min)
        return np.clip(calibrated, 0.0, 1.0)
    else:
        return 1.0 / (1.0 + np.exp(-scores))


def _select_optimal_threshold(
    scores: np.ndarray,
    labels: np.ndarray,
    method: str = "youden",
) -> float:
    """Select optimal anomaly threshold using Youden's J or F1 maximization."""
    if len(scores) == 0 or len(labels) == 0:
        return 0.5
    thresholds = np.linspace(float(np.min(scores)), float(np.max(scores)), 200)
    best_score = -1.0
    best_thresh = 0.5
    for thresh in thresholds:
        pred = (scores >= thresh).astype(int)
        tp = int(np.sum((pred == 1) & (labels == 1)))
        fp = int(np.sum((pred == 1) & (labels == 0)))
        fn = int(np.sum((pred == 0) & (labels == 1)))
        tn = int(np.sum((pred == 0) & (labels == 0)))
        if method == "youden":
            sensitivity = tp / max(tp + fn, 1)
            specificity = tn / max(tn + fp, 1)
            j = sensitivity + specificity - 1
            if j > best_score:
                best_score = j
                best_thresh = thresh
        else:
            precision = tp / max(tp + fp, 1)
            recall = tp / max(tp + fn, 1)
            f1 = 2 * precision * recall / max(precision + recall, 1e-10)
            if f1 > best_score:
                best_score = f1
                best_thresh = thresh
    return float(best_thresh)


def _smote_augment(
    X: np.ndarray,
    y: np.ndarray,
    minority_class: int = 1,
    k_neighbors: int = 5,
    random_state: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """SMOTE-like synthetic oversampling for minority class.

    Generates synthetic samples by interpolating between minority class neighbors.
    Returns (X_augmented, y_augmented) with synthetic samples added.
    """
    rng = np.random.RandomState(random_state)
    minority_mask = y == minority_class
    X_minority = X[minority_mask]

    if len(X_minority) < 2:
        return X, y

    n_synthetic = min(len(X_minority), max(1, int(len(X_minority) * 0.5)))
    actual_k = min(k_neighbors, len(X_minority) - 1)

    if actual_k < 1:
        return X, y

    synthetic_samples = []
    for _ in range(n_synthetic):
        idx = rng.randint(0, len(X_minority))
        sample = X_minority[idx]

        distances = np.linalg.norm(X_minority - sample, axis=1)
        neighbor_indices = np.argsort(distances)[1: actual_k + 1]

        if len(neighbor_indices) == 0:
            continue

        neighbor_idx = rng.choice(neighbor_indices)
        neighbor = X_minority[neighbor_idx]

        alpha = rng.random()
        synthetic = sample + alpha * (neighbor - sample)
        synthetic_samples.append(synthetic)

    if not synthetic_samples:
        return X, y

    X_synthetic = np.array(synthetic_samples)
    X_augmented = np.vstack([X, X_synthetic])
    y_augmented = np.concatenate([y, np.full(len(synthetic_samples), minority_class)])

    return X_augmented, y_augmented


class MLAnomalyDetector:
    """Per-behavior Isolation Forest + calibrated supervised classifier."""

    def __init__(self, load_persisted: bool = False):
        self.models: dict[str, IsolationForest] = {}
        self.ensembles: dict[str, list[IsolationForest]] = {}
        self.supervised: object = None
        self.supervised_name = "none"
        self.supervised_by_stream: dict[str, object] = {}
        self.supervised_name_by_stream: dict[str, str] = {}
        self.trained_at: str | None = None
        self.n_samples = 0
        self.events_at_train = 0
        self.encoders: dict[str, LabelEncoder] = {}
        self.thresholds: dict[str, float] = dict(_DEFAULT_THRESHOLDS)
        self.baselines: dict[str, np.ndarray] = {}
        self._persisted = False
        #: Roadmap 4.1 - online learning: model versioning + feedback weights.
        self.version = 0
        self.versions: list[dict] = []
        self.last_train_kind = "initial"
        #: Per-behavior multiplier applied to anomaly scores; analysts damp
        #: false positives (weight < 1) and reinforce true positives (> 1).
        self.feedback_weights: dict[str, float] = {}
        #: Where the serving models came from: "none" (never trained),
        #: "bootstrap" (bundled seed model on a fresh deployment) or
        #: "user" (trained on this deployment's own telemetry).
        self.model_source = "none"
        #: Phase 2.4: ensemble stacking meta-learner for IF + supervised + Markov fusion.
        self.ensemble = EnsembleStacker() if HAS_ENSEMBLE else None
        #: Phase 4: recall booster wrapper (UEBA + temporal + adversarial + recall-thresholds).
        self.recall_booster = None
        #: Phase 2.3: robustness evaluation result (updated after each train).
        self.robustness: dict = {}
        #: Phase 3: online learning wrapper for incremental updates.
        self.online_learner = OnlineLearner(self) if HAS_ENSEMBLE else None
        self._load_meta()
        if load_persisted and not self.models:
            if not self._load_bundle():
                self._load_bootstrap()

    # ------------------------------------------------------------------
    # Persistence (models + metadata)
    # ------------------------------------------------------------------
    def _bundle_path(self) -> Path:
        return Path(ML_MODEL_BUNDLE)

    def _prev_bundle_path(self) -> Path:
        """Archive bundle for A/B: kept one version behind the live one."""
        return Path(ML_MODEL_BUNDLE).with_suffix(".prev.joblib")

    def _meta_path(self):
        return ML_META_FILE

    def _load_meta(self) -> None:
        """Restore the last training snapshot so staleness survives restarts."""
        try:
            path = self._meta_path()
            if not path or not os.path.exists(path):
                return
            with open(path, encoding="utf-8") as fh:
                meta = json.load(fh)
            self.trained_at = meta.get("trained_at")
            self.n_samples = int(meta.get("n_samples", 0))
            self.events_at_train = int(meta.get("events_at_train", 0))
            self.supervised_name = meta.get("supervised", "none")
            self.thresholds = {
                **dict(_DEFAULT_THRESHOLDS),
                **{k: float(v) for k, v in (meta.get("thresholds") or {}).items()},
            }
            self.version = int(meta.get("version", 0))
            self.versions = list(meta.get("versions") or [])
            self.last_train_kind = meta.get("train_kind", "initial")
            self.feedback_weights = {
                k: float(v) for k, v in (meta.get("feedback_weights") or {}).items()
            }
        except (OSError, ValueError, TypeError):
            logger.warning("Could not read ML metadata at %s", ML_META_FILE)

    def _save_meta(self) -> None:
        try:
            path = self._meta_path()
            if not path:
                return
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "trained_at": self.trained_at,
                        "n_samples": self.n_samples,
                        "events_at_train": self.events_at_train,
                        "supervised": self.supervised_name,
                        "thresholds": self.thresholds,
                        "feature_version": ML_FEATURE_VERSION,
                        "version": self.version,
                        "versions": self.versions[-ML_VERSION_HISTORY:],
                        "train_kind": self.last_train_kind,
                        "feedback_weights": self.feedback_weights,
                    },
                    fh,
                    indent=2,
                )
        except OSError:
            logger.warning("Could not persist ML metadata to %s", ML_META_FILE)

    def _save_bundle(self) -> None:
        """Persist the trained models so restarts do not cold-start."""
        if not self.models:
            return
        try:
            import joblib

            bundle = {
                "feature_version": ML_FEATURE_VERSION,
                "models": self.models,
                "encoders": self.encoders,
                "supervised": self.supervised,
                "supervised_name": self.supervised_name,
                "supervised_by_stream": self.supervised_by_stream,
                "supervised_name_by_stream": self.supervised_name_by_stream,
                "thresholds": self.thresholds,
                "baselines": {k: v.tolist() for k, v in self.baselines.items()},
                "version": self.version,
                "feedback_weights": self.feedback_weights,
            }
            path = self._bundle_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                import shutil

                shutil.copy2(path, self._prev_bundle_path())
            joblib.dump(bundle, path, compress=3)
            self._persisted = True
        except Exception:
            logger.exception("Unexpected error")
            logger.warning("Could not persist ML model bundle", exc_info=True)

    def _load_bundle(self) -> bool:
        """Restore persisted models; ignored when the feature space changed."""
        path = self._bundle_path()
        if not path.exists():
            return False
        try:
            import joblib

            bundle = joblib.load(path)
            if bundle.get("feature_version") != ML_FEATURE_VERSION:
                logger.info("ML bundle has a different feature version; retraining")
                return False
            self.models = bundle.get("models", {})
            self.encoders = bundle.get("encoders", {})
            self.supervised = bundle.get("supervised")
            self.supervised_name = bundle.get("supervised_name", "none")
            self.supervised_by_stream = bundle.get("supervised_by_stream") or {}
            self.supervised_name_by_stream = (
                bundle.get("supervised_name_by_stream") or {}
            )
            self.thresholds = {
                **dict(_DEFAULT_THRESHOLDS),
                **bundle.get("thresholds", {}),
            }
            self.baselines = {
                k: np.asarray(v, dtype=float)
                for k, v in (bundle.get("baselines") or {}).items()
            }
            self.version = int(bundle.get("version", 0))
            self.feedback_weights = {
                k: float(v) for k, v in (bundle.get("feedback_weights") or {}).items()
            }
            self._persisted = True
            self.model_source = "user" if not bundle.get("bootstrap") else "bootstrap"
            return bool(self.models)
        except Exception:
            logger.exception("Unexpected error")
            logger.warning("Could not load ML model bundle; retraining", exc_info=True)
            return False

    def rollback(self) -> bool:
        """Roll back to the previous model version.

        Loads the ``.prev.joblib`` archive that was saved before the last
        ``_save_bundle()`` call.  Returns True if rollback succeeded.
        """
        import joblib

        prev_path = self._prev_bundle_path()
        if not prev_path.exists():
            logger.warning("No previous model bundle to rollback to")
            return False
        try:
            bundle = joblib.load(prev_path)
            if bundle.get("feature_version") != ML_FEATURE_VERSION:
                logger.warning("Previous bundle has incompatible feature version")
                return False
            self.models = bundle.get("models", {})
            self.encoders = bundle.get("encoders", {})
            self.supervised = bundle.get("supervised")
            self.supervised_name = bundle.get("supervised_name", "none")
            self.supervised_by_stream = bundle.get("supervised_by_stream") or {}
            self.supervised_name_by_stream = bundle.get("supervised_name_by_stream") or {}
            self.thresholds = {**dict(_DEFAULT_THRESHOLDS), **bundle.get("thresholds", {})}
            self.baselines = {k: np.asarray(v, dtype=float) for k, v in (bundle.get("baselines") or {}).items()}
            self.version = int(bundle.get("version", 0))
            self.feedback_weights = {k: float(v) for k, v in (bundle.get("feedback_weights") or {}).items()}
            self.model_source = "user" if not bundle.get("bootstrap") else "bootstrap"
            self._save_meta()
            logger.info("Rolled back to model version %d", self.version)
            return True
        except Exception:
            logger.exception("Unexpected error")
            logger.warning("Failed to rollback model bundle", exc_info=True)
            return False

    def _load_bootstrap(self) -> bool:
        """Day-1 cold start: load the bundled seed model.

        Fresh deployments have no locally-trained bundle, which used to mean
        a blind detector (default thresholds, no supervised opinion). The
        bootstrap asset - trained offline on a deterministic synthetic
        corpus - provides sane per-stream thresholds and a supervised
        network classifier until the first real retrain supersedes it.
        """
        if not ML_BOOTSTRAP_ENABLED:
            return False
        if not ML_ALLOW_BOOTSTRAP:
            # High-assurance deployments can refuse the synthetic seed model and
            # stay untrained until enough REAL telemetry is collected.
            logger.info("Bootstrap model refused (ML_ALLOW_BOOTSTRAP=0)")
            return False
        path = Path(ML_BOOTSTRAP_BUNDLE)
        if not path.exists():
            return False
        try:
            import joblib

            bundle = joblib.load(path)
            if bundle.get("feature_version") != ML_FEATURE_VERSION:
                logger.info("Bootstrap bundle feature version mismatch; ignoring")
                return False
            if not bundle.get("models"):
                return False
            self.models = bundle.get("models", {})
            self.encoders = bundle.get("encoders", {})
            self.supervised = bundle.get("supervised")
            self.supervised_name = bundle.get("supervised_name", "none")
            self.supervised_by_stream = bundle.get("supervised_by_stream") or {}
            self.supervised_name_by_stream = (
                bundle.get("supervised_name_by_stream") or {}
            )
            self.thresholds = {
                **dict(_DEFAULT_THRESHOLDS),
                **bundle.get("thresholds", {}),
            }
            self.baselines = {
                k: np.asarray(v, dtype=float)
                for k, v in (bundle.get("baselines") or {}).items()
            }
            self.n_samples = int(bundle.get("n_samples", 0))
            self.trained_at = bundle.get("trained_at")
            self.version = 0  # bootstrap is pre-versioning; real train starts at 1
            self.model_source = "bootstrap"
            self._persisted = False  # never A/B-archive the shipped asset
            logger.info(
                "Loaded bootstrap ML model (%s streams, thresholds %.2f/%.2f)",
                "/".join(sorted(self.models)),
                self.thresholds.get("process", 0.5),
                self.thresholds.get("network", 0.5),
            )
            return True
        except Exception:
            logger.exception("Unexpected error")
            logger.warning("Could not load bootstrap ML bundle", exc_info=True)
            return False

    # ------------------------------------------------------------------
    # Roadmap 4.1 - online feedback + versioning (improved)
    # ------------------------------------------------------------------
    def apply_feedback(
        self, verdict: str, behavior: str | None = None, score: float = 0.5
    ) -> None:
        """Adjust the per-behavior anomaly-score weight from analyst verdicts.

        Improved feedback mechanism with:
        1. Per-threshold-region adjustments (low/medium/high score regions)
        2. Confidence-weighted feedback (more verdicts = stronger adjustment)
        3. Asymmetric dampening (FP penalized more than TP reinforced)
        4. Feedback history tracking for analysis

        ``false_positive`` dampens the signal (stronger for high-confidence FPs);
        ``true_positive`` reinforces it (stronger for borderline TPs).
        """
        behavior = behavior or "login"
        if verdict not in ("true_positive", "false_positive"):
            return

        current = self.feedback_weights.get(behavior, 1.0)

        # Initialize feedback history if not present
        if not hasattr(self, "_feedback_history"):
            self._feedback_history: dict[str, int] = {}

        # Track feedback count for confidence weighting
        feedback_key = f"{behavior}_{verdict}"
        feedback_count = self._feedback_history.get(feedback_key, 0) + 1
        self._feedback_history[feedback_key] = feedback_count

        # Confidence factor: more feedback = stronger adjustment (diminishing returns)
        confidence = min(1.0, feedback_count / 10.0)

        # Score-region dependent adjustment
        if score > 0.8:
            # High-confidence anomaly: strong FP signal
            adjustment = 0.90 if verdict == "false_positive" else 1.02
        elif score > 0.5:
            # Medium-confidence: moderate adjustment
            adjustment = 0.95 if verdict == "false_positive" else 1.05
        else:
            # Low-confidence: weak adjustment (borderline cases)
            adjustment = 0.98 if verdict == "false_positive" else 1.08

        # Apply confidence weighting
        if verdict == "false_positive":
            # FP penalized more: asymmetric dampening
            new_weight = current * (adjustment**confidence)
        else:
            # TP reinforced with diminishing returns
            new_weight = current * (adjustment**confidence)

        # Bounds: FP can damp to 0.3, TP can boost to 2.0
        new_weight = max(0.3, min(2.0, new_weight))
        self.feedback_weights[behavior] = new_weight

        try:
            self._save_meta()
            path = self._bundle_path()
            if path.exists():
                import joblib

                bundle = joblib.load(path)
                bundle["feedback_weights"] = dict(self.feedback_weights)
                bundle["feedback_history"] = self._feedback_history
                joblib.dump(bundle, path, compress=3)
        except Exception:
            logger.exception("Unexpected error")
            logger.warning("Could not persist feedback weights", exc_info=True)
        logger.info(
            "ML feedback %s -> %s weight %.3f (score=%.3f, confidence=%d)",
            verdict,
            behavior,
            self.feedback_weights[behavior],
            score,
            feedback_count,
        )

    def _weighted_score(self, behavior: str, score: float) -> float:
        return float(
            max(0.0, min(1.0, score * self.feedback_weights.get(behavior, 1.0)))
        )

    def get_feedback_stats(self) -> dict:
        """Get feedback statistics for monitoring."""
        if not hasattr(self, "_feedback_history"):
            self._feedback_history = {}
        return {
            "weights": dict(self.feedback_weights),
            "history": dict(self._feedback_history),
            "total_feedback": sum(self._feedback_history.values()),
        }

    # ------------------------------------------------------------------
    # Canary / Shadow Scoring
    # ------------------------------------------------------------------
    def shadow_score_events(
        self,
        candidate_model: object,
        features_list: list[list[float]],
        behavior: str,
    ) -> list[float]:
        """Score events with a candidate model for A/B comparison.

        Returns scores from the candidate model without affecting production.
        Used for canary deployments and shadow scoring.
        """
        if candidate_model is None or not features_list:
            return [0.0] * len(features_list)

        try:
            X = np.array(features_list, dtype=float)
            if hasattr(candidate_model, "decision_function"):
                # Isolation Forest
                raw = 0.5 - candidate_model.decision_function(X)
                baseline = self.baselines.get(behavior)
                if baseline is not None and len(baseline) > 0:
                    ranks = np.interp(
                        raw, baseline, np.linspace(0.0, 1.0, len(baseline))
                    )
                    ranks = np.clip(ranks, 0.0, 1.0)
                else:
                    ranks = np.clip(raw, 0.0, 1.0)
                return ranks.tolist()
            elif hasattr(candidate_model, "predict_proba"):
                # Supervised classifier
                proba = candidate_model.predict_proba(X)
                if proba.shape[1] > 1:
                    return proba[:, 1].tolist()
            return [0.0] * len(features_list)
        except Exception:
            logger.exception("Unexpected error")
            logger.warning("Shadow scoring failed", exc_info=True)
            return [0.0] * len(features_list)

    def compare_models(
        self,
        production_scores: list[float],
        candidate_scores: list[float],
        true_labels: list[int],
    ) -> dict:
        """Compare production vs candidate model performance.

        Returns comparison metrics for A/B testing decisions.
        """
        if not production_scores or not candidate_scores or not true_labels:
            return {"error": "insufficient data"}

        prod_arr = np.array(production_scores)
        cand_arr = np.array(candidate_scores)
        labels = np.array(true_labels)

        def compute_metrics(scores, threshold=0.5):
            predicted = scores > threshold
            tp = int(((predicted) & (labels == 1)).sum())
            fp = int(((predicted) & (labels == 0)).sum())
            fn = int(((~predicted) & (labels == 1)).sum())
            tn = int(((~predicted) & (labels == 0)).sum())
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (
                2 * precision * recall / (precision + recall)
                if (precision + recall) > 0
                else 0.0
            )
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            return {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
            }

        prod_metrics = compute_metrics(prod_arr)
        cand_metrics = compute_metrics(cand_arr)

        # Determine if candidate is better
        f1_delta = cand_metrics["f1_score"] - prod_metrics["f1_score"]
        fpr_delta = (
            cand_metrics["false_positive_rate"] - prod_metrics["false_positive_rate"]
        )

        recommendation = "keep_production"
        if f1_delta > 0.05 and fpr_delta <= 0.02:
            recommendation = "deploy_candidate"
        elif f1_delta < -0.05:
            recommendation = "reject_candidate"

        return {
            "production": prod_metrics,
            "candidate": cand_metrics,
            "f1_delta": round(f1_delta, 4),
            "fpr_delta": round(fpr_delta, 4),
            "recommendation": recommendation,
            "n_samples": len(true_labels),
        }

    def version_info(self) -> dict:
        """Snapshot for /ml/status: serving version + history + feedback."""
        return {
            "version": self.version,
            "train_kind": self.last_train_kind,
            "trained_at": self.trained_at,
            "history": list(self.versions[-ML_VERSION_HISTORY:]),
            "feedback_weights": dict(self.feedback_weights),
        }

    # ------------------------------------------------------------------
    # Recall booster integration (Phase 4)
    # ------------------------------------------------------------------
    def set_recall_booster(self, booster) -> None:
        """Attach a RecallBooster instance for UEBA + temporal + recall-threshold scoring."""
        self.recall_booster = booster

    def update_recall_baselines(self, session, since: datetime | None = None) -> None:
        """Refresh UEBA and temporal cross-stream baselines from recent events."""
        if self.recall_booster is not None:
            self.recall_booster.update_baselines(session, since)

    def score_event_with_recall(self, behavior: str, features: list[float],
                                user: str = "", event_id: int = 0,
                                facts: dict | None = None,
                                ts: datetime | None = None,
                                source_ip: str = "",
                                target_user: str = "") -> float:
        """Score an event with recall enhancement (UEBA + temporal + booster)."""
        if self.recall_booster is not None:
            return self.recall_booster.score_event(
                behavior, features, user=user, event_id=event_id,
                facts=facts, ts=ts, source_ip=source_ip, target_user=target_user,
            )
        return self.score_event_for_behavior(behavior, features)

    # ------------------------------------------------------------------
    def _events_since_train(self, session) -> int:
        if not self.trained_at:
            return 0
        try:
            since = datetime.fromisoformat(self.trained_at)
        except ValueError:
            return 0
        return int(
            session.scalar(
                select(func.count(NormalizedEvent.id)).where(
                    NormalizedEvent.timestamp > since
                )
            )
            or 0
        )

    def _drift_result(self, session=None) -> tuple[bool, str]:
        """Sustained-anomaly drift check over recently *scored* events.

        Returns ``(drifted, reason)``. When recent traffic keeps landing above
        the per-stream thresholds, the learned baseline no longer matches the
        live distribution - exactly the "attacker became the new normal"
        scenario. A drifted model is marked stale so the scheduler retrains
        and the operator sees the signal.
        """
        if not self.trained_at or not self.models:
            return False, "untrained"
        close = session is None
        session = session or SessionLocal()
        try:
            try:
                since = datetime.fromisoformat(self.trained_at)
            except ValueError:
                return False, "unparseable-trained-at"
            rows = session.execute(
                select(NormalizedEvent.event_id, NormalizedEvent.ml_score).where(
                    NormalizedEvent.timestamp >= since,
                    NormalizedEvent.ml_score.isnot(None),
                )
            ).all()
            flagged = 0
            total = 0
            for event_id, ml_score in rows:
                behavior = _behavior_of(int(event_id))
                threshold = self.thresholds.get(behavior, 0.5)
                total += 1
                if float(ml_score or 0.0) > threshold:
                    flagged += 1
            if total < ML_DRIFT_MIN_SAMPLES:
                return (
                    False,
                    f"insufficient-recent-scores ({total}<{ML_DRIFT_MIN_SAMPLES})",
                )
            rate = flagged / total
            if rate > ML_DRIFT_RATE:
                return True, (
                    f"drifted: {rate:.1%} of {total} recent events flagged "
                    f"(> {ML_DRIFT_RATE:.0%})"
                )
            return False, f"ok ({rate:.1%} flagged)"
        finally:
            if close:
                session.close()

    def is_stale(self, session=None) -> tuple[bool, str]:
        """True when the model should be retrained (age, volume, or drift)."""
        if not self.trained_at:
            return True, "never-trained"
        try:
            age = datetime.now(UTC) - datetime.fromisoformat(self.trained_at)
        except ValueError:
            return True, "unparseable-trained-at"
        if age > timedelta(minutes=ML_RETRAIN_AFTER_MINUTES):
            return True, (
                f"trained {age.seconds // 60}m ago " f"(> {ML_RETRAIN_AFTER_MINUTES}m)"
            )
        if session is not None:
            new_events = self._events_since_train(session)
            if new_events >= ML_RETRAIN_MIN_NEW_EVENTS:
                return (
                    True,
                    f"{new_events} new events since training (>= {ML_RETRAIN_MIN_NEW_EVENTS})",
                )
            new_verdicts = int(
                session.scalar(
                    select(func.count(Verdict.id)).where(
                        Verdict.created_at > datetime.fromisoformat(self.trained_at)
                    )
                )
                or 0
            )
            if new_verdicts >= ML_RETRAIN_MIN_NEW_VERDICTS:
                return True, (
                    f"{new_verdicts} new analyst verdicts (>= {ML_RETRAIN_MIN_NEW_VERDICTS})"
                )
        drifted, drift_reason = self._drift_result(session)
        if drifted:
            return True, drift_reason
        return False, "fresh"

    # ------------------------------------------------------------------
    @property
    def is_ready(self) -> bool:
        return HAS_SKLEARN and bool(self.models)

    # ------------------------------------------------------------------
    @staticmethod
    def _compact_baseline(raws: np.ndarray, max_points: int = 1024) -> np.ndarray:
        """Sorted, de-duplicated copy of the training raw scores (monotone CDF)."""
        arr = np.sort(np.asarray(raws, dtype=float))
        unique = np.unique(arr)
        if len(unique) <= max_points:
            return unique
        idx = np.linspace(0, len(unique) - 1, max_points).astype(int)
        return unique[idx]

    @classmethod
    def _rank_of(cls, raws, baseline: np.ndarray | None) -> np.ndarray:
        """Position of raw scores within the training CDF, in [0, 1].

        A raw score sitting at the training median maps to ~0.5; one more
        extreme than 97% of the baseline maps to ~0.97. Falls back to the raw
        score when no CDF is available.
        """
        raws = np.atleast_1d(np.asarray(raws, dtype=float))
        if baseline is None or len(baseline) == 0:
            return np.clip(raws, 0.0, 1.0)
        if len(baseline) == 1:
            # A single-point baseline cannot discriminate anything - map every
            # score to the median rank instead of degenerating to 0 (which
            # would push the CFAR boundary to the 0.05 floor and flag all
            # traffic).
            return np.full_like(raws, 0.5)
        ranks = np.interp(raws, baseline, np.linspace(0.0, 1.0, len(baseline)))
        return np.clip(ranks, 0.0, 1.0)

    # ------------------------------------------------------------------
    # Threshold tuning
    # ------------------------------------------------------------------
    @staticmethod
    def _tune_threshold(
        model,
        X: np.ndarray,
        y,
        supervised=None,
        target_fpr: float | None = None,
        stream_name: str | None = None,
        ensembles: list | None = None,
        meta=None,
    ):
        """Return ``(threshold, baseline_cdf)`` for a freshly-fit stream model.

        The threshold lives in the *deployed* score space - the rank of the
        IsolationForest raw score when no supervised classifier is active,
        otherwise the exact score :meth:`_combined_score` produces (ensemble
        meta-learner when trained, else ``0.6*rank + 0.4*p``). Tuning on the
        deployed space keeps the decision boundary consistent with what
        actually runs:

        * **CFAR boundary (always)** - the ``(1 - target_fpr)`` quantile of
          the training score distribution, so at most ``target_fpr`` of the
          locally-learned baseline falls above it. Label-free, so a
          pure-benign history still flags tails.
        * **F1 grid (when labels exist)** - the boundary maximising F1 on the
          labelled split. The final boundary never sits *stricter* than the
          CFAR one (more sensitive of the two), which prevents recall
          collapse when labels are sparse or noisy.

        ``baseline_cdf`` is always the raw-score CDF of the *primary* model
        (the input to :meth:`_rank_of`), so the stored baselines keep their
        semantics. When ``ensembles`` is provided, ranks are the median of
        member ranks — the same statistic :meth:`_combined_score` deploys —
        so the CFAR floor actually bounds the live FPR. When ``meta`` is
        provided and trained, blended scores go through
        ``meta.predict(rank, p)`` to match the stacked deployment path.
        """
        # Phase 4: per-stream FPR budgets - login gets tighter FPR (0.05),
        # process/network get looser (0.15/0.10) for better recall.
        if target_fpr is None:
            if stream_name and stream_name in ML_STREAM_FPR:
                target_fpr = ML_STREAM_FPR[stream_name]
            else:
                target_fpr = ML_TARGET_FPR
        if len(X) == 0:
            return 0.5, np.empty((0,))
        raws = MLAnomalyDetector._score_batch(model, X)
        baseline = MLAnomalyDetector._compact_baseline(raws)
        ranks = MLAnomalyDetector._rank_of(raws, baseline)
        if ensembles:
            member_ranks = []
            for ens in ensembles:
                ens_raws = MLAnomalyDetector._score_batch(ens, X)
                member_ranks.append(
                    MLAnomalyDetector._rank_of(ens_raws, baseline)
                )
            ranks = np.median(np.vstack(member_ranks), axis=0)
        if supervised is not None:
            try:
                proba = supervised.predict_proba(X)
                p = proba[:, 1] if proba.shape[1] > 1 else np.zeros(len(X))
            except Exception:
                logger.exception("Unexpected error")
                p = np.zeros(len(X))
            if meta is not None and getattr(meta, "is_trained", False):
                scores = np.array(
                    [float(meta.predict(r, pi)) for r, pi in zip(ranks, p)],
                    dtype=float,
                )
            else:
                scores = 0.6 * ranks + 0.4 * p
        else:
            scores = ranks
        score_baseline = MLAnomalyDetector._compact_baseline(scores)
        if len(score_baseline):
            cfar = float(np.quantile(score_baseline, 1.0 - target_fpr))
        else:
            cfar = 0.5
        cfar = float(np.clip(cfar, 0.05, 0.98))
        if y is None or len(np.unique(y)) < 2:
            return cfar, baseline
        # The F1 grid may only lower the boundary while keeping the
        # labelled-benign false-alarm rate inside the same budget CFAR uses.
        # The boundary must stay at or above the benign floor, otherwise the
        # F1 optimum collapses to a degenerate near-zero threshold (recall
        # driven by FN symmetry, not real separation).
        y_arr = np.asarray(y)
        scores_arr = np.asarray(scores)
        benign = scores_arr[y_arr == 0]
        if len(benign) > 0:
            floor = float(np.quantile(benign, 1.0 - target_fpr))
        else:
            floor = 0.05
        floor = float(np.clip(floor, 0.05, 0.98))
        # best_j must start as a *metric* sentinel (not floor): initializing
        # it to floor made `best_j > 0` true even when no Youden candidate
        # was ever accepted, returning the untouched best_j_t = -1.0 and
        # flagging every event (score > -1).
        best_t, best_f1 = floor, -1.0
        best_j, best_j_t = -1.0, floor
        for t in np.linspace(floor, 0.98, 47):
            pred = scores_arr > t
            tp = int(((pred) & (y_arr == 1)).sum())
            fp = int(((pred) & (y_arr == 0)).sum())
            fn = int(((~pred) & (y_arr == 1)).sum())
            tn = int(((~pred) & (y_arr == 0)).sum())
            if tp + fp + fn == 0:
                continue
            precision = tp / max(tp + fp, 1)
            recall = tp / max(tp + fn, 1)
            f1 = 2 * precision * recall / max(precision + recall, 1e-9)
            specificity = tn / max(tn + fp, 1)
            youden_j = recall + specificity - 1.0
            if f1 > best_f1:
                best_f1, best_t = f1, float(t)
            if youden_j > best_j:
                best_j, best_j_t = youden_j, float(t)
        if best_f1 <= 0:
            return cfar, baseline
        # Prefer Youden's J threshold when it found a positive boundary;
        # otherwise fall back to the F1 optimum (or CFAR above).
        if best_j > 0 and best_j_t >= floor:
            return best_j_t, baseline
        return best_t if best_t >= floor else cfar, baseline

    # ------------------------------------------------------------------
    # Label helpers (shared between supervised training and validation)
    # ------------------------------------------------------------------
    @staticmethod
    def _is_attack_sample(event_id: int, raw_json: dict) -> bool:
        """Heuristic ground truth for the supervised layer.

        ``raw_json`` is the full ``raw_json`` column (dict with ``facts``
        sub-dict *and* top-level keys like ``channel``).

        Improved heuristic that uses contextual signals less overlapping with
        the feature vector to reduce circular learning. Focuses on:
        1. Event-specific indicators not directly in feature vectors
        2. Behavioral context (unusual combinations)
        3. Known high-risk events by definition

        Analyst verdicts override this heuristic when available.
        """
        from backend.ml.realworld_labeler import is_attack_ip_offline
        facts = (raw_json or {}).get("facts") or {}
        eid = int(event_id)

        # High-risk events by definition (not dependent on feature-overlapping signals)
        if eid in (
            4720,
            4732,
            7045,
            4698,
        ):  # Account creation, group change, service install, scheduled task
            return True

        # Benign logon family (always safe)
        if eid in (4634, 4647, 4771):
            return False

        # PowerShell events: use metadata context, NOT feature-overlapping flags.
        # The supervised classifier consumes has_encoded/has_download/has_hidden
        # as features, so we must NOT use them for labeling (label leakage).
        if eid in (4104, 4103):
            # Label from non-feature context: channel name and user context.
            # channel lives at the raw_json top level (not inside facts).
            channel = str((raw_json or {}).get("channel", "") or "")
            str(facts.get("user", "") or "")
            # PowerShell on non-standard channels or by SYSTEM/root is suspicious
            if "Operational" not in channel and channel != "":
                return True
            # Label from event metadata that is NOT in the feature vector
            # (e.g., specific PowerShell providers, pipeline execution state)
            provider = str(facts.get("provider", "") or "")
            return bool(
                provider
                and provider not in ("Microsoft-Windows-PowerShell", "PowerShell")
            )

        # Failed logon (4625): contextual labeling — not ALL failures are attacks.
        if eid == 4625:
            sub_status_raw = facts.get("sub_status", 0)
            try:
                sub_status = int(sub_status_raw)
            except (ValueError, TypeError):
                try:
                    sub_status = int(str(sub_status_raw), 16)
                except (ValueError, TypeError):
                    sub_status = 0
            # Account locked (0xC0000234) or disabled (0xC0000072) — strong signal
            if sub_status in (3221226036, 3221225586):
                return True
            # Known attack IP
            sip = str(facts.get("source_ip", ""))
            if sip and sip != "-" and is_attack_ip_offline(sip):
                return True
            # Account does not exist (0xC0000064) — enumeration attempt
            if sub_status == 3221225572:
                return True
            # Logon failure with NTLM (0xC000006D) — suspicious
            if sub_status == 3221225581:
                return True
            # Wrong password (0xC000006A) alone is routine (typos, forgotten
            # passwords). Only elevate when combined with a non-interactive
            # / uncommon logon type (batch/service/unlock/cleartext/RDP) —
            # interactive (2) and network (3) failures are the benign baseline.
            if sub_status == 3221225578:
                lt = int(facts.get("logon_type", 0))
                if lt in (4, 5, 7, 8, 9, 10, 11):
                    return True
            return False

        # Successful logon (4624): logon_type IS in the feature vector.
        # Use non-overlapping signals only.
        if eid == 4624:
            # TargetUserName anomalies — the target user is NOT in the feature vector
            target_user = str(facts.get("target_user", "") or "")
            if target_user.lower() in ("system", "local service", "network service"):
                return True
            # LogonProcessName anomalies — NOT in feature vector
            logon_process = str(facts.get("logon_process", "") or "")
            if logon_process and logon_process not in ("NtLmSsp", "Kerberos", "Negotiate", "WDIGEST", "MSSECRPC"):
                return True
            # Unusual logon types: batch (4), service (5), unlock (7), network cleartext (8)
            lt = int(facts.get("logon_type", 0))
            if lt in (4, 5, 7, 8, 9, 10, 11):
                return True
            # Known attack IPs
            sip = str(facts.get("source_ip", ""))
            if sip and is_attack_ip_offline(sip):
                return True
            return False

        # Process events (Sysmon 1/10/11/13/17/19/23/25 + Windows 4688)
        if eid in (1, 10, 11, 13, 17, 19, 23, 25, 4688):
            image = str(
                facts.get("image_path", "") or facts.get("new_process", "")
                or facts.get("target_image", "") or ""
            )
            parent = str(facts.get("parent_process", "") or "")
            cmd = str(facts.get("command_line", "") or "")
            image_lower = image.lower()
            parent_lower = parent.lower()
            cmd_lower = cmd.lower()
            # Known attack tools — always suspicious regardless of path
            risk_names = (
                "mimikatz", "psexec", "nc.exe", "ncat", "netcat",
                "meterpreter", "cobaltstrike", "lazagne", "procdump",
                "sharpdump", "rubeus", "seatbelt", "sharpup", "purplesharp",
            )
            if any(r in image_lower for r in risk_names):
                return True
            # LOLBin abuse — only if NOT in system directory AND has suspicious cmd
            lolbins = ("mshta", "wscript", "cscript", "regsvr32", "rundll32", "msbuild")
            is_lolbin = any(l in image_lower for l in lolbins)
            is_system_path = any(p in image_lower for p in ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\program files\\"))
            if is_lolbin and not is_system_path:
                return True
            # Office app spawning script interpreter = macro execution
            if any(p in parent_lower for p in ("winword", "excel", "outlook")):
                if any(x in image_lower for x in ("powershell", "cmd", "wscript", "mshta", "cscript")):
                    return True
            # Encoded/suspicious PowerShell
            if "powershell" in image_lower and any(x in cmd_lower for x in ("-enc", "-encodedcommand", "frombase64", "invoke-expression", "iex")):
                return True
            # Suspicious parent-child: Office/script spawning certutil/bitsadmin
            if "powershell" in parent_lower and any(c in image_lower for c in ("certutil", "bitsadmin")):
                return True
            # Suspicious command patterns only with specific process context
            suspicious_cmds = (
                "invoke-expression", "iex(", "downloadstring",
                "invoke-webrequest", "certutil -decode", "reg save",
                "lsass", "sekurlsa", "kerberos::list", "misc::skeleton",
            )
            if any(s in cmd_lower for s in suspicious_cmds):
                return True
            # New process from a user-writable path (Temp/Downloads/Public/Users
            # outside system dirs) — the classic implant-dropper pattern. Path
            # location is context the supervised head can generalize on without
            # reusing the has_encoded/has_hidden feature flags as labels.
            writable_dir = any(
                p in image_lower
                for p in ("\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\",
                          "\\public\\", "\\users\\")
            )
            if writable_dir and not is_system_path and image_lower:
                return True
            # Sysmon EventID 10 (Process Access): lsass access = credential theft
            if eid == 10:
                granted = str(facts.get("granted_access", "")).lower()
                target = image_lower
                if "lsass" in target and granted in ("0x1010", "0x1410", "0x1438", "0x1038", "0x1fffff"):
                    return True
                if any(t in target for t in ("lsass", "sekurlsa")):
                    return True
            return False

        # Network connections: use protocol/port context NOT in feature vector
        if (
            eid == 5156 or eid == 5157
        ):  # Windows Filtering Platform connection allowed/blocked
            # Destination port context — port is NOT directly in the 16-dim subnet feature vector
            dest_port = int(facts.get("dest_port", 0) or 0)
            # Known attack ports
            return dest_port in (4444, 5555, 6666, 8443, 1234, 31337)

        # Default: use explicit attack indicators
        return bool(facts.get("is_anomalous") or facts.get("attack"))

    @staticmethod
    def _labeled_network_samples(
        session, since: datetime | None
    ) -> tuple[np.ndarray, np.ndarray, list[str]]:
        """Per-event network features with attack labels for the network stream.

        Multi-signal labeling:
        1. Threat-intel IP match (remote_ip OR source_ip)
        2. Network-typed events with known attack ports
        3. IQR-based outlier detection (only on events with non-empty IPs)
        """
        from backend.ml.realworld_labeler import is_attack_ip_offline

        X, metas = _load_network_features(session, since)
        rows_x: list[list[float]] = X.tolist() if X.size else []
        rows_meta: list[dict] = list(metas)
        # Parallel labels: -1 = event-derived (fill below), 0/1 = NetworkConnection
        pending: list[int] = [-1] * len(rows_meta)

        def _is_attack_ip(ip: str) -> bool:
            if not ip:
                return False
            return bool(
                ip.startswith(_NET_ATTACK_PREFIXES)
                or is_attack_ip_offline(ip)
            )

        # Also attribute labels from NetworkConnection flows (the live network
        # telemetry path): group by remote_ip and emit one sample per IP so
        # threat-intel / documentation-prefix hits train the supervised head.
        try:
            from backend.database.models import NetworkConnection as _NC

            nc_stmt = select(
                _NC.remote_ip,
                func.count(_NC.id),
                func.count(func.distinct(_NC.remote_port)),
                func.sum(_NC.bytes_sent),
                func.sum(_NC.bytes_recv),
                func.avg(_NC.duration_seconds),
                func.min(_NC.observed_at),
            )
            if since is not None:
                nc_stmt = nc_stmt.where(_NC.observed_at >= since)
            nc_rows = session.execute(
                nc_stmt.group_by(_NC.remote_ip)
            ).all()
        except Exception:
            logger.debug("NetworkConnection label load failed", exc_info=True)
            nc_rows = []

        # Match score_network_connection's deployed vector layout.
        import math as _math

        now_ref = datetime.now(UTC)
        hour = now_ref.hour
        for ip, count, dports, bsent, brecv, dur, obs in nc_rows:
            remote_ip = str(ip or "unknown")
            count_i = int(count or 0)
            dports_i = int(dports or 0)
            is_atk_i = 1 if _is_attack_ip(remote_ip) else 0

            def _ip_num(ip: str) -> float:
                try:
                    parts = ip.split(".")
                    if len(parts) == 4:
                        return sum(
                            int(p) << (8 * (3 - i)) for i, p in enumerate(parts)
                        ) / 4_294_967_296.0
                except Exception:
                    return 0.0
                return 0.0

            def _is_priv(ip: str) -> float:
                return 1.0 if (
                    ip.startswith("10.")
                    or ip.startswith("172.16.")
                    or ip.startswith("192.168.")
                ) else 0.0

            port_cat = 0.0
            if dports_i > 0:
                if dports_i < 1024:
                    port_cat = 0.25
                elif dports_i < 10240:
                    port_cat = 0.5
                else:
                    port_cat = 0.75
            hour_sin = _math.sin(2 * _math.pi * hour / 24)
            hour_cos = _math.cos(2 * _math.pi * hour / 24)
            feats = [
                0.5, 1.0, 0.0, 0.0,
                hour_sin, hour_cos,
                1.0 if hour in _NIGHT_HOURS else 0.0,
                1.0 if now_ref.weekday() >= 5 else 0.0,
                _ip_num("0.0.0.0"), _ip_num(remote_ip),
                0.0, _is_priv(remote_ip),
                1.0 if remote_ip.startswith("169.254.") else 0.0,
                1.0 if remote_ip.startswith(("224.", "225.")) else 0.0,
                1.0 if remote_ip in ("127.0.0.1", "::1") else 0.0,
                float(dports_i) / 65535.0,
                port_cat,
                0.0, 0.5,
                min(count_i / 100.0, 1.0), 0.0,
                float(is_atk_i), 0.0,
                0.5, 0.0,
                min(count_i / 50.0, 1.0),
                0.0, 0.0, 0.0,
            ]
            # Prefer the NetworkConnection row when the same IP already exists.
            replaced = False
            for j, m in enumerate(rows_meta):
                if m.get("remote_ip", "") == remote_ip:
                    rows_x[j] = feats
                    pending[j] = is_atk_i
                    replaced = True
                    break
            if not replaced:
                rows_meta.append({
                    "remote_ip": remote_ip,
                    "source_ip": "",
                    "event_id": 0,
                    "eid": 3,
                    "timestamp": obs.isoformat() if obs else "",
                })
                rows_x.append(feats)
                pending.append(is_atk_i)

        if not rows_meta:
            return np.empty((0, 29)), np.empty((0,), dtype=int), []

        # Event-derived labels (NetworkConnection rows already resolved above).
        y = np.zeros(len(rows_meta), dtype=int)
        for i, m in enumerate(rows_meta):
            if pending[i] >= 0:
                y[i] = pending[i]
                continue
            ip = m.get("remote_ip", "")
            src_ip = m.get("source_ip", "")
            eid = m.get("eid", 0)
            if _is_attack_ip(ip) or _is_attack_ip(src_ip):
                y[i] = 1
            elif eid in NETWORK_EVENTS and ip and ip.startswith(
                _NET_ATTACK_PREFIXES
            ):
                y[i] = 1

        X_all = np.array(rows_x, dtype=float) if rows_x else np.empty((0, 29))
        ips = [m.get("remote_ip", "") for m in rows_meta]

        # IQR outlier detection only on event-derived rows that have IPs
        if X_all.shape[0] > 10 and X_all.shape[1] >= 22:
            has_ip_mask = np.array([
                1 if rows_meta[i].get("remote_ip") or rows_meta[i].get("source_ip") else 0
                for i in range(len(rows_meta))
            ], dtype=bool)
            ip_indices = np.where(has_ip_mask)[0]

            if len(ip_indices) > 10:
                feat_cols = X_all[ip_indices][:, [17, 18, 19, 20, 23, 24]]
                q25 = np.percentile(feat_cols, 25, axis=0)
                q75 = np.percentile(feat_cols, 75, axis=0)
                iqr = q75 - q25
                iqr[iqr < 1e-8] = 1.0
                upper = q75 + 2.0 * iqr

                for idx in ip_indices:
                    if y[idx] == 1:
                        continue
                    vals = X_all[idx, [17, 18, 19, 20, 23, 24]]
                    n_outlier = int(sum(vals > upper))
                    if n_outlier >= 2:
                        y[idx] = 1
                    elif any(vals > q75 + 3.0 * iqr):
                        y[idx] = 1

        return X_all, y, ips

    @staticmethod
    def _labeled_samples(
        session,
    ) -> dict[str, tuple[list[list[float]], list[list[float]]]]:
        """Per-stream labelled samples: attack vectors vs benign baseline.

        Builds labels from the *real* feature vectors (via
        :func:`event_feature_vector`) so the supervised classifiers are
        trained on the same space used for scoring.
        """
        out: dict[str, tuple[list[list[float]], list[list[float]]]] = {
            "login": ([], []),
            "process": ([], []),
            "network": ([], []),
        }
        rows = session.execute(
            select(
                NormalizedEvent.id, NormalizedEvent.raw_json, NormalizedEvent.event_id
            )
        ).all()
        verdicts = _verdict_map(session)
        with _feature_pass_cache():
            for event_id, raw, eid in rows:
                if orm_event_is_corrupted({"user": "-", "raw_json": raw})[0]:
                    continue
                behavior = _behavior_of(int(eid))
                if behavior not in out:
                    continue
                features = event_feature_vector({"event_id": eid, "raw_json": raw}, _shared_session=session)
                if not features:
                    continue
                if event_id in verdicts:
                    is_attack = bool(verdicts[event_id])
                else:
                    is_attack = MLAnomalyDetector._is_attack_sample(eid, raw or {})
                (out[behavior][0] if is_attack else out[behavior][1]).append(features)

        net_X, net_y, net_ips = MLAnomalyDetector._labeled_network_samples(
            session, None
        )
        for i, ip in enumerate(net_ips):
            (out["network"][0] if net_y[i] else out["network"][1]).append(
                net_X[i].tolist()
            )
        return out

    def _validation_data(
        self, session, since: datetime | None
    ) -> dict[str, tuple[np.ndarray, np.ndarray]]:
        """Windowed labelled validation set, grouped by behavior stream.

        ``since=None`` validates on the FULL history.
        """
        stmt = select(
            NormalizedEvent.id,
            NormalizedEvent.raw_json,
            NormalizedEvent.event_id,
            NormalizedEvent.timestamp,
        )
        if since is not None:
            stmt = stmt.where(NormalizedEvent.timestamp >= since)
        rows = session.execute(stmt).all()
        out: dict[str, list] = {
            "login": [[], []],
            "process": [[], []],
            "network": [[], []],
        }
        verdicts = _verdict_map(session)
        with _feature_pass_cache():
            for row_id, raw, event_id, timestamp in rows:
                if orm_event_is_corrupted({"user": "-", "raw_json": raw})[0]:
                    continue
                features = event_feature_vector(
                    {"event_id": event_id, "raw_json": raw, "timestamp": timestamp},
                    _shared_session=session,
                )
                if not features:
                    continue
                behavior = _behavior_of(int(event_id))
                if row_id in verdicts:
                    label = verdicts[row_id]
                else:
                    label = (
                        1 if MLAnomalyDetector._is_attack_sample(event_id, raw or {}) else 0
                    )
                out[behavior][0].append(features)
                out[behavior][1].append(label)
        return {
            beh: (np.array(x, dtype=float), np.array(y, dtype=int))
            for beh, (x, y) in out.items()
            if len(x) >= 4 and len(set(y)) >= 2
        }

    # ------------------------------------------------------------------
    def train(
        self,
        session=None,
        hours: int | None = 24,
        validate: bool = False,
        persist: bool = True,
        cutoff: datetime | None = None,
        kind: str = "initial",
    ) -> dict:
        """Train per-stream Isolation Forests + supervised classifier.

        ``hours=None`` trains on the FULL collected history (every event /
        connection, no sample window); ``hours=N`` restricts to the last N
        hours. Production paths default to the full history so the model
        reflects everything the collector has gathered.

        ``validate=True`` gates replacement behind a labelled-window
        comparison against the currently loaded models (production path);
        tests and cold starts always train freely.

        ``persist=False`` trains in-memory only (evaluation harnesses) so a
        validation run can never overwrite the production bundle.

        ``cutoff`` (e.g. a campaign start) caps the training window so the
        baseline fit never sees the attack window.

        ``kind`` (roadmap 4.1) records the training kind ("initial",
        "incremental", "drift", "scheduled") in the version history; every
        successful persistent train bumps ``version`` and archives the old
        bundle for A/B.
        """
        if not HAS_SKLEARN:
            return {"status": "sklearn-not-installed", "trained": False}

        close = session is None
        session = session or SessionLocal()
        # Reset the feature-error counter for this retrain; helpers that hit
        # DB failures increment it (and roll back) via _feature_db_error().
        global _FEATURE_ERROR_COUNT
        _FEATURE_ERROR_COUNT = 0
        try:
            since = None if not hours else datetime.now(UTC) - timedelta(hours=hours)

            # ── Bulk feature loading (O(N) sliding window) ──────────
            from collections import defaultdict as _dd
            _all_ids = LOGIN_EVENTS | PROCESS_EVENTS
            _stmt = select(
                NormalizedEvent.id, NormalizedEvent.event_id,
                NormalizedEvent.timestamp, NormalizedEvent.raw_json,
                NormalizedEvent.user,
            ).where(NormalizedEvent.event_id.in_(_all_ids))
            if since is not None:
                _stmt = _stmt.where(NormalizedEvent.timestamp >= since)
            if cutoff is not None:
                _stmt = _stmt.where(NormalizedEvent.timestamp < cutoff)
            _stmt = _stmt.order_by(NormalizedEvent.timestamp)
            _rows = session.execute(_stmt).all()
            _events = []
            for _r in _rows:
                try:
                    _raw = _r.raw_json or {}
                    if isinstance(_raw, str):
                        try:
                            _raw = json.loads(_raw)
                        except Exception:
                            logger.exception("Unexpected error")
                            _raw = {}
                    if not isinstance(_raw, dict):
                        _raw = {}
                    _facts = _raw.get("facts") or _raw
                    if not isinstance(_facts, dict):
                        _facts = {}
                    _ts = _r.timestamp
                    if _ts.tzinfo is None:
                        _ts = _ts.replace(tzinfo=UTC)
                    _events.append({"id": _r.id, "event_id": _r.event_id, "ts": _ts, "facts": _facts, "user": _r.user or ""})
                except Exception:
                    logger.exception("Unexpected error")
                    continue
            _N = len(_events)

            # Index by stream
            _login_idx = [i for i, e in enumerate(_events) if e["event_id"] in LOGIN_EVENTS]
            _proc_idx = [i for i, e in enumerate(_events) if e["event_id"] in PROCESS_EVENTS]

            # time_since_prev per stream
            _tsp = {}
            for _name, _indices in [("login", _login_idx), ("process", _proc_idx)]:
                for _k, _idx in enumerate(_indices):
                    _tsp[(_name, _idx)] = 0.0 if _k == 0 else (_events[_idx]["ts"] - _events[_indices[_k-1]]["ts"]).total_seconds() / 3600.0

            # Recent counts (1h, 24h) - sliding window
            _r1h = _dd(int); _r24h = _dd(int)
            for _name, _indices in [("login", _login_idx), ("process", _proc_idx)]:
                if not _indices:
                    continue
                _left1 = 0; _left24 = 0
                for _k, _idx in enumerate(_indices):
                    _ev_ts = _events[_idx]["ts"]
                    while _left1 < _k and (_ev_ts - _events[_indices[_left1]]["ts"]).total_seconds() > 3600:
                        _left1 += 1
                    while _left24 < _k and (_ev_ts - _events[_indices[_left24]]["ts"]).total_seconds() > 86400:
                        _left24 += 1
                    _r1h[(_name, _idx)] = _k - _left1
                    _r24h[(_name, _idx)] = _k - _left24

            # Failed login velocity per IP
            _fail_ip = _dd(list)
            for _i, _e in enumerate(_events):
                if _e["event_id"] == 4625:
                    _ip = str(_e["facts"].get("source_ip", ""))
                    if _ip:
                        _fail_ip[_ip].append((_e["ts"], _i))

            # Logon type entropy (1h) — O(N) sliding window
            _lt1h: dict[int, dict[int, int]] = _dd(lambda: _dd(int))
            _left = 0
            _running_lt: dict[int, int] = _dd(int)
            for _k, _idx in enumerate(_login_idx):
                _ev_ts = _events[_idx]["ts"]
                while _left < _k and (_ev_ts - _events[_login_idx[_left]]["ts"]).total_seconds() > 3600:
                    _leaving_lt = int(_events[_login_idx[_left]]["facts"].get("logon_type", 0))
                    _running_lt[_leaving_lt] -= 1
                    _left += 1
                _cur_lt = int(_events[_idx]["facts"].get("logon_type", 0))
                _running_lt[_cur_lt] += 1
                _lt1h[_idx] = dict(_running_lt)

            # IP diversity per user (24h)
            _user_logins = _dd(list)
            for _i, _e in enumerate(_events):
                if _e["event_id"] in (4624, 4625):
                    _user_logins[_e["user"]].append((_e["ts"], _i, str(_e["facts"].get("source_ip", ""))))
            _ip_div = {}
            for _user, _logins in _user_logins.items():
                _left = 0
                for _k, (_ts, _idx, _ip) in enumerate(_logins):
                    while _left < _k and (_ts - _logins[_left][0]).total_seconds() > 86400:
                        _left += 1
                    _unique = set(_logins[_j][2] for _j in range(_left, _k + 1))
                    _ip_div[_idx] = len(_unique) / max(_k - _left + 1, 1)

            # Login z-score (24h)
            _lz = {}
            _left = 0
            for _k, _idx in enumerate(_login_idx):
                _ev_ts = _events[_idx]["ts"]
                while _left < _k and (_ev_ts - _events[_login_idx[_left]]["ts"]).total_seconds() > 86400:
                    _left += 1
                if _k - _left < 2:
                    _lz[_idx] = 0.0
                    continue
                _gaps = [(_events[_login_idx[_j]]["ts"] - _events[_login_idx[_j-1]]["ts"]).total_seconds() / 60.0
                         for _j in range(max(_left + 1, _k - 49), _k + 1)]
                if len(_gaps) < 2:
                    _lz[_idx] = 0.0
                    continue
                _mg = sum(_gaps) / len(_gaps)
                _sg = (sum((_g - _mg) ** 2 for _g in _gaps) / len(_gaps)) ** 0.5
                _lz[_idx] = 0.0 if _sg == 0 else min(1.0, max(0.0, abs((_gaps[-1] - _mg) / _sg) / 3.0))

            # Cross-stream (1h counts) - O(N) sliding window
            _all_sorted = sorted(range(_N), key=lambda _i: _events[_i]["ts"])
            _cross = {}
            _left = 0
            _cs_fail = 0
            _cs_proc = 0
            _cs_net = 0
            _cs_types: set[int] = set()
            for _k, _idx in enumerate(_all_sorted):
                _ev_ts = _events[_idx]["ts"]
                while _left < _k and (_ev_ts - _events[_all_sorted[_left]]["ts"]).total_seconds() > 3600:
                    _le = _events[_all_sorted[_left]]
                    if _le["event_id"] == 4625:
                        _cs_fail -= 1
                    if _le["event_id"] in PROCESS_EVENTS:
                        _cs_proc -= 1
                    if _le["event_id"] in NETWORK_EVENTS:
                        _cs_net -= 1
                    _cs_types.discard(_le["event_id"])
                    _left += 1
                _cur_eid = _events[_idx]["event_id"]
                if _cur_eid == 4625:
                    _cs_fail += 1
                if _cur_eid in PROCESS_EVENTS:
                    _cs_proc += 1
                if _cur_eid in NETWORK_EVENTS:
                    _cs_net += 1
                _cs_types.add(_cur_eid)
                _ts = (_events[_all_sorted[-1]]["ts"] - _ev_ts).total_seconds() / 3600.0 if _k < len(_all_sorted) - 1 else 0.0
                _cross[_idx] = [
                    min(_cs_fail / 10, 1), min(_cs_proc / 10, 1), min(_cs_net / 10, 1),
                    min(_cs_fail / max(_cs_proc, 1), 1), min(_ts, 1),
                    1.0 if _cs_fail > 0 and _cs_proc > 0 else 0.0,
                    1.0 if _cs_proc > 0 and _cs_net > 0 else 0.0,
                    min(len(_cs_types) / 5, 1),
                ]

            # Pre-compute O(N) features (moved from O(N²) inside _build_login)
            # Per-user failed/success ratio (not global constant)
            _precomp_user_fail: dict[str, int] = _dd(int)
            _precomp_user_total: dict[str, int] = _dd(int)
            for _e2 in _events:
                if _e2["event_id"] in (4624, 4625):
                    _u2 = _e2["user"]
                    _precomp_user_total[_u2] += 1
                    if _e2["event_id"] == 4625:
                        _precomp_user_fail[_u2] += 1

            _precomp_user_ips: dict[str, set[str]] = _dd(set)
            for _e2 in _events:
                if _e2["event_id"] in (4624, 4625):
                    _precomp_user_ips[_e2["user"]].add(str(_e2["facts"].get("source_ip", "")))
            _precomp_dist_ips = {u: min(1.0, len(ips) / 10.0) for u, ips in _precomp_user_ips.items()}

            # Per-user hour distribution (not global constant)
            _precomp_user_hcounts: dict[str, dict[int, int]] = _dd(lambda: _dd(int))
            _precomp_user_hours: dict[str, set[int]] = _dd(set)
            for _e2 in _events:
                if _e2["event_id"] in LOGIN_EVENTS:
                    _u2 = _e2["user"]
                    _eh = _e2["ts"].hour
                    _precomp_user_hcounts[_u2][_eh] += 1
                    _precomp_user_hours[_u2].add(_eh)

            # Pre-compute per-IP failed login velocity for label gating
            _fail_ip_count: dict[str, int] = {}
            for _e2 in _events:
                if _e2["event_id"] == 4625:
                    _sip2 = str(_e2["facts"].get("source_ip", ""))
                    if _sip2:
                        _fail_ip_count[_sip2] = _fail_ip_count.get(_sip2, 0) + 1

            from backend.ml.realworld_labeler import is_attack_ip_offline

            # Build login feature matrix (v9: 38 features, no label leakage)
            def _build_login(_ev, _idx):
                _f = _ev["facts"]
                _lt = int(_f.get("logon_type", 0))
                _sip = str(_f.get("source_ip", ""))
                _sub_raw = _f.get("sub_status", 0)
                try:
                    _sub = int(_sub_raw)
                except (ValueError, TypeError):
                    _sub = int(str(_sub_raw), 16) if str(_sub_raw).startswith("0x") else 0
                _locked = int(bool(_f.get("is_locked", 0)))
                _h = _ev["ts"].hour
                _hs = math.sin(2 * math.pi * _h / 24)
                _hc = math.cos(2 * math.pi * _h / 24)
                _night = 1.0 if _h in _NIGHT_HOURS else 0.0
                _we = 1.0 if _ev["ts"].weekday() >= 5 else 0.0
                _unusual = 1.0 if _lt > 0 and _lt not in _COMMON_LOGON_TYPES else 0.0
                _tsp_v = _tsp.get(("login", _idx), 0)
                _r1h_v = _r1h.get(("login", _idx), 0)
                _r24h_v = _r24h.get(("login", _idx), 0)
                _f5 = _f15 = _f60 = 0.0
                if _sip in _fail_ip:
                    _now = _ev["ts"]
                    for _ts2, _ in reversed(_fail_ip[_sip]):
                        _dm = (_now - _ts2).total_seconds() / 60
                        if _dm > 60:
                            break
                        _f60 += 1
                        if _dm <= 15:
                            _f15 += 1
                        if _dm <= 5:
                            _f5 += 1
                _tc: dict[int, int] = _lt1h.get(_idx, {})
                _ent = sum(-(c / sum(_tc.values())) * math.log2(c / sum(_tc.values())) for c in _tc.values() if c > 0) if _tc else 0.0
                _me = math.log2(max(len(_tc), 1))
                _nent = min(1.0, _ent / max(_me, 1)) if _me > 0 else 0.0
                _idiv = _ip_div.get(_idx, 0)
                _z = _lz.get(_idx, 0)
                _cr = _cross.get(_idx, [0] * 8)
                _bh = 1.0 if 8 <= _h < 18 and _ev["ts"].weekday() < 5 else 0.0
                # v7 features
                _lp = str(_f.get("logon_process", "") or "").lower()
                _auth = 0.7 if "ntlm" in _lp else (0.1 if "kerberos" in _lp else 0.5)
                # Per-user features (not global constants)
                _dist_ips = _precomp_dist_ips.get(_ev["user"], 0.0)
                _user_fail = _precomp_user_fail.get(_ev["user"], 0)
                _user_total = _precomp_user_total.get(_ev["user"], 0)
                _fs_ratio = _user_fail / max(_user_total, 1)
                _user_hours = _precomp_user_hours.get(_ev["user"], set())
                _hent = sum(-(_precomp_user_hcounts.get(_ev["user"], {}).get(_eh, 0) / max(_user_total, 1)) * math.log2(_precomp_user_hcounts.get(_ev["user"], {}).get(_eh, 0) / max(_user_total, 1)) for _eh in _user_hours if _precomp_user_hcounts.get(_ev["user"], {}).get(_eh, 0) > 0) if _user_hours else 0.0
                _hmax_u = math.log2(max(len(_user_hours), 1))
                _hdist = min(1.0, _hent / max(_hmax_u, 1)) if _hmax_u > 0 else 0.0
                # Threat intel score (computed, not hardcoded 0.0)
                _tip = 0.0
                if _sip:
                    if _sip.startswith(("203.0.113.", "198.51.100.", "192.0.2.")):
                        _tip = 0.9
                    elif is_attack_ip_offline(_sip):
                        _tip = 0.85
                    elif _sip.startswith("10.") or _sip.startswith("192.168."):
                        _tip = 0.1
                    else:
                        _tip = 0.4
                # Kill chain phase (from event type, not hardcoded 0.3)
                _kc = 0.0 if _ev["event_id"] == 4624 else (
                    0.25 if _ev["event_id"] == 4625 else (
                    0.5 if _ev["event_id"] in (4740, 4648) else 0.0))
                # Burst score: short-term rate / long-term rate (not hardcoded 0.5)
                _burst = min(_r1h_v / max(_r24h_v / 24.0, 0.01), 2.0) if _r24h_v > 0 else (1.0 if _r1h_v > 0 else 0.0)
                # Per-IP total failed logins (not global constant)
                _ip_total_fail = _fail_ip_count.get(_sip, 0)
                return [_lt, _sub / 3221226036.0,
                        (int(_sip.split(".")[0]) << 24 | int(_sip.split(".")[1]) << 16 | int(_sip.split(".")[2]) << 8 | int(_sip.split(".")[3])) / 4294967296.0 if _sip and _sip.count(".") == 3 else 0.0,
                        _locked, _hs, _hc, _night, _we, _unusual,
                        min(_tsp_v / 24, 1), min(_r1h_v / 10, 1), min(_r24h_v / 100, 1), _tip,
                        min(_f5 / 2, 1), min(_f15 / 5, 1), min(_f60 / 10, 1),
                        _nent, _idiv, _z, min(_ip_total_fail / 20.0, 1.0), *_cr, _bh, _burst, _kc, _fs_ratio, _hdist,
                        _auth, _dist_ips, min(_r1h_v / 5, 1.0), min(_r24h_v / 50.0, 1.0)]

            def _cmd_ent(s):
                if not s:
                    return 0.0
                cc: dict[str, int] = {}
                for c in s:
                    cc[c] = cc.get(c, 0) + 1
                return min(1.0, -sum((v / len(s)) * math.log2(v / len(s)) for v in cc.values()) / 7.0)

            def _build_process(_ev, _idx):
                _f = _ev["facts"]
                _h = _ev["ts"].hour
                _hs = math.sin(2 * math.pi * _h / 24)
                _hc = math.cos(2 * math.pi * _h / 24)
                _night = 1.0 if _h in _NIGHT_HOURS else 0.0
                _we = 1.0 if _ev["ts"].weekday() >= 5 else 0.0
                _img = str(_f.get("image_path", "")).lower()
                _cmd = str(_f.get("command_line", ""))
                _par = str(_f.get("parent_process", "")).lower()
                _he = int(bool(_f.get("has_encoded", 0)))
                _hd = int(bool(_f.get("has_download", 0)))
                _hh = int(bool(_f.get("has_hidden", 0)))
                _cl = len(_cmd)
                _lol = 1.0 if any(x in _img for x in ["certutil", "bitsadmin", "mshta", "wscript", "cscript"]) else 0.0
                _rp = 1.0 if any(x in _par for x in ["winword", "excel", "outlook", "wscript"]) else 0.0
                _ce = _cmd_ent(_cmd)
                _tsp_v = _tsp.get(("process", _idx), 0)
                _r1h_v = _r1h.get(("process", _idx), 0)
                _r24h_v = _r24h.get(("process", _idx), 0)
                _cr = _cross.get(_idx, [0] * 8)
                _bh = 1.0 if 8 <= _h < 18 and _ev["ts"].weekday() < 5 else 0.0
                # v7 features: path entropy, system dir, parent risk, cmd tokens, chain depth
                _pe = _cmd_ent(_img) if _img else 0.0
                _sysdir = 1.0 if "system32" in _img or "syswow64" in _img else (0.5 if "windows" in _img else 0.0)
                _prisk = 0.9 if any(x in _par for x in ["powershell", "cmd", "wscript", "cscript", "mshta"]) else (0.6 if any(x in _par for x in ["winword", "excel", "outlook"]) else 0.3)
                _ctokens = min(1.0, len(_cmd.split()) / 30.0) if _cmd else 0.0
                _cdepth = 0.0
                # v10 features: writable dir, user dir, encoded, download, attack tool, Office parent
                _writable = 1.0 if any(x in _img for x in ("\\downloads\\", "\\appdata\\", "\\temp\\", "\\public\\")) else 0.0
                _userdir = 1.0 if "\\users\\" in _img else 0.0
                _enc_cmd = 1.0 if any(x in _cmd.lower() for x in ("-enc", "-encodedcommand", "frombase64")) else 0.0
                _dl_cmd = 1.0 if any(x in _cmd.lower() for x in ("invoke-webrequest", "curl", "wget", "downloadstring", "bitsadmin")) else 0.0
                _atk_tool = 1.0 if any(x in _img for x in ("mimikatz", "psexec", "rubeus", "seatbelt", "procdump", "purplesharp", "lazagne", "sharpup")) else 0.0
                _office_parent = 1.0 if any(x in _par for x in ("winword", "excel", "outlook")) else 0.0
                _is_lsass = 1.0 if "lsass" in _img or "lsass" in str(_f.get("target_image", "")).lower() else 0.0
                _cmd_has_ps = 1.0 if "powershell" in _img and _cmd else 0.0
                return [_ev["event_id"], _hs, _hc, _night, _we, _he, _hd, _hh,
                        min(_cl / 500, 1), _lol, _rp, _ce,
                        min(_tsp_v / 24, 1), min(_r1h_v / 10, 1), min(_r24h_v / 100, 1), min(_r1h_v / 50, 1),
                        *_cr, _bh, _pe, _sysdir, _prisk, _ctokens, _cdepth,
                        _writable, _userdir, _enc_cmd, _dl_cmd, _atk_tool,
                        _office_parent, _is_lsass, _cmd_has_ps]

            # Train in the *deployed* feature space: event_feature_vector is
            # what scoring uses. The bulk _build_login/_build_process helpers
            # drifted (38-dim process train vs 45-dim score) and produced
            # garbage scores / FPR once models were applied to live events.
            def _deployed_features(ev: dict) -> list[float] | None:
                return event_feature_vector(
                    {
                        "event_id": ev["event_id"],
                        "raw_json": {"facts": ev["facts"]},
                        "timestamp": ev["ts"],
                    },
                    _shared_session=session,
                )

            with _feature_pass_cache():
                _login_pairs = [
                    (i, f) for i in _login_idx if (f := _deployed_features(_events[i]))
                ]
                _proc_pairs = [
                    (i, f) for i in _proc_idx if (f := _deployed_features(_events[i]))
                ]
            login_X = (
                np.array([f for _, f in _login_pairs], dtype=float)
                if _login_pairs
                else np.empty((0, 37))
            )
            process_X = (
                np.array([f for _, f in _proc_pairs], dtype=float)
                if _proc_pairs
                else np.empty((0, 45))
            )
            _login_idx = [i for i, _ in _login_pairs]
            _proc_idx = [i for i, _ in _proc_pairs]

            # ── Hybrid labeling: analyst verdicts + threat intel + heuristic ──
            from backend.ml.realworld_labeler import get_analyst_labels, get_attack_ips
            _analyst_labels = get_analyst_labels(session)
            # Populate IP cache so is_attack_ip_offline works during training
            get_attack_ips(session, force=True)

            def _hybrid_label(ev):
                """Determine if an event is an attack using hybrid labeling."""
                _eid = int(ev["event_id"])
                _raw = {"facts": ev["facts"]}
                _sip = str(ev["facts"].get("source_ip", ""))
                # 1. Analyst verdict (authoritative)
                if ev["id"] in _analyst_labels:
                    return bool(_analyst_labels[ev["id"]])
                # 2. Threat-intel IP match
                if _sip and is_attack_ip_offline(_sip):
                    return True
                # 3. Heuristic fallback (uses _is_attack_sample for consistency)
                return MLAnomalyDetector._is_attack_sample(_eid, _raw)

            login_y = np.array([1 if _hybrid_label(_events[i]) else 0 for i in _login_idx], dtype=int) if _login_idx else np.empty((0,), dtype=int)
            process_y = np.array([1 if _hybrid_label(_events[i]) else 0 for i in _proc_idx], dtype=int) if _proc_idx else np.empty((0,), dtype=int)

            # Bulk network features from events table (per-event, 13K+ samples)
            _net_labeled_X, network_y, _net_labeled_ips = MLAnomalyDetector._labeled_network_samples(
                session, since
            )
            network_X = _net_labeled_X
            network_rows = [{"remote_ip": ip} for ip in _net_labeled_ips]

            new_models: dict[str, IsolationForest] = {}
            new_ensembles: dict[str, list[IsolationForest]] = {}
            new_thresholds: dict[str, float] = dict(_DEFAULT_THRESHOLDS)
            new_baselines: dict[str, np.ndarray] = {}
            stream_X: dict[str, np.ndarray] = {}
            stream_y: dict[str, np.ndarray] = {}
            convergence_warnings: list[str] = []
            for behavior, X, y in (
                ("login", login_X, login_y),
                ("process", process_X, process_y),
                ("network", network_X, network_y),
            ):
                # v8: Increased minimum from 3→10 for statistical reliability
                if len(X) < 10:
                    if len(X) >= 3:
                        convergence_warnings.append(
                            f"{behavior}: only {len(X)} samples (recommend 50+)"
                        )
                    continue

                # v8: Convergence check — warn if samples < 50 per stream
                if len(X) < 50:
                    convergence_warnings.append(
                        f"{behavior}: {len(X)} samples (recommend 50+ for convergence)"
                    )

                # v9: Hyperparameter tuning via grid search for better performance
                best_params = _grid_search_if(X, y, random_state=ML_RANDOM_STATE)
                ms = best_params.get("max_samples", 256)
                if ms == "auto":
                    ms = min(256, len(X))
                model = IsolationForest(
                    contamination=best_params.get("contamination", ML_CONTAMINATION),
                    random_state=ML_RANDOM_STATE,
                    n_estimators=best_params.get("n_estimators", 100),
                    max_samples=ms,
                    n_jobs=1,
                )
                model.fit(X)
                new_models[behavior] = model

                # v8: Multi-contamination ensemble for better recall on unseen
                # attacks. Skipped on small streams: 5 contaminations x 50 trees
                # is ~2s of pure overhead when N < 50 (tests / cold start).
                if len(X) >= 50:
                    ensemble = _multi_contamination_ensemble(
                        X,
                        n_estimators=min(50, max(20, len(X))),
                        random_state=ML_RANDOM_STATE,
                    )
                    new_ensembles[behavior] = ensemble

                stream_X[behavior] = X
                stream_y[behavior] = y

            if not new_models:
                return {"status": "insufficient-data", "trained": False}

            # v7: K-fold cross-validation for each stream model
            cv_results: dict[str, dict] = {}
            for behavior in ("login", "process", "network"):
                X_cv: np.ndarray | None = stream_X.get(behavior)
                y_cv: np.ndarray | None = stream_y.get(behavior)
                if X_cv is not None and y_cv is not None and len(X_cv) >= 10:
                    # Full 5-fold x 100-tree CV is ~3s/stream on test-sized
                    # data; use 3 folds x 50 trees when the stream is small.
                    _small = len(X_cv) < 100
                    cv = _kfold_cross_validate(
                        IsolationForest, X_cv, y_cv,
                        n_folds=min(3 if _small else 5, len(X_cv) // 2),
                        contamination=ML_CONTAMINATION,
                        random_state=ML_RANDOM_STATE,
                        n_estimators=50 if _small else 100,
                    )
                    cv["n_normal"] = int(np.sum(y_cv == 0))
                    cv["n_anomaly"] = int(np.sum(y_cv == 1))
                    cv_results[behavior] = cv
                    logger.info(
                        f"ML CV [{behavior}]: mean={cv['mean_score']:.4f}, "
                        f"std={cv['std_score']:.4f}, folds={len(cv['fold_scores'])}, "
                        f"labels=normal:{cv['n_normal']}/anomaly:{cv['n_anomaly']}"
                    )

            # Refuse to promote models when feature extraction was broken
            # (too many DB helper failures) or when a stream with both label
            # classes shows zero CV separation (degenerate / poisoned features).
            if _FEATURE_ERROR_COUNT >= _FEATURE_ERROR_ABORT_THRESHOLD:
                logger.error(
                    "ML retrain aborted: %d feature helper failures "
                    "(threshold %d) - features would be silently zeroed",
                    _FEATURE_ERROR_COUNT,
                    _FEATURE_ERROR_ABORT_THRESHOLD,
                )
                return {
                    "status": "feature-errors",
                    "trained": False,
                    "feature_errors": _FEATURE_ERROR_COUNT,
                }
            degenerate = [
                b
                for b, cv in cv_results.items()
                if cv.get("n_anomaly", 0) > 0
                and cv.get("n_normal", 0) > 0
                and cv["mean_score"] < 1e-9
            ]
            if degenerate and self.models:
                # Keep the previous (known) models rather than promote a
                # zero-separation retrain; first cold start still proceeds.
                logger.error(
                    "ML retrain rejected: zero CV separation on stream(s) %s "
                    "(features likely degenerate) - keeping existing models",
                    degenerate,
                )
                return {
                    "status": "cv-degenerate",
                    "trained": False,
                    "streams": degenerate,
                    "cv": {b: cv_results[b]["mean_score"] for b in degenerate},
                }
            if degenerate:
                logger.warning(
                    "ML first train has zero CV separation on %s "
                    "(cold start / thin labels) - promoting with caution",
                    degenerate,
                )

            # v7: SMOTE-like augmentation for supervised training
            augmented_X: dict[str, np.ndarray] = {}
            augmented_y: dict[str, np.ndarray] = {}
            for behavior in ("login", "process", "network"):
                X_sm: np.ndarray | None = stream_X.get(behavior)
                y_sm: np.ndarray | None = stream_y.get(behavior)
                if X_sm is not None and y_sm is not None and len(X_sm) >= 4:
                    atk_count = int(np.sum(y_sm == 1))
                    if 2 <= atk_count < len(X_sm) // 2:
                        X_aug, y_aug = _smote_augment(
                            X_sm, y_sm, minority_class=1,
                            k_neighbors=min(5, atk_count - 1),
                            random_state=ML_RANDOM_STATE,
                        )
                        augmented_X[behavior] = X_aug
                        augmented_y[behavior] = y_aug
                        logger.info(
                            f"ML SMOTE [{behavior}]: {len(X_sm)} -> {len(X_aug)} samples "
                            f"({atk_count} attacks augmented)"
                        )
                    else:
                        # Must use this stream's X_sm/y_sm — the bare X/y names
                        # still point at the last IF-loop stream and would train
                        # the supervised head on the wrong feature space.
                        augmented_X[behavior] = X_sm
                        augmented_y[behavior] = y_sm
                else:
                    if X_sm is not None:
                        augmented_X[behavior] = X_sm
                    if y_sm is not None:
                        augmented_y[behavior] = y_sm

            # Supervised layer: per-stream attack-vs-baseline classifiers. Streams
            # have their own feature spaces (login/process 9-dim, network
            # 9-dim), so each is trained on its own vector space. Network
            # buckets are aggregates, so even a handful of labelled attack IPs
            # carries signal (rate + novelty separate cleanly).
            # NOTE: reuse already-loaded stream_X/stream_y instead of
            # re-scanning the full DB via _labeled_samples().
            new_supervised_by_stream: dict[str, object] = {}
            new_supervised_name_by_stream: dict[str, str] = {}
            new_supervised = None
            new_supervised_name = "none"
            for behavior in ("login", "process", "network"):
                X_sup: np.ndarray | None = augmented_X[behavior] if behavior in augmented_X else stream_X.get(behavior)
                y_sup: np.ndarray | None = augmented_y[behavior] if behavior in augmented_y else stream_y.get(behavior)
                if X_sup is None or y_sup is None or len(X_sup) < 4:
                    continue
                atk_mask = y_sup.astype(bool)
                ben_mask = ~atk_mask
                atk = X_sup[atk_mask]
                ben = X_sup[ben_mask]
                # Thin cold-start streams still deserve a supervised head when
                # both classes are present; SMOTE (above) expands the minority.
                min_attacks = 3 if behavior == "network" else 5
                if len(atk) < min_attacks or len(ben) < 3:
                    continue
                # Cap supervised training to 5000 samples for speed
                max_sup = 5000
                if len(ben) > max_sup:
                    _rng = np.random.RandomState(ML_RANDOM_STATE)
                    ben = ben[_rng.choice(len(ben), max_sup, replace=False)]
                X_all = np.vstack([ben, atk])
                y_all = np.array([0] * len(ben) + [1] * len(atk))
                stream_model, stream_name = self._build_classifier(X_all, y_all)
                new_supervised_by_stream[behavior] = stream_model
                new_supervised_name_by_stream[behavior] = stream_name

            # Thresholds are tuned in the deployed score space (IF rank blended
            # with the supervised attack probability when available), so the
            # stored boundary matches what scoring actually compares against.
            # Sample down for large datasets to keep tuning fast.
            for behavior in new_models:
                _Xt, _yt = stream_X[behavior], stream_y.get(behavior)
                if len(_Xt) > 5000:
                    _rng = np.random.RandomState(42)
                    _sel = _rng.choice(len(_Xt), 5000, replace=False)
                    _Xt, _yt = _Xt[_sel], _yt[_sel] if _yt is not None else None
                new_thresholds[behavior], new_baselines[behavior] = (
                    self._tune_threshold(
                        new_models[behavior], _Xt, _yt,
                        supervised=new_supervised_by_stream.get(behavior),
                        ensembles=new_ensembles.get(behavior),
                        stream_name=behavior,
                    )
                )
            # Singular fallback keeps legacy callers (score_event) working.
            if new_supervised_by_stream:
                best_stream = (
                    "login"
                    if "login" in new_supervised_by_stream
                    else next(iter(new_supervised_by_stream))
                )
                new_supervised = new_supervised_by_stream[best_stream]
                new_supervised_name = new_supervised_name_by_stream[best_stream]

            n_samples = int(len(login_X) + len(process_X) + len(network_X))

            # Validation gate: only replace models that are not worse.
            if (
                validate
                and self.models
                and self._gate_replacement(session, since, new_models)
            ):
                logger.info("ML retrain: keeping existing models (no improvement)")
                return {
                    "status": "kept-existing",
                    "trained": True,
                    "samples": self.n_samples,
                    "streams": list(self.models.keys()),
                    "supervised": self.supervised_name,
                    "trained_at": self.trained_at,
                }

            self.models = new_models
            self.ensembles = new_ensembles
            self.thresholds = new_thresholds
            self.baselines = new_baselines
            self.supervised = new_supervised
            self.supervised_name = new_supervised_name
            self.supervised_by_stream = new_supervised_by_stream
            self.supervised_name_by_stream = new_supervised_name_by_stream
            self.n_samples = n_samples
            self.encoders = {}  # No longer using LabelEncoder for network

            # Phase 2.4: Train ensemble meta-learner on held-out base model predictions
            if self.ensemble is not None and len(new_models) >= 2:
                try:
                    self._train_ensemble_meta(
                        session, new_models, new_supervised_by_stream, new_baselines,
                        stream_X=stream_X, stream_y=stream_y,
                    )
                except Exception:
                    logger.exception("Unexpected error")
                    logger.debug(
                        "Ensemble meta-learner training skipped", exc_info=True
                    )

                # Re-tune thresholds in the *stacked* score space once the
                # meta-learner is live. Without this the stored boundary was
                # fit on 0.6*rank+0.4*p while _combined_score deploys
                # meta.predict(...), so CFAR no longer bounded live FPR.
                if (
                    self.ensemble is not None
                    and self.ensemble.is_trained
                    and new_supervised_by_stream
                ):
                    for behavior in new_models:
                        sup = new_supervised_by_stream.get(behavior)
                        if sup is None:
                            continue
                        _Xt, _yt = stream_X[behavior], stream_y.get(behavior)
                        if len(_Xt) > 5000:
                            _rng = np.random.RandomState(42)
                            _sel = _rng.choice(len(_Xt), 5000, replace=False)
                            _Xt = _Xt[_sel]
                            _yt = _yt[_sel] if _yt is not None else None
                        new_thresholds[behavior], _ = self._tune_threshold(
                            new_models[behavior], _Xt, _yt,
                            supervised=sup,
                            ensembles=new_ensembles.get(behavior),
                            meta=self.ensemble,
                            stream_name=behavior,
                        )
                    self.thresholds = new_thresholds

            # Phase 2.3: Run robustness evaluation on trained models.
            # Skipped for tiny baselines (and BARAQ_ML_SKIP_ROBUSTNESS=1):
            # hundreds of IF predict calls at ~50ms each dominate train() wall time.
            _skip_rob = os.environ.get("BARAQ_ML_SKIP_ROBUSTNESS", "0").lower() not in (
                "", "0", "false",
            )
            if HAS_ENSEMBLE and new_models and not _skip_rob and n_samples >= 30:
                try:
                    self.robustness = evaluate_robustness(
                        _QuickModelProxy(new_models, new_baselines),
                        X_login=stream_X.get("login"),
                        X_process=stream_X.get("process"),
                        X_network=stream_X.get("network"),
                    )
                except Exception:
                    logger.exception("Unexpected error")
                    logger.debug("Robustness evaluation skipped", exc_info=True)

            if self.n_samples < ML_TRAIN_MIN_SAMPLES:
                logger.info(
                    "Only %d samples; training anyway (min %d)",
                    self.n_samples,
                    ML_TRAIN_MIN_SAMPLES,
                )

            self.trained_at = datetime.now(UTC).isoformat()
            self.events_at_train = int(
                session.scalar(select(func.count(NormalizedEvent.id))) or 0
            )
            self.version += 1
            self.model_source = "user"  # real telemetry supersedes bootstrap
            self.last_train_kind = kind
            self.versions.append(
                {
                    "version": self.version,
                    "kind": kind,
                    "trained_at": self.trained_at,
                    "samples": self.n_samples,
                    "events_at_train": self.events_at_train,
                    "streams": list(self.models.keys()),
                    "supervised": self.supervised_name,
                    "thresholds": {k: round(v, 3) for k, v in self.thresholds.items()},
                }
            )
            self.versions = self.versions[-ML_VERSION_HISTORY:]
            if persist:
                self._save_meta()
                self._save_bundle()
            logger.info(
                "ML models trained on %d samples; streams=%s supervised=%s thresholds=%s",
                self.n_samples,
                list(self.models.keys()),
                self.supervised_name,
                {k: round(v, 2) for k, v in self.thresholds.items()},
            )

            # Phase 4: Hold-out evaluation on most recent 20% of data
            # (never seen during training) for honest recall/FPR metrics.
            _holdout_metrics: dict[str, dict] = {}
            try:
                _total_events = int(
                    session.scalar(select(func.count(NormalizedEvent.id))) or 0
                )
                if _total_events >= 100:
                    _holdout_cutoff = session.execute(
                        select(NormalizedEvent.timestamp)
                        .order_by(NormalizedEvent.timestamp.desc())
                        .offset(int(_total_events * 0.8))
                        .limit(1)
                    ).scalar()
                    if _holdout_cutoff:
                        for behavior in new_models:
                            _X_eval, _y_eval = [], []
                            _stmt = select(
                                NormalizedEvent.id,
                                NormalizedEvent.raw_json,
                                NormalizedEvent.event_id,
                                NormalizedEvent.timestamp,
                            ).where(NormalizedEvent.timestamp >= _holdout_cutoff)
                            _rows = session.execute(_stmt).all()
                            for _row_id, _raw, _eid, _ts in _rows:
                                _beh = _behavior_of(int(_eid))
                                if _beh != behavior:
                                    continue
                                _feats = event_feature_vector(
                                    {
                                        "event_id": _eid,
                                        "raw_json": _raw or {},
                                        "timestamp": _ts,
                                    },
                                    _shared_session=session,
                                )
                                if not _feats:
                                    continue
                                _X_eval.append(_feats)
                                # Use heuristic label for evaluation
                                _y_eval.append(
                                    1
                                    if MLAnomalyDetector._is_attack_sample(
                                        int(_eid), _raw or {}
                                    )
                                    else 0
                                )
                            if len(_X_eval) >= 10 and len(set(_y_eval)) >= 2:
                                _X_eval_arr = np.array(_X_eval, dtype=float)
                                _y_eval_arr = np.array(_y_eval, dtype=int)
                                _model = new_models[behavior]
                                _scores = detector.score_events(
                                    [list(f) for f in _X_eval_arr]
                                )
                                # Evaluate at the stream's new threshold
                                _thresh = new_thresholds[behavior]
                                _pred = np.array(_scores) > _thresh
                                _tp = int(np.sum((_pred) & (_y_eval_arr == 1)))
                                _fp = int(np.sum((_pred) & (_y_eval_arr == 0)))
                                _fn = int(np.sum((~_pred) & (_y_eval_arr == 1)))
                                _tn = int(np.sum((~_pred) & (_y_eval_arr == 0)))
                                _recall = _tp / max(_tp + _fn, 1)
                                _fpr = _fp / max(_fp + _tn, 1)
                                _precision = _tp / max(_tp + _fp, 1)
                                _holdout_metrics[behavior] = {
                                    "recall": round(_recall, 4),
                                    "fpr": round(_fpr, 4),
                                    "precision": round(_precision, 4),
                                    "threshold": round(_thresh, 3),
                                    "samples": len(_X_eval),
                                }
            except Exception:
                logger.exception("Hold-out evaluation failed")

            return {
                "status": "ok",
                "trained": True,
                "samples": self.n_samples,
                "streams": list(self.models.keys()),
                "supervised": self.supervised_name,
                "thresholds": self.thresholds,
                "trained_at": self.trained_at,
                "holdout_metrics": _holdout_metrics,
            }
        finally:
            if close:
                session.close()

    def _gate_replacement(self, session, since, new_models) -> bool:
        """True = keep the existing models (new ones did not beat them).

        Compares per-stream ROC-AUC on a labelled validation window; when no
        stream can be compared the retrain proceeds.
        """
        try:
            from sklearn.metrics import roc_auc_score
        except ImportError:
            return False
        deltas: list[float] = []
        for behavior, (X, y) in self._validation_data(session, since).items():
            old = self.models.get(behavior)
            new = new_models.get(behavior)
            if old is None or new is None or len(X) < 6:
                continue
            try:
                old_auc = roc_auc_score(y, old.decision_function(X))
                new_auc = roc_auc_score(y, new.decision_function(X))
            except ValueError:
                continue
            deltas.append(new_auc - old_auc)
        if not deltas:
            return False
        return sum(deltas) / len(deltas) < -0.02

    def _train_ensemble_meta(
        self,
        session,
        new_models: dict,
        new_supervised_by_stream: dict,
        new_baselines: dict,
        stream_X: dict | None = None,
        stream_y: dict | None = None,
    ) -> None:
        """Train the ensemble stacking meta-learner on base model predictions.

        Uses pre-computed stream_X/stream_y when available to avoid re-querying
        the full event table via _labeled_samples().
        """
        if self.ensemble is None or not HAS_ENSEMBLE:
            return

        all_if_scores = []
        all_sup_probas = []
        all_labels = []

        for behavior, model in new_models.items():
            # Prefer pre-computed features over expensive _labeled_samples
            if stream_X and behavior in stream_X and stream_y and behavior in stream_y:
                X = stream_X[behavior]
                y = stream_y[behavior]
            else:
                labeled = self._labeled_samples(session)
                if behavior not in labeled:
                    continue
                atk, ben = labeled[behavior]
                if not atk or not ben:
                    continue
                X = np.vstack([ben, atk])
                y = np.array([0] * len(ben) + [1] * len(atk))
            if len(X) < 10:
                continue
            # Cap ensemble training to 3000 samples for speed
            if len(X) > 3000:
                _rng = np.random.RandomState(ML_RANDOM_STATE)
                _sel = _rng.choice(len(X), 3000, replace=False)
                X, y = X[_sel], y[_sel]

            try:
                raws = self._score_batch(model, X)
                if_ranks = self._rank_of(raws, new_baselines.get(behavior))
            except Exception:
                logger.exception("Unexpected error")
                continue

            sup = new_supervised_by_stream.get(behavior)
            sup_probas = np.zeros(len(X))
            if sup is not None:
                try:
                    proba = sup.predict_proba(X)
                    if proba.shape[1] > 1:
                        sup_probas = proba[:, 1]
                except Exception:
                    logger.exception("Unexpected error")

            all_if_scores.append(if_ranks)
            all_sup_probas.append(sup_probas)
            all_labels.append(y)

        if not all_if_scores:
            return

        if_scores = np.concatenate(all_if_scores)
        sup_probas = np.concatenate(all_sup_probas)
        labels = np.concatenate(all_labels)

        self.ensemble.train_meta(if_scores, sup_probas, None, labels)

    @staticmethod
    def _build_classifier(X, y):
        """XGBoost when available, else sklearn random forest, calibrated.

        Adaptive selection: gradient boosting needs volume to shine - on the
        small labelled corpora typical of early deployments it overfits the
        few attack patterns seen and *loses* recall versus a shallow random
        forest (measured ~15 points on the hold-out suite). Below
        ``_XGB_MIN_SAMPLES`` we deliberately prefer the forest.

        Phase 2: Enhanced calibration with Platt scaling fallback and
        calibration quality validation via Brier score.

        Phase 4: Cost-sensitive learning - false negatives (missed attacks)
        are weighted 5x higher than false positives, since missing an attack
        is worse than a false alarm in a SOC.
        """
        pos = int(y.sum())
        neg = int(len(y) - pos)
        # Cost-sensitive: false negatives cost 5x false positives
        cost_sensitive_scale = (neg / max(pos, 1)) * 5.0 if pos and neg else 1.0
        if HAS_XGBOOST and len(y) >= _XGB_MIN_SAMPLES:
            model = XGBClassifier(
                n_estimators=120,
                max_depth=3,
                learning_rate=0.08,
                random_state=ML_RANDOM_STATE,
                eval_metric="logloss",
                scale_pos_weight=cost_sensitive_scale,
                subsample=0.9,
                colsample_bytree=0.9,
                min_child_weight=2,
            )
            model.fit(X, y)
            name = "xgboost"
        else:
            model = RandomForestClassifier(
                n_estimators=80,
                max_depth=5,
                random_state=ML_RANDOM_STATE,
                class_weight="balanced_subsample",
                min_samples_leaf=2,
            )
            model.fit(X, y)
            name = "random_forest"

        # Phase 2: Enhanced calibration with quality validation
        if len(y) >= 18 and min(pos, neg) >= 4:
            try:
                from sklearn.calibration import (
                    CalibratedClassifierCV,
                    calibration_curve,
                )
                from sklearn.metrics import brier_score_loss

                # Try isotonic regression first (preferred, non-parametric)
                min_cv = min(3, min(pos, neg))
                cal = CalibratedClassifierCV(model, cv=min_cv, method="isotonic")
                cal.fit(X, y)

                # Validate calibration quality via Brier score
                try:
                    proba = cal.predict_proba(X)[:, 1]
                    brier = brier_score_loss(y, proba)
                    # Also check calibration curve deviation
                    fraction_pos, mean_pred = calibration_curve(y, proba, n_bins=5)
                    calibration_error = float(np.mean(np.abs(fraction_pos - mean_pred)))
                    # If calibration is poor (Brier > 0.25 or ECE > 0.15), try Platt
                    if brier > 0.25 or calibration_error > 0.15:
                        raise ValueError(
                            f"Poor calibration: Brier={brier:.3f}, ECE={calibration_error:.3f}"
                        )
                except Exception:
                    # Fall back to Platt scaling (parametric, sigmoid)
                    try:
                        cal_platt = CalibratedClassifierCV(
                            model, cv=min_cv, method="sigmoid"
                        )
                        cal_platt.fit(X, y)
                        return cal_platt, name + "+platt"
                    except Exception:
                        logger.exception("Unexpected error")
                return cal, name + "+calibrated"
            except Exception:
                logger.exception("Unexpected error")
        elif len(y) >= 12 and min(pos, neg) >= 3:
            # Minimum calibration with Platt scaling only (small sample)
            try:
                from sklearn.calibration import CalibratedClassifierCV

                cal = CalibratedClassifierCV(model, cv=2, method="sigmoid")
                cal.fit(X, y)
                return cal, name + "+platt"
            except Exception:
                logger.exception("Unexpected error")
        return model, name

    # ------------------------------------------------------------------
    def _combined_score(self, behavior: str, model, features: list[float]) -> float:
        """Blend IF anomaly signal with supervised classifier probability.

        v8: Uses multi-contamination ensemble when available for better recall.
        """
        raw = self._score_with(model, features)
        base = float(self._rank_of([raw], self.baselines.get(behavior))[0])

        # v8: Use multi-contamination ensemble for more robust scoring
        if self.ensembles.get(behavior):
            ensemble_scores = []
            for ens_model in self.ensembles[behavior]:
                ens_raw = self._score_with(ens_model, features)
                ens_base = float(self._rank_of([ens_raw], self.baselines.get(behavior))[0])
                ensemble_scores.append(ens_base)
            # Median of ensemble scores is more robust than single model
            base = float(np.median(ensemble_scores))

        classifier = self.supervised_by_stream.get(behavior) or self.supervised
        if classifier is None:
            return base
        p = self.supervised_proba(features, classifier)

        # Phase 2.4: Use ensemble meta-learner when available
        if self.ensemble is not None and self.ensemble.is_trained:
            return float(max(0.0, min(1.0, self.ensemble.predict(base, p))))

        return float(max(0.0, min(1.0, 0.6 * base + 0.4 * p)))

    def _combined_score_batch(
        self, behavior: str, model, features_list: list[list[float]]
    ) -> list[float]:
        """Batched :meth:`_combined_score` - identical semantics, one
        ``decision_function`` / ``predict_proba`` call per behavior group."""
        if not features_list:
            return []
        try:
            X = np.array(features_list, dtype=float)
        except (TypeError, ValueError):
            return [
                self._combined_score(behavior, model, features)
                for features in features_list
            ]
        if (
            X.ndim != 2
            or X.shape[1] != model.n_features_in_
            or (self.ensembles.get(behavior) and any(
                ens.n_features_in_ != X.shape[1]
                for ens in self.ensembles[behavior]
            ))
        ):
            return [
                self._combined_score(behavior, model, features)
                for features in features_list
            ]

        try:
            # Mirror _score_with: clip(0.5 - decision) per row, then rank.
            raw = np.clip(0.5 - model.decision_function(X), 0.0, 1.0)
            base = self._rank_of(raw, self.baselines.get(behavior))
            if self.ensembles.get(behavior):
                ens_rows = []
                for ens_model in self.ensembles[behavior]:
                    ens_raw = np.clip(
                        0.5 - ens_model.decision_function(X), 0.0, 1.0
                    )
                    ens_rows.append(
                        self._rank_of(ens_raw, self.baselines.get(behavior))
                    )
                base = np.median(np.stack(ens_rows), axis=0)

            classifier = self.supervised_by_stream.get(behavior) or self.supervised
            p = np.zeros(len(features_list), dtype=float)
            if classifier is not None and X.shape[1] == classifier.n_features_in_:  # type: ignore[attr-defined]
                try:
                    proba = classifier.predict_proba(X)  # type: ignore[attr-defined]
                    if proba.shape[1] > 1:
                        p = proba[:, 1]
                except Exception:
                    logger.exception("Unexpected error")
                    p = np.zeros(len(features_list), dtype=float)
            if self.ensemble is not None and self.ensemble.is_trained:
                scores = np.clip(self.ensemble.predict_batch(base, p), 0.0, 1.0)
            else:
                scores = np.clip(0.6 * base + 0.4 * p, 0.0, 1.0)
            return [float(x) for x in scores]
        except Exception:
            logger.exception("Unexpected error")
            return [
                self._combined_score(behavior, model, features)
                for features in features_list
            ]

    def score_event(self, features: list[float]) -> float:
        """Anomaly score in [0,1]; higher = more anomalous.

        Routes to the per-behavior model via the event_id carried in the
        first feature (login/process vectors both start with it), falling
        back to the login model for generic callers.
        """
        if not self.is_ready:
            return 0.0
        try:
            behavior = _behavior_of(int(features[0]))
        except (TypeError, ValueError, IndexError):
            behavior = "login"
        if behavior not in self.models:
            behavior = "login" if "login" in self.models else next(iter(self.models))
        model = self.models.get(behavior)
        return self._weighted_score(
            behavior, self._combined_score(behavior, model, features)
        )

    def score_events(self, features_list: list[list[float]]) -> list[float]:
        """Batched :meth:`score_event` - one IsolationForest ``decision_function``
        and one supervised ``predict_proba`` per behavior group instead of one
        per row (the calibrated classifier pays a ~240-call joblib spawn per
        row when scored individually)."""
        if not self.is_ready or not features_list:
            return [0.0] * len(features_list)
        out: list[float] = [0.0] * len(features_list)
        groups: dict[str, list[int]] = {}
        for idx, features in enumerate(features_list):
            try:
                behavior = _behavior_of(int(features[0]))
            except (TypeError, ValueError, IndexError):
                behavior = "login"
            if behavior not in self.models:
                behavior = (
                    "login" if "login" in self.models else next(iter(self.models))
                )
            groups.setdefault(behavior, []).append(idx)
        for behavior, idxs in groups.items():
            model = self.models.get(behavior)
            if model is None:
                continue
            try:
                X = np.array([features_list[i] for i in idxs], dtype=float)
            except (TypeError, ValueError):
                continue
            if X.shape[1] != model.n_features_in_:
                continue
            try:
                raw = 0.5 - model.decision_function(X)
            except Exception:
                logger.exception("Unexpected error")
                continue
            base = self._rank_of(raw, self.baselines.get(behavior))
            classifier = self.supervised_by_stream.get(behavior) or self.supervised
            p = np.zeros(len(idxs), dtype=float)
            if classifier is not None and X.shape[1] == classifier.n_features_in_:  # type: ignore[attr-defined]
                try:
                    proba = classifier.predict_proba(X)  # type: ignore[attr-defined]
                    if proba.shape[1] > 1:
                        p = proba[:, 1]
                except Exception:
                    logger.exception("Unexpected error")
                    p = np.zeros(len(idxs), dtype=float)
            # Phase 2.4: Use ensemble meta-learner when available
            if self.ensemble is not None and self.ensemble.is_trained:
                scores = np.clip(self.ensemble.predict_batch(base, p), 0.0, 1.0)
            else:
                scores = np.clip(0.6 * base + 0.4 * p, 0.0, 1.0)
            weight = self.feedback_weights.get(behavior, 1.0)
            for pos, idx in enumerate(idxs):
                out[idx] = float(max(0.0, min(1.0, scores[pos] * weight)))
        return out

    def score_event_for_behavior(self, behavior: str, features: list[float]) -> float:
        model = self.models.get(behavior)
        if model is None:
            return 0.0
        return self._weighted_score(
            behavior, self._combined_score(behavior, model, features)
        )

    @staticmethod
    def _network_features(
        remote_ip: str,
        count: int = 1,
        distinct_ports: int = 1,
    ) -> list[float]:
        """v11 26-dim network feature row matching _load_network_features."""
        from backend.ml.realworld_labeler import is_attack_ip_offline
        import math

        is_atk = 1.0 if is_attack_ip_offline(remote_ip) else 0.0

        def _ip_num(ip: str) -> float:
            try:
                parts = ip.split(".")
                if len(parts) == 4:
                    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts)) / 4_294_967_296.0
            except Exception:
                logger.exception("Unexpected error")
            return 0.0

        def _is_priv(ip: str) -> bool:
            return ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168.")

        def _is_ll(ip: str) -> bool:
            return ip.startswith("169.254.") or ip.startswith("fe80")

        def _is_mc(ip: str) -> bool:
            return ip.startswith("224.") or ip.startswith("239.") or ip.startswith("ff")

        def _is_lb(ip: str) -> bool:
            return ip in ("127.0.0.1", "::1")

        now = datetime.now(UTC)
        hour = now.hour
        hour_sin = math.sin(2 * math.pi * hour / 24)
        hour_cos = math.cos(2 * math.pi * hour / 24)
        is_night = 1.0 if hour in _NIGHT_HOURS else 0.0
        is_weekend = 1.0 if now.weekday() >= 5 else 0.0

        port_cat = 0.0
        if distinct_ports > 0:
            if distinct_ports < 1024:
                port_cat = 0.25
            elif distinct_ports < 10240:
                port_cat = 0.5
            else:
                port_cat = 0.75

        return [
            0.5,
            1.0,
            0.0,
            0.0,
            hour_sin, hour_cos, is_night, is_weekend,
            _ip_num("0.0.0.0"), _ip_num(remote_ip),
            0.0, float(_is_priv(remote_ip)),
            float(_is_ll(remote_ip)), float(_is_mc(remote_ip)), float(_is_lb("0.0.0.0")),
            float(distinct_ports) / 65535.0,
            port_cat,
            0.0,
            0.5,
            min(count / 100.0, 1.0),
            0.0,
            is_atk, 0.0,
            0.5,
            0.0,
            min(count / 50.0, 1.0),
            0.0,
            0.0,
            0.0,
        ]

    def score_network_connection(
        self,
        remote_ip: str,
        count: int = 1,
        distinct_ports: int = 1,
        bytes_sent: int = 0,
        bytes_recv: int = 0,
        duration: float = 0.0,
    ) -> float:
        """Anomaly score for a network connection.

        v11 Feature vector: 26-dim per-event features matching _load_network_features.
        """
        model = self.models.get("network")
        if model is None:
            return 0.0

        features = self._network_features(remote_ip, count, distinct_ports)

        return self._weighted_score(
            "network",
            self._combined_score("network", model, features),
        )


    @staticmethod
    def _score_with(model, features: list[float]) -> float:
        """Anomaly score in [0,1]; higher = more anomalous.

        Uses the IsolationForest ``decision_function``: normal points score
        above 0 and anomalies below 0, so ``0.5 - decision`` maps the decision
        boundary onto 0.5 (matches sklearn's ``predict`` semantics).
        """
        arr = np.array([features], dtype=float)
        if arr.shape[1] != model.n_features_in_:
            return 0.0
        decision = float(model.decision_function(arr)[0])
        return float(max(0.0, min(1.0, 0.5 - decision)))

    @staticmethod
    def _score_batch(model, X) -> "np.ndarray":
        """Row-wise :meth:`_score_with` for a whole matrix, computed in one call.

        IsolationForest ``decision_function`` is row-independent, so this is
        numerically identical to mapping ``_score_with`` over ``X`` - but it
        pays sklearn's per-call overhead once instead of once per row. Scoring
        one row at a time builds and tears down a joblib ``Parallel`` per call
        (measured ~240 dispatches per row here), which made threshold tuning
        dominate the whole retrain.
        """
        arr = np.asarray(X, dtype=float)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if arr.ndim != 2 or arr.shape[1] != model.n_features_in_:
            return np.zeros(len(arr), dtype=float)
        decision = np.asarray(model.decision_function(arr), dtype=float)
        return np.clip(0.5 - decision, 0.0, 1.0)

    # ------------------------------------------------------------------
    def analyze_events(self, session=None, hours: int = 1) -> dict:
        """Score recent events per behavior stream and mark outliers."""
        if not self.is_ready:
            return {"status": "not-ready"}

        close = session is None
        session = session or SessionLocal()
        try:
            since = datetime.now(UTC) - timedelta(hours=hours)
            flagged = 0
            scored = 0
            # Pass-scoped cache: window aggregates (counts, baselines,
            # entropies) are identical for every event in this window, so
            # they are computed once instead of once per event.
            with _feature_pass_cache():
                events = session.scalars(
                    select(NormalizedEvent).where(NormalizedEvent.timestamp >= since)
                ).all()
                groups: dict[str, tuple[object, list, list]] = {}
                for ev in events:
                    if orm_event_is_corrupted(ev)[0]:
                        continue
                    behavior = _behavior_of(ev.event_id)
                    model = self.models.get(behavior)
                    if model is None:
                        continue
                    features = event_feature_vector(ev, _shared_session=session)
                    if features is None:
                        continue
                    grouped = groups.setdefault(
                        behavior, (model, [], [])
                    )
                    grouped[1].append(ev)
                    grouped[2].append(features)

            for behavior, (model, evs, feats) in groups.items():
                try:
                    scores = self._combined_score_batch(behavior, model, feats)
                except Exception:
                    logger.exception("Unexpected error")
                    scores = [0.0] * len(feats)
                for ev, features, combined in zip(evs, feats, scores):
                    try:
                        # Recall booster: apply UEBA + temporal + threshold
                        # enhancements when a booster is attached.
                        if self.recall_booster is not None:
                            facts = (ev.raw_json or {}).get("facts") or {}
                            score = self.recall_booster.score_event(
                                behavior, features,
                                user=ev.user or "",
                                event_id=ev.event_id,
                                facts=facts,
                                ts=ev.timestamp,
                                source_ip=str(facts.get("source_ip", "") or ""),
                                target_user=str(facts.get("target_user", "") or ""),
                            )
                        else:
                            score = self._weighted_score(behavior, float(combined))
                    except Exception:
                        logger.exception("Unexpected error")
                        continue
                    ev.ml_score = round(score, 4)
                    scored += 1
                    if score > self.thresholds.get(behavior, 0.5):
                        ev.is_anomaly = True
                        flagged += 1
                    # Feed the live event to the online learner: the reservoir
                    # buffer learns the normal behavior of each stream and the
                    # active-learning queue picks up uncertain events. The
                    # score is passed through so nothing is scored twice.
                    # NOTE: ev.id (autoincrement PK) is the unique, monotonic
                    # id the dedup watermark and the analyst-facing suggestion
                    # queue need; ev.event_id is the WINDOWS event id (4688),
                    # which repeats across rows.
                    if self.online_learner is not None:
                        try:
                            self.online_learner.score_and_buffer(
                                behavior,
                                features,
                                score=score,
                                event_id=ev.id,
                            )
                        except Exception:
                            logger.debug(
                                "online buffer failed for event %s",
                                ev.id,
                                exc_info=True,
                            )

            # Score network connection buckets in the same pass.
            if "network" in self.models:
                net_model = self.models["network"]
                net_rows = session.execute(
                    select(
                        NetworkConnection.remote_ip,
                        func.count(NetworkConnection.id),
                        func.count(func.distinct(NetworkConnection.remote_port)),
                        func.sum(NetworkConnection.bytes_sent),
                        func.sum(NetworkConnection.bytes_recv),
                        func.avg(NetworkConnection.duration_seconds),
                    )
                    .where(NetworkConnection.observed_at >= since)
                    .group_by(NetworkConnection.remote_ip)
                ).all()
                net_inputs = [
                    (
                        remote_ip or "unknown",
                        int(count),
                        int(distinct_ports),
                    )
                    for (
                        remote_ip,
                        count,
                        distinct_ports,
                        _bytes_sent,
                        _bytes_recv,
                        _duration,
                    ) in net_rows
                ]
                net_feats = [
                    self._network_features(ip, count, ports)
                    for ip, count, ports in net_inputs
                ]
                try:
                    net_scores = self._combined_score_batch(
                        "network", net_model, net_feats
                    )
                except Exception:
                    logger.exception("Unexpected error")
                    net_scores = [0.0] * len(net_feats)
                # One buffering pass per update interval: buckets have no
                # event id to dedupe on (see OnlineLearner.take_network_pass).
                buffer_network = (
                    self.online_learner is not None
                    and self.online_learner.take_network_pass()
                )
                for (_ip, _cnt, _ports), combined, nfeat in zip(
                    net_inputs, net_scores, net_feats
                ):
                    try:
                        score = self._weighted_score("network", float(combined))
                    except Exception:
                        logger.exception("Unexpected error")
                        continue
                    scored += 1
                    if score > self.thresholds.get("network", 0.5):
                        flagged += 1
                    if buffer_network:
                        try:
                            self.online_learner.score_and_buffer(
                                "network", nfeat, score=score
                            )
                        except Exception:
                            logger.debug(
                                "online buffer failed for network bucket",
                                exc_info=True,
                            )

            # Commit the online learner's dedup watermark for this pass:
            # every row in the window has now been offered to the buffers.
            if self.online_learner is not None:
                try:
                    self.online_learner.end_scoring_pass()
                except Exception:
                    logger.debug("online pass commit failed", exc_info=True)

            session.commit()
            return {"status": "ok", "scored": scored, "flagged": flagged}
        finally:
            if close:
                session.close()

    # ------------------------------------------------------------------
    def supervised_proba(self, features: list[float], classifier=None) -> float:
        """P(attack) from the supervised classifier, or 0.0 when untrained."""
        classifier = classifier or self.supervised
        if classifier is None:
            return 0.0
        arr = np.array([features], dtype=float)
        if arr.shape[1] != classifier.n_features_in_:
            return 0.0
        try:
            proba = classifier.predict_proba(arr)[0]
        except Exception:
            logger.exception("Unexpected error")
            return 0.0
        return float(proba[1] if len(proba) > 1 else 0.0)

    def _contribution_result(self, session=None) -> dict:
        """Operator-facing ML contribution signal (0-anomaly cold start).

        Fresh deployments flag no ML anomalies until enough real telemetry
        trains (``ML_TRAIN_MIN_SAMPLES``); until then detections are
        rule-only. This reports that state explicitly so the dashboard can
        warn instead of silently showing zero ML detections.
        """
        streams = list(self.models.keys()) or list(BEHAVIOR_KEYS)
        if not self.is_ready:
            return {
                "ml_contribution": "not_ready",
                "zero_anomaly_streams": streams,
                "warning": (
                    "ML model not ready — detections rely on rules "
                    f"(expected until ML_TRAIN_MIN_SAMPLES="
                    f"{ML_TRAIN_MIN_SAMPLES} real samples)"
                ),
            }
        close = session is None
        session = session or SessionLocal()
        try:
            stmt = select(NormalizedEvent.event_id, NormalizedEvent.ml_score).where(
                NormalizedEvent.ml_score.isnot(None)
            )
            if self.trained_at:
                try:
                    since = datetime.fromisoformat(self.trained_at)
                    stmt = stmt.where(NormalizedEvent.timestamp >= since)
                except ValueError:
                    pass
            rows = session.execute(stmt).all()
            flagged = {s: 0 for s in streams}
            for event_id, ml_score in rows:
                behavior = _behavior_of(int(event_id))
                if behavior not in flagged:
                    continue
                threshold = self.thresholds.get(behavior, 0.5)
                if float(ml_score or 0.0) > threshold:
                    flagged[behavior] += 1
            zero_streams = [s for s in streams if flagged.get(s, 0) == 0]
            if sum(flagged.values()) == 0:
                return {
                    "ml_contribution": "zero_anomaly",
                    "zero_anomaly_streams": zero_streams,
                    "warning": (
                        "ML has not flagged anomalies yet — detections rely on "
                        "rules (expected until ML_TRAIN_MIN_SAMPLES="
                        f"{ML_TRAIN_MIN_SAMPLES} real samples)"
                    ),
                }
            return {
                "ml_contribution": "active",
                "zero_anomaly_streams": zero_streams,
                "warning": None,
            }
        except Exception:
            logger.exception("Unexpected error")
            return {
                "ml_contribution": "unknown",
                "zero_anomaly_streams": [],
                "warning": None,
            }
        finally:
            if close:
                session.close()

    def status(self, session=None) -> dict:
        drifted, drift_reason = self._drift_result(session)
        stale, reason = self.is_stale(session)
        result = {
            "has_sklearn": HAS_SKLEARN,
            "has_xgboost": HAS_XGBOOST,
            "ready": self.is_ready,
            "trained_at": self.trained_at,
            "samples": self.n_samples,
            "events_at_train": self.events_at_train,
            "streams": list(self.models.keys()),
            "supervised": self.supervised_name,
            "supervised_streams": dict(self.supervised_name_by_stream),
            "thresholds": {k: round(v, 3) for k, v in self.thresholds.items()},
            "feature_version": ML_FEATURE_VERSION,
            "persisted": self._persisted,
            "model_source": self.model_source,
            "stale": stale,
            "staleness_reason": reason,
            "drift": drifted,
            "drift_reason": drift_reason,
        }
        # Operator-facing: disclose when ML is not yet contributing (fresh
        # deployment, 0 flagged anomalies) so the UI can warn instead of
        # silently showing a healthy model that never fires.
        result.update(self._contribution_result(session))
        # Phase 2.4: ensemble meta-learner status
        if self.ensemble is not None:
            result["ensemble"] = self.ensemble.status()
        # Phase 2.3: robustness evaluation result
        if self.robustness:
            result["robustness"] = self.robustness
        return result


class _QuickModelProxy:
    """Minimal proxy for robustness evaluation (avoids circular import)."""

    def __init__(self, models: dict, baselines: dict):
        self._models = models
        self._baselines = baselines

    @property
    def models(self):
        return self._models

    def decision_function(self, X):
        for model in self._models.values():
            return model.decision_function(X)
        raise ValueError("No models available")

    def predict(self, X):
        for model in self._models.values():
            return model.predict(X)
        raise ValueError("No models available")

    def score(self, X, y=None):
        for model in self._models.values():
            try:
                return model.score(X, y) if y is not None else model.score(X)
            except Exception:
                logger.exception("Unexpected error")
                continue
        return 0.0


_detector: MLAnomalyDetector | None = None


def get_detector() -> MLAnomalyDetector:
    global _detector
    if _detector is None:
        _detector = MLAnomalyDetector(load_persisted=True)
    return _detector
