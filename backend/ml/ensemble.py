"""Ensemble stacking meta-learner for multi-model fusion.

Phase 2.4 + v7/v8 enhancements: Combines predictions from Isolation Forest
(unsupervised), supervised classifiers (XGBoost/RF), and Markov chain
cross-stream detector into a single stacked prediction via a meta-learner.

v7 enhancements:
- Gradient boosting meta-learner as alternative to logistic regression
- Feature-level fusion with cross-model interaction features
- Confidence-weighted blending based on base model agreement

v8 enhancements:
- Time-window ensemble: multiple models trained on different time windows
- Weighted voting based on model recency and performance
"""

from __future__ import annotations

import logging
from collections import deque

import numpy as np

logger = logging.getLogger("baraq.ml.ensemble")

try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression

    HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    HAS_SKLEARN = False


class TimeWindowEnsemble:
    """Ensemble of models trained on different time windows.

    Maintains a sliding window of models trained at different time points.
    Newer models get higher weight, but older models provide stability
    against temporal bias.
    """

    def __init__(self, max_windows: int = 5, decay_factor: float = 0.8):
        self.max_windows = max_windows
        self.decay_factor = decay_factor
        self._windows: deque = deque(maxlen=max_windows)
        self._window_weights: deque = deque(maxlen=max_windows)

    def add_model(self, model, window_start, window_end, performance_score: float = 1.0):
        """Add a trained model for a specific time window."""
        self._windows.append({
            "model": model,
            "start": window_start,
            "end": window_end,
            "performance": performance_score,
        })
        # Weight by recency (newer = higher weight)
        n = len(self._windows)
        weights = [self.decay_factor ** (n - 1 - i) for i in range(n)]
        # Normalize weights
        total = sum(weights)
        self._window_weights = deque([w / total for w in weights] if total > 0 else weights, maxlen=self.max_windows)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Weighted average prediction across all time window models."""
        if not self._windows:
            return np.zeros(len(X))

        predictions = []
        for i, window in enumerate(self._windows):
            try:
                scores = window["model"].decision_function(X)
                # Normalize to [0, 1]
                normalized = 0.5 - scores
                predictions.append(normalized * self._window_weights[i])
            except Exception:
                continue

        if not predictions:
            return np.zeros(len(X))

        return np.sum(predictions, axis=0)

    def predict_single(self, features: list[float]) -> float:
        """Predict for a single sample."""
        X = np.array([features])
        result = self.predict(X)
        return float(result[0]) if len(result) > 0 else 0.0

    def get_window_info(self) -> list[dict]:
        """Get information about active time windows."""
        return [
            {
                "start": w["start"],
                "end": w["end"],
                "performance": w["performance"],
                "weight": self._window_weights[i] if i < len(self._window_weights) else 0.0,
            }
            for i, w in enumerate(self._windows)
        ]

    @property
    def n_windows(self) -> int:
        return len(self._windows)


class EnsembleStacker:
    """Stacking meta-learner that combines IF + supervised + Markov predictions.

    v7 enhancements:
    - Gradient boosting meta-learner for non-linear blending
    - Feature-level fusion with model agreement signals
    - Confidence-weighted fallback blending
    """

    def __init__(self):
        self.meta_model = None
        self.gb_model = None
        self.is_trained = False
        self.meta_weights: dict[str, float | str] = {}
        self._min_samples_for_meta = 30
        self._use_gradient_boosting = True
        #: Stream this learner belongs to (set by train_meta / PerStreamStacker).
        self.stream: str | None = None

    def extract_meta_features(
        self,
        if_scores: np.ndarray,
        supervised_probas: np.ndarray,
        markov_scores: np.ndarray | None = None,
    ) -> np.ndarray:
        """Create meta-feature matrix from base model predictions with feature-level fusion.

        Features:
        - Raw scores from each model
        - Pairwise interactions (IF*Sup, IF*Markov, Sup*Markov)
        - Agreement signals (model agreement binary features)
        - Variance of model predictions
        """
        n = len(if_scores)
        meta = np.column_stack([if_scores, supervised_probas])
        if markov_scores is not None and len(markov_scores) == n:
            meta = np.column_stack([meta, markov_scores])

        # Pairwise interaction features
        meta = np.column_stack([meta, if_scores * supervised_probas])
        if markov_scores is not None and len(markov_scores) == n:
            meta = np.column_stack([meta, if_scores * markov_scores])
            meta = np.column_stack([meta, supervised_probas * markov_scores])

            # v7: Model agreement signals
            if_threshold = 0.5
            sup_threshold = 0.5
            mark_threshold = 0.5
            if_agree = ((if_scores > if_threshold) == (supervised_probas > sup_threshold)).astype(float)
            all_agree = ((if_scores > if_threshold) &
                         (supervised_probas > sup_threshold) &
                         (markov_scores > mark_threshold)).astype(float)
            any_anomaly = ((if_scores > if_threshold) |
                           (supervised_probas > sup_threshold) |
                           (markov_scores > mark_threshold)).astype(float)
            meta = np.column_stack([meta, if_agree, all_agree, any_anomaly])

            # v7: Prediction variance (disagreement signal)
            all_scores = np.column_stack([if_scores, supervised_probas, markov_scores])
            pred_variance = np.var(all_scores, axis=1)
            meta = np.column_stack([meta, pred_variance])

        return meta

    @staticmethod
    def _cv_auc(meta_X: np.ndarray, y: np.ndarray, max_folds: int = 3) -> float:
        """Cross-validated ROC-AUC of the meta-feature space, 0.5 = chance.

        Model *selection* must not use training accuracy: a depth-3 gradient
        booster memorises its leaves and always beats a linear model in-sample,
        which is exactly how the pooled learner ended up emitting a constant.
        """
        try:
            from sklearn.metrics import roc_auc_score
            from sklearn.model_selection import StratifiedKFold
        except ImportError:  # pragma: no cover
            return 0.5
        pos = int(y.sum())
        if pos < 4 or pos == len(y):
            return 0.5
        folds = min(max_folds, pos)
        scores = []
        try:
            skf = StratifiedKFold(n_splits=folds, shuffle=False)
            for tr, te in skf.split(meta_X, y):
                if len(np.unique(y[tr])) < 2 or len(np.unique(y[te])) < 2:
                    continue
                model = LogisticRegression(
                    C=1.0, class_weight="balanced", max_iter=200, random_state=42
                )
                model.fit(meta_X[tr], y[tr])
                proba = model.predict_proba(meta_X[te])[:, 1]
                scores.append(float(roc_auc_score(y[te], proba)))
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Meta CV failed: %s", exc)
            return 0.5
        return float(np.mean(scores)) if scores else 0.5

    def train_meta(
        self,
        if_scores: np.ndarray,
        supervised_probas: np.ndarray,
        markov_scores: np.ndarray | None,
        y_true: np.ndarray,
        stream: str | None = None,
    ) -> dict:
        """Train the meta-learner on held-out base model predictions.

        v7: Tries both logistic regression and gradient boosting, keeps the better one.

        Selection is by **cross-validated AUC** (see :meth:`_cv_auc`), not by
        training accuracy, and the gradient booster is only considered when
        there are enough positives to justify a non-linear boundary.  A stream
        with a handful of attacks must keep the monotone linear blend, or the
        boosted learner collapses to the prior and every benign row receives
        the same score.
        """
        if not HAS_SKLEARN:
            return {"status": "sklearn-not-installed", "trained": False}

        n = len(y_true)
        if n < self._min_samples_for_meta:
            self.meta_weights = {"if": 0.6, "supervised": 0.4, "markov": 0.0}
            return {
                "status": "insufficient-data",
                "trained": False,
                "fallback_weights": dict(self.meta_weights),
                "min_required": self._min_samples_for_meta,
            }

        y_true = np.asarray(y_true).astype(int)
        pos = int(y_true.sum())
        if pos == 0 or pos == n:
            self.meta_weights = {"if": 0.6, "supervised": 0.4, "markov": 0.0}
            return {
                "status": "single-class",
                "trained": False,
                "fallback_weights": dict(self.meta_weights),
            }

        meta_X = self.extract_meta_features(if_scores, supervised_probas, markov_scores)
        cv_auc = self._cv_auc(meta_X, y_true)

        results: dict[str, dict] = {}

        # Logistic regression: monotone in both base scores, so per-event
        # ranking survives calibration.  This is the safe default.
        try:
            lr_model = LogisticRegression(
                C=1.0, class_weight="balanced", max_iter=200, random_state=42,
            )
            lr_model.fit(meta_X, y_true)
            results["logistic_regression"] = {"model": lr_model, "accuracy": cv_auc}
        except Exception as e:
            logger.debug("Logistic regression meta-learner failed: %s", e)

        # v7: Try gradient boosting - only with a meaningful positive count.
        if self._use_gradient_boosting and pos >= 30:
            try:
                gb_model = GradientBoostingClassifier(
                    n_estimators=50,
                    max_depth=3,
                    learning_rate=0.1,
                    random_state=42,
                )
                gb_model.fit(meta_X, y_true)
                results["gradient_boosting"] = {"model": gb_model, "accuracy": cv_auc}
            except Exception as e:
                logger.debug("Gradient boosting meta-learner failed: %s", e)

        if not results:
            self.meta_weights = {"if": 0.6, "supervised": 0.4, "markov": 0.0}
            return {"status": "training-failed", "trained": False, "error": "all meta-learners failed"}

        # Pick best model by cross-validated AUC (ties keep logistic regression:
        # insertion order means max() is stable and LR stays first).
        best_name = max(results, key=lambda k: results[k]["accuracy"])
        best_result = results[best_name]
        self.stream = stream

        if best_name == "gradient_boosting":
            self.gb_model = best_result["model"]
            self.meta_model = None
        else:
            self.meta_model = best_result["model"]
            self.gb_model = None

        self.is_trained = True

        # Extract learned weights for interpretability
        if self.meta_model is not None:
            coef = self.meta_model.coef_[0]
            self.meta_weights = {
                "if": round(float(coef[0]), 4),
                "supervised": round(float(coef[1]), 4),
                "markov": round(float(coef[2]), 4) if len(coef) > 2 else 0.0,
            }
        else:
            self.meta_weights = {"meta_learner": best_name}

        return {
            "status": "ok",
            "trained": True,
            "meta_learner": best_name,
            "weights": dict(self.meta_weights),
            "cv_auc": round(float(cv_auc), 4),
            "n_samples": n,
            "n_positives": pos,
            "candidates": {k: round(v["accuracy"], 4) for k, v in results.items()},
        }

    def predict(
        self,
        if_score: float,
        supervised_proba: float,
        markov_score: float = 0.0,
    ) -> float:
        """Produce fused prediction from base model scores.

        v7: Uses gradient boosting when available, falls back to logistic regression,
        then to confidence-weighted blending.

        Meta-features MUST match ``extract_meta_features`` used in training:
        when markov is absent the model was fit on ``[if, sup, if*sup]``
        (3 columns).  Building a 6-column vector here made every
        ``predict_proba`` raise on shape mismatch and silently fall through
        to the weighted blend — so the stacked learner never actually ran.
        """
        has_markov = markov_score != 0.0
        meta = self.extract_meta_features(
            np.array([if_score]),
            np.array([supervised_proba]),
            np.array([markov_score]) if has_markov else None,
        )

        # Agreement features only exist in training when markov is present
        # (extract_meta_features already appended them for that path).
        # Try gradient boosting first
        if self.gb_model is not None:
            try:
                proba = self.gb_model.predict_proba(meta)[0]
                return float(proba[1]) if len(proba) > 1 else float(proba[0])
            except Exception:
                pass

        # Try logistic regression
        if self.meta_model is not None:
            try:
                proba = self.meta_model.predict_proba(meta)[0]
                return float(proba[1]) if len(proba) > 1 else float(proba[0])
            except Exception:
                pass

        # v7: Confidence-weighted fallback
        weights = {"if": 0.5, "supervised": 0.35, "markov": 0.15}
        if markov_score == 0.0:
            weights = {"if": 0.6, "supervised": 0.4, "markov": 0.0}

        score = (
            weights["if"] * if_score
            + weights["supervised"] * supervised_proba
            + weights["markov"] * markov_score
        )
        return float(max(0.0, min(1.0, score)))

    def predict_batch(
        self,
        if_scores: np.ndarray,
        supervised_probas: np.ndarray,
        markov_scores: np.ndarray | None = None,
    ) -> np.ndarray:
        """Batch prediction for efficiency."""
        if self.is_trained:
            meta_X = self.extract_meta_features(if_scores, supervised_probas, markov_scores)

            # Try gradient boosting first
            if self.gb_model is not None:
                try:
                    proba = self.gb_model.predict_proba(meta_X)
                    return proba[:, 1] if proba.shape[1] > 1 else proba[:, 0]
                except Exception:
                    pass

            # Try logistic regression
            if self.meta_model is not None:
                try:
                    proba = self.meta_model.predict_proba(meta_X)
                    return proba[:, 1] if proba.shape[1] > 1 else proba[:, 0]
                except Exception:
                    pass

        # v7: Confidence-weighted fallback
        if markov_scores is not None and len(markov_scores) == len(if_scores):
            scores = 0.5 * if_scores + 0.35 * supervised_probas + 0.15 * markov_scores
        else:
            scores = 0.6 * if_scores + 0.4 * supervised_probas
        return np.clip(scores, 0.0, 1.0)

    def status(self) -> dict:
        """Current state of the meta-learner."""
        active_model = "none"
        if self.gb_model is not None:
            active_model = "gradient_boosting"
        elif self.meta_model is not None:
            active_model = "logistic_regression"

        return {
            "is_trained": self.is_trained,
            "has_sklearn": HAS_SKLEARN,
            "active_meta_learner": active_model,
            "meta_weights": dict(self.meta_weights),
            "min_samples_required": self._min_samples_for_meta,
            "stream": self.stream,
        }


class PerStreamStacker:
    """One meta-learner per behaviour, with a safe monotone fallback.

    A single pooled meta-learner cannot work across streams with different
    class priors: the pooled positive rate dominates the rare stream and the
    learner emits the prior for every ordinary event (a one-value "score" that
    makes per-event triage impossible).  Each stream now gets its own learner,
    trained on its own out-of-fold predictions, and a stream whose learner
    cannot beat the plain ``0.6*rank + 0.4*proba`` blend is left on the blend.

    Every method tolerates an untrained/incompatible stream and degrades to the
    blend, so a partial training run can never make scoring worse than the
    pre-ensemble behaviour.
    """

    MIN_POSITIVES = 5
    MIN_NEGATIVES = 20
    MIN_AUC_GAIN = 0.0

    def __init__(self, streams=("login", "process", "network")):
        self.streams = tuple(streams)
        self.stacked: dict[str, EnsembleStacker] = {
            s: EnsembleStacker() for s in self.streams
        }
        #: Per-stream audit trail: why the meta was accepted or rejected.
        self.decisions: dict[str, dict] = {}

    # -- state ---------------------------------------------------------
    @property
    def is_trained(self) -> bool:
        return any(st.is_trained for st in self.stacked.values())

    def trained_for(self, stream: str) -> bool:
        learner = self.stacked.get(stream)
        return bool(learner is not None and learner.is_trained)

    @staticmethod
    def _blend(if_scores, supervised_probas):
        return np.clip(0.6 * np.asarray(if_scores, float)
                       + 0.4 * np.asarray(supervised_probas, float), 0.0, 1.0)

    # -- training ------------------------------------------------------
    @staticmethod
    def _auc(y: np.ndarray, scores: np.ndarray) -> float | None:
        try:
            from sklearn.metrics import roc_auc_score

            if len(np.unique(y)) < 2:
                return None
            return float(roc_auc_score(y, scores))
        except Exception:  # pragma: no cover - defensive
            return None

    def fit_stream(
        self,
        stream: str,
        if_scores: np.ndarray,
        supervised_probas: np.ndarray,
        y_true: np.ndarray,
    ) -> dict:
        """Fit ``stream``'s meta-learner, keeping it only if it earns its keep.

        Acceptance rule: the learner must beat the monotone blend on the same
        (out-of-fold) rows by ``MIN_AUC_GAIN`` and produce more than one
        distinct score for benign rows.  Rejected learners stay untrained and
        scoring falls back to the blend.
        """
        learner = self.stacked.get(stream)
        if learner is None:
            return {"status": "unknown-stream", "trained": False}

        y = np.asarray(y_true).astype(int)
        pos = int(y.sum())
        neg = int(len(y) - pos)
        if pos < self.MIN_POSITIVES or neg < self.MIN_NEGATIVES:
            decision = {
                "status": "insufficient-labels",
                "trained": False,
                "n_positives": pos,
                "n_negatives": neg,
                "min_positives": self.MIN_POSITIVES,
            }
            self.decisions[stream] = decision
            return decision

        result = learner.train_meta(
            np.asarray(if_scores, float),
            np.asarray(supervised_probas, float),
            None,
            y,
            stream=stream,
        )
        if not result.get("trained"):
            self.decisions[stream] = result
            return result

        # Gate on measured separation, not on the fact that fitting succeeded.
        meta_scores = np.asarray(
            [learner.predict(float(a), float(b))
             for a, b in zip(if_scores, supervised_probas)],
            dtype=float,
        )
        blend_scores = self._blend(if_scores, supervised_probas)
        meta_auc = self._auc(y, meta_scores)
        blend_auc = self._auc(y, blend_scores)
        benign_meta = meta_scores[y == 0]
        distinct_benign = len(np.unique(np.round(benign_meta, 12)))

        accepted = (
            meta_auc is not None
            and blend_auc is not None
            and meta_auc >= blend_auc + self.MIN_AUC_GAIN
            and distinct_benign > 1
        )
        decision = {
            "status": "accepted" if accepted else "rejected",
            "trained": bool(accepted),
            "meta_auc": None if meta_auc is None else round(meta_auc, 4),
            "blend_auc": None if blend_auc is None else round(blend_auc, 4),
            "distinct_benign_scores": distinct_benign,
            "n_samples": int(len(y)),
            "n_positives": pos,
            "meta_learner": result.get("meta_learner"),
            "reason": (
                "separates better than the blend"
                if accepted
                else (
                    "meta collapsed to a point mass"
                    if distinct_benign <= 1
                    else "no AUC gain over the blend"
                )
            ),
        }
        if not accepted:
            learner.is_trained = False
            learner.meta_model = None
            learner.gb_model = None
        self.decisions[stream] = decision
        logger.info("Per-stream meta for %s: %s", stream, decision["reason"])
        return decision

    # -- inference -----------------------------------------------------
    def predict(self, stream: str, if_score: float, supervised_proba: float) -> float:
        learner = self.stacked.get(stream)
        if learner is not None and learner.is_trained:
            return float(np.clip(learner.predict(if_score, supervised_proba), 0.0, 1.0))
        return float(self._blend(if_score, supervised_proba))

    def predict_batch(
        self,
        stream: str,
        if_scores: np.ndarray,
        supervised_probas: np.ndarray,
    ) -> np.ndarray:
        learner = self.stacked.get(stream)
        if learner is not None and learner.is_trained:
            return np.clip(
                learner.predict_batch(if_scores, supervised_probas), 0.0, 1.0
            )
        return self._blend(if_scores, supervised_probas)

    # -- reporting -----------------------------------------------------
    def status(self) -> dict:
        return {
            "is_trained": self.is_trained,
            "streams": {
                stream: {
                    **learner.status(),
                    "decision": self.decisions.get(stream),
                }
                for stream, learner in self.stacked.items()
            },
        }
