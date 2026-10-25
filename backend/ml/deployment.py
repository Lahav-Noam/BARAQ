"""ML deployment gate and shadow-mode helpers.

BARAQ's ML layer is not allowed to take response actions on its own.  This
module makes that contract explicit and gives operators a single source of
truth for the currently loaded model:

* ``off``      - do not score.
* ``shadow``   - score and persist monitoring rows, but do not set
                 ``is_anomaly``/``ml_score`` on telemetry.
* ``advisory`` - current production behaviour: event scores may contribute to
                 analyst-facing risk, but no autonomous action is taken.

There is deliberately no ``enforce`` mode.  A model may only be promoted to
that state after a validated manifest shows a campaign-held-out evaluation,
contemporaneous benign traffic, a local FPR estimate, and a single-feature
baseline check.  See ``docs/ml-deployment-readiness.md``.

The manifest is written by ``scripts/ml_deployment_gate.py`` and is separate
from ``model_meta.json`` so a model cannot be promoted by editing training
metadata alone.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from backend.config import (
    ML_DEPLOYMENT_MODE,
    ML_DEPLOYMENT_MODES,
    ML_FEATURE_VERSION,
    ML_MANIFEST_FILE,
    ML_MODEL_BUNDLE,
)

logger = logging.getLogger("baraq.ml.deployment")

#: Manifest statuses understood by the runtime.  ``validated`` is the only
#: status that would permit enforcement; ``shadow`` and ``blocked`` are
#: monitoring-only.
MANIFEST_STATUSES = ("validated", "shadow", "blocked", "missing")


@dataclass(frozen=True)
class DeploymentManifest:
    status: str = "missing"
    mode: str = "shadow"
    model_version: int = 0
    feature_version: int = 0
    generated_at: str = ""
    bundle_sha256: str = ""
    criteria: dict[str, Any] = field(default_factory=dict)
    evaluation: dict[str, Any] = field(default_factory=dict)
    blocking_reasons: list[str] = field(default_factory=list)
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "mode": self.mode,
            "model_version": self.model_version,
            "feature_version": self.feature_version,
            "generated_at": self.generated_at,
            "bundle_sha256": self.bundle_sha256,
            "criteria": self.criteria,
            "evaluation": self.evaluation,
            "blocking_reasons": self.blocking_reasons,
            "source": self.source,
        }


def _env_mode() -> str:
    mode = os.environ.get("BARAQ_ML_DEPLOYMENT_MODE", ML_DEPLOYMENT_MODE)
    mode = (mode or "").strip().lower()
    return mode if mode in ML_DEPLOYMENT_MODES else "shadow"


def configured_mode() -> str:
    """Return the effective ML mode, re-reading the environment for tests.

    A ``blocked`` manifest means the bundle's provenance is untrusted (for
    example, a corrupt manifest).  In that case even advisory scoring is
    downgraded to shadow; a missing manifest does not change the configured
    mode, but enforcement is still impossible.
    """
    mode = _env_mode()
    if mode != "off" and load_manifest().status == "blocked":
        return "shadow"
    return mode


@lru_cache(maxsize=8)
def _cached_sha256(path: str, mtime_ns: int, size: int) -> str:
    # The cache key includes size and mtime so a promoted/rolled-back bundle
    # is re-hashed automatically without reading the file on every status poll.
    del mtime_ns, size
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bundle_sha256(path: Path | str | None = None) -> str:
    target = Path(path or ML_MODEL_BUNDLE)
    try:
        stat = target.stat()
    except OSError:
        return ""
    try:
        return _cached_sha256(str(target), stat.st_mtime_ns, stat.st_size)
    except OSError:
        return ""


def load_manifest(path: Path | str | None = None) -> DeploymentManifest:
    target = Path(path or ML_MANIFEST_FILE)
    if not target.exists():
        return DeploymentManifest(
            status="missing",
            mode=_env_mode(),
            feature_version=ML_FEATURE_VERSION,
            bundle_sha256=bundle_sha256(),
            blocking_reasons=[
                "No deployment manifest exists for the loaded bundle.",
                "A model without a campaign-held-out validation manifest cannot be used for enforcement.",
            ],
            source=str(target),
        )
    try:
        raw = json.loads(target.read_text())
    except (OSError, ValueError) as exc:
        logger.warning("Could not read ML manifest %s: %s", target, exc)
        return DeploymentManifest(
            status="blocked",
            mode=_env_mode(),
            feature_version=ML_FEATURE_VERSION,
            bundle_sha256=bundle_sha256(),
            blocking_reasons=[f"Manifest is unreadable: {exc}"],
            source=str(target),
        )
    status = str(raw.get("status", "blocked")).lower()
    if status not in MANIFEST_STATUSES:
        status = "blocked"
    return DeploymentManifest(
        status=status,
        mode=str(raw.get("mode", _env_mode())).lower(),
        model_version=int(raw.get("model_version", 0) or 0),
        feature_version=int(raw.get("feature_version", 0) or 0),
        generated_at=str(raw.get("generated_at", "") or ""),
        bundle_sha256=str(raw.get("bundle_sha256", "") or ""),
        criteria=raw.get("criteria") if isinstance(raw.get("criteria"), dict) else {},
        evaluation=raw.get("evaluation") if isinstance(raw.get("evaluation"), dict) else {},
        blocking_reasons=[
            str(x) for x in (raw.get("blocking_reasons") or []) if str(x).strip()
        ],
        source=str(target),
    )


def enforcement_allowed(manifest: DeploymentManifest | None = None) -> bool:
    manifest = manifest or load_manifest()
    return manifest.status == "validated"


def deployment_status(manifest: DeploymentManifest | None = None) -> dict[str, Any]:
    manifest = manifest or load_manifest()
    mode = configured_mode()
    return {
        "mode": mode,
        "mode_description": {
            "off": "ML scoring disabled.",
            "shadow": "Scores are stored for monitoring only; event flags and risk are unchanged.",
            "advisory": "Scores may inform analyst-facing risk; no autonomous action.",
        }.get(mode, "Unknown mode; falling back to shadow."),
        "manifest": manifest.to_dict(),
        "enforcement_allowed": enforcement_allowed(manifest),
        "feature_version": ML_FEATURE_VERSION,
        "bundle_sha256": bundle_sha256(),
        "checked_at": datetime.now(UTC).isoformat(),
    }
