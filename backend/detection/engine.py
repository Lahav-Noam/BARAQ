"""v2 detection engine (Phase 2).

Runs the detector registry over canonical EVENTs and produces DETECTIONs.

Hard boundary (Phase 2.14): evaluating an event has zero side effects on
alerts, incidents, entity_risk, risk_events, playbooks, SOAR or ML
production scoring. The only persistence a detection ever has is the
``detections`` table - and even that is opt-in via ``persist``.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from backend import config
from backend.detection.context import DetectionContext
from backend.detection.contract import DETECTION
from backend.detection.models import DetectionRecord
from backend.detection.registry import Registry, default_registry
from backend.telemetry.contract import EVENT

logger = logging.getLogger("baraq.detection.engine")


def _ensure_not_production_db() -> None:
    """Phase 0.7/2.14 isolation: the detection store is a v2 table and must
    never be written into the v1 production database."""
    if (
        not config.V2_ENGINES_ALLOW_PROD
        and make_url(config.DATABASE_URL).database == config.PRODUCTION_DB_NAME
    ):
        raise RuntimeError(
            f"refusing: v2 detection store is read-only against the "
            f"production database '{config.PRODUCTION_DB_NAME}'"
        )


def run_detection(
    event: EVENT,
    context: DetectionContext | None = None,
    registry: Registry | None = None,
) -> list[DETECTION]:
    """Evaluate one canonical EVENT against every enabled detector.

    Pure: creates no rows, mutates no state. Returns detections in
    registry order.
    """
    registry = registry or default_registry()
    findings: list[DETECTION] = []
    for detector in registry.enabled_detectors():
        if not detector.supports(event):
            continue
        try:
            finding = detector.evaluate(event, context)
        except Exception as exc:
            logger.warning(
                "detector %s failed on event %s: %s",
                detector.id,
                event.action,
                exc,
            )
            continue
        if finding is not None:
            findings.append(finding)
    return findings


def run_detections(
    events: list[EVENT],
    context: DetectionContext | None = None,
    registry: Registry | None = None,
) -> list[DETECTION]:
    """Evaluate a batch of events. Deterministic order: event order, then
    registry order."""
    findings: list[DETECTION] = []
    for event in events:
        findings.extend(run_detection(event, context, registry))
    return findings


def persist(db: Session, detection: DETECTION) -> DetectionRecord:
    """Persist one detection into the v2 ``detections`` table.

    The ONLY table this engine ever writes. Idempotent per detection_id:
    replaying the same campaign updates the existing row (merge event ids,
    widen first_seen/last_seen, refresh severity/confidence/evidence) instead
    of creating duplicates - one row per rule + campaign key.
    """
    _ensure_not_production_db()
    existing = db.scalars(
        select(DetectionRecord).where(
            DetectionRecord.detection_id == detection.detection_id
        )
    ).first()
    if existing:
        existing.severity = detection.severity
        existing.confidence = detection.confidence
        existing.title = detection.title
        existing.description = detection.description
        existing.evidence = [e.to_dict() for e in detection.evidence]
        existing.observables = [dict(o) for o in detection.observables]
        existing.event_ids = sorted(set(existing.event_ids) | set(detection.event_ids))  # type: ignore[arg-type]
        existing.updated_at = datetime.now(UTC)
        existing.first_seen = min(existing.first_seen, detection.first_seen)
        existing.last_seen = max(existing.last_seen, detection.last_seen)
        db.commit()
        return existing
    row = DetectionRecord(
        detection_id=detection.detection_id,
        detector_id=detection.detector_id,
        detector_version=detection.detector_version,
        title=detection.title,
        description=detection.description,
        severity=detection.severity,
        confidence=detection.confidence,
        timestamp=detection.timestamp,
        first_seen=detection.first_seen,
        last_seen=detection.last_seen,
        event_id=detection.event_id,
        event_ids=list(detection.event_ids),
        host_id=detection.host_id,
        host_name=detection.host_name,
        user_id=detection.user_id,
        username=detection.username,
        source_ip=detection.source_ip,
        destination_ip=detection.destination_ip,
        mitre_tactic=detection.mitre_tactic,
        mitre_technique=detection.mitre_technique,
        evidence=[e.to_dict() for e in detection.evidence],
        observables=[dict(o) for o in detection.observables],
        status=detection.status,
    )
    db.add(row)
    db.commit()
    return row


def run_and_persist(
    db: Session,
    events: list[EVENT],
    context: DetectionContext | None = None,
    registry: Registry | None = None,
) -> list[DetectionRecord]:
    """Evaluate + persist in one step (API / dev use). Returns stored rows."""
    findings = run_detections(events, context, registry)
    return [persist(db, f) for f in findings]
