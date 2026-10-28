"""Investigation API - attack chain reconstruction for an alert."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.audit import client_ip, log_action
from backend.database.connection import get_db
from backend.database.models import (
    Alert,
    AlertEventLink,
    NetworkConnection,
    NormalizedEvent,
)
from backend.security import actor_name, require_auth, tenant_scope

router = APIRouter(
    prefix="/api/investigation",
    tags=["investigation"],
    dependencies=[Depends(require_auth)],
)


@router.get("/process-tree")
def process_tree(
    request: Request,
    alert_id: int | None = None,
    host: str = "",
    hours: int = 6,
    db: Session = Depends(get_db),
):
    """Standalone process-tree reconstruction.

    Either scope by alert (the tree is built around its evidence events) or by
    host + window, so analysts can pivot from any page to full process lineage.
    """
    from backend.investigation.process_tree import build_process_tree

    if alert_id is not None:
        scope = tenant_scope(request)
        stmt = select(Alert).where(Alert.id == alert_id)
        if scope is not None:
            stmt = stmt.where(Alert.org == scope)
        alert = db.scalars(stmt).first()
        if not alert:
            raise HTTPException(404, "Alert not found")
        evidence_events = [link.event for link in alert.events if link.event]
        return build_process_tree(db, evidence_events, org=alert.org or "")

    if host:
        since = datetime.now(UTC) - timedelta(hours=hours)
        events = db.scalars(
            select(NormalizedEvent)
            .where(
                NormalizedEvent.host == host,
                NormalizedEvent.timestamp >= since,
            )
            .order_by(NormalizedEvent.timestamp.asc())
            .limit(2000)
        ).all()
        return build_process_tree(db, list(events))

    raise HTTPException(400, "Provide alert_id or host")


def _related_events(db: Session, alert: Alert, window_minutes: int = 30) -> list[dict]:
    """Host/user-scoped events around the alert's evidence window."""
    link = db.scalars(
        select(AlertEventLink)
        .where(AlertEventLink.alert_id == alert.id)
        .order_by(AlertEventLink.event_id)
        .limit(1)
    ).first()
    if not link:
        return []

    from datetime import timedelta

    anchor = db.get(NormalizedEvent, link.event_id)
    if not anchor:
        return []
    start = anchor.timestamp - timedelta(minutes=window_minutes)
    end = anchor.timestamp + timedelta(minutes=window_minutes)
    q = select(NormalizedEvent).where(NormalizedEvent.timestamp.between(start, end))
    hosts = {ev.event.host for ev in alert.events if ev.event and ev.event.host}
    users = {ev.event.user for ev in alert.events if ev.event and ev.event.user}
    if hosts:
        q = q.where(NormalizedEvent.host.in_(list(hosts)))
    if users:
        q = q.where(NormalizedEvent.user.in_(list(users)))
    q = q.order_by(NormalizedEvent.timestamp).limit(200)
    rows = db.scalars(q).all()
    return [e.to_dict() for e in rows]


def _attack_chain(db: Session, alert: Alert) -> list[dict]:
    """Rebuild a kill-chain narrative from linked evidence events."""
    chain = []
    steps: dict[str, list[str]] = {}
    for link in sorted(alert.events, key=lambda l: l.event_id):
        event = link.event
        step = {
            4625: "Credential probing",
            4624: "Access granted",
            4720: "Account creation",
            4732: "Privilege assignment",
            4672: "Privileged logon",
            4104: "Script execution",
            7045: "Persistence installed",
            4698: "Scheduled persistence",
        }.get(event.event_id, "Observation")
        steps.setdefault(step, [])
        steps[step].append(
            f"Event {event.event_id} {event.timestamp.isoformat()} "
            f"user={event.user} | {event.message[:120]}"
        )

    for step_name, lines in steps.items():
        chain.append({"step": step_name, "details": lines})
    if not chain:
        chain.append({"step": "Evidence", "details": [alert.evidence]})
    return chain


@router.get("/alert/{alert_id}")
def investigate(alert_id: int, request: Request, db: Session = Depends(get_db)):
    scope = tenant_scope(request)
    stmt = select(Alert).where(Alert.id == alert_id)
    if scope is not None:
        stmt = stmt.where(Alert.org == scope)
    alert = db.scalars(stmt).first()
    if not alert:
        raise HTTPException(404, "Alert not found")

    from backend.investigation import build_investigation

    story = build_investigation(db, alert)

    evidence_events = [link.event.to_dict() for link in alert.events]
    related = _related_events(db, alert)
    chain = _attack_chain(db, alert)

    # RAG: similar past (resolved) incidents to ground the analyst's triage.
    try:
        from backend.ai.assistant import SecurityAssistant

        similar = SecurityAssistant(db).similar_resolved_alerts(alert.name, limit=3)
        similar_incidents = [
            {
                "id": s.id,
                "name": s.name,
                "severity": s.severity,
                "mitre_id": s.mitre_id,
                "evidence": (s.evidence or "")[:300],
                "recommendation": (s.recommendation or "")[:300],
                "updated_at": s.updated_at.isoformat() if s.updated_at else None,
            }
            for s in similar
        ]
    except Exception:
        similar_incidents = []

    # Network context: connections around the alert window
    if alert.mitre_id == "T1046":
        conns = db.scalars(
            select(NetworkConnection)
            .order_by(NetworkConnection.observed_at.desc())
            .limit(50)
        ).all()
        network = [c.to_dict() for c in conns]
    else:
        network = []

    return {
        "alert": alert.to_dict(include_events=True),
        "evidence_events": evidence_events,
        "related_events": related,
        "attack_chain": chain,
        "network_context": network,
        "similar_incidents": similar_incidents,
        "process_tree": story["process_tree"],
        "related_alerts": story["related_alerts"],
        "suggested_verdict": story["suggested_verdict"],
        "story_confidence": story["story_confidence"],
        "timeline": story["timeline"],
        "risk_profile": story["risk_profile"],
        "summary": (
            f"Attack chain for {alert.name} ({alert.mitre_id} / {alert.mitre_tactic}): "
            f"{len(evidence_events)} evidence events, {len(related)} related events "
            f"across {len(chain)} kill-chain step(s); process tree "
            f"{story['process_tree'].get('node_count', 0)} nodes "
            f"(completeness {story['process_tree'].get('completeness', 0.0):.0%}), "
            f"{len(story['related_alerts'])} related alert(s), "
            f"story confidence {story['story_confidence'].get('label', 'n/a')}."
        ),
    }
