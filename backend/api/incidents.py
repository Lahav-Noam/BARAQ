"""Incident (case) management API.

Incidents group related alerts into trackable cases with severity, status,
ownership, MITRE mapping and an analyst comment timeline.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.audit import client_ip, log_action
from backend.database.connection import get_db
from backend.database.models import (
    Alert,
    Incident,
    IncidentAlertLink,
    IncidentComment,
)
from backend.security import actor_name, require_admin, require_auth, tenant_scope

logger = logging.getLogger("baraq.api.incidents")

router = APIRouter(
    prefix="/api/incidents",
    tags=["incidents"],
    dependencies=[Depends(require_auth)],
)


class IncidentStatus(str, Enum):
    open = "open"
    investigating = "investigating"
    contained = "contained"
    resolved = "resolved"
    closed = "closed"


class IncidentSeverity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=256)
    description: str = Field(default="", max_length=5000)
    severity: IncidentSeverity = IncidentSeverity.high
    owner: str = Field(default="", max_length=128)
    host: str = Field(default="", max_length=128)
    alert_ids: list[int] = Field(default_factory=list)
    mitre_id: str = Field(default="", max_length=16)
    mitre_name: str = Field(default="", max_length=128)


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=256)
    description: str | None = Field(default=None, max_length=5000)
    severity: IncidentSeverity | None = None
    status: IncidentStatus | None = None
    owner: str | None = Field(default=None, max_length=128)
    host: str | None = Field(default=None, max_length=128)


class IncidentCommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=4000)
    kind: str = Field(default="comment", pattern="^(comment|action|status)$")


class IncidentLinkAlerts(BaseModel):
    alert_ids: list[int] = Field(default_factory=list)


def _publish_incident(incident: Incident) -> None:
    """Push an incident update to realtime dashboard clients (best-effort)."""
    try:
        from backend.realtime import publish_incident

        publish_incident(incident.to_dict())
    except Exception:
        logger.debug(
            "Failed to publish incident #%s over realtime", incident.id, exc_info=True
        )


def _with_links(stmt):
    """Eager-load alert links (with their alert) and comments in one pass."""
    return stmt.options(
        selectinload(Incident.alerts).selectinload(IncidentAlertLink.alert),
        selectinload(Incident.comments),
    )


@router.get("")
def list_incidents(
    request: Request,
    status: IncidentStatus | None = None,
    severity: IncidentSeverity | None = None,
    limit: int = Query(50, ge=1, le=200),
    include_demo: int = Query(0, ge=0, le=1),
    db: Session = Depends(get_db),
):
    scope = tenant_scope(request)
    stmt = _with_links(
        select(Incident).order_by(Incident.created_at.desc()).limit(limit)
    )
    if scope is not None:
        stmt = stmt.where(Incident.org == scope)
    if not include_demo:
        stmt = stmt.where(Incident.demo.is_(False))
    if status:
        stmt = stmt.where(Incident.status == status.value)
    if severity:
        stmt = stmt.where(Incident.severity == severity.value)
    rows = db.scalars(stmt).all()
    return {"items": [i.to_dict() for i in rows]}


# P1-13: first-response SLA targets per severity (minutes). The same ladder
# drives the Dashboard's aging panel, so the numbers never diverge.
SLA_MINUTES = {"critical": 15, "high": 60, "medium": 120, "low": 240}
ACTIVE_STATUSES = ("open", "acknowledged", "investigating", "contained")


@router.get("/workload")
def workload(request: Request, db: Session = Depends(get_db)):
    """Analyst workload + SLA posture for open cases (backend-computed).

    Per-owner open/overdue counts, per-severity SLA buckets (within /
    overdue), aging bands and first-response time statistics derived from
    the incident ``responded_at`` clock.
    """
    scope = tenant_scope(request)
    stmt = _with_links(select(Incident).order_by(Incident.created_at.desc()))
    if scope is not None:
        stmt = stmt.where(Incident.org == scope)
    rows = db.scalars(stmt).all()

    now = datetime.now(UTC)
    active = [i for i in rows if i.status in ACTIVE_STATUSES and not i.demo]

    owners: dict[str, dict] = {}
    sla: dict[str, dict] = {
        sev: {"open": 0, "within": 0, "overdue": 0} for sev in SLA_MINUTES
    }
    aging = {"0-15": 0, "15-60": 0, "60-240": 0, "240+": 0}

    for incident in active:
        owner = incident.owner or "unassigned"
        bucket = owners.setdefault(owner, {"owner": owner, "open": 0, "overdue": 0})
        bucket["open"] += 1
        anchor = incident.created_at or incident.opened_at
        age_minutes = (now - anchor).total_seconds() / 60 if anchor else 0.0
        if age_minutes <= 15:
            aging["0-15"] += 1
        elif age_minutes <= 60:
            aging["15-60"] += 1
        elif age_minutes <= 240:
            aging["60-240"] += 1
        else:
            aging["240+"] += 1
        sev = incident.severity if incident.severity in SLA_MINUTES else "high"
        bucket_sla = sla[sev]
        bucket_sla["open"] += 1
        if age_minutes > SLA_MINUTES[sev]:
            bucket_sla["overdue"] += 1
            bucket["overdue"] += 1
        else:
            bucket_sla["within"] += 1

    # First-response times (minutes) for every engaged case.
    response_times = []
    for incident in rows:
        anchor = incident.created_at or incident.opened_at
        if incident.responded_at and anchor:
            delta = (incident.responded_at - anchor).total_seconds() / 60
            if delta >= 0:
                response_times.append(delta)

    response_stats = {
        "count": 0,
        "avg_minutes": None,
        "median_minutes": None,
        "p95_minutes": None,
    }
    if response_times:
        ordered = sorted(response_times)
        n = len(ordered)
        response_stats = {
            "count": n,
            "avg_minutes": round(sum(ordered) / n, 1),
            "median_minutes": round(ordered[n // 2], 1),
            "p95_minutes": round(ordered[min(n - 1, int(0.95 * n))], 1),
        }

    return {
        "active_total": len(active),
        "unassigned": owners.get("unassigned", {}).get("open", 0),
        "owners": sorted(owners.values(), key=lambda o: -o["open"]),
        "sla": sla,
        "aging": aging,
        "response": response_stats,
    }


@router.get("/stats")
def incidents_stats_alias(
    request: Request,
    db: Session = Depends(get_db),
):
    """Alias for /incidents/workload (frontend compat)."""
    return workload(request=request, db=db)


@router.get("/{incident_id}")
def get_incident(incident_id: int, request: Request, db: Session = Depends(get_db)):
    scope = tenant_scope(request)
    stmt = _with_links(select(Incident)).where(Incident.id == incident_id)
    if scope is not None:
        stmt = stmt.where(Incident.org == scope)
    incident = db.scalars(stmt).first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident.to_dict(include_links=True)


@router.get("/{incident_id}/investigation")
def incident_investigation(
    incident_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    """Phase-1 investigation enrichment for an incident.

    Aggregates everything the analyst needs from the incident's linked
    alerts: evidence events, files / processes / network / registry
    entities, the who-what-when-where-how-why summary, the process tree
    and a full-confidence recomputation with factor breakdown.
    """
    scope = tenant_scope(request)
    stmt = _with_links(select(Incident)).where(Incident.id == incident_id)
    if scope is not None:
        stmt = stmt.where(Incident.org == scope)
    incident = db.scalars(stmt).first()
    if not incident:
        raise HTTPException(404, "Incident not found")

    from backend.investigation.confidence import incident_confidence
    from backend.investigation.enrichment import enrich_incident

    enrichment = enrich_incident(db, incident)
    confidence = incident_confidence(db, incident, enrichment=enrichment)
    return {
        "incident_id": incident.id,
        "ref": f"INC-{incident.id:04d}",
        "title": incident.title,
        "confidence": confidence,
        "enrichment": enrichment,
    }


@router.post("", dependencies=[Depends(require_admin)])
def create_incident(
    body: IncidentCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    actor = actor_name(request)
    incident = Incident(
        title=body.title,
        description=body.description,
        severity=body.severity.value,
        owner=body.owner,
        host=body.host,
        org="",
        mitre_id=body.mitre_id,
        mitre_name=body.mitre_name,
        opened_at=datetime.now(UTC),
    )
    db.add(incident)
    db.flush()

    for alert_id in body.alert_ids:
        scope = tenant_scope(request)
        stmt = select(Alert).where(Alert.id == alert_id)
        if scope is not None:
            stmt = stmt.where(Alert.org == scope)
        alert = db.scalars(stmt).first()
        if alert:
            db.add(IncidentAlertLink(incident_id=incident.id, alert_id=alert_id))
            incident.org = alert.org or incident.org

    db.add(
        IncidentComment(
            incident_id=incident.id,
            author=actor,
            body=f"Incident created by {actor}",
            kind="status",
        )
    )

    linked_alerts = []
    scope = tenant_scope(request)
    for a in body.alert_ids:
        stmt = select(Alert).where(Alert.id == a)
        if scope is not None:
            stmt = stmt.where(Alert.org == scope)
        alert_row = db.scalars(stmt).first()
        if alert_row:
            linked_alerts.append(alert_row)
    max_risk = (
        max((a.risk_score or 0.0) for a in linked_alerts if a) if linked_alerts else 0.0
    )
    incident.risk_score = max_risk
    incident.risk_level = (
        "CRITICAL" if max_risk >= 80 else "HIGH" if max_risk >= 60 else "MEDIUM"
    )

    db.commit()
    db.refresh(incident)
    log_action(
        db,
        actor,
        "incident.create",
        "incident",
        str(incident.id),
        f"Created incident '{body.title}'",
        client_ip(request),
    )
    _publish_incident(incident)
    return incident.to_dict(include_links=True)


@router.patch("/{incident_id}", dependencies=[Depends(require_admin)])
def update_incident(
    incident_id: int,
    body: IncidentUpdate,
    request: Request,
    db: Session = Depends(get_db),
):
    scope = tenant_scope(request)
    stmt = select(Incident).where(Incident.id == incident_id)
    if scope is not None:
        stmt = stmt.where(Incident.org == scope)
    incident = db.scalars(stmt).first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    actor = actor_name(request)
    changes: list[str] = []

    # Original values: the SLA checks below must compare against what the
    # record looked like BEFORE this request - the generic field loop would
    # otherwise mutate e.g. ``owner`` first and make "owner changed" false.
    prev_owner = incident.owner

    for field, value in body.model_dump(exclude_unset=True).items():
        if value is None:
            continue
        if isinstance(value, Enum):
            value = value.value
        if getattr(incident, field) != value:
            changes.append(f"{field}->{value}")
            setattr(incident, field, value)

    if body.status is not None:
        now = datetime.now(UTC)
        if body.status.value in ("resolved", "closed") and not incident.resolved_at:
            incident.resolved_at = now
        if body.status.value == "closed" and not incident.closed_at:
            incident.closed_at = now
        if body.status.value in ("open", "investigating", "contained"):
            incident.closed_at = None
        # First-response SLA clock: the moment an analyst engages the case.
        if (
            body.status.value in ("investigating", "contained", "resolved", "closed")
            and incident.responded_at is None
        ):
            incident.responded_at = now
            changes.append("responded_at->set")

    # Assigning an owner also counts as a first response (the case is engaged).
    if body.owner and body.owner != prev_owner and incident.responded_at is None:
        incident.responded_at = datetime.now(UTC)
        changes.append("responded_at->set")

    if changes:
        db.add(
            IncidentComment(
                incident_id=incident.id,
                author=actor,
                body=", ".join(changes),
                kind="status",
            )
        )
        db.commit()
        db.refresh(incident)
        log_action(
            db,
            actor,
            "incident.update",
            "incident",
            str(incident.id),
            "Updated: " + "; ".join(changes),
            client_ip(request),
        )
        _publish_incident(incident)
    return incident.to_dict(include_links=True)


@router.post("/{incident_id}/alerts", dependencies=[Depends(require_admin)])
def link_alerts(
    incident_id: int,
    body: IncidentLinkAlerts,
    request: Request,
    db: Session = Depends(get_db),
):
    scope = tenant_scope(request)
    stmt = select(Incident).where(Incident.id == incident_id)
    if scope is not None:
        stmt = stmt.where(Incident.org == scope)
    incident = db.scalars(stmt).first()
    if not incident:
        raise HTTPException(404, "Incident not found")

    linked: list[int] = []
    existing = {l.alert_id for l in incident.alerts}
    for alert_id in body.alert_ids:
        if alert_id in existing:
            continue
        stmt = select(Alert).where(Alert.id == alert_id)
        if scope is not None:
            stmt = stmt.where(Alert.org == scope)
        alert = db.scalars(stmt).first()
        if not alert:
            raise HTTPException(404, f"Alert {alert_id} not found")
        db.add(IncidentAlertLink(incident_id=incident_id, alert_id=alert_id))
        if not incident.org:
            incident.org = alert.org
        linked.append(alert_id)

    actor = actor_name(request)
    if linked:
        db.add(
            IncidentComment(
                incident_id=incident_id,
                author=actor,
                body=f"Linked alerts: {', '.join(map(str, linked))}",
                kind="action",
            )
        )
        db.commit()
        db.refresh(incident)
        log_action(
            db,
            actor,
            "incident.link_alerts",
            "incident",
            str(incident_id),
            f"Linked alerts {linked}",
            client_ip(request),
        )
        _publish_incident(incident)
    return incident.to_dict(include_links=True)


@router.post("/{incident_id}/comments")
def add_comment(
    incident_id: int,
    body: IncidentCommentCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    scope = tenant_scope(request)
    stmt = select(Incident).where(Incident.id == incident_id)
    if scope is not None:
        stmt = stmt.where(Incident.org == scope)
    incident = db.scalars(stmt).first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    comment = IncidentComment(
        incident_id=incident_id,
        author=actor_name(request),
        body=body.body,
        kind=body.kind,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment.to_dict()
