"""Threat-intel API: enrich indicators on demand or from an alert's evidence."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.audit import client_ip, log_action
from backend.database.connection import get_db
from backend.database.models import Alert
from backend.security import actor_name, require_admin, require_auth, tenant_scope
from backend.threatintel.service import enrich_alert, lookup_indicator

logger = logging.getLogger("baraq.api.threatintel")

router = APIRouter(
    prefix="/api/intel",
    tags=["threat-intel"],
    dependencies=[Depends(require_auth)],
)


class IntelLookup(BaseModel):
    indicator: str = Field(min_length=1, max_length=256)


class IntelMatch(BaseModel):
    text: str = Field(min_length=1, max_length=8192)


@router.get("/feeds")
def list_feeds(db: Session = Depends(get_db)):
    """List configured threat-intel feed subscriptions + last-run state."""
    from backend.intel.feeds import feed_states

    return {"feeds": feed_states(db)}


@router.post("/feeds/refresh", dependencies=[Depends(require_admin)])
def refresh_feeds(request: Request, db: Session = Depends(get_db)):
    """Run the threat-intel feed ingestion once (synchronous)."""
    from backend.intel.feeds import refresh_feeds as run_refresh

    summary = run_refresh(db)
    log_action(
        db,
        actor_name(request),
        "intel.refresh",
        "feeds",
        "all",
        f"Threat-intel feed refresh: {len(summary['feeds'])} feed(s)",
        client_ip(request),
    )
    return summary


@router.post("/match")
def match_iocs(body: IntelMatch, db: Session = Depends(get_db)):
    """Match free text against known-bad indicators in the intel cache."""
    from backend.intel.feeds import match_text

    return {"matches": match_text(db, body.text)}


@router.post("/lookup")
def intel_lookup(
    body: IntelLookup,
    refresh: bool = Query(False),
    db: Session = Depends(get_db),
):
    """Look up a single indicator (IP / domain / hash)."""
    return lookup_indicator(db, body.indicator, refresh=refresh)


@router.get("/alert/{alert_id}")
def alert_intel(
    alert_id: int,
    request: Request,
    refresh: bool = Query(False),
    db: Session = Depends(get_db),
):
    """Enrich all indicators found in an alert's evidence."""
    scope = tenant_scope(request)
    stmt = select(Alert).where(Alert.id == alert_id)
    if scope is not None:
        stmt = stmt.where(Alert.org == scope)
    alert = db.scalars(stmt).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    items = enrich_alert(db, alert, refresh=refresh)
    actors: list[dict] = []
    try:
        from backend.graph import get_graph_store
        from backend.graph.actors import upsert_actors

        actors = upsert_actors(db, get_graph_store(), items)
    except Exception as exc:
        logger.warning(
            "Threat-actor attribution failed for alert %s: %s", alert_id, exc
        )
    return {
        "alert_id": alert_id,
        "alert_name": alert.name,
        "items": items,
        "actors": actors,
    }


@router.post("/save")
def save_verdict(
    body: IntelLookup,
    request: Request,
    db: Session = Depends(get_db),
):
    """Persist an analyst manual verdict override for an indicator.

    Accepted categories: malicious / suspicious / benign / unknown.
    The override is stored in the cache record so future lookups return it
    immediately (authoritative analyst input wins over provider feeds).
    """
    from backend.database.models import ThreatIntelRecord
    from backend.threatintel import _DOMAIN_RE, _IPV4_RE

    indicator = body.indicator.strip().lower()
    kind = (
        "ip"
        if _IPV4_RE.match(indicator)
        else "domain" if _DOMAIN_RE.match(indicator) else "hash"
    )
    row = (
        db.query(ThreatIntelRecord)
        .filter(ThreatIntelRecord.indicator == indicator)
        .one_or_none()
    )
    if row is None:
        row = ThreatIntelRecord(indicator=indicator, kind=kind)
        db.add(row)
    row.kind = kind
    row.category = "malicious"
    row.label = "Analyst-marked indicator"
    row.confidence = 1.0
    row.sources = (row.sources or []) + ["analyst"]
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor_name(request),
        "intel.save",
        "indicator",
        indicator,
        "Analyst marked indicator malicious",
        client_ip(request),
    )
    return row.to_dict()
