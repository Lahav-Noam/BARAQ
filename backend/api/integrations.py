"""Ticketing integrations API (roadmap 6.3)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.audit import client_ip, log_action
from backend.database.connection import get_db
from backend.database.models import Alert
from backend.integrations import dispatch_alert, integration_status
from backend.security import actor_name, require_admin, require_auth, tenant_scope

router = APIRouter(
    prefix="/api/integrations",
    tags=["integrations"],
    dependencies=[Depends(require_auth)],
)


@router.get("/status")
def status():
    """Health of the ticketing integrations (Jira / ServiceNow)."""
    return integration_status()


@router.post("/dispatch/{alert_id}", dependencies=[Depends(require_admin)])
def dispatch(alert_id: int, request: Request, db: Session = Depends(get_db)):
    """Push one alert to the configured ticketing systems."""
    scope = tenant_scope(request)
    stmt = select(Alert).where(Alert.id == alert_id)
    if scope is not None:
        stmt = stmt.where(Alert.org == scope)
    alert = db.scalars(stmt).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    result = dispatch_alert(db, alert)
    log_action(
        db,
        actor_name(request),
        "integration.dispatch",
        "alert",
        str(alert_id),
        str(result.get("results", [])),
        client_ip(request),
    )
    return {"alert_id": alert_id, **result}
