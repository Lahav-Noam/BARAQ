"""SOAR automation playbooks API.

Analysts manage playbooks (trigger conditions -> ordered actions) and the
detection pipeline fires them automatically against matching new alerts.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.audit import client_ip, log_action
from backend.automation.playbooks import (
    find_matching_playbooks,
    run_playbook,
    validate_playbook,
)
from backend.database.connection import get_db
from backend.database.models import Alert, AutomationPlaybook, PlaybookRun
from backend.security import actor_name, require_admin, require_auth, tenant_scope

router = APIRouter(
    prefix="/api/automation",
    tags=["automation"],
    dependencies=[Depends(require_auth)],
)


class PlaybookCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field("", max_length=2000)
    enabled: bool = True
    triggers: dict = Field(default_factory=dict)
    actions: list = Field(..., min_length=1)


class PlaybookUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    description: str | None = Field(None, max_length=2000)
    enabled: bool | None = None
    triggers: dict | None = None
    actions: list | None = None


def _get_playbook(db: Session, playbook_id: int) -> AutomationPlaybook:
    playbook = db.get(AutomationPlaybook, playbook_id)
    if playbook is None:
        raise HTTPException(404, "playbook not found")
    return playbook


@router.get("/playbooks")
def list_playbooks(db: Session = Depends(get_db)):
    """All automation playbooks, enabled first."""
    rows = db.scalars(
        select(AutomationPlaybook).order_by(
            AutomationPlaybook.enabled.desc(), AutomationPlaybook.id
        )
    ).all()
    return {"total": len(rows), "playbooks": [p.to_dict() for p in rows]}


@router.post("/playbooks", dependencies=[Depends(require_admin)])
def create_playbook(
    body: PlaybookCreate, request: Request, db: Session = Depends(get_db)
):
    """Create a playbook (admin). Validates triggers and actions."""
    try:
        triggers, actions = validate_playbook(body.triggers, body.actions)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    existing = db.scalars(
        select(AutomationPlaybook).where(AutomationPlaybook.name == body.name)
    ).first()
    if existing:
        raise HTTPException(409, f"playbook '{body.name}' already exists")
    playbook = AutomationPlaybook(
        name=body.name.strip(),
        description=body.description,
        enabled=body.enabled,
        triggers=triggers,
        actions=actions,
    )
    db.add(playbook)
    db.commit()
    log_action(
        db,
        actor_name(request),
        "playbook.create",
        "playbook",
        str(playbook.id),
        f"Created playbook '{playbook.name}' ({len(actions)} action(s), "
        f"enabled={body.enabled})",
        client_ip(request),
    )
    return playbook.to_dict()


@router.patch("/playbooks/{playbook_id}", dependencies=[Depends(require_admin)])
def update_playbook(
    playbook_id: int,
    body: PlaybookUpdate,
    request: Request,
    db: Session = Depends(get_db),
):
    """Update any field of a playbook (admin)."""
    playbook = _get_playbook(db, playbook_id)
    before = {k: str(playbook.to_dict().get(k))[:120] for k in ("name", "enabled")}
    updates = body.model_dump(exclude_none=True)
    if body.name is not None:
        updates["name"] = body.name.strip()
    if body.triggers is not None or body.actions is not None:
        try:
            triggers, actions = validate_playbook(
                updates.get("triggers", playbook.triggers or {}),
                updates.get("actions", playbook.actions or []),
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        updates["triggers"] = triggers
        updates["actions"] = actions
    for key, value in updates.items():
        setattr(playbook, key, value)
    db.commit()
    changed = [
        f"{k}: {before.get(k, '')} -> {str(playbook.to_dict().get(k))[:120]}"
        for k in updates
        if k in ("name", "enabled")
    ]
    if "triggers" in updates or "actions" in updates:
        changed.append(f"logic: {len(playbook.actions or [])} action(s)")
    log_action(
        db,
        actor_name(request),
        "playbook.update",
        "playbook",
        str(playbook.id),
        f"Updated '{playbook.name}': " + "; ".join(changed),
        client_ip(request),
    )
    return playbook.to_dict()


@router.delete("/playbooks/{playbook_id}", dependencies=[Depends(require_admin)])
def delete_playbook(playbook_id: int, request: Request, db: Session = Depends(get_db)):
    """Delete a playbook and its run history (admin)."""
    playbook = _get_playbook(db, playbook_id)
    name = playbook.name
    db.delete(playbook)
    db.commit()
    log_action(
        db,
        actor_name(request),
        "playbook.delete",
        "playbook",
        str(playbook_id),
        f"Deleted playbook '{name}'",
        client_ip(request),
    )
    return {"deleted": True, "id": playbook_id}


@router.post("/playbooks/{playbook_id}/test", dependencies=[Depends(require_admin)])
def test_playbook(
    playbook_id: int,
    request: Request,
    alert_id: int = Query(..., description="alert to run the playbook against"),
    db: Session = Depends(get_db),
):
    """Dry-run a playbook against an existing alert without persisting."""
    playbook = _get_playbook(db, playbook_id)
    scope = tenant_scope(request)
    stmt = select(Alert).where(Alert.id == alert_id)
    if scope is not None:
        stmt = stmt.where(Alert.org == scope)
    alert = db.scalars(stmt).first()
    if alert is None:
        raise HTTPException(404, "alert not found")
    from backend.automation.playbooks import matches

    matched = matches(alert, playbook.triggers or {})
    log_action(
        db,
        actor_name(request),
        "playbook.test",
        "playbook",
        str(playbook.id),
        f"Dry-run '{playbook.name}' against alert #{alert_id} ({alert.name}) -> "
        f"{'matched' if matched else 'no match'}",
        client_ip(request),
    )
    return {
        "matched": matched,
        "playbook": playbook.name,
        "alert": alert.name,
        "rule": alert.rule,
    }


@router.post("/playbooks/{playbook_id}/run", dependencies=[Depends(require_admin)])
def run_playbook_now(
    playbook_id: int,
    request: Request,
    alert_id: int = Query(..., description="alert to run the playbook against"),
    db: Session = Depends(get_db),
):
    """Manually execute a playbook against an alert and log the run."""
    playbook = _get_playbook(db, playbook_id)
    scope = tenant_scope(request)
    stmt = select(Alert).where(Alert.id == alert_id)
    if scope is not None:
        stmt = stmt.where(Alert.org == scope)
    alert = db.scalars(stmt).first()
    if alert is None:
        raise HTTPException(404, "alert not found")
    run = run_playbook(db, playbook, alert, triggered_by="manual")
    db.commit()
    log_action(
        db,
        actor_name(request),
        "playbook.run",
        "playbook",
        str(playbook.id),
        f"Manual run of '{playbook.name}' against alert #{alert_id} ({alert.name}) "
        f"-> {run.status}",
        client_ip(request),
    )
    return run.to_dict()


@router.get("/runs")
def list_runs(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    playbook_id: int | None = None,
    alert_id: int | None = None,
    db: Session = Depends(get_db),
):
    """Execution log of automation playbook runs (newest first).

    Tenant-scoped: runs record the alert's org, so an analyst only ever sees
    their own organization's automation history.
    """
    org = tenant_scope(request)
    stmt = select(PlaybookRun).order_by(PlaybookRun.created_at.desc())
    if org is not None:
        stmt = stmt.where(PlaybookRun.org == org)
    if playbook_id:
        stmt = stmt.where(PlaybookRun.playbook_id == playbook_id)
    if alert_id:
        stmt = stmt.where(PlaybookRun.alert_id == alert_id)
    runs = db.scalars(stmt.limit(limit)).all()
    return {"total": len(runs), "runs": [r.to_dict() for r in runs]}


@router.get("/runs/{run_id}")
def get_run(
    request: Request,
    run_id: int,
    db: Session = Depends(get_db),
):
    """Full detail for one automation run, for the drill-down view.

    Returns the run, the alert it fired on (so the UI can link straight to the
    investigation), the playbook definition with its triggers, and the
    org-scoped audit trail for the same event.
    """
    run = db.get(PlaybookRun, run_id)
    if run is None:
        raise HTTPException(404, "run not found")
    org = tenant_scope(request)
    if org is not None and (run.org or "") != org:
        raise HTTPException(404, "run not found")

    playbook = db.get(AutomationPlaybook, run.playbook_id)
    alert = db.get(Alert, run.alert_id) if run.alert_id else None

    # Org-scope the related objects too
    org = tenant_scope(request)
    if org is not None:
        if playbook is not None and getattr(playbook, "org", None) not in (None, "", org):
            playbook = None
        if alert is not None and getattr(alert, "org", None) not in (None, "", org):
            alert = None

    return {
        "run": run.to_dict(),
        "playbook": playbook.to_dict() if playbook else None,
        "alert": alert.to_dict() if alert else None,
        "actions_total": len(run.results or []),
        "actions_failed": sum(
            1 for r in (run.results or []) if str(r.get("status")) == "failed"
        ),
    }


@router.get("/preview")
def preview_match(
    request: Request,
    alert_id: int = Query(...),
    db: Session = Depends(get_db),
):
    """Which enabled playbooks would fire for a given alert?"""
    scope = tenant_scope(request)
    stmt = select(Alert).where(Alert.id == alert_id)
    if scope is not None:
        stmt = stmt.where(Alert.org == scope)
    alert = db.scalars(stmt).first()
    if alert is None:
        raise HTTPException(404, "alert not found")
    matching = find_matching_playbooks(db, alert)
    return {
        "alert_id": alert_id,
        "matching": [p.to_dict() for p in matching],
    }
