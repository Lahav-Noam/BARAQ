"""Multi-endpoint ingest + fleet status + remote agent control API.

Remote BARAQ agents POST collected telemetry to :func:`ingest`, which
attributes every record to the reporting host and pushes it through the
standard pipeline. Endpoint rows track per-host volume and last-seen so the
dashboard can show an endpoint fleet at a glance.

The same channel carries remote agent control: analysts queue commands
(block_ip / kill_process / quarantine / escalate) for an agent; the agent
polls ``GET /api/commands/pending`` on its next cycle, executes them and
reports the outcome to ``POST /api/commands/{id}/result``.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import UTC, datetime
from enum import Enum

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.system import run_pipeline
from backend.audit import client_ip, log_action
from backend.config import AGENT_KEYS, agent_org
from backend.database.connection import get_db
from backend.database.models import AgentCommand, Endpoint, NormalizedEvent, Verdict
from backend.security import actor_name, require_admin, require_auth, tenant_scope

logger = logging.getLogger("baraq.api.endpoints")


def _safe_like(value: str) -> str:
    """Escape LIKE metacharacters to prevent pattern injection."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


router = APIRouter(
    prefix="/api",
    tags=["endpoints"],
)

AGENT_KEY_HEADER = "X-Agent-Key"

_VERSION_RE = re.compile(r"^\d{1,6}(\.\d{1,6}){0,3}(-[0-9A-Za-z][0-9A-Za-z._-]{0,31})?$")
_PROCESS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$")
_SHELL_META = set("'\"`$;|&<>\n\r\t*?()[]{}^%!")


def require_agent(
    x_agent_key: str | None = Header(default=None, alias=AGENT_KEY_HEADER),
) -> str:
    """Resolve the calling agent's id from the X-Agent-Key header."""
    agent_id = AGENT_KEYS.get((x_agent_key or "").strip())
    if not agent_id:
        raise HTTPException(401, "Missing or invalid agent key (X-Agent-Key header)")
    return agent_id


class IngestRequest(BaseModel):
    records: list[dict] = Field(..., min_length=1, max_length=2000)
    host: str = Field(default="", max_length=128)
    agent_id: str = Field(default="", max_length=64)
    #: Fleet metadata (roadmap 3.4) reported on every heartbeat/ingest.
    agent_version: str = Field(default="", max_length=32)
    os_info: str = Field(default="", max_length=128)
    tags: str = Field(default="", max_length=256)


def _validate_ingest_records(records: list[dict]) -> None:
    """Reject malformed agent records with a 400 before they reach the pipeline.

    The normalizer coerces ``event_id`` to int, so a non-numeric value would
    otherwise bubble up as an unhelpful 500.
    """
    for idx, record in enumerate(records):
        if not isinstance(record, dict):
            raise HTTPException(400, f"record[{idx}] must be an object")
        event_id = record.get("event_id", 0)
        if not isinstance(event_id, int) and not str(event_id).isdigit():
            raise HTTPException(
                400,
                f"record[{idx}].event_id must be numeric, got {event_id!r}",
            )
        if not str(record.get("source", "")).strip():
            raise HTTPException(400, f"record[{idx}] missing source")
        if not str(record.get("timestamp", "")).strip():
            raise HTTPException(400, f"record[{idx}] missing timestamp")


def _refresh_health(endpoint: Endpoint) -> None:
    """Recompute health_status from last_seen (ok/stale/offline)."""
    from backend.config import AGENT_OFFLINE_SECONDS, AGENT_STALE_SECONDS

    now = datetime.now(UTC)
    age = (
        (now - endpoint.last_seen).total_seconds()
        if endpoint.last_seen
        else float("inf")
    )
    if age <= AGENT_STALE_SECONDS:
        endpoint.health_status = "ok"
    elif age <= AGENT_OFFLINE_SECONDS:
        endpoint.health_status = "stale"
    else:
        endpoint.health_status = "offline"


@router.post("/ingest")
def ingest(
    body: IngestRequest,
    x_agent_key: str | None = Header(default=None, alias=AGENT_KEY_HEADER),
    db: Session = Depends(get_db),
):
    """Agent intake: validate key, tag host, run the full pipeline."""
    agent_id = AGENT_KEYS.get((x_agent_key or "").strip())
    if not agent_id:
        raise HTTPException(401, "Missing or invalid agent key (X-Agent-Key header)")

    _validate_ingest_records(body.records)
    host = (body.host or agent_id)[:128]
    org = agent_org(agent_id)
    for record in body.records:
        record["host"] = host

    try:
        from backend.config import INGEST_ASYNC_DETECT

        result = run_pipeline(db, body.records, org=org, detect=not INGEST_ASYNC_DETECT)
    except Exception as exc:
        logger.exception("Ingest from agent %s failed", agent_id)
        raise HTTPException(500, f"Ingest pipeline failed: {exc}")

    endpoint = db.get(Endpoint, agent_id)
    if endpoint is None:
        endpoint = Endpoint(
            agent_id=agent_id,
            host=host,
            org=org,
            records_total=0,
            events_total=0,
            alerts_total=0,
        )
        db.add(endpoint)
    endpoint.host = host
    endpoint.org = org
    endpoint.last_seen = datetime.now(UTC)
    endpoint.records_total += len(body.records)
    endpoint.events_total += result["saved_events"]
    endpoint.alerts_total += result["alerts_created"]
    if body.agent_version:
        endpoint.agent_version = body.agent_version
    if body.os_info:
        endpoint.os_info = body.os_info
    if body.tags:
        existing = {t for t in endpoint.tags.split(",") if t}
        existing.update(t for t in body.tags.split(",") if t)
        endpoint.tags = ",".join(sorted(existing))
    _refresh_health(endpoint)
    db.commit()

    logger.info(
        "Agent %s (%s) org=%s ingested %d records -> %d alerts",
        agent_id,
        host,
        org or "(system)",
        len(body.records),
        result["alerts_created"],
    )
    return {"agent_id": agent_id, "host": host, "org": org, **result}


@router.get("/endpoints", dependencies=[Depends(require_auth)])
def list_endpoints(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    tag: str | None = Query(None, max_length=64),
    health: str | None = Query(None, max_length=16),
    db: Session = Depends(get_db),
):
    scope = tenant_scope(request)
    stmt = select(Endpoint)
    if scope is not None:
        stmt = stmt.where(Endpoint.org == scope)
    if tag:
        stmt = stmt.where(Endpoint.tags.ilike(f"%{_safe_like(tag)}%"))
    rows = db.scalars(stmt.order_by(Endpoint.last_seen.desc()).limit(limit)).all()
    for ep in rows:
        _refresh_health(ep)
    if health:
        rows = [ep for ep in rows if ep.health_status == health]
    db.commit()
    return {"items": [ep.to_dict() for ep in rows], "total": len(rows)}


@router.get("/endpoints/overview", dependencies=[Depends(require_auth)])
def fleet_overview(request: Request, db: Session = Depends(get_db)):
    """Fleet dashboard: health buckets, org/tag breakdown, update posture."""
    from collections import Counter

    from backend.config import AGENT_STALE_SECONDS

    scope = tenant_scope(request)
    stmt = select(Endpoint)
    if scope is not None:
        stmt = stmt.where(Endpoint.org == scope)
    rows = db.scalars(stmt).all()
    for ep in rows:
        _refresh_health(ep)
    db.commit()

    health = Counter(ep.health_status for ep in rows)
    orgs = Counter(ep.org or "(system)" for ep in rows)
    versions = Counter(ep.agent_version or "unknown" for ep in rows)
    tag_counter: Counter[str] = Counter()
    for ep in rows:
        for t in (ep.tags or "").split(","):
            if t:
                tag_counter[t] += 1
    stale = [ep.agent_id for ep in rows if ep.health_status == "stale"]
    offline = [ep.agent_id for ep in rows if ep.health_status == "offline"]
    return {
        "total": len(rows),
        "health": dict(health),
        "by_org": dict(orgs),
        "by_version": dict(versions),
        "by_tag": dict(tag_counter),
        "stale_agents": stale,
        "offline_agents": offline,
        "stale_after_seconds": AGENT_STALE_SECONDS,
        "totals": {
            "records": sum(ep.records_total for ep in rows),
            "events": sum(ep.events_total for ep in rows),
            "alerts": sum(ep.alerts_total for ep in rows),
        },
    }


class TagUpdate(BaseModel):
    tags: str = Field("", max_length=256)


@router.post("/endpoints/{agent_id}/tags", dependencies=[Depends(require_admin)])
def set_agent_tags(
    agent_id: str,
    body: TagUpdate,
    request: Request,
    db: Session = Depends(get_db),
):
    """Set (replace) the tag group for one agent - drives fleet grouping."""
    scope = tenant_scope(request)
    stmt = select(Endpoint).where(Endpoint.agent_id == agent_id)
    if scope is not None:
        stmt = stmt.where(Endpoint.org == scope)
    endpoint = db.scalars(stmt).first()
    if endpoint is None:
        raise HTTPException(404, "Unknown agent - has it reported yet?")
    tags = ",".join(sorted({t for t in body.tags.split(",") if t}))
    endpoint.tags = tags
    db.commit()
    log_action(
        db,
        actor_name(request),
        "endpoint.tags",
        "agent",
        agent_id,
        f"tags -> {tags or '(none)'}",
        client_ip(request),
    )
    return endpoint.to_dict()


# ---------------------------------------------------------------------------
# Remote agent control
# ---------------------------------------------------------------------------


class CommandAction(str, Enum):
    block_ip = "block_ip"
    #: Undo for block_ip. Without this a false-positive containment is
    #: permanent - the firewall rule has no TTL and the agent had no way to
    #: remove it, so the analyst had to RDP in and run netsh by hand.
    unblock_ip = "unblock_ip"
    kill_process = "kill_process"
    quarantine = "quarantine"
    isolate = "isolate"
    disable_account = "disable_account"
    escalate = "escalate"
    #: Fleet auto-update (roadmap 3.4): target = version to install.
    update_agent = "update_agent"


class CommandCreate(BaseModel):
    action: CommandAction
    target: str = Field("", max_length=256)
    note: str = Field("", max_length=500)
    sha256: str = Field("", max_length=64, pattern=r"^[0-9A-Fa-f]{64}$")


class CommandResult(BaseModel):
    status: str = Field("success", pattern="^(success|failed)$")
    detail: str = Field("", max_length=2000)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _validate_target(action: str, target: str) -> str:
    """Validate a command target before it is stored and sent to an agent."""
    target = (target or "").strip()
    if action == "escalate":
        return target
    if not target:
        raise HTTPException(422, f"{action} requires a target")
    if action in ("block_ip", "unblock_ip"):
        try:
            return str(ipaddress.ip_address(target))
        except ValueError:
            raise HTTPException(422, f"{action} requires a valid IP address") from None
    if action == "kill_process":
        if not _PROCESS_RE.match(target):
            raise HTTPException(422, "kill_process target must be a process name or PID")
        return target
    if action == "quarantine":
        if len(target) > 400 or _SHELL_META & set(target):
            raise HTTPException(422, "quarantine target contains forbidden characters")
        if not re.match(r"^([A-Za-z]:[\\/]|\\\\|/)", target):
            raise HTTPException(422, "quarantine target must be an absolute path")
        if ".." in re.split(r"[\\/]+", target):
            raise HTTPException(422, "quarantine target must not traverse directories")
        return target
    if action == "isolate":
        if not (_HOSTNAME_RE.match(target) or _is_ip(target)):
            raise HTTPException(422, "isolate target must be a hostname or IP address")
        return target
    if action == "disable_account":
        if not _ACCOUNT_RE.match(target):
            raise HTTPException(422, "disable_account target must be an account name")
        return target
    if action == "update_agent":
        if not _VERSION_RE.match(target):
            raise HTTPException(422, "update_agent target must be a version, e.g. 2.1.0")
        return target
    raise HTTPException(422, f"unsupported action: {action}")


def _apply_command_side_effects(db: Session, command: AgentCommand) -> None:
    """Fleet bookkeeping when an agent command is created/resolved.

    ``update_agent`` flips the endpoint's update_status so the fleet view
    shows the rollout; ``report_result`` clears it on success.
    """
    endpoint = db.get(Endpoint, command.agent_id)
    if endpoint is None:
        return
    if command.action == "update_agent":
        endpoint.update_status = {
            "pending": "pending",
            "success": "current",
            "failed": "failed",
        }.get(command.status, "pending")
    if command.status == "failed":
        endpoint.errors_total = (endpoint.errors_total or 0) + 1
    db.commit()


@router.post("/endpoints/{agent_id}/commands", dependencies=[Depends(require_admin)])
def queue_command(
    agent_id: str,
    body: CommandCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    scope = tenant_scope(request)
    stmt = select(Endpoint).where(Endpoint.agent_id == agent_id)
    if scope is not None:
        stmt = stmt.where(Endpoint.org == scope)
    if not db.scalars(stmt).first():
        raise HTTPException(404, "Unknown agent - has it reported yet?")
    target = _validate_target(body.action.value, body.target)
    command = AgentCommand(
        agent_id=agent_id,
        action=body.action.value,
        target=target,
        sha256=body.sha256.lower(),
        status="pending",
        detail=body.note,
    )
    db.add(command)
    db.commit()
    _apply_command_side_effects(db, command)
    log_action(
        db,
        actor_name(request),
        "command.queue",
        "agent",
        agent_id,
        f"{body.action.value} {target} -> command #{command.id}",
        client_ip(request),
    )
    logger.info(
        "Queued %s %s for agent %s (command #%s)",
        body.action.value,
        target,
        agent_id,
        command.id,
    )
    return command.to_dict()


@router.get("/endpoints/{agent_id}/commands", dependencies=[Depends(require_auth)])
def list_agent_commands(
    agent_id: str,
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    scope = tenant_scope(request)
    if scope is not None and not db.scalar(
        select(Endpoint).where(Endpoint.agent_id == agent_id, Endpoint.org == scope)
    ):
        raise HTTPException(404, "Unknown agent")
    rows = db.scalars(
        select(AgentCommand)
        .where(AgentCommand.agent_id == agent_id)
        .order_by(AgentCommand.created_at.desc())
        .limit(limit)
    ).all()
    return {"agent_id": agent_id, "items": [c.to_dict() for c in rows]}


@router.get("/commands", dependencies=[Depends(require_auth)])
def list_commands(
    request: Request,
    status: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    stmt = select(AgentCommand)
    scope = tenant_scope(request)
    if scope is not None:
        stmt = stmt.where(
            AgentCommand.agent_id.in_(
                select(Endpoint.agent_id).where(Endpoint.org == scope)
            )
        )
    if status:
        stmt = stmt.where(AgentCommand.status == status)
    stmt = stmt.order_by(AgentCommand.created_at.desc()).limit(limit)
    rows = db.scalars(stmt).all()
    return {"items": [c.to_dict() for c in rows]}


@router.get("/commands/pending", dependencies=[Depends(require_agent)])
def pending_commands(
    agent_id: str = Depends(require_agent), db: Session = Depends(get_db)
):
    rows = db.scalars(
        select(AgentCommand)
        .where(AgentCommand.agent_id == agent_id, AgentCommand.status == "pending")
        .order_by(AgentCommand.created_at.asc())
        .limit(20)
    ).all()
    return {"items": [c.to_dict() for c in rows]}


@router.post("/commands/{command_id}/result", dependencies=[Depends(require_agent)])
def report_result(
    command_id: int,
    body: CommandResult,
    agent_id: str = Depends(require_agent),
    db: Session = Depends(get_db),
):
    command = db.get(AgentCommand, command_id)
    if not command or command.agent_id != agent_id:
        raise HTTPException(404, "Command not found for this agent")
    if command.status != "pending":
        return command.to_dict()
    command.status = body.status
    command.detail = body.detail
    command.executed_at = datetime.now(UTC)
    db.commit()
    _apply_command_side_effects(db, command)
    logger.info(
        "Agent %s executed command #%s -> %s", agent_id, command_id, body.status
    )
    return command.to_dict()


# =====================================================================
# Analyst feedback loop (ML ground truth)
# =====================================================================


class VerdictCreate(BaseModel):
    event_id: int = Field(..., ge=1)
    verdict: str = Field(...)  # true_positive | false_positive
    note: str = Field(default="", max_length=500)


@router.post("/ml/verdicts", dependencies=[Depends(require_admin)])
def record_verdict(
    body: VerdictCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    """Store an analyst verdict on a scored event (feedback ground truth).

    Upserts - a second verdict on the same event overwrites the first. The
    verdict becomes the authoritative training label for that event.
    """
    if body.verdict not in ("true_positive", "false_positive"):
        raise HTTPException(422, "verdict must be true_positive | false_positive")
    scope = tenant_scope(request)
    stmt = select(NormalizedEvent).where(NormalizedEvent.id == body.event_id)
    if scope is not None:
        stmt = stmt.where(NormalizedEvent.org == scope)
    event = db.scalars(stmt).first()
    if event is None:
        raise HTTPException(404, "No such event")
    row = db.scalars(select(Verdict).where(Verdict.event_id == body.event_id)).first()
    if row is None:
        row = Verdict(
            event_id=body.event_id,
            verdict=body.verdict,
            note=body.note,
            created_by=actor_name(request),
        )
        db.add(row)
    else:
        row.verdict = body.verdict
        row.note = body.note or row.note
    db.commit()
    # Roadmap 4.1 - online learning: fold the verdict into the live detector
    # (damp/boost the per-behavior anomaly score) immediately.
    try:
        from backend.ml.anomaly import _behavior_of, event_feature_vector, get_detector

        detector = get_detector()
        behavior = _behavior_of(event.event_id)
        detector.apply_feedback(body.verdict, behavior)
        # Also record in the online learner's buffer for incremental retraining
        if detector.online_learner is not None:
            try:
                features = event_feature_vector(event)
                if features:
                    detector.online_learner.record_verdict(
                        behavior,
                        features,
                        body.verdict == "true_positive",
                        event_id=event.id,
                    )
            except Exception:
                logger.debug("online learner verdict record failed", exc_info=True)
    except Exception:
        logger.debug("ML feedback fold-in failed", exc_info=True)
    log_action(
        db,
        actor_name(request),
        "verdict.record",
        "event",
        str(body.event_id),
        f"{body.verdict} - {body.note or 'no note'}",
        client_ip(request),
    )
    return row.to_dict()


@router.get("/verdicts", dependencies=[Depends(require_auth)])
def list_verdicts(
    verdict: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    """List analyst verdicts (optionally filtered to one class)."""
    from backend.audit import client_ip  # noqa: F401  (unused helper guard)

    stmt = select(Verdict).order_by(Verdict.created_at.desc()).limit(limit)
    if verdict:
        stmt = (
            select(Verdict)
            .where(Verdict.verdict == verdict)
            .order_by(Verdict.created_at.desc())
            .limit(limit)
        )
    rows = db.scalars(stmt).all()
    event_ids = [v.event_id for v in rows]
    events = (
        {
            e.id: e
            for e in db.scalars(
                select(NormalizedEvent).where(NormalizedEvent.id.in_(event_ids))
            )
        }
        if event_ids
        else {}
    )
    items = []
    for v in rows:
        item = v.to_dict()
        ev = events.get(v.event_id)
        item["event_id"] = v.event_id
        item["event_type"] = ev.event_id if ev else None
        item["category"] = ev.parsed_json.get("category") if ev else None
        item["risk_score"] = ev.risk_score if ev else None
        item["timestamp"] = ev.timestamp.isoformat() if (ev and ev.timestamp) else None
        items.append(item)
    return {"items": items, "total": len(items)}


# =====================================================================
# Real-world ML labeling stats
# =====================================================================

@router.get("/ml/labeling-stats", dependencies=[Depends(require_auth)])
def ml_labeling_stats(db: Session = Depends(get_db)):
    """Stats about real-world data feeding the ML training pipeline.

    Shows how many threat-intel IPs and analyst verdicts are available
    for training, so operators can see the ML is learning from real data.
    """
    from backend.ml.realworld_labeler import get_attack_ips, get_threat_intel_stats

    stats = get_threat_intel_stats(db)
    stats["active_attack_ips"] = len(get_attack_ips(db))
    try:
        from backend.ml.anomaly import get_detector
        detector = get_detector()
        stats["model_version"] = detector.version
        stats["model_trained_at"] = detector.trained_at
        stats["model_samples"] = detector.n_samples
        stats["model_events_at_train"] = detector.events_at_train
        stats["model_source"] = detector.model_source
        stats["feedback_weights"] = dict(detector.feedback_weights)
    except Exception:
        stats["model_error"] = "detector not available"
    return stats


# =====================================================================
# Model rollback
# =====================================================================

@router.post("/ml/rollback", dependencies=[Depends(require_auth)])
def ml_rollback(request: Request, db: Session = Depends(get_db)):
    """Roll back the ML model to the previous version.

    Restores the model bundle from before the last training run.
    """
    try:
        from backend.ml.anomaly import get_detector
        detector = get_detector()
        success = detector.rollback()
        if success:
            return {"status": "ok", "version": detector.version, "message": f"Rolled back to version {detector.version}"}
        else:
            raise HTTPException(status_code=404, detail="No previous model version available for rollback")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Rollback failed: {e!s}")


@router.get("/ml/model-history", dependencies=[Depends(require_auth)])
def ml_model_history(request: Request, db: Session = Depends(get_db)):
    """Return model version history for monitoring."""
    try:
        from backend.ml.anomaly import get_detector
        detector = get_detector()
        return {
            "current_version": detector.version,
            "trained_at": detector.trained_at,
            "model_source": detector.model_source,
            "n_samples": detector.n_samples,
            "events_at_train": detector.events_at_train,
            "history": detector.versions,
            "feedback_weights": dict(detector.feedback_weights),
        }
    except Exception as e:
        return {"error": str(e)}
