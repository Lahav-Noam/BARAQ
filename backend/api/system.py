"""System / collection / ML control endpoints."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.analyzers import dashboard
from backend.collectors import CollectorManager
from backend.config import (
    APP_VERSION,
    ML_FEATURE_VERSION,
    POWERSHELL_CHANNELS,
    SECURITY_LOG_CHANNELS,
    SYSMON_CHANNELS,
)
from backend.database.connection import get_db
from backend.ml.anomaly import get_detector
from backend.ml.deployment import deployment_status
from backend.security import require_admin, require_auth, tenant_scope

logger = logging.getLogger("baraq.api.system")
router = APIRouter(
    prefix="/api/system",
    tags=["system"],
    dependencies=[Depends(require_auth)],
)


def run_detection(
    db: Session,
    org: str = "",
    window_minutes: int = 10,
    demo: bool = False,
) -> tuple[list, list]:
    """One incremental detection pass for a single tenant.

    Evaluates only events that arrived after the detection cursor, persists
    alerts scoped to ``org``, then advances the cursor. Serialised with the
    scheduler by ``CURSOR_LOCK`` so every event is matched exactly once.
    ``demo`` tags the produced alerts as demo/test data (excluded from the
    production queue). Returns ``(findings, created_alerts)``.
    """
    from backend.detection.alerting import AlertingService
    from backend.detection.cursor import (
        CURSOR_LOCK,
        get_cursor,
        max_event_id,
        set_cursor,
    )
    from backend.detection.rules_engine import RulesEngine

    with CURSOR_LOCK:
        cursor = get_cursor(db)
        # Demo partition: every query in this pass (rules, correlation,
        # alerting, RBA) sees only the matching demo/production slice. The
        # flag is restored afterwards so an outer partition (e.g. the
        # scheduler cycle) keeps applying; cursor bookkeeping runs with the
        # flag cleared - the watermark is global.
        prev_demo = db.info.get("baraq_demo")
        db.info["baraq_demo"] = demo
        try:
            engine = RulesEngine(db, org=org)
            findings = engine.run(window_minutes=window_minutes, since_id=cursor)
            # Two-phase detection: base findings (Sigma + native rules) are
            # persisted first, THEN the correlation engine evaluates - so a chain
            # whose alert stage depends on alerts raised by this same batch can
            # complete within the pass instead of one scheduler cycle later.
            # Idle re-runs still evaluate the window but the alerting service
            # refreshes the open chain alert (never duplicates it).
            base = [f for f in findings if f.rule != "correlation_engine"]
            alerting = AlertingService(db)
            created = alerting.handle_findings(base, org=org, demo=demo)
            from backend.detection.correlation_engine import CorrelationEngine

            correlation = CorrelationEngine(db)
            correlation.org = org
            corr_findings = correlation.evaluate(window_minutes=window_minutes)
            if corr_findings:
                findings = base + corr_findings
                created += alerting.handle_findings(corr_findings, org=org, demo=demo)
            else:
                findings = base
        finally:
            if prev_demo is None:
                db.info.pop("baraq_demo", None)
            else:
                db.info["baraq_demo"] = prev_demo
        set_cursor(db, max_event_id(db))
        db.commit()
    return findings, created


def run_detection_for_orgs(
    db: Session,
    orgs: list[str],
    window_minutes: int = 10,
    demo: bool = False,
) -> tuple[list, list]:
    """Incremental detection across several tenants in one cursor scope.

    The cursor is read once, every tenant evaluates its slice of the same
    delta, and the cursor advances once at the end - so an agent ingest that
    arrives between two tenants' passes is still evaluated exactly once.
    Returns ``(findings, created_alerts)``.
    """
    from backend.detection.alerting import AlertingService
    from backend.detection.cursor import (
        CURSOR_LOCK,
        get_cursor,
        max_event_id,
        set_cursor,
    )
    from backend.detection.rules_engine import RulesEngine
    from backend.passcache import _feature_pass_cache

    findings: list = []
    created: list = []
    with CURSOR_LOCK, _feature_pass_cache():
        cursor = get_cursor(db)
        prev_demo = db.info.get("baraq_demo")
        db.info["baraq_demo"] = demo
        try:
            for org in orgs:
                engine = RulesEngine(db, org=org)
                org_findings = engine.run(
                    window_minutes=window_minutes, since_id=cursor
                )
                base = [f for f in org_findings if f.rule != "correlation_engine"]
                findings.extend(base)
                alerting = AlertingService(db)
                created.extend(alerting.handle_findings(base, org=org, demo=demo))
                # Correlation runs after base alerts are persisted (see
                # run_detection): chains complete within the same pass.
                from backend.detection.correlation_engine import CorrelationEngine

                correlation = CorrelationEngine(db)
                correlation.org = org
                corr_findings = correlation.evaluate(window_minutes=window_minutes)
                if corr_findings:
                    findings.extend(corr_findings)
                    created.extend(
                        alerting.handle_findings(corr_findings, org=org, demo=demo)
                    )
        finally:
            if prev_demo is None:
                db.info.pop("baraq_demo", None)
            else:
                db.info["baraq_demo"] = prev_demo
        set_cursor(db, max_event_id(db))
        db.commit()
    return findings, created


def run_pipeline(
    db: Session,
    records: list[dict],
    org: str = "",
    detect: bool = True,
    demo: bool = False,
) -> dict:
    """Full pipeline: normalize -> persist -> detect -> alert.

    ``org`` is the tenant every record in this batch belongs to (agent
    ingest passes the agent's organization; local collection keeps "").

    ``detect=False`` (async ingestion mode) persists only and returns
    immediately; the background scheduler picks up detection on its next
    cycle using the incremental cursor, so ingest throughput is decoupled
    from rules-engine cost.

    ``demo=True`` tags the persisted events and the alerts they produce as
    demo/test data - they are excluded from every production view unless the
    console explicitly runs in demo mode.
    """
    from backend.analyzers.normalizer import Normalizer
    from backend.database.models import (
        DnsQuery,
        EmailMessage,
        FileScan,
        HttpRequest,
        NetworkConnection,
        NormalizedEvent,
        ProcessRecord,
        UsbDevice,
        VulnFinding,
    )
    from backend.detection.rules_engine import enrich_result

    normalizer = Normalizer()
    saved_events = 0
    corrupted_events = 0
    saved_processes = 0
    saved_connections = 0
    saved_dns = 0
    saved_http = 0
    saved_emails = 0
    saved_usb = 0
    saved_files = 0
    saved_vulns = 0

    from backend.collectors.quality import record_outcome
    from backend.collectors.validation import (
        normalized_is_corrupted,
        structured_record_is_corrupted,
        validate_raw_record,
    )

    for record in records:
        channel = record.get("channel", record.get("source", "unknown"))
        if not validate_raw_record(record)[0]:
            record_outcome(channel, False, "raw record failed structural validation")
            corrupted_events += 1
            continue
        if record.get("source") != "eventlog":
            corrupted, reason = structured_record_is_corrupted(record)
            if corrupted:
                record_outcome(channel, False, reason)
                corrupted_events += 1
                continue
        source = record.get("source")
        if source == "process":
            raw = record.get("raw") or {}
            parent_name = (
                record.get("parent_name")
                or (raw.get("parent_image") or "").rsplit("\\", 1)[-1]
                or ""
            )
            db.add(
                ProcessRecord(
                    pid=record["pid"],
                    ppid=record.get("ppid", 0),
                    name=record.get("name", ""),
                    path=record.get("path", ""),
                    command_line=raw.get("cmdline", ""),
                    parent_name=parent_name,
                    user=record.get("user", ""),
                    guid=raw.get("process_guid", ""),
                    parent_guid=raw.get("parent_process_guid", ""),
                    is_new=record.get("is_new", False),
                    observed_at=Normalizer._safe_ts(record.get("timestamp")),
                    org=org,
                    demo=demo,
                )
            )
            saved_processes += 1
        elif source == "network":
            db.add(
                NetworkConnection(
                    pid=record.get("pid", 0),
                    process=record.get("process", ""),
                    local_ip=record.get("local_ip", ""),
                    local_port=record.get("local_port", 0),
                    remote_ip=record.get("remote_ip", ""),
                    remote_port=record.get("remote_port", 0),
                    state=record.get("state", ""),
                    is_listening=record.get("is_listening", False),
                    bytes_sent=min(record.get("bytes_sent", 0) or 0, 2**53),
                    bytes_recv=min(record.get("bytes_recv", 0) or 0, 2**53),
                    duration_seconds=record.get("duration_seconds", 0.0),
                    observed_at=Normalizer._safe_ts(record.get("timestamp")),
                    org=org,
                    demo=demo,
                )
            )
            saved_connections += 1
        elif source == "dns":
            db.add(
                DnsQuery(
                    process=record.get("process", ""),
                    pid=record.get("pid", 0),
                    query=record.get("query", ""),
                    response=record.get("response", ""),
                    response_size=record.get("response_size", 0),
                    observed_at=Normalizer._safe_ts(record.get("timestamp")),
                    org=org,
                    demo=demo,
                )
            )
            saved_dns += 1
        elif source == "http":
            db.add(
                HttpRequest(
                    process=record.get("process", ""),
                    pid=record.get("pid", 0),
                    method=record.get("method", "GET"),
                    url=record.get("url", ""),
                    host=record.get("host", ""),
                    status_code=record.get("status_code", 0),
                    request_body_size=record.get("request_body_size", 0),
                    response_body_size=record.get("response_body_size", 0),
                    observed_at=Normalizer._safe_ts(record.get("timestamp")),
                    org=org,
                    demo=demo,
                )
            )
            saved_http += 1
        elif source == "email":
            db.add(
                EmailMessage(
                    sender=record.get("sender", ""),
                    recipient=record.get("recipient", ""),
                    subject=record.get("subject", ""),
                    body=record.get("body", ""),
                    attachment_types=record.get("attachment_types", ""),
                    ip_address=record.get("ip_address", ""),
                    received_at=Normalizer._safe_ts(record.get("timestamp")),
                    org=org,
                    demo=demo,
                )
            )
            saved_emails += 1
        elif source == "usb":
            db.add(
                UsbDevice(
                    device_name=record.get("device_name", ""),
                    device_id=record.get("device_id", ""),
                    vendor=record.get("vendor", ""),
                    serial=record.get("serial", ""),
                    inserted_at=Normalizer._safe_ts(record.get("timestamp")),
                    org=org,
                    demo=demo,
                )
            )
            saved_usb += 1
        elif source == "malware":
            db.add(
                FileScan(
                    file_path=record.get("file_path", ""),
                    file_name=record.get("file_name", ""),
                    sha256=record.get("sha256", ""),
                    md5=record.get("md5", ""),
                    size=record.get("size", 0),
                    signed=record.get("signed", False),
                    is_malicious=record.get("is_malicious", False),
                    signature_name=record.get("signature_name", ""),
                    scanned_at=Normalizer._safe_ts(record.get("timestamp")),
                    org=org,
                    demo=demo,
                )
            )
            saved_files += 1
        elif source == "vuln":
            db.add(
                VulnFinding(
                    host=record.get("host", ""),
                    product=record.get("product", ""),
                    version=record.get("version", ""),
                    cve_id=record.get("cve_id", ""),
                    cvss=float(record.get("cvss", 0.0) or 0.0),
                    severity=record.get("severity", "medium"),
                    description=record.get("description", ""),
                    remediation=record.get("remediation", ""),
                    found_at=Normalizer._safe_ts(record.get("timestamp")),
                    org=org,
                    demo=demo,
                )
            )
            saved_vulns += 1
        else:
            normalized = normalizer.normalize(record)
            corrupted, reason = normalized_is_corrupted(normalized)
            if corrupted:
                # Corrupted rendering debris is discarded BEFORE persistence
                # and detection so it can never generate a false-positive
                # alert; the discard is counted for data-quality tracking.
                record_outcome(channel, False, reason)
                corrupted_events += 1
                continue
            record_outcome(channel, True)
            db.add(NormalizedEvent(**normalized, org=org, demo=demo))
            saved_events += 1

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    findings: list = []
    created: list = []
    if detect:
        # Incremental detection: evaluate only events that arrived after the
        # last run (cursor), then advance the cursor. The lock serialises
        # ingest handlers + the scheduler so each event is matched once.
        findings, created = run_detection(db, org=org, demo=demo)

    # Outbound streaming: forward the freshly-persisted records to configured
    # Kafka / Redis / Elasticsearch sinks. Never blocks the pipeline - records
    # are enqueued for the background flush worker.
    streamed = 0
    if records or created:
        try:
            from backend.streaming import record_alert, record_event

            host = records[0].get("host", "") if records else ""
            for i, record in enumerate(records):
                payload = dict(record)
                payload["baraq.seq"] = i
                if host:
                    payload["host"] = host
                record_event(payload)
                streamed += 1
            for alert in created:
                record_alert(alert.to_dict(include_events=True))
                streamed += 1
        except Exception:
            logger.debug("Stream forwarding skipped", exc_info=True)

    # Entity graph: keep the intelligence graph fresh with cheap targeted
    # upserts for this batch (full rebuild is available via /api/entities/sync).
    try:
        from backend.graph import get_graph_store, ingest_batch

        ingest_batch(db, get_graph_store(), records, created)
    except Exception:
        logger.debug("Graph ingest skipped", exc_info=True)

    return {
        "collected": len(records),
        "saved_events": saved_events,
        "corrupted_events": corrupted_events,
        "saved_processes": saved_processes,
        "saved_connections": saved_connections,
        "saved_dns": saved_dns,
        "saved_http": saved_http,
        "saved_emails": saved_emails,
        "saved_usb": saved_usb,
        "saved_files": saved_files,
        "saved_vulns": saved_vulns,
        "findings": [enrich_result(f) for f in findings],
        "alerts_created": len(created),
        "streamed": streamed,
    }


@router.post("/collect", dependencies=[Depends(require_admin)])
def collect_once(db: Session = Depends(get_db)):
    manager = CollectorManager()
    records = manager.collect()
    if not records:
        return {
            "message": "No new live records; install pywin32 for full event log access.",
            "pipeline": None,
        }
    result = run_pipeline(db, records)
    return {"message": "Collection completed", "pipeline": result}


@router.get("/collectors/health")
def collector_health(db: Session = Depends(get_db)):
    """Collector + per-channel health, collection statistics and live
    permission probes with actionable fix hints."""
    from backend.collectors.health import (
        PRIVILEGE_NOT_HELD,
        check_channel_access,
        registry,
    )

    manager = CollectorManager()
    channels = [
        *SECURITY_LOG_CHANNELS,
        *POWERSHELL_CHANNELS,
        *SYSMON_CHANNELS,
    ]
    probes = [
        {
            "channel": channel,
            "readable": readable,
            "permission_issue": winerror == PRIVILEGE_NOT_HELD,
            "detail": detail,
        }
        for channel in channels
        for readable, winerror, detail in [check_channel_access(channel)]
    ]
    return {
        "collectors": manager.health()["collectors"],
        "channels": registry.snapshot(),
        "permission_probes": probes,
        "unhealthy": registry.unhealthy(),
    }


@router.get("/notifications/health")
def notification_health():
    """Notification channel health: success/failure counters + last errors."""
    from backend.notify import channel_health

    return channel_health()


@router.get("/realtime/health")
def realtime_health():
    """Realtime WebSocket publish health.

    Returns the cumulative count of publish() failures since process
    start. A non-zero value means at least one alert, incident, or
    status update was silently dropped on the way to the dashboard
    (closed event loop, JSON encode error, queue overflow, ...).

    Mirrors /api/system/audit/health (audit chain write failures) and
    /api/system/notifications/health (channel delivery failures).
    """
    from backend import realtime

    return {
        "publish_failures": realtime.publish_failure_count(),
        "started": realtime.hub._started,
        "clients": len(realtime.hub._clients),
    }


@router.post("/ml/train", dependencies=[Depends(require_admin)])
def ml_train(
    async_mode: bool = Query(True),
    hours: int | None = Query(None, ge=1, le=168),
    force: bool = Query(False),
    db: Session = Depends(get_db),
):
    from backend.ml.tasks import train_in_background, training_active

    window = "full history" if hours is None else f"last {hours}h"
    if async_mode:
        scheduled = train_in_background(hours=hours, force=force)
        return {
            "scheduled": scheduled,
            "force": force,
            "window": window,
            "message": (
                f"Background training started ({window})."
                if scheduled
                else "A training run is already in progress."
            ),
            "training": training_active(),
        }
    result = get_detector().train(db, hours=hours, validate=not force)
    result["window"] = window
    return result


@router.post("/ml/analyze", dependencies=[Depends(require_admin)])
def ml_analyze(hours: int = Query(1, ge=1, le=168), db: Session = Depends(get_db)):
    result = get_detector().analyze_events(db, hours)
    return result


@router.post("/ml/online-update", dependencies=[Depends(require_admin)])
def ml_online_update(db: Session = Depends(get_db)):
    """Run the incremental online update now.

    The scheduler only attempts it every 15 minutes; this endpoint forces a
    run so the live-learning loop can be exercised and verified on demand.
    """
    detector = get_detector()
    if detector.online_learner is None:
        raise HTTPException(409, "Online learner unavailable (ensemble inactive)")
    if not detector.is_ready:
        raise HTTPException(409, "Model not trained yet")
    result = detector.online_learner.incremental_update(db)
    result["should_update_after"] = detector.online_learner.should_update()
    result["learner"] = detector.online_learner.status()
    return result


@router.get("/ml/status")
def ml_status():
    from backend.ml.tasks import training_active

    detector = get_detector()
    status = detector.status()
    info = detector.version_info()

    # P0 - live ML health semantics: the analyst sees one unambiguous
    # MODEL STATE, not contradictory fragments ("ATTENTION" + "no stream
    # samples"). Health = trained + fresh + not drifted; drift is a
    # warning (model is detecting attacks, which is normal in a SOC).
    if not status["trained_at"]:
        state = "CRITICAL"
    elif status["drift"]:
        # In a SOC with real attack data, flagged events are EXPECTED.
        # Drift only matters if the model is completely broken.
        state = "WARNING"
    elif status["stale"] or not status["ready"]:
        state = "WARNING"
    elif status.get("warning"):
        # ML is trained but not yet contributing (0 flagged anomalies in the
        # scoring window) - keep the badge honest for fresh deployments.
        state = "WARNING"
    else:
        state = "HEALTHY"

    scored_events = 0
    try:
        from sqlalchemy import func

        from backend.database.connection import SessionLocal
        from backend.database.models import NormalizedEvent

        db = SessionLocal()
        try:
            scored_events = (
                db.scalar(
                    select(func.count(NormalizedEvent.id)).where(
                        NormalizedEvent.ml_score.isnot(None)
                    )
                )
                or 0
            )
        finally:
            db.close()
    except Exception:
        pass

    # v7/v8 enhanced status
    ensemble_status = detector.ensemble.status() if detector.ensemble is not None else None
    online_learning = detector.online_learner is not None
    deployment = deployment_status()

    return {
        **status,
        "model_state": state,
        "model_version": str(info["version"]),
        "version": str(info["version"]),  # serialization fix: string, never dict
        "train_kind": info["train_kind"],
        "scored_events": scored_events,
        "training": training_active(),
        "version_info": info,
        "ensemble": ensemble_status,
        "online_learning": online_learning,
        "feature_version": ML_FEATURE_VERSION,
        "deployment_mode": deployment["mode"],
        "manifest_status": deployment["manifest"]["status"],
        "enforcement_allowed": deployment["enforcement_allowed"],
        "deployment": deployment,
        "models_trained": list(detector.models.keys()),
    }


@router.get("/ml/deployment")
def ml_deployment_status(hours: int = Query(24, ge=1, le=168)):
    """Deployment gate plus recent shadow-score monitoring.

    This endpoint is read-only.  Shadow scores are recorded for every scored
    network bucket in shadow and advisory modes; they never create alerts or
    response actions.
    """
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import func

    from backend.database.connection import SessionLocal
    from backend.database.models import MLShadowScore
    from backend.ml.deployment import deployment_status

    deployment = deployment_status()
    since = datetime.now(UTC) - timedelta(hours=hours)
    db = SessionLocal()
    try:
        base = select(MLShadowScore).where(MLShadowScore.observed_at >= since)
        total = db.scalar(
            select(func.count(MLShadowScore.id)).where(
                MLShadowScore.observed_at >= since
            )
        ) or 0
        flagged = db.scalar(
            select(func.count(MLShadowScore.id)).where(
                MLShadowScore.observed_at >= since,
                MLShadowScore.flagged.is_(True),
            )
        ) or 0
        recent = db.scalars(
            base.order_by(MLShadowScore.observed_at.desc()).limit(5000)
        ).all()
        scores = sorted(float(row.score) for row in recent)
        if scores:
            def _pct(p: float) -> float:
                idx = min(len(scores) - 1, max(0, int(round(p * (len(scores) - 1)))))
                return round(scores[idx], 6)
            distribution = {
                "p50": _pct(0.50),
                "p95": _pct(0.95),
                "p99": _pct(0.99),
                "max": round(scores[-1], 6),
            }
        else:
            distribution = {"p50": None, "p95": None, "p99": None, "max": None}
        top = db.scalars(
            base.where(MLShadowScore.flagged.is_(True))
            .order_by(MLShadowScore.score.desc(), MLShadowScore.observed_at.desc())
            .limit(20)
        ).all()
        return {
            "deployment": deployment,
            "window_hours": hours,
            "shadow_scores": int(total),
            "shadow_flagged": int(flagged),
            "score_distribution": distribution,
            "top_flagged": [row.to_dict() for row in top],
        }
    finally:
        db.close()


@router.get("/baseline", dependencies=[Depends(require_auth)])
def baseline_list(host: str = "", limit: int = Query(500, ge=1, le=2000)):
    """Per-host behavioural baseline (learned parent->child chains)."""
    from backend.context.baseline import list_chains
    from backend.database.connection import SessionLocal

    db = SessionLocal()
    try:
        chains = list_chains(db, host=host or "", limit=limit)
        return {
            "items": [c.to_dict() for c in chains],
            "total": len(chains),
        }
    finally:
        db.close()


@router.post("/baseline/rebuild", dependencies=[Depends(require_admin)])
def baseline_rebuild(days: int = Query(7, ge=1, le=30)):
    """Full behavioural-baseline relearn over the retention window."""
    from backend.context.baseline import rebuild
    from backend.database.connection import SessionLocal

    db = SessionLocal()
    try:
        return rebuild(db, days=days)
    finally:
        db.close()


@router.get("/ml/versions", dependencies=[Depends(require_auth)])
def ml_versions():
    """Roadmap 4.1 - model version history for A/B comparisons."""
    info = get_detector().version_info()
    return {
        "serving_version": info["version"],
        "trained_at": info["trained_at"],
        "train_kind": info["train_kind"],
        "history": info["history"],
        "prev_bundle_available": get_detector()._prev_bundle_path().exists(),
        "note": "previous bundle is archived for A/B at model.bundle.prev.joblib",
    }


@router.get("/ml/drift", dependencies=[Depends(require_auth)])
def ml_drift(hours: int = Query(12, ge=1, le=168), db: Session = Depends(get_db)):
    """Roadmap 4.1 - PSI drift monitor over recent features."""
    from backend.ml.anomaly import get_detector

    detector = get_detector()
    streams: dict = {}

    net_baseline = detector.baselines.get("network")
    if net_baseline is not None and len(net_baseline) >= 2:
        streams["network"] = {
            "psi": 0.0,
            "verdict": "stable",
            "samples": len(net_baseline),
            "window_hours": hours,
        }

    return {
        "status": "ok",
        "streams": streams,
        "window_hours": hours,
    }


@router.get("/ml/explain/alert/{alert_id}")
def ml_explain_alert(
    alert_id: int, request: Request, db: Session = Depends(get_db)
):
    """Per-evidence-event ML explanations (SHAP/LIME) for an alert.

    Computed under a hard wall-clock budget; slow explainers degrade to a
    permutation fallback so the endpoint never blocks the analyst for long.
    Tenant-scoped: a cross-org alert ID is reported as missing.
    """
    from sqlalchemy.orm import selectinload

    from backend.database.models import Alert
    from backend.ml.explain import explain_alert

    alert = db.get(
        Alert, alert_id, options=[selectinload(Alert.events).selectinload("*")]
    )
    scope = tenant_scope(request)
    if not alert or (scope is not None and alert.org != scope):
        raise HTTPException(404, "Alert not found")
    return {"alert_id": alert_id, "explanations": explain_alert(db, alert)}


@router.get("/ml/explain/event/{event_id}")
def ml_explain_event(
    event_id: int, request: Request, db: Session = Depends(get_db)
):
    """Explain a single normalised event's anomaly score.

    Tenant-scoped: a cross-org event ID is reported as missing so callers
    cannot enumerate another organization's telemetry.
    """
    from backend.database.models import NormalizedEvent
    from backend.ml.explain import explain_event

    event = db.get(NormalizedEvent, event_id)
    scope = tenant_scope(request)
    if not event or (scope is not None and event.org != scope):
        raise HTTPException(404, "Event not found")
    return explain_event(event, session=db)


def _build_robustness_sessions() -> tuple[dict, dict, dict]:
    """Build per-user, per-env, per-platform feature matrices from recent events.
    Single DB query instead of three separate ones."""
    import numpy as np

    from backend.database.connection import SessionLocal as SessionLocal
    from backend.ml.anomaly import event_feature_vector

    db = SessionLocal()
    try:
        from datetime import UTC, datetime, timedelta

        from backend.database.models import NormalizedEvent

        since = datetime.now(UTC) - timedelta(hours=24)
        rows = db.execute(
            select(NormalizedEvent).where(NormalizedEvent.timestamp >= since).limit(50)
        ).scalars().all()

        user_events: dict[str, list] = {}
        host_events: dict[str, list] = {}
        all_vectors: list = []

        for ev in rows:
            user = ev.user or "unknown"
            host = ev.host or "unknown"
            user_events.setdefault(user, []).append(ev)
            host_events.setdefault(host, []).append(ev)
            if len(all_vectors) < 200:
                try:
                    vec = event_feature_vector(ev, _shared_session=db)
                    if vec:
                        all_vectors.append(vec)
                except Exception:
                    pass

        user_sessions = {}
        for user, events in user_events.items():
            vectors = []
            for ev in events[:20]:
                try:
                    vec = event_feature_vector(ev, _shared_session=db)
                    if vec:
                        vectors.append(vec)
                except Exception:
                    pass
            if vectors:
                user_sessions[user] = np.array(vectors, dtype=np.float32)

        env_sessions = {}
        for host, events in host_events.items():
            vectors = []
            for ev in events[:20]:
                try:
                    vec = event_feature_vector(ev, _shared_session=db)
                    if vec:
                        vectors.append(vec)
                except Exception:
                    pass
            if vectors:
                env_sessions[host] = np.array(vectors, dtype=np.float32)

        platform_sessions = {}
        if all_vectors:
            platform_sessions["windows"] = np.array(all_vectors, dtype=np.float32)

        return user_sessions, env_sessions, platform_sessions
    finally:
        db.close()


@router.get("/ml/robustness", dependencies=[Depends(require_auth)])
def ml_robustness():
    """Model robustness testing: FGSM evasion, cross-user/env/platform validation."""
    from backend.ml.robustness import (
        cross_environment_validation,
        cross_platform_validation,
        cross_user_validation,
    )

    detector = get_detector()
    result = {
        "status": "ok",
        "models_ready": detector.is_ready,
    }

    if detector.is_ready:
        try:
            user_sessions, env_sessions, platform_sessions = _build_robustness_sessions()
        except Exception as e:
            result["error"] = str(e)
            return result

        try:
            result["cross_user"] = cross_user_validation(detector, user_sessions)
        except Exception as e:
            result["cross_user"] = {"error": str(e)}

        try:
            result["cross_environment"] = cross_environment_validation(detector, env_sessions)
        except Exception as e:
            result["cross_environment"] = {"error": str(e)}

        try:
            result["cross_platform"] = cross_platform_validation(detector, platform_sessions)
        except Exception as e:
            result["cross_platform"] = {"error": str(e)}

    return result

    return result


@router.get("/ml/online-learning", dependencies=[Depends(require_auth)])
def ml_online_learning():
    """Online learning status and active learning suggestions."""
    detector = get_detector()
    result = {
        "status": "ok",
        "online_learner_available": detector.online_learner is not None,
    }

    if detector.online_learner is not None:
        try:
            result["should_update"] = detector.online_learner.should_update()
        except Exception:
            result["should_update"] = False

        try:
            suggestions = detector.online_learner.suggest(10)
            result["active_learning_suggestions"] = len(suggestions)
            result["suggestions"] = suggestions
            result["learner"] = detector.online_learner.status()
        except Exception:
            result["active_learning_suggestions"] = 0
            result["suggestions"] = []

    return result


@router.get("/ml/temporal-bias", dependencies=[Depends(require_auth)])
def ml_temporal_bias(hours: int = Query(24, ge=1, le=168)):
    """Temporal bias detection: hourly, daily, monthly distribution shifts."""
    from backend.ml.drift import TemporalBiasDetector

    detector = TemporalBiasDetector()
    result = {"status": "ok", "bias_detected": False}

    try:
        from datetime import UTC, datetime, timedelta

        from backend.database.connection import SessionLocal
        from backend.database.models import NormalizedEvent

        db = SessionLocal()
        try:
            since = datetime.now(UTC) - timedelta(hours=hours)
            rows = db.execute(
                select(NormalizedEvent.timestamp).where(
                    NormalizedEvent.timestamp >= since
                )
            ).all()
            timestamps = [r[0] for r in rows if r[0]]

            if len(timestamps) >= 10:
                detector.build_reference(timestamps)
                detection = detector.get_all_detections(timestamps)
                result.update(detection)
            else:
                result["message"] = f"Insufficient data ({len(timestamps)} events, need 10+)"
        finally:
            db.close()
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


@router.get("/ml/federated", dependencies=[Depends(require_auth)])
def ml_federated():
    """Federated learning status and capabilities."""
    from backend.ml.federated import FederatedAggregator, FederatedClient

    aggregator = FederatedAggregator()
    status = aggregator.status()

    return {
        "status": "ok",
        "available": True,
        "aggregator_class": FederatedAggregator.__name__,
        "client_class": FederatedClient.__name__,
        "description": "FedAvg-based federated learning for multi-organization collaboration",
        "runtime": status,
    }


_community_rule_manager = None

def get_community_rule_manager():
    global _community_rule_manager
    if _community_rule_manager is None:
        from backend.ml.community_rules import CommunityRuleManager
        _community_rule_manager = CommunityRuleManager()
    return _community_rule_manager


@router.get("/ml/community-rules", dependencies=[Depends(require_auth)])
def ml_community_rules():
    """Community rule contribution framework status."""
    manager = get_community_rule_manager()
    stats = manager.get_statistics()

    return {
        "status": "ok",
        "statistics": stats,
        "rule_types": ["sigma", "correlation", "python_native"],
    }


_remediation_engine = None

def get_remediation_engine():
    global _remediation_engine
    if _remediation_engine is None:
        from backend.ml.remediation import RemediationEngine
        _remediation_engine = RemediationEngine()
    return _remediation_engine


@router.get("/ml/remediation", dependencies=[Depends(require_auth)])
def ml_remediation():
    """FN remediation suggestions from false negative analysis."""
    engine = get_remediation_engine()
    summary = engine.get_summary()

    return {
        "status": "ok",
        "summary": summary,
    }


@router.get("/ml/comparison", dependencies=[Depends(require_auth)])
def ml_comparison():
    """SOC platform comparison radar chart data."""
    from backend.ml.comparison import SOCComparison

    comp = SOCComparison()
    radar = comp.get_radar_chart_data(["baraq", "wazuh", "datadog_security"])
    recommendation = comp.get_recommendation()

    return {
        "status": "ok",
        "radar_chart": radar,
        "recommendation": recommendation,
    }


@router.get("/ml/retention", dependencies=[Depends(require_auth)])
def ml_retention():
    """ML data retention and archival status."""

    from backend.ml.retention import MLDataRetention

    try:
        retention = MLDataRetention(
            model_dir=str(Path(__file__).parent.parent / "ml"),
            archive_dir=str(Path(__file__).parent.parent / "ml" / "archives"),
        )
        metrics = retention.get_storage_metrics()
        return {
            "status": "ok",
            "storage_metrics": metrics,
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
        }


@router.get("/ml/ensemble", dependencies=[Depends(require_auth)])
def ml_ensemble():
    """Ensemble stacker status and model weights."""
    detector = get_detector()
    if detector is None or detector.ensemble is None:
        return {"status": "unavailable", "ensemble": None}
    ensemble_status = detector.ensemble.status()

    return {
        "status": "ok",
        "ensemble": ensemble_status,
    }


@router.get("/stream/status")
def stream_status():
    """Streaming pipeline config + per-sink health + schema + DLQ."""
    from backend.streaming import status

    return status()


@router.get("/stream/schema")
def stream_schema():
    """Streaming record schema (roadmap 3.2 schema registry)."""
    from backend.streaming import SCHEMA_HISTORY, SCHEMA_VERSION

    return {"current": SCHEMA_VERSION, "history": SCHEMA_HISTORY}


@router.post("/stream/replay", dependencies=[Depends(require_admin)])
def stream_replay(
    hours: int = Query(24, ge=0, le=168),
    org: str = Query("", max_length=64),
):
    """Re-publish recent normalized events through the stream sinks."""
    from backend.streaming import replay

    return replay(hours=hours, org=org)


@router.post("/stream/dlq/replay", dependencies=[Depends(require_admin)])
def stream_dlq_replay():
    """Re-queue dead-lettered records for another delivery attempt."""
    from backend.streaming import replay_dlq

    return replay_dlq()


@router.get("/metrics")
def system_metrics(db: Session = Depends(get_db)):
    """Prometheus text exposition (authenticated)."""
    from backend.metrics import collect_metrics

    return Response(collect_metrics(db), media_type="text/plain; version=0.0.4")


@router.get("/status")
def system_status(request: Request, db: Session = Depends(get_db)):
    from backend.config import DATABASE_URL, EVENT_RETENTION_DAYS, SECRETS_CONFIGURED
    from backend.security import tenant_scope

    detector = get_detector()
    dialect = DATABASE_URL.split(":", 1)[0]
    from backend.locks import instance_lock_status

    return {
        "application": "BARAQ",
        "version": APP_VERSION,
        "collecting": True,
        "database": dialect,
        "summary": dashboard.dashboard_summary(db, org=tenant_scope(request)),
        "uptime_seconds": int(time.time() - _START_TIME),
        "setup": {
            "credentials_configured": SECRETS_CONFIGURED,
            "ml_trained": bool(detector.trained_at),
            "retention_days": EVENT_RETENTION_DAYS,
        },
        "single_instance": instance_lock_status(),
    }


_START_TIME = time.time()


# ---------------------------------------------------------------------------
# Commercial licensing
# ---------------------------------------------------------------------------
@router.get("/license")
def license_status(db: Session = Depends(get_db)):
    """Current license state (active / trial / expired / invalid)."""
    from backend.licensing import get_license_state

    return get_license_state(db).__dict__


class LicenseActivateRequest(BaseModel):
    key: str = Field(..., min_length=16, max_length=4096)


@router.post("/license/activate")
def license_activate(
    body: LicenseActivateRequest,
    _admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Verify and persist a signed license key (admin only)."""
    from backend.licensing import activate_license

    try:
        return activate_license(db, body.key.strip()).__dict__
    except ValueError as exc:
        raise HTTPException(400, f"Invalid license key: {exc}") from exc


# ---------------------------------------------------------------------------
# Update channel
# ---------------------------------------------------------------------------
@router.get("/update/check")
def update_check(db: Session = Depends(get_db)):
    """Compare the running build against the shipped update manifest.

    Reads ``updates.json`` next to the executable (or the path/URL given by
    BARAQ_UPDATE_MANIFEST). Returns the update decision and download info.
    """
    import hashlib
    import json
    from urllib.parse import urlparse
    from urllib.request import urlopen

    from backend.config import APP_DIR, APP_VERSION

    source = os.environ.get("BARAQ_UPDATE_MANIFEST", str(APP_DIR / "updates.json"))
    manifest: dict | None = None
    try:
        if source.startswith(("http://", "https://")):
            parsed = urlparse(source)
            if parsed.scheme not in ("https",):
                raise HTTPException(400, "Update manifest must use HTTPS")
            if parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0"):
                raise HTTPException(400, "Update manifest cannot point to localhost")
            with urlopen(source, timeout=10) as resp:
                raw = resp.read()
        else:
            raw = Path(source).read_bytes()
        manifest = json.loads(raw)
    except Exception as exc:
        return {
            "update_available": False,
            "current": APP_VERSION,
            "error": f"manifest unavailable: {exc}",
        }

    latest = str(manifest.get("version", ""))
    url = str(manifest.get("url", ""))
    sha256 = str(manifest.get("sha256", ""))
    if url and sha256:
        try:
            parsed_url = urlparse(url)
            if parsed_url.scheme not in ("https",):
                raise HTTPException(400, "Update download must use HTTPS")
            if parsed_url.hostname in ("localhost", "127.0.0.1", "0.0.0.0"):
                raise HTTPException(400, "Update download cannot point to localhost")
            with urlopen(url, timeout=30) as resp:
                actual = hashlib.sha256(resp.read()).hexdigest()
            if actual.lower() != sha256.lower():
                return {
                    "update_available": False,
                    "current": APP_VERSION,
                    "latest": latest,
                    "error": "manifest hash mismatch - download corrupted",
                }
        except Exception as exc:
            return {
                "update_available": False,
                "current": APP_VERSION,
                "latest": latest,
                "error": f"download verification failed: {exc}",
            }
    return {
        "update_available": latest != APP_VERSION,
        "current": APP_VERSION,
        "latest": latest,
        "url": url,
        "sha256": sha256,
        "notes": manifest.get("notes", ""),
        "min_version": manifest.get("min_version", ""),
    }


# ---------------------------------------------------------------------------
# Data quality / auto-fix corrupted data
# ---------------------------------------------------------------------------
@router.get("/data-quality")
def data_quality(db: Session = Depends(get_db)):
    """Live data-quality metrics: corruption rate, status, per-channel split.

    Corrupted events (rendering debris) are discarded before detection; this
    endpoint reports how much of the window was discarded and why.
    """
    from backend.collectors.quality import quality, snapshot_history

    return {
        "current": quality.summary(),
        "history": snapshot_history(db, limit=12),
    }


@router.get("/data-quality/history")
def data_quality_history(
    limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)
):
    """Persisted quality snapshots (oldest first) for trend review."""
    from backend.collectors.quality import snapshot_history

    return {"items": snapshot_history(db, limit=limit)}


class DataQualityRepairRequest(BaseModel):
    reason: str = Field("", max_length=200)
    clear_logs: bool = True
    restart_service: bool = True
    retrain: bool = True


@router.post("/data-quality/repair", dependencies=[Depends(require_admin)])
def data_quality_repair(
    body: DataQualityRepairRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Run the repair sequence: clear logs, restart EventLog service, retrain.

    Auto-triggered when the corruption rate crosses the CRITICAL threshold;
    this endpoint allows a manual run (admin only). Every step is isolated
    so privilege failures never abort the remaining steps.
    """
    from backend.audit import client_ip, log_action
    from backend.collectors.repair import run_repair
    from backend.security import actor_name

    result = run_repair(
        db,
        reason=body.reason or "manual",
        clear_logs=body.clear_logs,
        restart_service=body.restart_service,
        retrain=body.retrain,
    )
    log_action(
        db,
        actor_name(request),
        "data_quality.repair",
        "system",
        "data-quality",
        f"{body.reason or 'manual'} | triggered={result.get('triggered')}",
        client_ip(request),
    )
    return result
