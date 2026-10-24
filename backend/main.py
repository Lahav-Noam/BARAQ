"""BARAQ FastAPI application."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.api import (
    alerting,
    alerts,
    approval,
    assistant,
    attack_path_api,
    auth,
    automation,
    behavior_groups,
    bookmarks,
    compliance,
    correlations,
    dashboard,
    dataset,
    detections,
    endpoints,
    evaluation,
    events,
    export,
    fleet_api,
    graph,
    hunting,
    incidents,
    incidents_v2,
    insider_threat_api,
    integrations,
    intel,
    investigation,
    mitre_gap_api,
    ml_dataset_import,
    rba,
    realtime,
    reports,
    risk,
    saved,
    search,
    system,
    telemetry,
    ueba_api,
)
from backend.auth import session_fresh_for_user, verify_token
from backend.config import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    API_KEYS,
    AUTH_ENABLED,
    BARAQ_ENV,
    BEHAVIOR_GROUPS_ENABLED,
    CORS_ORIGINS,
    DEFAULT_ADMIN_PASSWORD,
    HSTS_MAX_AGE,
    INSECURE_BOOTSTRAP_PASSWORD,
    IS_PRODUCTION,
    METRICS_PUBLIC,
    SECURITY_HEADERS,
    SINGLE_INSTANCE,
)

# Import the new settings module
from backend.settings import get_settings

settings = get_settings()

from backend.audit import client_ip
from backend.database.connection import SessionLocal, get_db, init_db
from backend.logging_config import setup_logging

setup_logging()
logger = logging.getLogger("baraq")

# Roadmap 5.2 - optional OpenTelemetry export (no-op when not configured).
from backend.observability import setup_observability

setup_observability()

from backend import config

logger.info("BARAQ starting — env=%s, debug=%s, telemetry_v2=%s, alerts_v2=%s, correlation=%s, risk=%s",
    config.BARAQ_ENV, not config.IS_PRODUCTION, config.TELEMETRY_V2_ENABLED, config.ALERTS_V2_ENABLED, config.CORRELATION_ENABLED, config.RISK_ENABLED)

if config._USING_DEV_KEYS and config.ALLOW_DEV_KEYS:
    logger.warning(
        "BARAQ is accepting the public development API keys (baraq-dev-*). "
        "These are well-known credentials and must NOT be enabled in any "
        "deployment that is not a single-user lab. Set BARAQ_API_KEYS in .env "
        "or the DPAPI vault, then set BARAQ_ALLOW_DEV_KEYS=0 and restart."
    )


def _rotate_legacy_bootstrap_password(user) -> bool:
    """Replace a retired shared bootstrap hash with the per-install one.

    Returns True when the row was legacy and has been rewritten. The caller
    owns the transaction commit. ``ADMIN_PASSWORD`` is the value ``config``
    generated (or adopted) for this start, so the credential written to
    ``first_run_credentials.txt`` becomes the working bootstrap password.
    """
    from backend.auth import hash_password, verify_password

    if not verify_password(INSECURE_BOOTSTRAP_PASSWORD, user.password_hash):
        return False
    user.password_hash = hash_password(ADMIN_PASSWORD)
    user.must_change_password = True
    return True


def _seed_admin_user() -> None:
    """Create the bootstrap admin account if the users table is empty."""
    from sqlalchemy import select

    from backend.auth import hash_password
    from backend.database.models import User

    db = SessionLocal()
    try:
        existing = db.scalar(select(User).where(User.username == ADMIN_USERNAME))
        if existing:
            # Upgraded deployments may still carry the retired shared
            # shared bootstrap hash from a bundled release seed. Rotate it to the
            # per-install password and force a change before the rest of the
            # API unlocks. The test profile deliberately seeds that value in
            # fixtures, so leave it alone there.
            if BARAQ_ENV != "test" and _rotate_legacy_bootstrap_password(existing):
                db.commit()
                logger.warning(
                    "Admin user '%s' still used the retired shared bootstrap "
                    "password; rotated it to the newly generated credential "
                    "and a password change is required before the console "
                    "unlocks.",
                    ADMIN_USERNAME,
                )
            return
        must_change_password = ADMIN_PASSWORD in (
            DEFAULT_ADMIN_PASSWORD,
            INSECURE_BOOTSTRAP_PASSWORD,
        )
        admin = User(
            username=ADMIN_USERNAME,
            password_hash=hash_password(ADMIN_PASSWORD),
            role="admin",
            full_name="BARAQ Administrator",
            is_active=True,
            must_change_password=must_change_password,
        )
        db.add(admin)
        db.commit()
        logger.info("Seeded bootstrap admin user '%s'", ADMIN_USERNAME)
        logger.debug("Admin user '%s' created with role='admin', must_change_password=%s",
                      ADMIN_USERNAME, must_change_password)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


_scheduler_thread: threading.Thread | None = None
_scheduler_stop = threading.Event()


#: Declarative schedule for the rare-cycle steps in ``_scheduler_loop``.
#: Each entry is ``(every_n_cycles, label, callable)``. The callable is
#: invoked only when ``counter % every_n_cycles == 0``. With the
#: default 15 s interval (COLLECT_INTERVAL_SECONDS), the wall-clock
#: frequencies are::
#:
#:     2     -> every cycle  (online learning attempt - the 15-minute
#:                          wall-clock gate lives in should_update())
#:     4     -> ~1 min      (per-host chain learning, ML auto-train probe,
#:                          entity-risk decay)
#:     6     -> ~1.5 min    (entity-risk backfill sweep + escalate)
#:     20    -> ~5 min      (dashboard snapshot)
#:     120   -> ~30 min     (ML drift check + watch retrain)
#:     240   -> ~1 h        (dataset auto-export, retention purge,
#:                          scheduled reports)
#:     720   -> ~3 h        (threat-intel feed refresh)
#:     5760  -> ~daily      (rule precision auto-tune)
#:
#: NOTE: cycle duration is NOT fixed - it is 15 s of sleep plus the
#: cycle's work (observed 15 s idle to >90 s under load). Steps that
#: promise "every N minutes" must gate on wall-clock time inside their
#: callable, not on this counter; the counter only decides how often
#: that gate is consulted.
#:
#: This table is the single source of truth for 'how often does step X
#: run?'. The hot inline counter checks in ``_scheduler_loop`` are kept
#: in sync with this comment by code review. A future refactor can
#: replace the inline checks with a dispatcher that reads this table
#: without changing the cadence.
SCHEDULER_CYCLE_FREQUENCY_SECONDS: dict[str, int] = {
    "chain_learning": 4 * 15,
    "ml_drift_check": 120 * 15,
    "dashboard_snapshot": 20 * 15,
    "ml_analyze_events": 4 * 15,
    "ml_stale_check": 4 * 15,
    "entity_risk_decay": 4 * 15,
    "entity_risk_sweep": 6 * 15,
    "dataset_auto_export": 240 * 15,
    "ml_online_update": 2 * 15,
    "retention_purge": 240 * 15,
    "audit_retention_purge": 240 * 15,
    "scheduled_reports": 240 * 15,
    "threat_intel_refresh": 720 * 15,
    "rule_precision_auto_tune": 5760 * 15,
}


def _scheduler_loop(interval_seconds: int = 15):
    """Background collection + detection loop."""
    logger.info("Scheduler started (interval=%ss)", interval_seconds)
    from backend.analyzers import dashboard
    from backend.collectors import CollectorManager
    from backend.database.connection import SessionLocal
    from backend.ml.anomaly import get_detector

    manager = CollectorManager()
    from backend.api.system import run_detection_for_orgs, run_pipeline

    counter = 0
    #: Remaining wide-window warm-up passes for the online learner's
    #: buffers (login/process can be nearly empty in the last hour).
    warmup_passes = 3
    while not _scheduler_stop.is_set():
        cycle_start = time.monotonic()
        #: Per-stage wall times for this cycle, logged once per cycle so
        #: latency regressions are attributable without re-profiling.
        _timings: list[tuple[str, float]] = []
        _lap = [cycle_start]

        def _mark(label: str) -> None:
            now = time.monotonic()
            _timings.append((label, now - _lap[0]))
            _lap[0] = now

        try:
            db = SessionLocal()
            # Production partition for the whole cycle: detection, RBA,
            # entity-risk escalation and ML all query on this session, and
            # every query must see production data only (demo/test telemetry
            # is excluded unless a demo run explicitly opts in).
            db.info["baraq_demo"] = False
            try:
                from sqlalchemy import func, select

                from backend.config import AGENT_ORGS, ML_TRAIN_MIN_SAMPLES
                from backend.database.models import NormalizedEvent

                # 1. Persist local host telemetry (never inline-detect: the
                #    detection pass below covers every tenant in one cursor
                #    scope, so a local batch is detected the same cycle).
                records = manager.collect()
                if records:
                    result = run_pipeline(db, records, org="", detect=False)
                    logger.info(
                        "Scheduler cycle: %d records collected",
                        result["collected"],
                    )
                _mark("collect")

                # 2. Incremental detection for every tenant ("" system org
                #    plus each configured agent organization). With
                #    BARAQ_INGEST_ASYNC_DETECT=1 this is the only place the
                #    rules engine runs; each event is evaluated exactly once.
                orgs = [""] + sorted({o for o in AGENT_ORGS.values() if o})
                _findings, created = run_detection_for_orgs(db, orgs)
                if created:
                    logger.info(
                        "Scheduler cycle: %d new alert(s) across %d tenant(s)",
                        len(created),
                        len(orgs),
                    )
                _mark("detection")
                counter += 1
                from backend.realtime import publish_status

                publish_status({"summary": dashboard.dashboard_summary(db)})
                _mark("summary")

                # Dataset collector: consume new telemetry into the research
                # store every cycle (batched, never blocks ingestion).
                try:
                    from backend.dataset.scheduler import dataset_sweep

                    swept = dataset_sweep(db)
                    if swept.get("collected"):
                        logger.info(
                            "Dataset collector: %d event(s) collected (total %d)",
                            swept["collected"],
                            swept["total"],
                        )
                    if swept.get("target_reached"):
                        logger.info(
                            "Dataset collector: target reached, collection complete"
                        )
                except Exception:
                    logger.exception("Dataset sweep failed")
                _mark("dataset")

                # Phase 4: aggregate new alerts into behavior groups (v2 alerts).
                phase4_groups: list = []
                if BEHAVIOR_GROUPS_ENABLED and created:
                    try:
                        from backend.aggregation.engine import process_alerts
                        from backend.alerting.models import AlertRecord

                        v2_alerts: list[AlertRecord] = []
                        for v1_alert in created:
                            fp_payload = {
                                "detector_id": v1_alert.rule or "",
                                "host_id": "",
                                "host_name": (v1_alert.host or "").strip().lower()
                                or "none",
                                "user_id": "",
                                "username": "",
                                "source_ip": "",
                                "mitre_technique": v1_alert.mitre_id or "",
                            }
                            fp_blob = json.dumps(
                                fp_payload, sort_keys=True, separators=(",", ":")
                            )
                            alert_fp = hashlib.sha256(
                                fp_blob.encode("utf-8")
                            ).hexdigest()
                            evidence_list = None
                            if v1_alert.evidence:
                                evidence_list = [
                                    {"type": "text", "data": v1_alert.evidence}
                                ]
                            record = AlertRecord(
                                alert_id="",
                                alert_fingerprint=alert_fp,
                                detector_id=v1_alert.rule or "",
                                detector_version="1.0.0",
                                title=v1_alert.name or "",
                                description=v1_alert.description or "",
                                severity=v1_alert.severity or "medium",
                                confidence=float(v1_alert.confidence or 0.0),
                                status=(v1_alert.status or "open").upper(),
                                first_seen=v1_alert.created_at,
                                last_seen=v1_alert.updated_at,
                                occurrence_count=max(
                                    1, int(v1_alert.trigger_count or 1)
                                ),
                                host_id="",
                                host_name=v1_alert.host or "",
                                user_id="",
                                username="",
                                source_ip="",
                                destination_ip="",
                                mitre_tactic=v1_alert.mitre_tactic or "",
                                mitre_technique=v1_alert.mitre_id or "",
                                evidence=evidence_list,
                                observables=[],
                                detection_ids=[],
                                created_at=v1_alert.created_at,
                                updated_at=v1_alert.updated_at,
                            )
                            db.add(record)
                            db.flush()
                            record.alert_id = f"ALR-{record.id:06d}"
                            db.flush()
                            v2_alerts.append(record)
                        db.commit()
                        phase4_groups = process_alerts(db, v2_alerts)
                        if phase4_groups:
                            logger.info(
                                "Scheduler cycle: %d behavior group(s) updated",
                                len(phase4_groups),
                            )
                    except Exception:
                        logger.exception("Phase 4 aggregation failed")
                counter += 1
                if counter % 4 == 0:  # every ~1 min: per-host chain learning
                    try:
                        from backend.context.baseline import learn_chains

                        res = learn_chains(db, hours=24)
                        if res["chains_created"] or res["chains_updated"]:
                            logger.info(
                                "Baseline: %d chain(s) created, %d updated across %d host(s)",
                                res["chains_created"],
                                res["chains_updated"],
                                len(res["hosts"]),
                            )
                    except Exception:
                        logger.exception("Behavioural baseline learning failed")
                if counter % 5760 == 0:  # ~daily: rule precision auto-tuning
                    try:
                        from backend.detection.rule_precision import auto_tune

                        res = auto_tune(db)
                        if res["damped"]:
                            logger.warning(
                                "Rule precision auto-tune damped %d rule(s)",
                                len(res["damped"]),
                            )
                    except Exception:
                        logger.exception("Rule precision auto-tune failed")
                if counter % 240 == 0:  # every ~1 hour: dataset auto-export check
                    try:
                        from backend.dataset.scheduler import dataset_maybe_export

                        due = dataset_maybe_export(db)
                        if due.get("due"):
                            logger.info(
                                "Dataset auto-export ran: %s",
                                due.get("result", {}).get("status"),
                            )
                    except Exception:
                        logger.exception("Dataset auto-export check failed")
                if counter % 20 == 0:
                    dashboard.snapshot(db)
                if counter % 4 == 0 and get_detector().is_ready:
                    # Buffer warm-up: the learner only sees what this pass
                    # scores, and the last hour can hold almost no login or
                    # process events. While those buffers are cold, score a
                    # 24 h window (a few passes at startup) so the model
                    # learns this host's history instead of waiting hours
                    # for new events to trickle in.
                    hours = 1
                    learner = get_detector().online_learner
                    if learner is not None and warmup_passes > 0:
                        cold = (
                            learner.buffers["login"].size < 256
                            or learner.buffers["process"].size < 256
                        )
                        if cold:
                            hours = 24
                            warmup_passes -= 1
                        else:
                            warmup_passes = 0
                    get_detector().analyze_events(db, hours=hours)
                if counter % 4 == 0:
                    stale, reason = get_detector().is_stale(db)
                    if stale:
                        from backend.ml.tasks import (
                            train_in_background,
                            training_active,
                        )

                        if training_active():
                            logger.debug(
                                "Auto-train skipped: background training already running"
                            )
                        elif reason == "never-trained":
                            total_events = (
                                db.scalar(select(func.count(NormalizedEvent.id))) or 0
                            )
                            if total_events >= ML_TRAIN_MIN_SAMPLES:
                                logger.info(
                                    "ML never trained; initial auto-training on %d events",
                                    total_events,
                                )
                                scheduled = train_in_background(
                                    hours=None, validate=False
                                )
                                if not scheduled:
                                    logger.debug(
                                        "Auto-train: could not acquire training lock"
                                    )
                        else:
                            logger.info("ML model stale (%s); retraining", reason)
                            scheduled = train_in_background(hours=None, validate=False)
                            if not scheduled:
                                logger.debug(
                                    "Auto-train: could not acquire training lock"
                                )

                _mark("phase4+baseline+ml")
                # RBA - Correlate alerts into incidents
                from backend.detection.rba import RBAManager

                rba = RBAManager(db)
                rba.process_all_hosts(org="")

                # Entity RBA - decay accumulated risk, raise escalated
                # notables for entities above threshold.
                notables: list = []  # defined unconditionally: referenced below
                try:
                    from backend.config import ENTITY_RISK_ENABLED
                    from backend.risk.entity_risk import EntityRiskManager

                    if ENTITY_RISK_ENABLED:
                        risk = EntityRiskManager(db)
                        if counter % 4 == 0:
                            risk.decay()
                        if counter % 6 == 0:
                            # Backfill: fold recent alerts into the risk store
                            # (idempotent - alerts already reflected are skipped),
                            # so entities keep accruing risk even when a detection
                            # cycle misses the alert-creation hook.
                            risk.sweep_entities_from_events(hours=24, org="")
                            notables = risk.escalate(org="")
                            if notables:
                                from backend.realtime import publish_alert

                                for notable in notables:
                                    try:
                                        publish_alert(notable.to_dict())
                                    except Exception as exc:
                                        logger.debug(
                                            "Failed to publish notable alert %s: %s",
                                            notable.to_dict().get("alert_id"), exc,
                                        )
                except Exception:
                    logger.exception("Entity RBA cycle failed")

                # Phase 7: create/update incidents from groups, correlations and risks.
                if phase4_groups or notables:
                    try:
                        from backend.incidents.engine import create_incident

                        findings: list[dict] = []
                        risks: list[dict] = (
                            [n.to_dict() for n in notables] if notables else []
                        )
                        alerts: list[dict] = [a.to_dict() for a in created]
                        result = create_incident(
                            db,
                            groups=[g.to_dict() for g in phase4_groups],
                            findings=findings,
                            risks=risks,
                            alerts=alerts,
                            actor="system",
                        )
                        if result.get("incident_created"):
                            logger.info(
                                "Phase 7 incident created: %s",
                                result.get("incident_id"),
                            )
                    except Exception:
                        logger.exception("Phase 7 incident creation failed")
                _mark("rba+incidents")
                # against the baselines; on "drift" retrain so the baseline
                # follows the environment. Retrains always use the FULL
                # collected history (hours=None) - the model must reflect
                # every event gathered, not a sample window.
                if counter % 120 == 0 and get_detector().is_ready:
                    try:
                        from backend.ml.drift import check_drift
                        from backend.ml.tasks import train_in_background

                        drift = check_drift(db, hours=12)
                        if drift.get("status") == "drift":
                            started = train_in_background(hours=None, kind="drift")
                            logger.warning(
                                "ML drift detected; background retrain %s",
                                "started" if started else "already running",
                            )
                        elif drift.get("status") == "watch":
                            started = train_in_background(
                                hours=None, kind="incremental"
                            )
                            logger.info(
                                "ML drift watch; background retrain %s",
                                "started" if started else "already running",
                            )
                    except Exception:
                        logger.exception("ML drift check failed")
                if counter % 2 == 0:  # every cycle (counter advances 2x/cycle)
                    # Phase 3: Online learning - incremental update via
                    # sliding-window buffer instead of full retrain.
                    # Consulted every cycle; should_update() owns the actual
                    # 15-minute wall-clock gate, because cycle durations vary
                    # too much (15-90 s) for a counter to mean "15 minutes".
                    try:
                        detector = get_detector()
                        if (
                            detector.online_learner is not None
                            and detector.online_learner.should_update()
                        ):
                            result = detector.online_learner.incremental_update(db)
                            logger.info(
                                "ML online update: updated=%s streams=%s "
                                "buffer=%s errors=%s",
                                result.get("updated"),
                                result.get("streams_updated"),
                                result.get("buffer_sizes"),
                                result.get("errors"),
                            )
                        elif detector.is_ready:
                            # Fallback: full retrain if online learner not ready
                            from datetime import UTC, datetime, timedelta

                            from sqlalchemy import func as _func

                            from backend.config import ML_INCREMENTAL_MIN_VERDICTS
                            from backend.database.models import Verdict as _Verdict

                            recent_verdicts = (
                                db.scalar(
                                    select(_func.count(_Verdict.id)).where(
                                        _Verdict.created_at
                                        >= datetime.now(UTC) - timedelta(hours=24)
                                    )
                                )
                                or 0
                            )
                            if recent_verdicts >= ML_INCREMENTAL_MIN_VERDICTS:
                                from backend.ml.tasks import train_in_background

                                started = train_in_background(
                                    hours=None, kind="incremental"
                                )
                                logger.info(
                                    "ML full retrain (%d verdicts in 24h, online "
                                    "learner not ready): %s",
                                    recent_verdicts,
                                    "started" if started else "already running",
                                )
                    except Exception:
                        logger.exception("ML online update failed")
                    from backend.database.retention import purge_old_data

                    purged = purge_old_data(db)
                    if any(purged.values()):
                        logger.info(
                            "Retention: purged %d old record(s)",
                            sum(purged.values()),
                        )
                    # Roadmap 3.3: the chained audit trail ages out on its own
                    # regulatory window (BARAQ_AUDIT_RETENTION_DAYS).
                    from backend.compliance import purge_old_audit
                    from backend.config import AUDIT_RETENTION_DAYS

                    if purge_old_audit(db, AUDIT_RETENTION_DAYS):
                        logger.info("Audit retention: old entries purged")
                if counter % 720 == 0:  # every ~3 hours: threat-intel feeds
                    # Roadmap 4.3: ingest configured STIX/TAXII/MISP/URL feeds
                    # into the intel cache; failure must not wedge the loop.
                    try:
                        from backend.intel.feeds import refresh_feeds

                        summary = refresh_feeds(db)
                        if summary["feeds"]:
                            logger.info("Threat-intel feed refresh: %s", summary)
                    except Exception:
                        logger.exception("Threat-intel feed refresh failed")
                if counter % 240 == 0:  # every ~1 hour: scheduled reports
                    # Roadmap 6.2: generate due reports (and email them when
                    # SMTP + recipients are configured).
                    try:
                        from backend.reports.schedule import run_due_schedules

                        summary = run_due_schedules(db)
                        if summary["due"]:
                            logger.info("Scheduled reports: %s", summary)
                    except Exception:
                        logger.exception("Scheduled reports failed")
            finally:
                _mark("rest")
                db.close()
        except Exception as exc:
            logger.exception("Scheduler cycle failed: %s", exc)
        finally:
            from backend.metrics import record_scheduler_cycle_seconds

            record_scheduler_cycle_seconds(time.monotonic() - cycle_start)
            if _timings:
                logger.info(
                    "Scheduler stages: %s",
                    " ".join(f"{label}={secs:.1f}s" for label, secs in _timings),
                )
        _scheduler_stop.wait(interval_seconds)
    logger.info("Scheduler stopped")


@asynccontextmanager
async def lifespan(app: FastAPI):
    import os

    from backend.realtime import hub

    hub.bind(asyncio.get_running_loop())
    init_db()
    _seed_admin_user()
    from backend.auth import prune_revoked_tokens

    prune_revoked_tokens()
    from backend.licensing import enforce_license

    db = SessionLocal()
    try:
        enforce_license(db)
    finally:
        db.close()
    from backend.config import TLS_ENABLED

    if (
        IS_PRODUCTION
        and not TLS_ENABLED
        and os.environ.get("BARAQ_ALLOW_PLAINTEXT_PROD", "0").lower()
        not in ("1", "true", "yes", "on")
    ):
        raise RuntimeError(
            "Production mode requires TLS: set BARAQ_TLS=1 with a valid "
            "certificate (BARAQ_TLS_CERT/BARAQ_TLS_KEY), or set "
            "BARAQ_ALLOW_PLAINTEXT_PROD=1 to override (not recommended)."
        )
    # Startup collector permission probe: report unreadable channels up
    # front (with the fix command) instead of failing silently each cycle.
    # Run in background thread so 24+ channel probes don't block startup.
    from backend.collectors.health import check_collector_permissions
    from backend.config import (
        ALL_EXTENDED_CHANNELS,
        POWERSHELL_CHANNELS,
        SECURITY_LOG_CHANNELS,
        SYSMON_CHANNELS,
    )

    def _bg_collector_check():
        check_collector_permissions(
            [
                *SECURITY_LOG_CHANNELS,
                *POWERSHELL_CHANNELS,
                *SYSMON_CHANNELS,
                *ALL_EXTENDED_CHANNELS,
            ]
        )

    threading.Thread(target=_bg_collector_check, daemon=True).start()
    # Capability banner: many high-value detections depend on the Sysmon channel.
    # When it is absent the platform silently loses in-memory / process-tree
    # coverage, so call it out loudly at startup (see red_team_validation.md #2/#4).
    from backend.collectors.sysmon import is_sysmon_available

    if not is_sysmon_available():
        logger.warning(
            "CAPABILITY GAP: Sysmon channel unavailable - in-memory credential "
            "access (T1003), parent-child process-tree anomalies (T1059/T1218) and "
            "file-delete churn detections are DISABLED. Install Sysmon with a "
            "full schema to restore full coverage."
        )
    from backend.locks import acquire_instance_lock, release_instance_lock

    global _scheduler_thread
    no_scheduler = os.environ.get("BARAQ_NO_SCHEDULER", "0").lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    # Roadmap 3.1: BARAQ_ROLE=api runs the API without a scheduler - the
    # scheduler lives in its own service (backend/scheduler_service.py).
    from backend.config import APP_ROLE, SCHEDULER_ENABLED

    if APP_ROLE not in ("all", "api", "scheduler"):
        logger.warning("BARAQ_ROLE=%s not recognised; treating as 'all'", APP_ROLE)
    no_scheduler = no_scheduler or not SCHEDULER_ENABLED or APP_ROLE == "api"
    scheduler_owner = True
    if SINGLE_INSTANCE and APP_ROLE != "api":
        from backend.database.connection import engine as app_engine

        scheduler_owner = acquire_instance_lock(app_engine)
        if not scheduler_owner:
            logger.critical(
                "Another BARAQ instance holds the instance lock; "
                "scheduler is DISABLED here (API reads still served). Start "
                "only one server or set BARAQ_SINGLE_INSTANCE=0."
            )
    if (
        scheduler_owner
        and not no_scheduler
        and (not _scheduler_thread or not _scheduler_thread.is_alive())
    ):
        _scheduler_stop.clear()
        from backend.config import COLLECT_INTERVAL_SECONDS

        _scheduler_thread = threading.Thread(
            target=_scheduler_loop, args=(COLLECT_INTERVAL_SECONDS,), daemon=True
        )
        _scheduler_thread.start()
    from backend.streaming import start as start_streaming

    start_streaming()
    from backend.monitor import data_quality as dq_monitor

    dq_monitor.start()
    logger.info(
        "BARAQ API is ready (profile=%s%s, scheduler=%s)",
        BARAQ_ENV,
        ", production gate active" if IS_PRODUCTION else "",
        "on" if scheduler_owner and not no_scheduler else "off",
    )
    if scheduler_owner and not no_scheduler:
        # The single-writer scheduler is a deliberate scalability
        # ceiling. Detection, RBA, entity-risk escalation, ML drift,
        # dataset sweeps and threat-intel refreshes all run
        # sequentially on the lock-holder; adding API replicas does
        # not increase detection throughput. Per-cycle duration is
        # tracked via baraq_scheduler_cycle_seconds on
        # /api/system/metrics -- a value persistently above
        # COLLECT_INTERVAL_SECONDS means the ceiling is being hit.
        logger.info(
            "Single-writer scheduler active (InstanceLock via %s); "
            "baraq_scheduler_cycle_seconds on /api/system/metrics is the "
            "ceiling signal.",
            "PostgreSQL advisory lock" if SINGLE_INSTANCE else "Redis SET NX EX",
        )
    yield
    _scheduler_stop.set()
    if _scheduler_thread:
        _scheduler_thread.join(timeout=5)
    try:
        from backend.monitor import data_quality as dq_monitor

        dq_monitor.stop()
    except Exception as exc:
        logger.debug("Failed to stop data quality monitor: %s", exc)
    release_instance_lock()
    logger.info("BARAQ API shut down")


app = FastAPI(
    title="BARAQ API",
    description=(
        "Intelligent Lightweight Security Operations Center Platform for "
        "Real-Time Windows Threat Detection and Incident Analysis"
    ),
    version="1.0.0",
    lifespan=lifespan,
    # Production profile hides the interactive API surface (schema leaks
    # endpoints/fields and invites attack-surface probing).
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "X-API-Key", "X-CSRF-Token", "Content-Type", "X-Org"],
    expose_headers=["X-Baraq-Code"],
)
app.add_middleware(GZipMiddleware, minimum_size=500)

# ---------------------------------------------------------------------------
# API hardening (roadmap 5.3): security headers, rate limiting, IP ACLs.
# Middleware order matters: the cheap IP/rate gates run before auth so
# unauthenticated floods are rejected without touching the key store.
# ---------------------------------------------------------------------------
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "X-XSS-Protection": "1; mode=block",
}

#: API responses carry no HTML/CSS/JS of their own, so the most restrictive
#: policy possible is used. The SPA page (and its hashed /assets/* files)
#: needs a policy that still allows the app to run: same-origin bundles,
#: the small inline bootstrap/fail-safe scripts in index.html, React's
#: inline style attributes, the data: favicon, the MFA QR-code images, and
#: the realtime WebSocket. Anything else stays blocked.
_API_CSP = "default-src 'none'; frame-ancestors 'none'"
_SPA_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https://api.qrserver.com; "
    "font-src 'self'; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
    "form-action 'self'; base-uri 'self'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    if SECURITY_HEADERS:
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if HSTS_MAX_AGE > 0:
            response.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={HSTS_MAX_AGE}",
            )
        # The SPA mount at "/" serves the entry HTML plus its assets; every
        # other path (API, reports, docs) is not browser-rendered app code
        # and keeps the lock-down policy.
        csp = _SPA_CSP if not request.url.path.startswith("/api/") else _API_CSP
        response.headers.setdefault("Content-Security-Policy", csp)
    return response


#: Rate limiting: delegated to backend.redis which uses Redis when
#: available and falls back to in-memory dicts for single-node dev.
from backend import redis as _redis_mod
from backend.redis import rate_cleanup, rate_increment

#: Back-compat alias: hardening tests clear the in-memory bucket via
#: ``backend.main._rate_buckets`` (same object as redis._rate_buckets).
_rate_buckets = _redis_mod._rate_buckets

RATE_WINDOW_SECONDS = 60


def _client_identity(request: Request) -> str:
    key = request.headers.get("X-API-Key", "") or (
        request.headers.get("Authorization", "")[:32]
    )
    return key or client_ip(request)


def _ip_allowed(request: Request) -> bool:
    """Enforce BARAQ_API_IP_BLOCKLIST / BARAQ_API_IP_WHITELIST (CIDRs)."""
    from backend.config import API_IP_BLOCKLIST, API_IP_WHITELIST

    if not API_IP_BLOCKLIST and not API_IP_WHITELIST:
        return True
    import ipaddress

    remote = client_ip(request)
    try:
        addr = ipaddress.ip_address(remote)
    except ValueError:
        return False
    for block in API_IP_BLOCKLIST:
        if addr in ipaddress.ip_network(block, strict=False):
            return False
    if API_IP_WHITELIST:
        for allow in API_IP_WHITELIST:
            if addr in ipaddress.ip_network(allow, strict=False):
                return True
        return False
    return True


def _rate_allowed(request: Request, identity: str) -> tuple[bool, int]:
    """Fixed-window rate gate; returns (allowed, retry_after_seconds)."""
    from backend.config import API_RATE_BURST, API_RATE_LIMIT

    if API_RATE_LIMIT <= 0:
        return True, 0
    count, remaining = rate_increment(identity, RATE_WINDOW_SECONDS)
    if count > API_RATE_BURST:
        return False, max(1, int(remaining) + 1)
    rate_cleanup()
    return True, 0


@app.middleware("http")
async def api_gates(request: Request, call_next):
    """IP ACLs (403) and API rate limiting (429) before authentication."""
    if request.method == "OPTIONS":
        logger.debug("CORS preflight: %s %s", request.method, request.url.path)
    path = request.url.path
    if path.startswith("/api/") and not path.startswith(
        ("/api/health", "/api/auth/login")
    ):
        if not _ip_allowed(request):
            return JSONResponse(
                {"detail": "Client IP not permitted"},
                status_code=403,
            )
        allowed, retry_after = _rate_allowed(request, _client_identity(request))
        if not allowed:
            return JSONResponse(
                {
                    "detail": "API rate limit exceeded",
                    "retry_after_seconds": retry_after,
                },
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
    response = await call_next(request)
    try:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
    except Exception:
        pass
    return response


# ---------------------------------------------------------------------------
# API key authentication (RBAC). Every /api/* request must carry a valid
# X-API-Key; the resolved role is stored on request.state for the endpoint
# role dependencies (require_auth / require_admin in backend/security.py).
# Health, docs and static mounts are excluded.
# ---------------------------------------------------------------------------
_PUBLIC_PREFIXES = (
    "/api/health",
    "/api/version",
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/mfa/verify",
    "/api/auth/refresh",
    "/api/auth/password-reset",
    "/api/auth/oidc/login",
    "/api/auth/oidc/callback",
    "/api/auth/oidc/status",
    "/docs",
    "/openapi.json",
    "/redoc",
)
#: Routes that authenticate with their own scheme (X-Agent-Key) instead of X-API-Key.
_AGENT_PATHS = ("/api/ingest", "/api/commands/")
#: Methods that change server state; cookie-authenticated calls to these must
#: carry a valid CSRF token (see api_key_auth below).
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_CSRF_HEADER = "X-CSRF-Token"


def _csrf_token_matches(request: Request) -> bool:
    """Double-submit CSRF check: the X-CSRF-Token header must equal the
    baraq_csrf cookie value (constant-time compare). Only meaningful for
    cookie-authenticated browser sessions."""
    from backend.config import CSRF_ENABLED

    if not CSRF_ENABLED:
        return True
    cookie = request.cookies.get("baraq_csrf", "")
    header = request.headers.get(_CSRF_HEADER, "")
    if not cookie or not header:
        return False
    import hmac

    return hmac.compare_digest(cookie, header)


def _session_still_valid(payload: dict) -> bool:
    """Fail-closed liveness and freshness check for a Bearer session."""
    from backend.database.models import User

    uid = payload.get("uid")
    if not isinstance(uid, int):
        return False
    db = SessionLocal()
    try:
        user = db.get(User, uid)
        return bool(user and user.is_active and session_fresh_for_user(payload, user))
    except Exception:
        logger.warning("Session liveness check failed (fail-closed)", exc_info=True)
        return False
    finally:
        db.close()


@app.middleware("http")
async def api_key_auth(request: Request, call_next):
    path = request.url.path
    if (
        AUTH_ENABLED
        and path.startswith("/api/")
        and not path.startswith(_PUBLIC_PREFIXES)
        and not path.startswith(_AGENT_PATHS)
    ):
        # New session-token auth: Authorization: Bearer <token> (or the
        # httpOnly session cookie set at login, so the token never touches JS).
        authorization = request.headers.get("Authorization", "")
        from_cookie = False
        if not authorization.lower().startswith("bearer "):
            session = request.cookies.get("baraq_session", "")
            if session:
                authorization = f"Bearer {session}"
                from_cookie = True
        if from_cookie and not config.CSRF_ENABLED:
            logger.warning("CSRF protection disabled via BARAQ_CSRF_ENABLED=0")
        if authorization.lower().startswith("bearer "):
            secret = authorization[7:].strip()
            payload = verify_token(secret, expected_type="access")
            if payload and not _session_still_valid(payload):
                payload = None
            if not payload:
                # Prometheus-style scrapers send the shared key as a Bearer
                # secret (Prometheus v3 no longer supports custom headers).
                role = API_KEYS.get(secret)
                if not role:
                    return JSONResponse(
                        {"detail": "Invalid or expired session token"},
                        status_code=401,
                    )
                request.state.api_role = role
                request.state.token_user = None
                return await call_next(request)
            request.state.api_role = payload.get("role", "analyst")
            request.state.token_user = payload
            # CSRF: when the session came from the cookie (browser flow),
            # state-changing calls must echo the double-submit token. API
            # callers with an explicit Authorization header cannot be CSRF'd.
            if (
                from_cookie
                and request.method in _STATE_CHANGING_METHODS
                and not _csrf_token_matches(request)
            ):
                return JSONResponse(
                    {"detail": "CSRF token missing or invalid (X-CSRF-Token)"},
                    status_code=403,
                )
        else:
            key = request.headers.get("X-API-Key", "").strip()
            role = API_KEYS.get(key)
            if not role:
                return JSONResponse(
                    {"detail": "Missing or invalid API key (X-API-Key header)"},
                    status_code=401,
                )
            request.state.api_role = role
            request.state.token_user = None
    elif AUTH_ENABLED:
        request.state.api_role = "admin"
    else:
        request.state.api_role = "admin"
    return await call_next(request)


@app.middleware("http")
async def request_body_limit(request: Request, call_next):
    """Reject oversized bodies (413) before routing or parsing them.

    Checks Content-Length when present and also guards chunked/streamed
    bodies whose final size is unknown up front.
    """
    from backend.config import MAX_REQUEST_BYTES

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(
                    {"detail": f"Request body exceeds {MAX_REQUEST_BYTES} bytes"},
                    status_code=413,
                )
        except ValueError:
            pass  # malformed Content-Length is handled by the server

    receive = request._receive
    received = 0

    async def limited_receive():
        nonlocal received
        message = await receive()
        if message["type"] == "http.request":
            received += len(message.get("body", b""))
            if received > MAX_REQUEST_BYTES:
                raise _BodyTooLargeError()
        return message

    request._receive = limited_receive
    try:
        return await call_next(request)
    except _BodyTooLargeError:
        return JSONResponse(
            {"detail": f"Request body exceeds {MAX_REQUEST_BYTES} bytes"},
            status_code=413,
        )


class _BodyTooLargeError(Exception):
    """Raised by the receive wrapper when a streamed body exceeds the cap."""


@app.exception_handler(_BodyTooLargeError)
async def _body_too_large_handler(request, exc):
    from backend.config import MAX_REQUEST_BYTES
    return JSONResponse(
        {"detail": f"Request body exceeds {MAX_REQUEST_BYTES} bytes"},
        status_code=413,
    )


for router in (
    dashboard.router,
    alerts.router,
    events.router,
    investigation.router,
    reports.router,
    assistant.router,
    evaluation.router,
    system.router,
    endpoints.router,
    incidents.router,
    incidents_v2.router,
    intel.router,
    integrations.router,
    hunting.router,
    graph.router,
    rba.router,
    ml_dataset_import.router,
    auth.router,
    realtime.router,
    compliance.router,
    search.router,
    automation.router,
    saved.router,
    dataset.router,
    telemetry.router,
    detections.router,
    detections.detectors_router,
    alerting.router,
    approval.router,
    bookmarks.router,
    behavior_groups.router,
    correlations.router,
    risk.router,
    export.router,
    ueba_api.router,
    insider_threat_api.router,
    fleet_api.router,
    mitre_gap_api.router,
    attack_path_api.router,
):
    app.include_router(router)

#: Allowlisted agent-distribution files (never mount the whole scripts/ tree).
_SCRIPTS_ROOT = Path(__file__).resolve().parent.parent / "scripts"
_AGENT_DIST_ALLOW = {
    "agent.py": "text/x-python",
    # Self-contained collector: the default agent for fleet rollouts, so it
    # must be downloadable or a remote one-liner install has nothing to fetch.
    "agent.ps1": "text/plain",
    "install_agent.ps1": "text/plain",
    "agent_updater.ps1": "text/plain",
    "baraq.crt": "application/x-pem-file",
    "cert": "application/x-pem-file",
}


@app.get("/scripts/{filename}")
async def serve_agent_dist(filename: str) -> Response:
    """Serve agent installer files to LAN endpoints.

    Only an allowlist is exposed: the agent scripts, the installer/updater and
    the public TLS certificate. The rest of scripts/ (provisioning, vault
    tools) is intentionally not downloadable.
    """
    name = filename.lower()
    if name not in _AGENT_DIST_ALLOW:
        raise HTTPException(status_code=404, detail="not found")
    # cert / baraq.crt both resolve to certs/baraq.crt
    if name in ("baraq.crt", "cert"):
        from backend.config import TLS_CERT_FILE

        path = Path(TLS_CERT_FILE)
    else:
        path = _SCRIPTS_ROOT / name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="not found")
    media = _AGENT_DIST_ALLOW[name]
    if name.endswith(".ps1"):
        media = "text/plain; charset=utf-8"
    return FileResponse(path, media_type=media)


def _safe_exc_msg(exc: Exception, max_len: int = 120) -> str:
    """Return a truncated, safe string of an exception for logging only."""
    raw = str(exc)
    if len(raw) > max_len:
        return raw[:max_len] + "..."
    return raw


@app.get("/api/health")
def health():
    """Readiness endpoint: checks critical dependencies.
    Returns 200 if ready, 503 if not ready.
    """
    checks = {}
    overall_status = "ok"
    status_code = 200

    # Database check with connection pool status
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        # Get pool status
        pool = db.get_bind().pool
        pool_status = {
            "size": pool.size(),
            "checked_in": pool.checkedin(),
            "checked_out": pool.checkedout(),
            "overflow": pool.overflow(),
        }
        checks["database"] = {
            "status": "ok",
            "message": "Database connection successful",
            "pool": pool_status,
        }
    except Exception as e:
        import logging as _log
        _log.getLogger("baraq.health").warning("Health DB check failed: %s", _safe_exc_msg(e))
        checks["database"] = {"status": "error", "message": "Database connection failed"}
        overall_status = "error"
        status_code = 503

    # ML model check (if ML is enabled) - WARNING only, never blocks startup
    if settings.ml_rule_weight > 0 or settings.ml_detection_weight > 0:
        try:
            from backend.ml.anomaly import get_detector

            if get_detector().is_ready:
                checks["ml_model"] = {"status": "ok", "message": "ML model is ready"}
            else:
                checks["ml_model"] = {
                    "status": "warning",
                    "message": "ML model not trained yet (will train on first data cycle)",
                }
                if overall_status == "ok":
                    overall_status = "warning"
        except Exception as e:
            import logging as _log
            _log.getLogger("baraq.health").warning("ML model check failed: %s", _safe_exc_msg(e))
            checks["ml_model"] = {
                "status": "warning",
                "message": "ML model check skipped",
            }
            if overall_status == "ok":
                overall_status = "warning"
    else:
        checks["ml_model"] = {
            "status": "skipped",
            "message": "ML model check skipped (ML weights are zero)",
        }

    # Data quality check
    from backend.collectors.quality import quality, status_for_rate

    rate = quality.window_rate()
    data_quality_status = "ok"
    if rate >= settings.data_quality_warn_rate:
        data_quality_status = "warning"
    if rate >= settings.data_quality_critical_rate:
        data_quality_status = "error"
        # Note: data quality error does not make the service unready (503) by default
        # but we can change this if needed. For now, we'll keep it as a warning/error in the check.
    checks["data_quality"] = {
        "status": data_quality_status,
        "corruption_rate": str(round(rate, 4)),
        "status_message": status_for_rate(rate),
    }
    if data_quality_status == "error" and overall_status == "ok":
        overall_status = "warning"

    # Single instance check. The lock is only meaningful for the process that
    # owns the scheduler: an api-only replica (BARAQ_ROLE=api) or a run with
    # the scheduler disabled is *supposed* not to hold it, so that is reported
    # as informational instead of an error - otherwise a correctly scaled
    # deployment shows a permanent false alarm on /api/health.
    from backend.config import APP_ROLE as _APP_ROLE, SCHEDULER_ENABLED as _SCHED_ENABLED
    from backend.locks import instance_lock_status

    lock_status = instance_lock_status()
    instance_locked = bool(lock_status.get("held"))
    expects_lock = bool(_SCHED_ENABLED) and _APP_ROLE != "api"
    if instance_locked:
        lock_state, lock_message = "ok", "Instance lock acquired"
    elif expects_lock:
        lock_state, lock_message = "error", "Instance lock not acquired"
    else:
        lock_state = "ok"
        lock_message = (
            "Instance lock not held (scheduler disabled or api-only role) - "
            "another instance owns the scheduler"
        )
    checks["single_instance"] = {"status": lock_state, "message": lock_message}
    if lock_state == "error" and overall_status == "ok":
        overall_status = "warning"

    # If we have any critical errors (database or ml_model), we already set status_code to 503
    # and overall_status to "error". Otherwise, we return 200 with the overall status.

    _no_cache = {
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
    }
    health_body = {
        "status": overall_status,
        "checks": checks,
        "data_quality": {
            "status": status_for_rate(rate),
            "corruption_rate": round(rate, 4),
        },
        "feature_flags": {
            "telemetry_v2": config.TELEMETRY_V2_ENABLED,
            "alerts_v2": config.ALERTS_V2_ENABLED,
            "correlation": config.CORRELATION_ENABLED,
            "risk": config.RISK_ENABLED,
        },
    }

    if status_code == 200:
        return JSONResponse(content=health_body, headers=_no_cache)
    else:
        return JSONResponse(
            status_code=status_code,
            content=health_body,
            headers=_no_cache,
        )


@app.get("/api/live")
def liveness():
    """Liveness endpoint: returns 200 if the application is running.
    This is a lightweight endpoint that does not check dependencies.
    """
    return {"status": "ok"}


@app.get("/api/version")
def version():
    """Public version endpoint: returns the current build version.

    Kept in step with the release recorded in CHANGELOG.md. It previously
    reported ``0.13.0`` while the project was at 1.0.8, which is worse than
    having no endpoint at all: an operator checking a deployment would be told
    it was running a seven-release-old build.
    """
    return {"version": "1.0.8", "build": "v6-phase2"}


@app.get("/metrics")
def prometheus_metrics(db: Session = Depends(get_db)):
    """Public Prometheus scrape target. Requires BARAQ_METRICS_PUBLIC=1
    (otherwise a scraper must use the authenticated /api/system/metrics route)."""
    from fastapi.responses import Response

    if not METRICS_PUBLIC:
        raise HTTPException(status_code=401, detail="Metrics endpoint is private")
    from backend.metrics import collect_metrics

    return Response(collect_metrics(db), media_type="text/plain; version=0.0.4")


# ---------------------------------------------------------------------------
# Serve the built React SPA (single-command deployment). Registered last so the
# API routes above always take precedence; unknown paths fall back to
# index.html to support client-side routing.
# ---------------------------------------------------------------------------
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


_ASSET_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript",
    ".css": "text/css",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
}


class _SPAMount(StaticFiles):
    """Serve the built SPA, falling back to index.html for client routes.

    Cache policy (prevents the "black screen" symptom caused by a stale
    cached index.html referencing hashed assets that no longer exist):
      * index.html (and any SPA fallback) -> ``no-store``; the browser must
        always fetch the latest entry point so it picks up new asset hashes.
      * /assets/* built files are content-hashed by Vite -> immutable caching.
    """

    def _apply_cache(self, path: str, response) -> Response:
        # ``path`` may arrive with a leading slash and, on Windows, as a native
        # path using backslashes (e.g. ``assets\\index-...js``).
        normalized = path.replace("\\", "/").lstrip("/")
        if normalized.startswith("assets/"):
            # Hashed by Vite: safe to cache forever in the browser.
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        else:
            # The SPA entry point must never be cached so the browser always
            # picks up the latest hashed asset references.
            response.headers["Cache-Control"] = "no-store"
        return response

    async def get_response(self, path: str, scope):
        try:
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code == 404:
                # Production profile: the interactive API surface is disabled
                # at construction; don't let the SPA fallback present those
                # known paths as valid routes (masked 200s are probe bait).
                if IS_PRODUCTION and path.lstrip("/").lower() in (
                    "docs",
                    "redoc",
                    "openapi.json",
                ):
                    raise
                index = FRONTEND_DIST / "index.html"
                if index.is_file():
                    return self._apply_cache(
                        "index.html",
                        FileResponse(index, media_type="text/html; charset=utf-8"),
                    )
            raise
        return self._apply_cache(path, response)


if FRONTEND_DIST.is_dir():

    @app.get("/{full_path:path}")
    async def _spa_fallback(full_path: str):

        stripped = full_path.strip("/").replace("\\", "/")
        static_file = FRONTEND_DIST / stripped
        if stripped:
            resolved = static_file.resolve()
            if not str(resolved).startswith(str(FRONTEND_DIST.resolve())):
                raise HTTPException(status_code=404, detail="Not Found")
        if stripped and static_file.is_file():
            ext = static_file.suffix.lower()
            ct = _ASSET_TYPES.get(ext, "application/octet-stream")
            resp = FileResponse(static_file, media_type=ct)
            if stripped.startswith("assets/"):
                # Content-hashed by Vite: safe to cache forever.
                resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            else:
                resp.headers["Cache-Control"] = "no-store"
            return resp
        index = FRONTEND_DIST / "index.html"
        if index.is_file():
            resp = FileResponse(index, media_type="text/html; charset=utf-8")
            resp.headers["Cache-Control"] = "no-store"
            return resp
        raise HTTPException(status_code=404, detail="Not Found")

    app.mount(
        "/assets",
        _SPAMount(directory=str(FRONTEND_DIST / "assets")),
        name="static-assets",
    )
