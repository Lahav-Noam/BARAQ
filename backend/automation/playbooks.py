"""SOAR automation playbooks - the BARAQ equivalent of a commercial SOAR.

Analysts define playbooks (name, trigger conditions, ordered actions) either
from the UI or the API; the detection pipeline fires them automatically
against every new alert that matches the triggers. Actions reuse the same
safe, idempotent execution helpers as the alert actions endpoint
(``backend.api.alerts``), so an action behaves identically whether an
analyst clicks it or a playbook runs it.

Trigger conditions (all dimensions AND together, values OR within a
dimension)::

    triggers:
      rules: [brute_force, pass_the_hash]   # any of these rule ids
      severity: [high, critical]            # any of these severities
      tactics: [Credential Access]          # any of these MITRE tactics
      min_risk_level: HIGH                  # risk_level at least this

Supported actions (in order of declaration):
    block_ip, kill_process, quarantine, isolate, disable_account, escalate,
    acknowledge, fix, create_incident, notify
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import DESTRUCTIVE_ACTIONS, SOAR_DESTRUCTIVE_ACTIONS_ENABLED
from backend.database.models import (
    Alert,
    AutomationPlaybook,
    Incident,
    PlaybookRun,
)

logger = logging.getLogger("baraq.automation")

#: Actions with side effects beyond bookkeeping - safe, reversible stubs by
#: default, overridable by the operator (see backend.api.alerts).
ACTION_KEYS = (
    "block_ip",
    "kill_process",
    "quarantine",
    "isolate",
    "disable_account",
    "escalate",
    "acknowledge",
    "fix",
    "create_incident",
    "notify",
)

_RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def validate_playbook(triggers: dict, actions: list) -> tuple[dict, list]:
    """Validate / normalize trigger conditions and actions.

    Raises ``ValueError`` on malformed input (mapped to HTTP 400 by the API).
    """
    if not isinstance(triggers, dict):
        raise ValueError("triggers must be a mapping")
    if not isinstance(actions, list) or not actions:
        raise ValueError("actions must be a non-empty list")
    normalized_actions = []
    for i, raw in enumerate(actions):
        if isinstance(raw, str):
            raw = {"action": raw}
        if not isinstance(raw, dict) or not isinstance(raw.get("action"), str):
            raise ValueError(f"actions[{i}] must be an action object or string")
        action = raw["action"].strip().lower()
        if action not in ACTION_KEYS:
            raise ValueError(f"actions[{i}] unknown action {action!r}")
        normalized_actions.append({"action": action})
    known = {"rules", "severity", "tactics", "min_risk_level"}
    unknown = set(triggers) - known
    if unknown:
        raise ValueError(f"unknown trigger key(s): {', '.join(sorted(unknown))}")
    for key in ("rules", "severity", "tactics"):
        values = triggers.get(key)
        if values is None:
            continue
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or not values:
            raise ValueError(f"trigger {key} must be a non-empty list")
        triggers = dict(triggers)
        triggers[key] = [str(v) for v in values]
    min_risk = triggers.get("min_risk_level")
    if min_risk is not None:
        min_risk = str(min_risk).upper()
        if min_risk not in _RISK_ORDER:
            raise ValueError("min_risk_level must be LOW/MEDIUM/HIGH/CRITICAL")
        triggers = dict(triggers)
        triggers["min_risk_level"] = min_risk
    return triggers, normalized_actions


def matches(alert: Alert, triggers: dict) -> bool:
    """Does an alert satisfy the playbook's trigger conditions?"""
    rules = triggers.get("rules") or []
    if rules and (alert.rule or "") not in rules:
        return False
    severities = triggers.get("severity") or []
    if severities and (alert.severity or "").lower() not in [
        s.lower() for s in severities
    ]:
        return False
    tactics = triggers.get("tactics") or []
    if tactics and (alert.mitre_tactic or "") not in tactics:
        return False
    min_risk = triggers.get("min_risk_level")
    return not (
        min_risk
        and _RISK_ORDER.get((alert.risk_level or "LOW").upper(), 0)
        < _RISK_ORDER[min_risk]
    )


def _execute_one(db: Session, alert: Alert, action: str) -> tuple[str, str]:
    """Run one action against an alert; returns (status, detail)."""
    from backend.api.alerts import _execute_action, _extract_target

    # Phase 0.12: destructive actions are SIMULATED unless explicitly enabled.
    if action in DESTRUCTIVE_ACTIONS and not SOAR_DESTRUCTIVE_ACTIONS_ENABLED:
        target = _extract_target(alert, action)
        return "success", (
            f"SIMULATED {action} on {target!r} - destructive SOAR actions "
            "disabled (BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED=0)."
        )

    if action == "create_incident":
        existing = db.scalars(
            select(Incident).where(
                Incident.org == (alert.org or ""),
                Incident.status == "open",
                Incident.title == f"Playbook incident: {alert.name}",
            )
        ).first()
        if existing:
            return "success", f"Open incident #{existing.id} already tracks this alert."
        incident = Incident(
            title=f"Playbook incident: {alert.name}",
            description=(
                f"Automatically opened by a playbook for {alert.rule} "
                f"({alert.mitre_id} {alert.mitre_tactic}). {alert.evidence[:300]}"
            ),
            severity=alert.severity,
            status="open",
            host=alert.host,
            org=alert.org or "",
            risk_score=alert.risk_score or 0.0,
            risk_level=(alert.risk_level or "MEDIUM").upper(),
            mitre_id=alert.mitre_id,
            mitre_name=alert.mitre_name,
        )
        db.add(incident)
        db.flush()
        return "success", f"Incident #{incident.id} opened from alert #{alert.id}."
    if action == "notify":
        from backend.notify import notify_alert

        try:
            notify_alert(alert.to_dict())
        except Exception as exc:
            return "failed", f"Notification channel error: {exc}"
        return "success", "Analyst notified out-of-band."

    # ── SOAR approval gate (P1) ────────────────────────────────────────────
    # Destructive actions executed by playbooks also require an APPROVED
    # request before they reach the agent.
    if action in DESTRUCTIVE_ACTIONS:
        from backend.response.approval import (
            ApprovalRequest,
            workflow,
        )

        action_params = {"action": action, "target": _extract_target(alert, action)}
        if not workflow.is_approved(action, action_params):
            existing = workflow.pending_for(action, action_params)
            if existing is None:
                existing = workflow.create_request(
                    ApprovalRequest(
                        action_type=action,
                        action_params=action_params,
                        requested_by=triggered_by,
                        justification="Auto-fired by playbook "
                        f"'{playbook.name}' on alert #{alert.id}",
                        approvers_required=1,
                    )
                )
            return "pending_approval", (
                f"Destructive action {action} requires approval "
                f"(request #{existing.id}) before execution"
            )

    target = _extract_target(alert, action)
    return _execute_action(action, target)


def run_playbook(
    db: Session,
    playbook: AutomationPlaybook,
    alert: Alert,
    triggered_by: str = "auto",
) -> PlaybookRun:
    """Execute one playbook against one alert and log the run."""
    results: list[dict[str, str]] = []
    statuses = []
    for step in playbook.actions or []:
        action = step.get("action", "") if isinstance(step, dict) else str(step)
        try:
            status, detail = _execute_one(db, alert, action)
        except Exception as exc:
            logger.exception("Playbook '%s' action %s failed", playbook.name, action)
            status, detail = "failed", f"error: {exc}"
        results.append({"action": action, "status": status, "detail": detail})
        statuses.append(status)
        logger.info(
            "Playbook '%s' on alert #%s: %s -> %s (%s)",
            playbook.name,
            alert.id,
            action,
            status,
            detail[:120],
        )
    overall = (
        "completed"
        if all(s == "success" for s in statuses)
        else "failed" if all(s == "failed" for s in statuses) else "partial"
    )
    run = PlaybookRun(
        playbook_id=playbook.id,
        alert_id=alert.id,
        playbook_name=playbook.name,
        alert_name=alert.name,
        rule=alert.rule,
        org=alert.org or "",
        results=results,
        status=overall,
        triggered_by=triggered_by,
    )
    db.add(run)
    db.flush()
    return run


def find_matching_playbooks(db: Session, alert: Alert) -> list[AutomationPlaybook]:
    """Enabled playbooks whose triggers match the alert (deterministic order)."""
    playbooks = db.scalars(
        select(AutomationPlaybook).where(AutomationPlaybook.enabled.is_(True))
    ).all()
    return [
        p
        for p in sorted(playbooks, key=lambda p: p.id)
        if matches(alert, p.triggers or {})
    ]


def fire_playbooks(
    db: Session, alert: Alert, triggered_by: str = "auto"
) -> list[PlaybookRun]:
    """Run every matching playbook for one alert; never raises."""
    runs: list[PlaybookRun] = []
    try:
        for playbook in find_matching_playbooks(db, alert):
            runs.append(run_playbook(db, playbook, alert, triggered_by=triggered_by))
        if runs:
            db.commit()
            try:
                from backend.audit import log_action

                for run in runs:
                    log_action(
                        db,
                        "system",
                        "playbook.auto",
                        "playbook",
                        str(run.playbook_id),
                        f"Auto-fired '{run.playbook_name}' on alert #{run.alert_id} "
                        f"({run.rule}) -> {run.status}",
                    )
            except Exception:
                logger.exception("Playbook audit logging failed")
    except Exception:
        logger.exception("Automation playbook pass failed for alert #%s", alert.id)
        db.rollback()
    return runs
