"""SQLAlchemy ORM models for the BARAQ local database (PostgreSQL)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON, TypeDecorator


class JSONColumnType(TypeDecorator):
    """JSON column that compiles to ``jsonb`` on PostgreSQL.

    Plain ``json`` has no equality operator in PostgreSQL, so GROUP BY /
    distinct on JSON columns requires ``jsonb``. Being a ``TypeDecorator``
    the choice follows the engine dialect at compile time.
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import JSONB

            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class EncryptedColumn(TypeDecorator):
    """AES-256-GCM field-level encryption applied transparently on write/read.

    Encrypts on ``bind`` (any non-empty string) and decrypts on ``result``.
    Legacy plaintext values are returned unchanged, so pre-hardening rows and
    development databases keep working. Queries that filter/group on these
    columns are NOT supported (encryption prevents index lookups) — the
    caller must filter in Python on loaded rows (which all rules already do).
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            value = json.dumps(value, default=str)
        from backend.crypto import encrypt_text

        return encrypt_text(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        from backend.crypto import decrypt_text

        return decrypt_text(value)


def utcnow() -> datetime:
    return datetime.now(UTC)


def canonical_timestamp(ts: datetime | None) -> str:
    """Normalise a timestamp to a deterministic UTC string (no microseconds).

    The same instant must hash identically at write time and read time, so
    timestamps are canonicalised regardless of the timezone they carry.
    """
    if ts is None:
        return ""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC).replace(microsecond=0).isoformat()


class Base(DeclarativeBase):
    pass


class User(Base):
    """An operator/analyst account. Passwords are stored as salted PBKDF2
    hashes; role is either ``admin`` or ``analyst``.

    Two-factor authentication (TOTP, see ``backend/totp.py``): ``totp_secret``
    holds the base32 shared secret (encrypted at rest) and ``totp_enabled``
    gates the second step on login. Operators provision 2FA via
    ``/api/auth/mfa/*``.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(16), default="analyst")  # admin | analyst
    #: Tenant scoping: "" (system/central), an organization id, or "all" for
    #: admins who must oversee every tenant. Analysts are pinned to their org.
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Self-service registration state: "" (normal), "pending" (awaiting admin
    #: verification), "rejected". Pending accounts are inactive until approved.
    registration_status: Mapped[str] = mapped_column(String(16), default="", index=True)
    totp_secret: Mapped[str] = mapped_column(EncryptedColumn(), default="")  # User
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    #: True while the account still signs in with the default bootstrap
    #: password; the console forces a change before the account is usable.
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    #: Timestamp of last password change. Tokens issued before this time
    #: are rejected, so a password change immediately invalidates all sessions.
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Session epoch watermark. Access tokens must be issued strictly after
    #: this instant; NULL means no session-wide invalidation has occurred.
    sessions_valid_after: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "org": self.org,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "registration_status": self.registration_status,
            "totp_enabled": self.totp_enabled,
            "must_change_password": bool(self.must_change_password),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": (
                self.last_login_at.isoformat() if self.last_login_at else None
            ),
        }


class AuditLog(Base):
    """Immutable trail of who did what, when. Wired into login, alert actions,
    command dispatch, report generation and user management.

    Tamper-evidence: every entry carries ``prev_hash`` (SHA-256 of the
    canonical form of the previous entry) and ``hash`` (SHA-256 of this
    entry's canonical form chained to ``prev_hash``). Altering any historical
    row breaks the chain and is detectable (see ``backend/audit.verify_chain``).
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(
        String(64), index=True
    )  # username / api key / system
    action: Mapped[str] = mapped_column(
        String(64), index=True
    )  # login, alert.status, command.queue, ...
    entity_type: Mapped[str] = mapped_column(String(32), default="")
    entity_id: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(EncryptedColumn(), default="")  # AuditLog
    ip: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    #: SHA-256 of the previous audit entry's canonical form ("0"*64 for genesis).
    prev_hash: Mapped[str] = mapped_column(String(64), default="0" * 64)
    #: SHA-256 chain hash of this entry.
    hash: Mapped[str] = mapped_column(String(64), default="0" * 64)

    def canonical(self) -> str:
        """Deterministic string hashed to build the chain."""
        ts = canonical_timestamp(self.created_at)
        return "|".join(
            [
                self.prev_hash or "",
                self.actor or "",
                self.action or "",
                self.entity_type or "",
                self.entity_id or "",
                self.detail or "",
                self.ip or "",
                ts,
            ]
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "actor": self.actor,
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "detail": self.detail,
            "ip": self.ip,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "hash": self.hash,
            "prev_hash": self.prev_hash,
        }


class NormalizedEvent(Base):
    """A normalised security event, the atomic unit of the pipeline.

    Raw Windows events from every collector are converted into this shape:
    Event ID / Category / User / Risk / Timestamp / Host / Message / Raw.
    """

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[int] = mapped_column(Integer, index=True, default=0)
    category: Mapped[str] = mapped_column(String(64), index=True, default="Other")
    source: Mapped[str] = mapped_column(String(32), index=True, default="unknown")
    user: Mapped[str] = mapped_column(String(128), index=True, default="-")
    host: Mapped[str] = mapped_column(String(128), default="-")
    #: Tenant scoping: telemetry from remote agents is tagged with the
    #: organization the agent key belongs to; "" is the local/system host.
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    #: Demo/test marker: rows created by the demo seeder are tagged so they
    #: never mix into the production alert queue unless the analyst
    #: explicitly switches the console into demo mode (``include_demo=1``).
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    risk: Mapped[str] = mapped_column(String(16), index=True, default="Low")
    severity: Mapped[str] = mapped_column(String(16), index=True, default="info")
    message: Mapped[str] = mapped_column(
        EncryptedColumn(), default=""
    )  # NormalizedEvent
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    #: Data-integrity status: "complete" or "truncated" when the collector or
    #: message formatter lost part of the event (detail in raw_json["data_integrity"]).
    data_integrity: Mapped[str] = mapped_column(
        String(16), default="complete", index=True
    )
    raw_json: Mapped[dict | None] = mapped_column(JSONColumnType, nullable=True)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    @property
    def facts(self) -> dict:
        """Safely parsed facts dict from raw_json (handles str or dict)."""
        rj = self.raw_json
        if rj is None:
            return {}
        if isinstance(rj, dict):
            return rj.get("facts") or {}
        if isinstance(rj, str):
            try:
                import json
                return (json.loads(rj) or {}).get("facts") or {}
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}

    @property
    def parsed_json(self) -> dict:
        """Safely parsed raw_json (handles str or dict)."""
        rj = self.raw_json
        if rj is None:
            return {}
        if isinstance(rj, dict):
            return rj
        if isinstance(rj, str):
            try:
                import json
                return json.loads(rj) or {}
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)

    verdict: Mapped[Verdict | None] = relationship(
        "Verdict", back_populates="event", uselist=False, passive_deletes=True
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "category": self.category,
            "source": self.source,
            "user": self.user,
            "host": self.host,
            "org": self.org,
            "demo": self.demo,
            "risk": self.risk,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "message": self.message,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "data_integrity": self.data_integrity,
            "raw": self.raw_json,
            "is_anomaly": self.is_anomaly,
            "ml_score": self.ml_score,
        }


class Alert(Base):
    """A detection alert enriched with MITRE ATT&CK mapping."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True, default="medium")
    status: Mapped[str] = mapped_column(String(16), index=True, default="open")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    mitre_id: Mapped[str] = mapped_column(String(16), index=True, default="T0000")
    mitre_name: Mapped[str] = mapped_column(String(128), default="")
    mitre_tactic: Mapped[str] = mapped_column(String(64), default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(EncryptedColumn(), default="")  # Alert
    rule: Mapped[str] = mapped_column(String(64), index=True, default="")
    host: Mapped[str] = mapped_column(String(128), index=True, default="")
    #: Tenant scoping: inherits the org of the evidence events ("" = system).
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    #: Demo/test marker - demo-seeded alerts never appear in the production
    #: queue unless the console runs in demo mode (see ``demo`` on events).
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    #: Correlation chain identifier, e.g. "CORR-20260815-00031". Set for
    #: multi-stage correlation notables and entity-risk escalations so
    #: analysts can trace every alert back to the chain that produced it.
    correlation_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    trigger_count: Mapped[int] = mapped_column(Integer, default=1)
    detection_method: Mapped[str] = mapped_column(
        String(16), index=True, default="rule"
    )
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), index=True, default="MEDIUM")
    #: P1 explainable risk: structured breakdown of how the score was built
    #: (hybrid composition, context modifier, per-signal dynamic adjustments).
    #: JSON payload - see ``backend.detection.alerting._risk_payload``.
    risk_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: P1 detection-time threat-intel annotation: reputation verdicts for
    #: the alert's indicators, computed while the alert is created (offline
    #: fast path - see ``backend.intel.detection``).
    intel_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Ticket links from ticketing integrations (roadmap 6.3), e.g.
    #: [{"system": "jira", "key": "SOC-42", "url": "..."}].
    ticket_links: Mapped[list] = mapped_column(JSONColumnType, default=list)
    events: Mapped[list[AlertEventLink]] = relationship(
        "AlertEventLink", back_populates="alert", cascade="all, delete-orphan"
    )
    notes: Mapped[list[AnalystNote]] = relationship(
        "AnalystNote", back_populates="alert", cascade="all, delete-orphan"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    def to_dict(self, include_events: bool = False) -> dict:
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "confidence": self.confidence,
            "score": self.score,
            "detection_method": self.detection_method,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "mitre_id": self.mitre_id,
            "mitre_name": self.mitre_name,
            "mitre_tactic": self.mitre_tactic,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "rule": self.rule,
            "host": self.host,
            "org": self.org,
            "demo": self.demo,
            "correlation_id": self.correlation_id,
            "event_count": self.event_count,
            "trigger_count": self.trigger_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_events:
            data["events"] = [
                link.event.to_dict()
                for link in sorted(self.events, key=lambda l: l.event_id)
            ]
            data["notes"] = [
                {"id": n.id, "note": n.note, "created_at": n.created_at.isoformat()}
                for n in sorted(self.notes, key=lambda n: n.created_at)
            ]
        data["ticket_links"] = self.ticket_links or []
        if self.risk_json:
            try:
                payload = json.loads(self.risk_json)
                data["risk_adjustments"] = payload.get("adjustments", [])
                data["risk_composition"] = {
                    "method": payload.get("method"),
                    "final": payload.get("final"),
                    "base": payload.get("base"),
                    "rule_share": payload.get("rule_share"),
                    "ml_share": payload.get("ml_share"),
                }
                data["context_modifier"] = payload.get("context_modifier", 1.0)
            except (TypeError, ValueError):
                pass
        if self.intel_json:
            try:
                payload = json.loads(self.intel_json)
                from backend.intel.detection import intel_hits

                data["intel_hits"] = intel_hits(payload)
                data["intel_indicators"] = payload.get("indicators", [])
                data["intel_checked_at"] = payload.get("checked_at")
            except (TypeError, ValueError):
                pass
        return data


class AlertEventLink(Base):
    """Many-to-many link between alerts and the evidence events."""

    __tablename__ = "alert_events"
    __table_args__ = (UniqueConstraint("alert_id", "event_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    event_id: Mapped[int] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), index=True
    )
    alert: Mapped[Alert] = relationship(back_populates="events")
    event: Mapped[NormalizedEvent] = relationship()


class Endpoint(Base):
    """A monitored host feeding telemetry via the ingest agent."""

    __tablename__ = "endpoints"

    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    host: Mapped[str] = mapped_column(String(128), index=True, default="")
    #: Tenant scoping: the organization owning this agent ("" = system fleet).
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    records_total: Mapped[int] = mapped_column(Integer, default=0)
    events_total: Mapped[int] = mapped_column(Integer, default=0)
    alerts_total: Mapped[int] = mapped_column(Integer, default=0)
    output_format_version: Mapped[str] = mapped_column(String(16), default="1.0")
    #: Agent fleet (roadmap 3.4): software version and OS banner reported on
    #: ingest so the fleet view can spot stale agents for auto-update.
    agent_version: Mapped[str] = mapped_column(String(32), default="")
    os_info: Mapped[str] = mapped_column(String(128), default="")
    #: Comma-separated tags for grouping the fleet (e.g. "dmz,web,prod").
    tags: Mapped[str] = mapped_column(String(256), default="")
    #: Computed-on-read health: ok | stale | offline | unknown.
    health_status: Mapped[str] = mapped_column(String(16), default="unknown")
    #: Auto-update state: none | pending | current (see update_agent command).
    update_status: Mapped[str] = mapped_column(String(16), default="none")
    errors_total: Mapped[int] = mapped_column(Integer, default=0)

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "host": self.host,
            "org": self.org,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "records_total": self.records_total,
            "events_total": self.events_total,
            "alerts_total": self.alerts_total,
            "agent_version": self.agent_version,
            "os_info": self.os_info,
            "tags": self.tags,
            "health_status": self.health_status,
            "update_status": self.update_status,
            "errors_total": self.errors_total,
        }


class ProcessRecord(Base):
    """Snapshot of a running process observed by the process collector."""

    __tablename__ = "processes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pid: Mapped[int] = mapped_column(Integer, index=True)
    ppid: Mapped[int] = mapped_column(Integer, default=0)
    #: Sysmon ProcessGuid / ParentProcessGuid (stable process identity across
    #: PID reuse) - empty for non-Sysmon sources.
    guid: Mapped[str] = mapped_column(String(64), default="", index=True)
    parent_guid: Mapped[str] = mapped_column(String(64), default="")
    name: Mapped[str] = mapped_column(String(256), index=True)
    path: Mapped[str] = mapped_column(Text, default="")
    command_line: Mapped[str] = mapped_column(
        EncryptedColumn(), default=""
    )  # ProcessRecord
    parent_name: Mapped[str] = mapped_column(String(256), default="")
    user: Mapped[str] = mapped_column(String(128), default="")
    is_new: Mapped[bool] = mapped_column(Boolean, default=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "ppid": self.ppid,
            "guid": self.guid,
            "parent_guid": self.parent_guid,
            "name": self.name,
            "path": self.path,
            "command_line": self.command_line,
            "parent_name": self.parent_name,
            "user": self.user,
            "is_new": self.is_new,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "org": self.org,
            "demo": self.demo,
        }


class NetworkConnection(Base):
    """An observed TCP connection or listening socket."""

    __tablename__ = "network_connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pid: Mapped[int] = mapped_column(Integer, default=0)
    process: Mapped[str] = mapped_column(String(256), default="")
    local_ip: Mapped[str] = mapped_column(String(64), default="")
    local_port: Mapped[int] = mapped_column(Integer, default=0)
    remote_ip: Mapped[str] = mapped_column(String(64), index=True, default="")
    remote_port: Mapped[int] = mapped_column(Integer, default=0)
    state: Mapped[str] = mapped_column(String(32), default="")
    is_listening: Mapped[bool] = mapped_column(Boolean, default=False)
    bytes_sent: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_recv: Mapped[int] = mapped_column(BigInteger, default=0)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "process": self.process,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "state": self.state,
            "is_listening": self.is_listening,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "duration_seconds": self.duration_seconds,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "org": self.org,
            "demo": self.demo,
        }


class MLShadowScore(Base):
    """A model score recorded for deployment monitoring, not enforcement.

    The ML layer is advisory.  This table records the score and operating
    threshold for each scored entity (currently one network bucket per remote
    IP) so operators can inspect score distributions, estimate local false
    positives, and compare a candidate model before it is promoted.  No alert
    or response action is created from this row.
    """

    __tablename__ = "ml_shadow_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    stream: Mapped[str] = mapped_column(String(32), default="network", index=True)
    model_version: Mapped[int] = mapped_column(Integer, default=0, index=True)
    feature_version: Mapped[int] = mapped_column(Integer, default=0)
    entity: Mapped[str] = mapped_column(String(256), default="", index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    threshold: Mapped[float] = mapped_column(Float, default=0.5)
    flagged: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    detail: Mapped[dict] = mapped_column(JSONColumnType, default=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "stream": self.stream,
            "model_version": self.model_version,
            "feature_version": self.feature_version,
            "entity": self.entity,
            "score": self.score,
            "threshold": self.threshold,
            "flagged": self.flagged,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "org": self.org,
            "demo": self.demo,
            "detail": self.detail or {},
        }


class DnsQuery(Base):
    """A DNS query observed by the DNS monitor (Sysmon Event 22 / snoop).

    No live packet capture by default; the collector reads the Sysmon DNS
    channel (Event 22) and/or a configured query snapshot file so the
    detection rules can reason over real resolver activity.
    """

    __tablename__ = "dns_queries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    process: Mapped[str] = mapped_column(String(256), default="")
    pid: Mapped[int] = mapped_column(Integer, default=0)
    query: Mapped[str] = mapped_column(String(512), index=True)
    response: Mapped[str] = mapped_column(String(512), default="")
    response_size: Mapped[int] = mapped_column(Integer, default=0)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "process": self.process,
            "pid": self.pid,
            "query": self.query,
            "response": self.response,
            "response_size": self.response_size,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "org": self.org,
            "demo": self.demo,
        }


class HttpRequest(Base):
    """Metadata for an HTTP/S request observed by the HTTP monitor.

    Mirrors what a local HTTP monitor (MITM proxy, Windows filter driver or
    Sysmon-assisted logging) can expose without deep packet inspection.
    """

    __tablename__ = "http_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    process: Mapped[str] = mapped_column(String(256), default="")
    pid: Mapped[int] = mapped_column(Integer, default=0)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    url: Mapped[str] = mapped_column(String(1024), index=True)
    host: Mapped[str] = mapped_column(String(256), default="")
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    request_body_size: Mapped[int] = mapped_column(Integer, default=0)
    response_body_size: Mapped[int] = mapped_column(Integer, default=0)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "process": self.process,
            "pid": self.pid,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "status_code": self.status_code,
            "request_body_size": self.request_body_size,
            "response_body_size": self.response_body_size,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "org": self.org,
            "demo": self.demo,
        }


class EmailMessage(Base):
    """An email message (metadata) ingested for phishing analysis.

    The email collector ingests real message metadata from a configured source
    (e.g. an EMF/.msg export directory or a local mail spool). No live inbox
    scraping is performed; detection runs over whichever messages are present.
    """

    __tablename__ = "emails"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender: Mapped[str] = mapped_column(String(256), default="")
    recipient: Mapped[str] = mapped_column(String(256), default="")
    subject: Mapped[str] = mapped_column(String(512), default="")
    body: Mapped[str] = mapped_column(EncryptedColumn(), default="")  # EmailMessage
    attachment_types: Mapped[str] = mapped_column(String(512), default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "sender": self.sender,
            "recipient": self.recipient,
            "subject": self.subject,
            "attachment_types": self.attachment_types,
            "ip_address": self.ip_address,
            "received_at": self.received_at.isoformat() if self.received_at else None,
            "org": self.org,
            "demo": self.demo,
        }


class UsbDevice(Base):
    """A removable/USB device insertion observed by the USB monitor.

    Mirrors Windows Security/Kernel-PnP events 6416 and 6420 (new external
    device recognised) captured via the event-log collector.
    """

    __tablename__ = "usb_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_name: Mapped[str] = mapped_column(String(256), default="")
    device_id: Mapped[str] = mapped_column(String(256), default="")
    vendor: Mapped[str] = mapped_column(String(128), default="")
    serial: Mapped[str] = mapped_column(String(128), default="")
    inserted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device_name": self.device_name,
            "device_id": self.device_id,
            "vendor": self.vendor,
            "serial": self.serial,
            "inserted_at": self.inserted_at.isoformat() if self.inserted_at else None,
            "org": self.org,
            "demo": self.demo,
        }


class FileScan(Base):
    """A file scanned by the malware/file-hash analyzer."""

    __tablename__ = "file_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_path: Mapped[str] = mapped_column(String(1024), index=True)
    file_name: Mapped[str] = mapped_column(String(256), default="")
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    md5: Mapped[str] = mapped_column(String(32), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    signed: Mapped[bool] = mapped_column(Boolean, default=False)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    signature_name: Mapped[str] = mapped_column(String(128), default="")
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "file_path": self.file_path,
            "file_name": self.file_name,
            "sha256": self.sha256,
            "md5": self.md5,
            "size": self.size,
            "signed": self.signed,
            "is_malicious": self.is_malicious,
            "signature_name": self.signature_name,
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
            "org": self.org,
            "demo": self.demo,
        }


class VulnFinding(Base):
    """A matched known-vulnerable product (CVE hit) on a monitored host.

    Produced by the vulnerability scanner (``source: vuln`` records) and
    aggregated into alerts by the vulnerability detection rule.
    """

    __tablename__ = "vuln_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host: Mapped[str] = mapped_column(String(128), index=True, default="")
    product: Mapped[str] = mapped_column(String(256), index=True)
    version: Mapped[str] = mapped_column(String(64), default="")
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    found_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "host": self.host,
            "product": self.product,
            "version": self.version,
            "cve_id": self.cve_id,
            "cvss": self.cvss,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "found_at": self.found_at.isoformat() if self.found_at else None,
            "org": self.org,
            "demo": self.demo,
        }


class DashboardSnapshot(Base):
    """Periodic roll-up of the platform KPIs used for trend charts."""

    __tablename__ = "dashboard_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    security_score: Mapped[float] = mapped_column(Float, default=100.0)
    total_events: Mapped[int] = mapped_column(Integer, default=0)
    active_alerts: Mapped[int] = mapped_column(Integer, default=0)
    critical_threats: Mapped[int] = mapped_column(Integer, default=0)
    events_last_hour: Mapped[int] = mapped_column(Integer, default=0)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "security_score": self.security_score,
            "total_events": self.total_events,
            "active_alerts": self.active_alerts,
            "critical_threats": self.critical_threats,
            "events_last_hour": self.events_last_hour,
        }


class ReportRecord(Base):
    """Metadata for a generated report file."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_type: Mapped[str] = mapped_column(String(32))  # executive | technical
    format: Mapped[str] = mapped_column(String(16))  # pdf | html | json | csv
    title: Mapped[str] = mapped_column(String(256))
    file_path: Mapped[str] = mapped_column(Text)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "report_type": self.report_type,
            "format": self.format,
            "title": self.title,
            "filename": self.file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1],
            "download_url": f"/api/reports/{self.id}/download",
            "org": self.org,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ReportSchedule(Base):
    """Scheduled report generation (roadmap 6.2).

    ``every_hours`` > 0 runs every N hours; ``hour_of_day`` >= 0 runs once
    per day at that local hour (hour_of_day wins when both are set).
    ``email_to`` non-empty attaches the report to an SMTP message after
    generation (reuses the BARAQ_SMTP_* settings).
    """

    __tablename__ = "report_schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), default="scheduled")
    report_type: Mapped[str] = mapped_column(String(32), default="executive")
    fmt: Mapped[str] = mapped_column(String(16), default="pdf")
    every_hours: Mapped[int] = mapped_column(Integer, default=24)
    hour_of_day: Mapped[int] = mapped_column(Integer, default=-1)
    email_to: Mapped[str] = mapped_column(String(512), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str] = mapped_column(Text, default="")
    runs_total: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "report_type": self.report_type,
            "format": self.fmt,
            "every_hours": self.every_hours,
            "hour_of_day": self.hour_of_day,
            "email_to": self.email_to,
            "enabled": self.enabled,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "last_error": self.last_error,
            "runs_total": self.runs_total,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AnalystNote(Base):
    """Analyst annotation attached to an alert during investigation."""

    __tablename__ = "analyst_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"))
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    alert: Mapped[Alert] = relationship(back_populates="notes")


class Bookmark(Base):
    __tablename__ = "bookmarks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    note: Mapped[str] = mapped_column(Text, nullable=True)
    tags: Mapped[list] = mapped_column(JSONColumnType, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    __table_args__ = (UniqueConstraint("user_id", "entity_type", "entity_id", name="uq_bookmark_entity"),)


class AssistantMessage(Base):
    """Chat history for the AI security assistant."""

    __tablename__ = "assistant_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    role: Mapped[str] = mapped_column(String(16))  # user | assistant
    content: Mapped[str] = mapped_column(EncryptedColumn())  # AssistantMessage
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "role": self.role,
            "content": self.content,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AlertAction(Base):
    """A response action taken on an alert (automated containment/triage)."""

    __tablename__ = "alert_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    action: Mapped[str] = mapped_column(
        String(32)
    )  # block_ip | kill_process | quarantine | escalate | ack
    target: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[str] = mapped_column(
        String(16), default="queued"
    )  # queued | success | failed
    detail: Mapped[str] = mapped_column(Text, default="")
    triggered_by: Mapped[str] = mapped_column(String(64), default="auto")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "action": self.action,
            "target": self.target,
            "status": self.status,
            "detail": self.detail,
            "triggered_by": self.triggered_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AgentCommand(Base):
    """A remote command queued for an agent by the SOC controller.

    The server stores the command (block_ip / kill_process / quarantine /
    escalate) and the agent picks it up on its next poll cycle via
    ``GET /api/commands/pending``, executes it locally and reports the
    outcome back with ``POST /api/commands/{id}/result``.
    """

    __tablename__ = "agent_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(
        String(32)
    )  # block_ip | kill_process | quarantine | escalate
    target: Mapped[str] = mapped_column(String(256), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(
        String(16), index=True, default="pending"
    )  # pending | success | failed
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "action": self.action,
            "target": self.target,
            "sha256": self.sha256,
            "status": self.status,
            "detail": self.detail,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
        }


class EvaluationRun(Base):
    """One evaluation-framework run: metrics for a scenario (or the suite)."""

    __tablename__ = "evaluation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scenario: Mapped[str] = mapped_column(String(64), index=True)
    total_samples: Mapped[int] = mapped_column(Integer, default=0)
    attack_samples: Mapped[int] = mapped_column(Integer, default=0)
    baseline_samples: Mapped[int] = mapped_column(Integer, default=0)
    true_positives: Mapped[int] = mapped_column(Integer, default=0)
    false_positives: Mapped[int] = mapped_column(Integer, default=0)
    true_negatives: Mapped[int] = mapped_column(Integer, default=0)
    false_negatives: Mapped[int] = mapped_column(Integer, default=0)
    accuracy: Mapped[float] = mapped_column(Float, default=0.0)
    precision: Mapped[float] = mapped_column(Float, default=0.0)
    recall: Mapped[float] = mapped_column(Float, default=0.0)
    f1_score: Mapped[float] = mapped_column(Float, default=0.0)
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.0)
    detection_time_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scenario": self.scenario,
            "total_samples": self.total_samples,
            "attack_samples": self.attack_samples,
            "baseline_samples": self.baseline_samples,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "detection_time_ms": round(self.detection_time_ms, 2),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Verdict(Base):
    """Analyst ground-truth on a scored event (the feedback loop).

    One verdict per event; posting again overwrites. Verdicts become the
    authoritative labels for supervised retraining - an analyst-confirmed
    attack is always labelled positive and a false-positive always negative,
    overriding the heuristic labeler.
    """

    __tablename__ = "verdicts"
    __table_args__ = (UniqueConstraint("event_id", name="uq_verdict_event"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("events.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    verdict: Mapped[str] = mapped_column(String(32))  # true_positive | false_positive
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    event: Mapped[NormalizedEvent] = relationship(
        "NormalizedEvent", back_populates="verdict"
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "verdict": self.verdict,
            "note": self.note,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def json_dumps(data) -> str:
    return json.dumps(data, default=str)


class Incident(Base):
    """A security incident: one or more related alerts tracked as a case.

    Analysts group alerts into incidents, assign ownership, track response
    status and build a timeline of investigation notes.
    """

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(256), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True, default="high")
    status: Mapped[str] = mapped_column(String(16), index=True, default="open")
    owner: Mapped[str] = mapped_column(String(128), default="")
    mitre_id: Mapped[str] = mapped_column(String(16), default="T0000")
    mitre_name: Mapped[str] = mapped_column(String(128), default="")
    host: Mapped[str] = mapped_column(String(128), index=True, default="")
    #: Tenant scoping: the org of the alerts that make up the case.
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    #: Demo/test marker (inherited from the source alerts).
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), index=True, default="MEDIUM")
    #: Story-level confidence (0..1) - how trustworthy the reconstructed
    #: incident narrative is (detection quality + correlation strength +
    #: enrichment quality - suppression signals).
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    #: Deduplication key: user|host|mitre|root_process|30min-window. Open
    #: incidents with the same key absorb new alerts instead of spawning
    #: duplicates (Phase-1 incident dedup engine).
    correlation_key: Mapped[str] = mapped_column(String(96), index=True, default="")
    #: P1-1 attack chain: reconstructed multi-stage path (JSON payload of
    #: ``backend.investigation.attack_chain.reconstruct_chain``), its
    #: confidence (0..1) and the deterministic risk boost (+0..20) stacked
    #: on the strongest contributing alert's risk.
    chain_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    chain_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    chain_risk: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    opened_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: First-response SLA clock: set when an analyst first engages the case
    #: (status leaves "open" or an owner is assigned). Never overwritten.
    responded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    alerts: Mapped[list[IncidentAlertLink]] = relationship(
        "IncidentAlertLink",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentAlertLink.alert_id",
    )
    comments: Mapped[list[IncidentComment]] = relationship(
        "IncidentComment",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentComment.created_at",
    )

    def to_dict(self, include_links: bool = False) -> dict:
        data = {
            "id": self.id,
            "ref": f"INC-{self.id:04d}",
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "owner": self.owner,
            "mitre_id": self.mitre_id,
            "mitre_name": self.mitre_name,
            "host": self.host,
            "org": self.org,
            "demo": self.demo,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "correlation_key": self.correlation_key,
            "chain": json.loads(self.chain_json) if self.chain_json else None,
            "chain_confidence": self.chain_confidence,
            "chain_risk": self.chain_risk,
            "alert_count": len(self.alerts),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "opened_at": self.opened_at.isoformat() if self.opened_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "responded_at": (
                self.responded_at.isoformat() if self.responded_at else None
            ),
        }
        if include_links:
            data["alerts"] = [
                {
                    "alert_id": l.alert_id,
                    "name": l.alert.name,
                    "severity": l.alert.severity,
                }
                for l in self.alerts
            ]
            data["comments"] = [c.to_dict() for c in self.comments]
        return data


class IncidentAlertLink(Base):
    """Link an incident to the alerts that make up the case."""

    __tablename__ = "incident_alerts"
    __table_args__ = (UniqueConstraint("incident_id", "alert_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    incident: Mapped[Incident] = relationship(back_populates="alerts")
    alert: Mapped[Alert] = relationship()

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "alert_id": self.alert_id,
            "alert_name": self.alert.name if self.alert else "",
            "alert_severity": self.alert.severity if self.alert else "",
        }


class IncidentComment(Base):
    """An analyst note/update appended to an incident timeline."""

    __tablename__ = "incident_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    author: Mapped[str] = mapped_column(String(128), default="analyst")
    body: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(
        String(16), default="comment"
    )  # comment | action | status
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    incident: Mapped[Incident] = relationship(back_populates="comments")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "author": self.author,
            "body": self.body,
            "kind": self.kind,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AlertVerdict(Base):
    """Analyst verdict on an alert (roadmap P2 - analyst feedback).

    Verdicts distinguish *real detections* (true_positive), *noise*
    (false_positive) and *expected behaviour* (expected_behavior - a
    legitimate workflow that the rule cannot tell apart from an attack).
    ``expected_behavior`` verdicts can also create a scoped suppression
    rule so the same workflow stops alerting. Verdicts feed the ML
    feedback weights the same way event verdicts do.
    """

    __tablename__ = "alert_verdicts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True, nullable=False
    )
    verdict: Mapped[str] = mapped_column(
        String(32)
    )  # true_positive | false_positive | expected_behavior
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    alert: Mapped[Alert] = relationship()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "verdict": self.verdict,
            "note": self.note,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class SuppressionRule(Base):
    """Scoped alert suppression (roadmap P2).

    An analyst declares that a specific detection is *expected behaviour*
    on a specific scope (rule / host / user) until an expiry date. While a
    matching rule is active, findings are suppressed instead of becoming
    alerts - the target of triage actions for known-good workflows.
    """

    __tablename__ = "suppression_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule: Mapped[str] = mapped_column(String(64), index=True)  # rule id or "*"
    host: Mapped[str] = mapped_column(
        String(128), default="*", index=True
    )  # host or "*"
    user: Mapped[str] = mapped_column(
        String(128), default="*", index=True
    )  # user or "*"
    reason: Mapped[str] = mapped_column(String(512), default="")
    created_by: Mapped[str] = mapped_column(String(128), default="")
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    suppressed_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule": self.rule,
            "host": self.host,
            "user": self.user,
            "reason": self.reason,
            "created_by": self.created_by,
            "org": self.org,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "suppressed_count": self.suppressed_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ThreatIntelRecord(Base):
    """Cached threat-intel verdict for a single indicator (IP / domain / hash)."""

    __tablename__ = "threat_intel_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(16), default="ip")  # ip | domain | hash
    category: Mapped[str] = mapped_column(
        String(16), index=True, default="unknown"
    )  # abusive | malicious | suspicious | benign | unknown
    label: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    sources: Mapped[list] = mapped_column(JSONColumnType, default=list)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "indicator": self.indicator,
            "kind": self.kind,
            "category": self.category,
            "label": self.label,
            "confidence": self.confidence,
            "sources": self.sources or [],
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
        }


class ThreatIntelFeedState(Base):
    """Last-run state for a configured threat-intel feed subscription."""

    __tablename__ = "threat_intel_feed_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    feed_type: Mapped[str] = mapped_column(String(16), default="")
    url: Mapped[str] = mapped_column(String(512), default="")
    last_success_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str] = mapped_column(Text, default="")
    ioc_count: Mapped[int] = mapped_column(Integer, default=0)
    total_fetched: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "feed_type": self.feed_type,
            "url": self.url,
            "last_success_at": (
                self.last_success_at.isoformat() if self.last_success_at else None
            ),
            "last_error": self.last_error,
            "ioc_count": self.ioc_count,
            "total_fetched": self.total_fetched,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class DataQualitySnapshot(Base):
    """Periodic snapshot of data-quality telemetry (auto-fix corrupted data).

    The collector-side tracker holds the live sliding window; every
    ``DATA_QUALITY_MONITOR_SECONDS`` the background monitor persists one of
    these rows so operators can review corruption history and repair events
    (/api/system/data-quality/history).
    """

    __tablename__ = "data_quality_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sampled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, default=utcnow
    )
    total: Mapped[int] = mapped_column(Integer, default=0)
    valid: Mapped[int] = mapped_column(Integer, default=0)
    corrupted: Mapped[int] = mapped_column(Integer, default=0)
    corruption_rate: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(16), default="healthy")
    #: Reason buckets -> counts, e.g. {"new_process is rendering debris": 12}.
    reasons: Mapped[dict] = mapped_column(JSONColumnType, default=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "sampled_at": self.sampled_at.isoformat() if self.sampled_at else None,
            "total": self.total,
            "valid": self.valid,
            "corrupted": self.corrupted,
            "corruption_rate": round(self.corruption_rate, 4),
            "status": self.status,
            "reasons": self.reasons or {},
        }


class EntityNode(Base):
    """An entity in the intelligence graph (user / device / process / IP /
    domain / file hash / technique / threat actor).

    Persisted by the configured graph provider (Postgres by default, Neo4j
    adapter optional). ``kind`` + ``name`` is the natural key; analytic
    counters (event_count, alert_count, risk_score) are refreshed by the
    extractor on each pipeline pass.
    """

    __tablename__ = "entity_nodes"
    __table_args__ = (UniqueConstraint("kind", "name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(
        String(24), index=True
    )  # user | device | process | ip | domain | file | technique | threat_actor
    name: Mapped[str] = mapped_column(String(512), index=True)
    display_name: Mapped[str] = mapped_column(String(512), default="")
    label: Mapped[str] = mapped_column(String(256), default="")
    risk_level: Mapped[str] = mapped_column(String(16), index=True, default="LOW")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    alerts_count: Mapped[int] = mapped_column(Integer, default=0)
    events_count: Mapped[int] = mapped_column(Integer, default=0)
    properties: Mapped[dict] = mapped_column(JSONColumnType, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    provider: Mapped[str] = mapped_column(String(16), default="postgres")

    def to_dict(self, include_props: bool = True) -> dict:
        data = {
            "kind": self.kind,
            "name": self.name,
            "display_name": self.display_name or self.name,
            "label": self.label,
            "risk_level": self.risk_level,
            "risk_score": round(self.risk_score, 2),
            "alerts_count": self.alerts_count,
            "events_count": self.events_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "id": self.id,
        }
        if include_props:
            data["properties"] = self.properties or {}
        return data


class EntityEdge(Base):
    """A directional relationship between two graph entities.

    Edges carry a verb label (e.g. ``user -> logon_on -> host``) plus a
    freshness/weight so the graph can rank "hot" connections. The Postgres
    provider merges on ``(src_kind, src_name, rel, dst_kind, dst_name)``.
    """

    __tablename__ = "entity_edges"
    __table_args__ = (
        UniqueConstraint("src_kind", "src_name", "rel", "dst_kind", "dst_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    src_kind: Mapped[str] = mapped_column(String(24), index=True)
    src_name: Mapped[str] = mapped_column(String(512), index=True)
    rel: Mapped[str] = mapped_column(String(32), index=True)
    dst_kind: Mapped[str] = mapped_column(String(24), index=True)
    dst_name: Mapped[str] = mapped_column(String(512), index=True)
    weight: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    properties: Mapped[dict] = mapped_column(JSONColumnType, default=dict)
    provider: Mapped[str] = mapped_column(String(16), default="postgres")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": {"kind": self.src_kind, "name": self.src_name},
            "rel": self.rel,
            "target": {"kind": self.dst_kind, "name": self.dst_name},
            "weight": self.weight,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "properties": self.properties or {},
        }


class LicenseRecord(Base):
    """Activated commercial license / persisted trial marker.

    Holds the signed license key string plus cached payload fields so
    status checks need not re-verify on every query. The signature itself
    is re-verified by backend.licensing on every state evaluation.
    """

    __tablename__ = "licenses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    license_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    customer: Mapped[str] = mapped_column(String(256), default="")
    edition: Mapped[str] = mapped_column(
        String(24), default="trial"
    )  # trial | standard | professional
    seats: Mapped[int] = mapped_column(Integer, default=1)
    license_key: Mapped[str] = mapped_column(Text, default="")
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    expires_at: Mapped[str] = mapped_column(String(64), default="")
    activated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.now(UTC)
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "license_id": self.license_id,
            "customer": self.customer,
            "edition": self.edition,
            "seats": self.seats,
            "expires_at": self.expires_at,
            "activated_at": (
                self.activated_at.isoformat() if self.activated_at else None
            ),
        }


class SystemState(Base):
    """Small key/value store for platform-level runtime state.

    Used by the incremental detection pipeline to persist the last-evaluated
    event cursor (``detection_cursor``) so a detection run only processes
    events that arrived since the previous run, instead of re-scanning the
    full window on every ingest.
    """

    __tablename__ = "system_state"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class EntityRisk(Base):
    """Risk-Based Alerting state: persistent risk per entity.

    Unlike the per-alert ``Alert.risk_score`` (computed once and forgotten),
    every detection adds a weighted delta to the *entity's* accumulated
    score. Scores decay exponentially over time (``ENTITY_RISK_DECAY_DAYS``)
    so a host with many low-severity hits is distinguishable from a clean
    host, and stale risk ages out. When the accumulated score crosses a
    threshold the RBA engine raises an escalated "entity notable" alert that
    links the contributing findings (see ``backend.risk.entity_risk``).
    """

    __tablename__ = "entity_risk"
    __table_args__ = (
        UniqueConstraint("entity_kind", "entity_name", "org", name="uq_entity_risk"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_kind: Mapped[str] = mapped_column(String(16), index=True)  # user | host | ip
    entity_name: Mapped[str] = mapped_column(String(512), index=True)
    #: Tenant scoping: "" = system fleet; otherwise the agent organization.
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    #: Demo/test marker - demo entities are excluded from production views.
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    #: Accumulated, decayed risk score (0-100+; unbounded in theory).
    score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), index=True, default="LOW")
    #: Count of alert contributions folded into this entity.
    alerts_count: Mapped[int] = mapped_column(Integer, default=0)
    #: Most recent contributing findings, e.g.
    #: [{"rule": "...", "mitre_id": "T1110", "delta": 12.5, "alert_id": 7}].
    contributions: Mapped[list] = mapped_column(JSONColumnType, default=list)
    #: Risk level at the last escalation pass. A new "Entity Risk
    #: Escalation" alert is only raised when the level *changed* (or none
    #: was ever raised); same-level climbs refresh the open notable instead
    #: of spamming the alert queue (one detection -> one contribution -> one
    #: appropriate alert).
    last_escalated_level: Mapped[str] = mapped_column(String(16), default="")
    last_escalated_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_escalated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: When the score last changed (drives the exponential decay).
    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "entity_kind": self.entity_kind,
            "entity_name": self.entity_name,
            "org": self.org,
            "demo": self.demo,
            "score": round(self.score, 2),
            "risk_level": self.risk_level,
            "alerts_count": self.alerts_count,
            "contributions": self.contributions or [],
            "last_escalated_level": self.last_escalated_level,
            "last_escalated_at": (
                self.last_escalated_at.isoformat() if self.last_escalated_at else None
            ),
            "last_updated": (
                self.last_updated.isoformat() if self.last_updated else None
            ),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class EntityRiskEvent(Base):
    """One risk accumulation event on an entity (the RBA timeline).

    Each entry records the delta added, the score immediately after, and the
    alert/rule that caused it - powering the per-entity risk timeline in the
    dashboard ("why did this host reach score 80?").
    """

    __tablename__ = "entity_risk_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_kind: Mapped[str] = mapped_column(String(16), index=True)
    entity_name: Mapped[str] = mapped_column(String(512), index=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    #: Demo/test marker (inherited from the source alert).
    demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    delta: Mapped[float] = mapped_column(Float, default=0.0)
    score_after: Mapped[float] = mapped_column(Float, default=0.0)
    source_rule: Mapped[str] = mapped_column(String(64), default="")
    mitre_id: Mapped[str] = mapped_column(String(16), default="T0000")
    alert_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "entity_kind": self.entity_kind,
            "entity_name": self.entity_name,
            "org": self.org,
            "demo": self.demo,
            "delta": round(self.delta, 2),
            "score_after": round(self.score_after, 2),
            "source_rule": self.source_rule,
            "mitre_id": self.mitre_id,
            "alert_id": self.alert_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class DetectionTuning(Base):
    """Runtime-adjustable detection configuration (on-the-fly tuning).

    Analysts tune risk weights and thresholds from the UI
    without touching config files; this table is the BARAQ equivalent. Keys
    understood by ``backend.detection.tuning``:

    * ``rule_risk_weights``   - {"rule_id": multiplier, ...} folded over the
      env defaults (``BARAQ_RULE_RISK_WEIGHTS``)
    * ``risk_thresholds``     - {"medium": 40, "high": 65, "critical": 85}
    * ``risk_decay_days``     - exponential half-life of entity scores
    * ``risk_notable_window_hours`` - dedup window for entity notables
    * ``entity_risk_enabled`` - master switch (true/false)

    Values are JSON; changes apply on the next accumulation/decay pass.
    """

    __tablename__ = "detection_tuning"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict | None] = mapped_column(JSONColumnType, nullable=True)
    updated_by: Mapped[str] = mapped_column(String(128), default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AutomationPlaybook(Base):
    """A SOAR automation playbook: when an alert matches -> run actions.

    The BARAQ equivalent of a SOAR playbook: analysts
    declare trigger conditions (rule ids, severities, MITRE tactics, minimum
    risk level) and an ordered action list (block_ip, kill_process,
    quarantine, isolate, disable_account, escalate, create_incident,
    notify). Matching alerts fire the playbook automatically from the
    detection pipeline (see backend.automation.playbooks).
    """

    __tablename__ = "automation_playbooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    #: Trigger conditions, e.g.
    #: {"rules": ["brute_force"], "severity": ["high", "critical"],
    #:  "tactics": ["Credential Access"], "min_risk_level": "HIGH"}.
    #: Dimensions AND together; values within a dimension OR together.
    triggers: Mapped[dict] = mapped_column(JSONColumnType, default=dict)
    #: Ordered actions, e.g. [{"action": "block_ip"}, {"action": "notify"}].
    actions: Mapped[list] = mapped_column(JSONColumnType, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "triggers": self.triggers or {},
            "actions": self.actions or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class PlaybookRun(Base):
    """Execution log of one automation playbook against one alert."""

    __tablename__ = "playbook_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    playbook_id: Mapped[int] = mapped_column(
        ForeignKey("automation_playbooks.id", ondelete="CASCADE"), index=True
    )
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    playbook_name: Mapped[str] = mapped_column(String(128), default="")
    alert_name: Mapped[str] = mapped_column(String(128), default="")
    rule: Mapped[str] = mapped_column(String(64), default="")
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    #: [{"action": "block_ip", "status": "success", "detail": "..."}]
    results: Mapped[list] = mapped_column(JSONColumnType, default=list)
    status: Mapped[str] = mapped_column(
        String(16), default="completed"
    )  # completed | partial | failed
    triggered_by: Mapped[str] = mapped_column(
        String(32), default="auto"
    )  # auto | manual
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "playbook_id": self.playbook_id,
            "alert_id": self.alert_id,
            "playbook_name": self.playbook_name,
            "alert_name": self.alert_name,
            "rule": self.rule,
            "org": self.org,
            "results": self.results or [],
            "status": self.status,
            "triggered_by": self.triggered_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class SavedSearch(Base):
    """An analyst-saved hunt query (the BARAQ equivalent of a saved search).

    Stores the query plus its time window so it can be re-run
    one-click, shared with the team, or pinned as a dashboard panel.
    """

    __tablename__ = "saved_searches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    query: Mapped[str] = mapped_column(Text)
    earliest: Mapped[str] = mapped_column(String(32), default="-24h")
    latest: Mapped[str] = mapped_column(String(32), default="")
    owner: Mapped[str] = mapped_column(String(128), default="")
    #: Tenant scoping: "" = global (everyone); otherwise one org.
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "query": self.query,
            "earliest": self.earliest,
            "latest": self.latest,
            "owner": self.owner,
            "org": self.org,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Dashboard(Base):
    """An analyst-built dashboard of search panels.

    Panels are declarative: each references a saved search (or an inline
    query) and a visualization (table | count | top | area). The backend
    renders each panel by running its search and post-aggregating where the
    visualization needs it.
    """

    __tablename__ = "dashboards"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    #: Ordered panels, e.g.
    #: [{"id": "p1", "title": "Failed logons", "saved_search_id": 3,
    #:   "viz": "top", "field": "user", "limit": 10, "cols": 2}]
    panels: Mapped[list] = mapped_column(JSONColumnType, default=list)
    owner: Mapped[str] = mapped_column(String(128), default="")
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "panels": self.panels or [],
            "owner": self.owner,
            "org": self.org,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# ---------------------------------------------------------------------------
# Research dataset collector (Telemetry -> Dataset Collector)
# ---------------------------------------------------------------------------


class DatasetCollection(Base):
    """One research dataset collection session (default: BARAQ_Research_Dataset).

    A single session is active at a time; when the target is reached the
    session is marked ``complete`` and collection stops (normal BARAQ
    telemetry keeps flowing). An admin can start a fresh session later.
    """

    __tablename__ = "dataset_collections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), default="BARAQ_Research_Dataset")
    #: active | paused | complete
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)
    target_events: Mapped[int] = mapped_column(Integer, default=1_000_000)
    events_per_file: Mapped[int] = mapped_column(Integer, default=100_000)
    export_interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    format: Mapped[str] = mapped_column(String(8), default="csv")
    anonymize: Mapped[bool] = mapped_column(Boolean, default=False)
    include_labels: Mapped[bool] = mapped_column(Boolean, default=True)
    total_events: Mapped[int] = mapped_column(Integer, default=0, index=True)
    parts: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_export_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "target_events": self.target_events,
            "events_per_file": self.events_per_file,
            "export_interval_hours": self.export_interval_hours,
            "format": self.format,
            "anonymize": self.anonymize,
            "include_labels": self.include_labels,
            "total_events": self.total_events,
            "parts": self.parts,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "last_export_at": (
                self.last_export_at.isoformat() if self.last_export_at else None
            ),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class DatasetEvent(Base):
    """One normalized research event (a copy of the relevant telemetry).

    Only a compact research representation is stored - never the full raw
    telemetry record. Uniqueness is enforced per collection on both the
    deterministic fingerprint and the source event id, so no event can be
    collected twice and no export can produce duplicates.
    """

    __tablename__ = "dataset_events"
    __table_args__ = (
        UniqueConstraint(
            "collection_id", "event_fingerprint", name="uq_dataset_fingerprint"
        ),
        UniqueConstraint(
            "collection_id", "source_event_id", name="uq_dataset_source_event"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    collection_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    event_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    source_event_id: Mapped[int] = mapped_column(Integer, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_type: Mapped[str] = mapped_column(String(64), default="", index=True)
    event_source: Mapped[str] = mapped_column(String(32), default="")
    payload_normalized: Mapped[dict] = mapped_column(JSONColumnType, default=dict)
    exported: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    export_batch_id: Mapped[int | None] = mapped_column(
        Integer, nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class DatasetExport(Base):
    """One export batch (manual or scheduled). Idempotent: only events with
    ``exported=False`` are selected, and the whole batch is committed only
    after the CSV files are written and validated."""

    __tablename__ = "dataset_exports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    collection_id: Mapped[int] = mapped_column(Integer, index=True)
    #: scheduled | manual
    trigger: Mapped[str] = mapped_column(String(16), default="scheduled")
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    files_count: Mapped[int] = mapped_column(Integer, default=0)
    #: running | completed | failed
    status: Mapped[str] = mapped_column(String(16), default="running", index=True)
    error_message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "collection_id": self.collection_id,
            "trigger": self.trigger,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "event_count": self.event_count,
            "files_count": self.files_count,
            "status": self.status,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class DatasetExportFile(Base):
    """One CSV part file of an export, with its SHA-256 checksum for
    independent verification (thesis reproducibility)."""

    __tablename__ = "dataset_export_files"
    __table_args__ = (UniqueConstraint("filename", name="uq_dataset_filename"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    export_id: Mapped[int] = mapped_column(Integer, index=True)
    collection_id: Mapped[int] = mapped_column(Integer, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    part_number: Mapped[int] = mapped_column(Integer, default=1)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    first_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: verified | failed
    status: Mapped[str] = mapped_column(String(16), default="verified")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "export_id": self.export_id,
            "collection_id": self.collection_id,
            "filename": self.filename,
            "part_number": self.part_number,
            "event_count": self.event_count,
            "sha256": self.sha256,
            "first_timestamp": (
                self.first_timestamp.isoformat() if self.first_timestamp else None
            ),
            "last_timestamp": (
                self.last_timestamp.isoformat() if self.last_timestamp else None
            ),
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class HostProcessChain(Base):
    """Per-host behavioural baseline (parent -> child process chain).

    Learned passively from telemetry during a training window: a chain seen
    repeatedly on a host is *normal for that host*. The FP-defence gate uses
    this to silence generic rule hits on known-good chains, and the inverse
    - a NOVEL chain - is annotated on alerts as elevated-signal context.

    This is the generic answer to LOLBin abuse: instead of hardcoding
    "chrome.exe spawning powershell.exe is suspicious", the system learns
    what each endpoint actually does and flags deviations.
    """

    __tablename__ = "host_process_chains"
    __table_args__ = (
        UniqueConstraint("host", "parent_name", "child_name", name="uq_host_chain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host: Mapped[str] = mapped_column(String(128), index=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    parent_name: Mapped[str] = mapped_column(String(128))
    child_name: Mapped[str] = mapped_column(String(128))
    occurrences: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "host": self.host,
            "org": self.org,
            "parent_name": self.parent_name,
            "child_name": self.child_name,
            "occurrences": self.occurrences,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class TokenRevocation(Base):
    """Server-side session-token revocation list.

    Every session token issued by ``backend.auth.create_token`` carries a
    random ``jti``. A token is rejected by ``backend.auth.verify_token``
    when its ``jti`` is present in this table -- so logout, admin
    disable, password change, or role demotion can invalidate outstanding
    tokens immediately instead of waiting for the 12-hour TTL.

    Rows are pruned opportunistically when older than the longest
    plausible TTL (see ``backend.auth.revoke_token``); the
    ``expires_at`` index keeps the prune query cheap.
    """

    __tablename__ = "token_revocations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    jti: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    #: Username that owned the token at revocation time (audit trail).
    username: Mapped[str] = mapped_column(String(64), default="", index=True)
    #: Optional reason recorded in the audit log.
    reason: Mapped[str] = mapped_column(String(64), default="")
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    #: Hard expiry -- the revoke entry can be dropped after this.
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "jti": self.jti,
            "username": self.username,
            "reason": self.reason,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
