"""Automated data retention - prune telemetry older than the configured window.

The scheduler calls :func:`purge_old_data` on a regular cadence so the
database never grows unbounded. Child rows (alert events / notes / actions)
are removed by the database-level ``ondelete=CASCADE`` foreign keys.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from backend.config import EVENT_RETENTION_DAYS, ML_SHADOW_RETENTION_DAYS
from backend.database.models import (
    Alert,
    DashboardSnapshot,
    DnsQuery,
    EmailMessage,
    FileScan,
    HttpRequest,
    MLShadowScore,
    NetworkConnection,
    NormalizedEvent,
    ProcessRecord,
    ThreatIntelRecord,
    UsbDevice,
    VulnFinding,
)

logger = logging.getLogger("baraq.db")

#: (model, timestamp column) for every telemetry/history table with a time column.
#: Chat history, audit logs, reports and users are operator data and are kept.
_PURGE_TARGETS: list[tuple] = [
    (NormalizedEvent, NormalizedEvent.timestamp),
    (ProcessRecord, ProcessRecord.observed_at),
    (NetworkConnection, NetworkConnection.observed_at),
    (DnsQuery, DnsQuery.observed_at),
    (HttpRequest, HttpRequest.observed_at),
    (EmailMessage, EmailMessage.received_at),
    (UsbDevice, UsbDevice.inserted_at),
    (FileScan, FileScan.scanned_at),
    (VulnFinding, VulnFinding.found_at),
    (DashboardSnapshot, DashboardSnapshot.timestamp),
    (Alert, Alert.created_at),
    # Stale cached intel verdicts age out with telemetry; fresh lookups re-populate.
    (ThreatIntelRecord, ThreatIntelRecord.checked_at),
]


def purge_old_data(
    session: Session, days: int = EVENT_RETENTION_DAYS
) -> dict[str, int]:
    """Delete every record older than ``days`` (default config value).

    Returns a map of ``{table_name: deleted_rows}``. Safe to run repeatedly;
    nothing is deleted when there is nothing old.
    """
    cutoff = datetime.now(UTC) - timedelta(days=days)
    purged: dict[str, int] = {}
    try:
        for model, column in _PURGE_TARGETS:
            result = session.execute(delete(model).where(column < cutoff))
            purged[model.__tablename__] = int(result.rowcount or 0)  # type: ignore[attr-defined]
        # Shadow scores are high-volume operational telemetry and have a
        # shorter retention window than the underlying events.
        shadow_cutoff = datetime.now(UTC) - timedelta(days=ML_SHADOW_RETENTION_DAYS)
        result = session.execute(
            delete(MLShadowScore).where(MLShadowScore.observed_at < shadow_cutoff)
        )
        purged[MLShadowScore.__tablename__] = int(result.rowcount or 0)  # type: ignore[attr-defined]
        session.commit()
    except Exception:
        session.rollback()
        raise
    total = sum(purged.values())
    if total:
        logger.info("Retention purge (older than %dd): %s", days, purged)
    return purged
