"""SOAR approval workflow — file-backed, multi-step approval for dangerous actions.

Approval requests are persisted to a JSON file so they survive service
restarts. A destructive action (block_ip, kill_process, isolate, disable_account,
quarantine) cannot execute until a request for that exact (action, target) pair
has been APPROVED by a second administrator.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

logger = logging.getLogger("baraq.soar.approval")

APPROVALS_DIR = Path(
    os.environ.get("BARAQ_APPROVALS_DIR", str(Path.home() / "AppData" / "Local" / "BARAQ"))
)
APPROVALS_FILE = APPROVALS_DIR / "approvals.json"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalRequest(BaseModel):
    action_type: str
    action_params: dict
    requested_by: str
    justification: str = ""
    approvers_required: int = 1
    expires_in_minutes: int = 60


class ApprovalRecord(BaseModel):
    id: str
    action_type: str
    action_params: dict
    requested_by: str
    justification: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    approvers_required: int
    approvals: list[str] = []
    rejections: list[str] = []
    created_at: str = ""
    expires_at: str = ""
    resolved_at: str | None = None

    def __init__(self, **data):
        super().__init__(**data)
        if not self.created_at:
            self.created_at = datetime.now(UTC).isoformat()
        if not self.expires_at:
            from datetime import timedelta

            self.expires_at = (
                datetime.now(UTC) + timedelta(minutes=self.expires_in_minutes)
            ).isoformat()

    def is_expired(self) -> bool:
        if self.status != ApprovalStatus.PENDING:
            return False
        return datetime.now(UTC) > datetime.fromisoformat(self.expires_at)


class ApprovalWorkflow:
    """File-backed approval workflow manager.

    Every mutation appends to ``APPROVALS_FILE`` so pending requests survive
    service restarts. The file is rewritten atomically on each change.
    """

    def __init__(self):
        self._pending: dict[str, ApprovalRecord] = {}
        self._load()

    # ── persistence ────────────────────────────────────────────────────────

    def _load(self) -> None:
        try:
            raw = json.loads(APPROVALS_FILE.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return
        for item in raw:
            try:
                record = ApprovalRecord(**item)
            except Exception:
                continue
            if record.is_expired():
                record.status = ApprovalStatus.EXPIRED
                record.resolved_at = datetime.now(UTC).isoformat()
            if record.status == ApprovalStatus.PENDING:
                self._pending[record.id] = record

    def _save(self) -> None:
        APPROVALS_DIR.mkdir(parents=True, exist_ok=True)
        tmp = APPROVALS_FILE.with_suffix(".json.tmp")
        payload = [r.model_dump() for r in self._pending.values()]
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(APPROVALS_FILE)

    # ── public API ─────────────────────────────────────────────────────────

    def _key(self, action_type: str, action_params: dict) -> str:
        """Stable key for an (action, target) pair."""
        target = action_params.get("target", "")
        return f"{action_type}:{target}"

    def create_request(self, req: ApprovalRequest) -> ApprovalRecord:
        # Reuse an existing APPROVED record for the same (action, target) so
        # repeat identical actions don't need re-approval.
        for record in self._pending.values():
            if (
                record.action_type == req.action_type
                and record.action_params == req.action_params
                and record.status == ApprovalStatus.APPROVED
            ):
                return record
        record = ApprovalRecord(
            id=str(uuid.uuid4())[:8],
            action_type=req.action_type,
            action_params=req.action_params,
            requested_by=req.requested_by,
            justification=req.justification,
            approvers_required=req.approvers_required,
        )
        self._pending[record.id] = record
        self._save()
        logger.info("Approval request created: %s for %s", record.id, req.action_type)
        return record

    def approve(self, request_id: str, approver: str) -> ApprovalRecord:
        record = self._pending.get(request_id)
        if not record:
            raise ValueError(f"Request {request_id} not found")
        if record.status != ApprovalStatus.PENDING:
            raise ValueError(f"Request {request_id} is {record.status}")
        if record.is_expired():
            record.status = ApprovalStatus.EXPIRED
            record.resolved_at = datetime.now(UTC).isoformat()
            self._save()
            raise ValueError(f"Request {request_id} has expired")
        if approver == record.requested_by:
            raise ValueError("Approver must be a different user than the requester")
        if approver not in record.approvals:
            record.approvals.append(approver)
        if len(record.approvals) >= record.approvers_required:
            record.status = ApprovalStatus.APPROVED
            record.resolved_at = datetime.now(UTC).isoformat()
            logger.info("Approval request %s APPROVED by %s", request_id, approver)
        self._save()
        return record

    def reject(self, request_id: str, approver: str, reason: str = "") -> ApprovalRecord:
        record = self._pending.get(request_id)
        if not record:
            raise ValueError(f"Request {request_id} not found")
        if record.status != ApprovalStatus.PENDING:
            raise ValueError(f"Request {request_id} is {record.status}")
        record.status = ApprovalStatus.REJECTED
        record.rejections.append(f"{approver}: {reason}")
        record.resolved_at = datetime.now(UTC).isoformat()
        self._save()
        logger.info(
            "Approval request %s REJECTED by %s: %s", request_id, approver, reason
        )
        return record

    def get_status(self, request_id: str) -> Optional[ApprovalRecord]:
        return self._pending.get(request_id)

    def is_approved(self, action_type: str, action_params: dict) -> bool:
        """True if an APPROVED request exists for this (action, target) pair."""
        key = self._key(action_type, action_params)
        for record in self._pending.values():
            if (
                record.action_type == action_type
                and record.action_params == action_params
                and record.status == ApprovalStatus.APPROVED
            ):
                return True
        return False

    def pending_for(self, action_type: str, action_params: dict) -> Optional[ApprovalRecord]:
        """Return the PENDING request for this (action, target), if any."""
        for record in self._pending.values():
            if (
                record.action_type == action_type
                and record.action_params == action_params
                and record.status == ApprovalStatus.PENDING
            ):
                return record
        return None

    def list_pending(self) -> list[ApprovalRecord]:
        return [r for r in self._pending.values() if r.status == ApprovalStatus.PENDING]


# Global singleton
workflow = ApprovalWorkflow()
