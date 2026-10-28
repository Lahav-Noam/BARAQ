"""AI Assistant API endpoints."""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.ai.assistant import SecurityAssistant
from backend.audit import client_ip, log_action
from backend.database.connection import get_db
from backend.security import actor_name, require_auth, resolve_user, tenant_scope

router = APIRouter(
    prefix="/api/assistant",
    tags=["assistant"],
    dependencies=[Depends(require_auth)],
)

# ── Assistant chat rate limiting ────────────────────────────────────────────
# Bug #7: the chat endpoint had no rate limiting. A sliding window per
# authenticated user prevents abuse / exfiltration loops via the assistant.
_ASSISTANT_RATE_WINDOW = 60  # seconds
_ASSISTANT_RATE_MAX = 30  # requests per window per user
_assistant_requests: dict[str, list[float]] = defaultdict(list)
_assistant_lock = Lock()


def _assistant_rate_check(user_id: int | str) -> None:
    """Raise 429 if the user has exceeded the assistant chat rate limit."""
    now = time.time()
    window_start = now - _ASSISTANT_RATE_WINDOW
    with _assistant_lock:
        key = str(user_id)
        timestamps = [t for t in _assistant_requests[key] if t > window_start]
        if len(timestamps) >= _ASSISTANT_RATE_MAX:
            retry_after = int(_ASSISTANT_RATE_WINDOW - (now - timestamps[0])) + 1
            raise HTTPException(
                status_code=429,
                detail=f"Assistant rate limit exceeded. Try again in {retry_after}s.",
                headers={"Retry-After": str(retry_after)},
            )
        timestamps.append(now)
        _assistant_requests[key] = timestamps


def _assistant(request: Request, db: Session):
    user = resolve_user(request, db)
    user_id = user.id if user is not None else None
    return SecurityAssistant(db, org=tenant_scope(request), user_id=user_id)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


class ExplainRequest(BaseModel):
    alert_id: int | None = Field(default=None, ge=1)
    query: str = Field(default="", max_length=2000)


class EntityExplainRequest(BaseModel):
    kind: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=1, max_length=512)


@router.post("/chat")
def chat(body: ChatRequest, request: Request, db: Session = Depends(get_db)):
    user = resolve_user(request, db)
    _assistant_rate_check(user.id if user is not None else client_ip(request))
    assistant = _assistant(request, db)
    response = assistant.chat(body.message)
    return {"reply": response, "history": assistant.history()}


@router.get("/history")
def history(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    assistant = _assistant(request, db)
    return {"items": assistant.history(limit)}


@router.delete("/history")
def clear_history(request: Request, db: Session = Depends(get_db)):
    assistant = _assistant(request, db)
    count = assistant.clear_history()
    log_action(
        db,
        actor_name(request),
        "assistant.clear_history",
        "assistant_messages",
        str(count),
        f"deleted {count} conversation message(s)",
        client_ip(request),
    )
    return {"cleared": count, "message": "Conversation history cleared."}


@router.post("/explain")
def explain(body: ExplainRequest, request: Request, db: Session = Depends(get_db)):
    assistant = _assistant(request, db)
    query = (
        body.query or f"explain alert {body.alert_id}"
        if body.alert_id
        else "explain the latest alert"
    )
    response = assistant.chat(query, persist=False)
    return {"reply": response}


@router.post("/summarize")
def summarize(request: Request, db: Session = Depends(get_db)):
    assistant = _assistant(request, db)
    response = assistant.chat("summarize the current incidents", persist=False)
    return {"reply": response}


@router.post("/explain-entity")
def explain_entity(
    body: EntityExplainRequest, request: Request, db: Session = Depends(get_db)
):
    assistant = _assistant(request, db)
    response = assistant.explain_entity(body.kind, body.name)
    return {"reply": response}
