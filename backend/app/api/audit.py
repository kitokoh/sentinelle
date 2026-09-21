"""Audit trail routes — read-only, ``admin`` only (v0.5, issue #13).

There is no write endpoint by design: the journal is append-only, filled by the
middleware. The only way to add to it is to perform an action on the platform.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.api.deps import admin_required, get_current_org_id, get_current_user
from app.db import get_session
from app.models import AuditLog, User

router = APIRouter(prefix="/audit", tags=["audit"])

MAX_LIMIT = 500


class AuditRead(BaseModel):
    id: int
    created_at: datetime
    actor_id: Optional[int]
    actor_email: Optional[str]
    org_id: Optional[int]
    action: str
    method: str
    path: str
    status_code: int
    entity: Optional[str]
    entity_id: Optional[int]
    ip: Optional[str]
    detail: str


@router.get("", response_model=list[AuditRead])
async def list_audit(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(admin_required),
    org_id: int = Depends(get_current_org_id),
    actor: Optional[str] = Query(None, description="Substring match on the actor's e-mail."),
    action: Optional[str] = Query(None, description="Substring match, e.g. 'targets.'"),
    entity: Optional[str] = None,
    entity_id: Optional[int] = None,
    since: Optional[datetime] = Query(None, description="ISO-8601 lower bound."),
    until: Optional[datetime] = Query(None, description="ISO-8601 upper bound."),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
) -> list[AuditLog]:
    """Newest first, filtered.

    Scoped to the caller's organization, plus the rows with no organization (an
    action performed before authentication, such as a failed login) — otherwise
    the very events an administrator most wants to see would be invisible.
    """
    query = select(AuditLog)
    if org_id is not None:
        query = query.where((AuditLog.org_id == org_id) | (AuditLog.org_id.is_(None)))
    if actor:
        query = query.where(AuditLog.actor_email.like(f"%{actor}%"))
    if action:
        query = query.where(AuditLog.action.like(f"%{action}%"))
    if entity:
        query = query.where(AuditLog.entity == entity)
    if entity_id is not None:
        query = query.where(AuditLog.entity_id == entity_id)
    if since:
        query = query.where(AuditLog.created_at >= since)
    if until:
        query = query.where(AuditLog.created_at <= until)

    query = (
        query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).offset(offset).limit(limit)
    )
    return list((await session.exec(query)).all())


@router.get("/actions", response_model=list[str])
async def list_actions(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(admin_required),
) -> list[str]:
    """Distinct action names, so the journal's filter is usable without guessing."""
    rows = await session.exec(select(AuditLog.action).distinct().order_by(AuditLog.action))
    return [action for action in rows.all() if action]
