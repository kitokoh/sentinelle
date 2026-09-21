"""Alert routes — the defensive side of the platform (v0.3, issues #1 & #3).

Read model: the SOC-wide stream of alerts produced either by the Suricata
sensor (``source="suricata"``) or by the local detection rules
(``source="rule"``). Alerts are intentionally *not* scoped to a user yet —
that arrives with multi-tenancy in v0.5 (#15); today the platform has a single
SOC view, which is what the dashboard counter needs.
"""

from datetime import datetime
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.api.deps import get_current_user
from app.db import get_session
from app.models import Alert, User, utcnow

router = APIRouter(prefix="/alerts", tags=["alerts"])

SEVERITIES = ("info", "low", "medium", "high", "critical")
#: Hard cap so a SOC export never turns into an accidental full-table dump.
MAX_LIMIT = 500


class AlertRead(BaseModel):
    id: int
    created_at: datetime
    source: str
    event_type: str
    severity: str
    src_ip: Optional[str]
    src_port: Optional[int]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    proto: Optional[str]
    rule_name: Optional[str]
    confidence: Optional[float]
    occurrences: int
    signature: Optional[str]
    detail: str
    status: str
    acknowledged_at: Optional[datetime]
    acknowledged_by: Optional[int]


class AlertDetail(AlertRead):
    payload: str


class AlertStats(BaseModel):
    total: int
    unacknowledged: int
    by_severity: dict[str, int]
    by_source: dict[str, int]


class AlertUpdate(BaseModel):
    """Only the lifecycle field is writable — alerts are evidence, not a CRUD table."""

    status: Literal["new", "ack"]


def _split_values(values: Optional[list[str]]) -> list[str]:
    """Accept both ``?severity=high&severity=low`` and ``?severity=high,low``."""
    if not values:
        return []
    flattened: list[str] = []
    for value in values:
        flattened.extend(part.strip() for part in str(value).split(",") if part.strip())
    return flattened


@router.get("/stats", response_model=AlertStats)
async def alert_stats(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> AlertStats:
    """Counters driving the sidebar badge and the dashboard cards."""
    total = (await session.exec(select(func.count()).select_from(Alert))).one()
    unacknowledged = (
        await session.exec(
            select(func.count()).select_from(Alert).where(Alert.status == "new")
        )
    ).one()

    severity_rows = (
        await session.exec(select(Alert.severity, func.count()).group_by(Alert.severity))
    ).all()
    by_severity = {severity: 0 for severity in SEVERITIES}
    by_severity.update({severity: count for severity, count in severity_rows})

    source_rows = (await session.exec(select(Alert.source, func.count()).group_by(Alert.source))).all()
    by_source = {source: count for source, count in source_rows}

    return AlertStats(
        total=total,
        unacknowledged=unacknowledged,
        by_severity=by_severity,
        by_source=by_source,
    )


@router.get("", response_model=list[AlertRead])
async def list_alerts(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
    severity: Optional[list[str]] = Query(None, description="Repeatable or comma-separated."),
    source: Optional[list[str]] = Query(None, description="suricata | rule | intel"),
    status_filter: Optional[list[str]] = Query(None, alias="status", description="new | ack"),
    rule_name: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    since: Optional[datetime] = Query(None, description="ISO-8601 lower bound on created_at."),
    until: Optional[datetime] = Query(None, description="ISO-8601 upper bound on created_at."),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
) -> list[Alert]:
    """List alerts newest first, with the filters the SOC page exposes."""
    query = select(Alert)

    severities = _split_values(severity)
    if severities:
        query = query.where(Alert.severity.in_(severities))

    sources = _split_values(source)
    if sources:
        query = query.where(Alert.source.in_(sources))

    statuses = _split_values(status_filter)
    if statuses:
        query = query.where(Alert.status.in_(statuses))

    if rule_name:
        query = query.where(Alert.rule_name == rule_name)
    if src_ip:
        query = query.where(Alert.src_ip == src_ip)
    if dst_ip:
        query = query.where(Alert.dst_ip == dst_ip)
    if since:
        query = query.where(Alert.created_at >= since)
    if until:
        query = query.where(Alert.created_at <= until)

    query = query.order_by(Alert.created_at.desc(), Alert.id.desc()).offset(offset).limit(limit)
    return list((await session.exec(query)).all())


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(
    alert_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> Alert:
    """Fetch one alert including its raw payload."""
    alert = await session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertRead)
async def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> Alert:
    """Acknowledge an alert (or reopen it).

    Acknowledgement is recorded with the acting user and a timestamp — the
    first line of the audit trail formalised in v0.5 (#13).
    """
    alert = await session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    alert.status = payload.status
    if payload.status == "ack":
        alert.acknowledged_at = utcnow()
        alert.acknowledged_by = current_user.id
    else:
        alert.acknowledged_at = None
        alert.acknowledged_by = None

    session.add(alert)
    await session.commit()
    await session.refresh(alert)
    return alert
