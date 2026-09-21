"""Threat-intel routes — the Renseignement page's backend (v0.4, issues #6–#10).

Read model: what the connectors pulled (``/iocs``, ``/feed``), what it matched
locally (``/matches``) and the single aggregate the page renders
(``/overview``). ``POST /sync`` triggers a full intel cycle on demand — useful on
a demo instance where waiting for the six-hourly cron makes no sense.
"""

import logging
from typing import Optional

import arq
from arq.connections import RedisSettings
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.db import get_session
from app.models import Alert, IntelFeedItem, Ioc, User
from app.services.intel import overview as intel_overview

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/intel", tags=["intel"])

MAX_LIMIT = 500
SEVERITIES = ("info", "low", "medium", "high", "critical")


class SyncRequest(BaseModel):
    """Optional narrowing of an on-demand sync; all enabled by default."""

    sources: Optional[list[str]] = None


@router.get("/overview")
async def get_overview(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Everything the Renseignement page needs, in one round trip."""
    return await intel_overview.build_overview(session)


@router.get("/iocs")
async def list_iocs(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
    type: Optional[str] = Query(None, description="ip | domain | url | md5 | sha1 | sha256 | email"),
    source: Optional[str] = Query(None, description="misp | otx"),
    severity: Optional[str] = Query(None, description="Repeatable or comma-separated."),
    search: Optional[str] = Query(None, description="Substring match on the indicator value."),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
) -> list[dict]:
    """List stored indicators, newest first."""
    query = select(Ioc)
    if type:
        query = query.where(Ioc.type == type)
    if source:
        # ``sources`` is a comma-separated list — a substring match is the honest
        # way to query it without pretending it is a relation.
        query = query.where(Ioc.sources.like(f"%{source}%"))
    if severity:
        values = [part.strip() for part in severity.split(",") if part.strip()]
        if values:
            query = query.where(Ioc.severity.in_(values))
    if search:
        query = query.where(Ioc.value.like(f"%{search}%"))

    query = query.order_by(Ioc.last_seen.desc(), Ioc.id.desc()).offset(offset).limit(limit)
    rows = (await session.exec(query)).all()
    return [intel_overview.ioc_to_dict(ioc) for ioc in rows]


@router.get("/feed")
async def list_feed(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
    source: Optional[str] = Query(None, description="Feed name, e.g. CERT-FR."),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
) -> list[IntelFeedItem]:
    """List CERT advisory items, newest first."""
    query = select(IntelFeedItem)
    if source:
        query = query.where(IntelFeedItem.source == source)
    query = (
        query.order_by(IntelFeedItem.published_at.desc(), IntelFeedItem.id.desc())
        .offset(offset)
        .limit(limit)
    )
    return list((await session.exec(query)).all())


@router.get("/matches")
async def list_matches(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
    status_filter: Optional[str] = Query(None, alias="status", description="new | ack"),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
) -> list[Alert]:
    """List the alerts raised by correlation (``source="intel"``)."""
    query = select(Alert).where(Alert.source == "intel")
    if status_filter:
        query = query.where(Alert.status == status_filter)
    query = (
        query.order_by(Alert.created_at.desc(), Alert.id.desc()).offset(offset).limit(limit)
    )
    return list((await session.exec(query)).all())


@router.post("/sync", status_code=status.HTTP_202_ACCEPTED)
async def trigger_sync(
    payload: SyncRequest | None = None,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Enqueue a full intel cycle (connectors + correlation) on the worker.

    Returns 503 rather than a 500 when Redis is unreachable: the platform is fine,
    only the queue is missing — the message says exactly that.
    """
    requested = set((payload.sources if payload else None) or [])
    settings = get_settings()

    try:
        redis = await arq.create_pool(RedisSettings.from_dsn(settings.REDIS_URL))
    except Exception as exc:  # noqa: BLE001 — any connection failure means "no queue"
        logger.warning("intel sync refused: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "The job queue is unreachable — start Redis (and the worker) to "
                "run a threat-intel sync."
            ),
        ) from exc

    try:
        job = await redis.enqueue_job("run_intel_sync")
    finally:
        await redis.close()

    configured = {
        "misp": bool(settings.MISP_URL and settings.MISP_API_KEY),
        "otx": bool(settings.OTX_API_KEY),
        "cert": bool(settings.CERT_FEEDS.strip()),
    }
    selected = sorted(requested) if requested else sorted(configured)
    return {
        "status": "queued",
        "job_id": job.job_id if job else None,
        "sources": selected,
        # Surfaced so a caller can tell "nothing was configured" from "nothing found".
        "configured": configured,
    }
