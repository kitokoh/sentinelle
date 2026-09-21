"""Monitoring endpoints (v0.6, issue #19).

``GET /metrics`` — Prometheus exposition format, deliberately **outside** ``/api``
(the scraper convention) and protected by an optional bearer token
(``METRICS_TOKEN``). When no token is configured the endpoint is open, which is
only acceptable while it is not reachable from outside — hence the warning in
:func:`metrics`.

``GET /api/health`` stays a plain liveness probe; the readiness view is
``GET /api/health/dependencies``, which reports the worker's heartbeat age. Two
separate endpoints on purpose: a liveness probe must not fail because a
*dependency* is down, or Kubernetes would restart a perfectly healthy API.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import get_settings
from app.db import get_session
from app.models import WorkerHeartbeat
from app.services import metrics

logger = logging.getLogger(__name__)

router = APIRouter(tags=["monitoring"])

_warned_about_open_metrics = False


def _authorise(request: Request) -> None:
    """Bearer-token check for the scrape endpoint."""
    global _warned_about_open_metrics
    expected = get_settings().METRICS_TOKEN
    if not expected:
        if not _warned_about_open_metrics:
            logger.warning(
                "METRICS_TOKEN is not set: /metrics is reachable without authentication. "
                "Set it, or keep the endpoint off the public network."
            )
            _warned_about_open_metrics = True
        return

    header = request.headers.get("authorization") or ""
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A bearer token is required to scrape metrics.",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get("/metrics", include_in_schema=False)
async def prometheus_metrics(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Expose the registry in Prometheus exposition format.

    Database and worker gauges are refreshed *at scrape time*: the dashboard can
    then never disagree with what the platform actually holds.
    """
    _authorise(request)

    settings = get_settings()
    await metrics.refresh_database_gauges(session)
    stale = await metrics.refresh_worker_gauges(session, settings.WORKER_STALE_SECONDS)
    if stale:
        logger.warning("worker heartbeat expired for: %s", ", ".join(stale))

    payload, content_type = metrics.render()
    return Response(content=payload, media_type=content_type)


@router.get("/api/health/dependencies", tags=["health"])
async def health_dependencies(
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Readiness view: are the moving parts actually moving?

    Public and unauthenticated like ``/api/health``: an orchestrator needs to
    reach it, and it exposes no data — only liveness and ages.
    """
    settings = get_settings()
    rows = list((await session.exec(select(WorkerHeartbeat))).all())
    moment = datetime.now(timezone.utc)

    workers = []
    for row in rows:
        last_seen: Optional[datetime] = row.last_seen_at
        if last_seen is not None and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        age = (moment - last_seen).total_seconds() if last_seen else None
        workers.append(
            {
                "name": row.name,
                "last_seen": last_seen.isoformat() if last_seen else None,
                "age_seconds": round(age, 1) if age is not None else None,
                "status": (
                    "down"
                    if metrics.worker_is_stale(last_seen, moment, settings.WORKER_STALE_SECONDS)
                    else "up"
                ),
            }
        )

    stale = [worker["name"] for worker in workers if worker["status"] == "down"]
    return {
        # A worker that has never reported is down, not unknown: that is precisely
        # the situation the check exists for.
        "status": "degraded" if (stale or not workers) else "ok",
        "stale_after_seconds": settings.WORKER_STALE_SECONDS,
        "workers": workers,
    }
