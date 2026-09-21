"""Configurable retention & purge (v0.3, issue #5).

Keeps the platform's data volume bounded and auditable — the kind of hygiene a
public-sector buyer asks about, and the concrete answer to "how long do you keep
personal data?".

Three tables are purged, each with its own clock:

  ==================  ==========================  ==========================
  table               timestamp used              why it is purgeable
  ==================  ==========================  ==========================
  ``findings``        via ``scans.created_at``    scan output, no timestamp
  ``alerts``          ``created_at``              defensive detections
  ``sensor_events``   ``occurred_at``             raw traffic evidence
  ==================  ==========================  ==========================

``scans`` and ``targets`` are **never** purged: they are the audit record of
what was authorised and run, which is exactly what must survive.

``RETENTION_DAYS <= 0`` disables purging entirely (useful for a demo instance
that must keep everything).
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Alert, Finding, Scan, SensorEvent

logger = logging.getLogger(__name__)


def _aware(moment: Optional[datetime]) -> datetime:
    current = moment or datetime.now(timezone.utc)
    return current if current.tzinfo else current.replace(tzinfo=timezone.utc)


async def purge_expired(
    session: AsyncSession,
    retention_days: int,
    now: Optional[datetime] = None,
) -> dict[str, int | bool]:
    """Delete rows older than ``retention_days`` and report what was removed.

    Returns a counter per table plus the ``enabled`` flag and ``cutoff`` date,
    so the caller can log a line an operator can act on.
    """
    moment = _aware(now)

    if retention_days is None or retention_days <= 0:
        logger.info("retention disabled (RETENTION_DAYS=%s) — nothing purged", retention_days)
        return {
            "enabled": False,
            "retention_days": int(retention_days or 0),
            "findings": 0,
            "alerts": 0,
            "sensor_events": 0,
        }

    cutoff = moment - timedelta(days=retention_days)

    # Findings carry no timestamp of their own: they expire with their scan.
    expired_scans = select(Scan.id).where(Scan.created_at < cutoff)
    findings = await session.execute(delete(Finding).where(Finding.scan_id.in_(expired_scans)))
    alerts = await session.execute(delete(Alert).where(Alert.created_at < cutoff))
    events = await session.execute(delete(SensorEvent).where(SensorEvent.occurred_at < cutoff))
    await session.commit()

    counters: dict[str, int | bool] = {
        "enabled": True,
        "retention_days": int(retention_days),
        "cutoff": cutoff.isoformat(),  # type: ignore[dict-item]
        "findings": findings.rowcount or 0,
        "alerts": alerts.rowcount or 0,
        "sensor_events": events.rowcount or 0,
    }
    logger.info("retention purge (cutoff %s): %s", cutoff.isoformat(), counters)
    return counters
