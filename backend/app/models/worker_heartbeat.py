"""WorkerHeartbeat — proof that the worker is alive (v0.6, issue #19).

A queue-based architecture has a specific failure mode: the API keeps serving,
the queue keeps accepting jobs, and nobody notices that nothing is consuming
them. The platform looks healthy while scans silently pile up.

Each worker job cycle refreshes its row here. ``/metrics`` exposes the age of the
most recent beat and ``deploy/monitoring/prometheus/alerts.yml`` fires when it
exceeds ``WORKER_STALE_SECONDS``. Reading the heartbeat from the database (rather
than from Redis) keeps it observable even when Redis is the thing that broke —
and keeps it testable without a broker.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel

from app.models.columns import utc_datetime_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class WorkerHeartbeat(SQLModel, table=True):
    __tablename__ = "worker_heartbeats"

    #: Name of the job family, e.g. ``arq-worker``.
    name: str = Field(primary_key=True)
    last_seen_at: datetime = Field(
        default_factory=utcnow, sa_column=utc_datetime_column(index=True)
    )
    #: Free-form context (jobs processed, last error…) — never sensitive.
    detail: Optional[str] = None
