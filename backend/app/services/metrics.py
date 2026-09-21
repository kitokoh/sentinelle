"""Prometheus instrumentation (v0.6, issue #19).

Design notes:

* **A private registry, not the global one.** ``prometheus_client`` registers
  process/GC collectors in the default registry, whose output varies with the
  Python build and makes tests flaky. Everything here lives in
  :data:`REGISTRY`, so ``/metrics`` exposes exactly what this module declares.
* **``route`` is the path *template*, never the raw path.** ``/api/scans/4711``
  must be recorded as ``/api/scans/{scan_id}``; otherwise every scan id becomes
  its own time series and Prometheus is drowned by cardinality.
* **Database-derived values are refreshed on scrape.** Gauges such as the number
  of stored indicators are cheap ``COUNT(*)`` queries, and reading them at scrape
  time means the dashboard can never disagree with the database.
* **Bounded queries only.** ``refresh_database_gauges`` runs one count per table;
  nothing here scans a growing table.
"""

import logging
from datetime import datetime, timezone
from typing import Iterable, Optional

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram
from prometheus_client import generate_latest
from sqlmodel import func, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Alert, IntelFeedItem, Ioc, WorkerHeartbeat

logger = logging.getLogger(__name__)

REGISTRY = CollectorRegistry()

HTTP_REQUESTS = Counter(
    "sentinelle_http_requests_total",
    "Requêtes HTTP traitées, par méthode, route et code de statut.",
    ["method", "route", "status"],
    registry=REGISTRY,
)

HTTP_DURATION = Histogram(
    "sentinelle_http_request_duration_seconds",
    "Durée de traitement des requêtes HTTP.",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=REGISTRY,
)

SCANS_CREATED = Counter(
    "sentinelle_scans_created_total",
    "Scans acceptés par l'API, par profil.",
    ["profile"],
    registry=REGISTRY,
)

ALERTS_CREATED = Counter(
    "sentinelle_alerts_created_total",
    "Alertes produites, par source et sévérité.",
    ["source", "severity"],
    registry=REGISTRY,
)

DETECTIONS = Counter(
    "sentinelle_detections_total",
    "Détections déclenchées par le moteur de règles.",
    ["rule"],
    registry=REGISTRY,
)

IOCS = Gauge(
    "sentinelle_iocs_total",
    "Indicateurs de compromis stockés, toutes sources confondues.",
    registry=REGISTRY,
)

FEED_ITEMS = Gauge(
    "sentinelle_intel_feed_items_total",
    "Avis CERT stockés.",
    registry=REGISTRY,
)

UNACKNOWLEDGED_ALERTS = Gauge(
    "sentinelle_alerts_unacknowledged",
    "Alertes non acquittées.",
    registry=REGISTRY,
)

WORKER_LAST_SEEN = Gauge(
    "sentinelle_worker_last_seen_timestamp_seconds",
    "Horodatage Unix du dernier battement de chaque worker.",
    ["worker"],
    registry=REGISTRY,
)

WORKER_UP = Gauge(
    "sentinelle_worker_up",
    "1 si le worker a émis un battement récent, 0 sinon.",
    ["worker"],
    registry=REGISTRY,
)


# --------------------------------------------------------------------------- #
# Recording
# --------------------------------------------------------------------------- #


def observe_request(method: str, route: str, status_code: int, duration_seconds: float) -> None:
    """Record one HTTP request. ``route`` must be a path template."""
    HTTP_REQUESTS.labels(method=method, route=route, status=str(status_code)).inc()
    HTTP_DURATION.labels(method=method, route=route).observe(duration_seconds)


def record_scan(profile: str) -> None:
    SCANS_CREATED.labels(profile=profile or "unknown").inc()


def record_alert(source: str, severity: str) -> None:
    ALERTS_CREATED.labels(source=source or "unknown", severity=severity or "info").inc()


def record_detections(detections: Iterable) -> None:
    """Count the detections produced by one ingestion cycle."""
    for detection in detections:
        kind = getattr(detection, "kind", None) or "unknown"
        DETECTIONS.labels(rule=kind).inc()


def record_ingest(summary: dict) -> None:
    """Feed the alert counters from an ingestion summary (see app.services.ingest)."""
    for _ in range(int(summary.get("rule_alerts_created", 0) or 0)):
        record_alert("rule", "unknown")
    for _ in range(int(summary.get("signature_alerts", 0) or 0)):
        record_alert("suricata", "unknown")


# --------------------------------------------------------------------------- #
# Worker liveness
# --------------------------------------------------------------------------- #


def worker_is_stale(
    last_seen: Optional[datetime],
    now: Optional[datetime] = None,
    threshold_seconds: int = 300,
) -> bool:
    """Has this worker missed its beat window?

    A missing heartbeat counts as stale: a worker that never came up is exactly
    what the alert is for.
    """
    if last_seen is None:
        return True
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    return (moment - last_seen).total_seconds() > threshold_seconds


async def refresh_worker_gauges(session: AsyncSession, threshold_seconds: int = 300) -> list[str]:
    """Publish every known worker's age and up/down state. Returns the stale names."""
    rows = (await session.exec(select(WorkerHeartbeat))).all()
    moment = datetime.now(timezone.utc)
    stale: list[str] = []

    for row in rows:
        last_seen = row.last_seen_at
        if last_seen is not None and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        WORKER_LAST_SEEN.labels(worker=row.name).set(
            last_seen.timestamp() if last_seen else 0
        )
        is_stale = worker_is_stale(last_seen, moment, threshold_seconds)
        WORKER_UP.labels(worker=row.name).set(0 if is_stale else 1)
        if is_stale:
            stale.append(row.name)
    return stale


# --------------------------------------------------------------------------- #
# Database-derived gauges
# --------------------------------------------------------------------------- #


async def refresh_database_gauges(session: AsyncSession) -> None:
    """Refresh the gauges that mirror the database, one bounded count each."""
    IOCS.set((await session.exec(select(func.count()).select_from(Ioc))).one())
    FEED_ITEMS.set((await session.exec(select(func.count()).select_from(IntelFeedItem))).one())
    UNACKNOWLEDGED_ALERTS.set(
        (
            await session.exec(
                select(func.count()).select_from(Alert).where(Alert.status == "new")
            )
        ).one()
    )


def render() -> tuple[bytes, str]:
    """Serialise the registry, ready to be returned by ``/metrics``."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
