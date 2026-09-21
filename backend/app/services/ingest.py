"""Ingestion pipeline: EVE events → ``sensor_events`` rows → ``alerts``.

One function, :func:`ingest_events`, is the whole contract — the worker job
(:func:`app.worker.jobs.ingest_eve`) only adds file tailing and session
handling around it. Keeping the pipeline database-explicit (it takes a session)
is what lets the tests drive it with fixtures and no sensor installed.

Pipeline, in order:

1. **Deduplicate** incoming events on ``event_id`` (against the DB *and*
   within the batch) so a restart never double-counts activity.
2. **Persist** every event as a ``sensor_events`` row — not just the alerts.
   The detection engine needs the raw window to work on.
3. **Signature alerts** — a Suricata ``alert`` record becomes an ``Alert``
   (``source="suricata"``) straight away: the sensor already did the detection.
4. **Local detection** — the declarative rules (#2) are evaluated over the
   trailing window of stored events and produce ``source="rule"`` alerts,
   deduplicated so one ongoing scan yields one alert with a rising
   ``occurrences`` counter instead of a storm.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Sequence

from sqlalchemy import func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Alert, SensorEvent
from app.services import detection as detection_service
from app.services import metrics
from app.services.suricata import severity_from_signature_level

logger = logging.getLogger(__name__)

_SENSOR_EVENT_FIELDS = (
    "event_id",
    "occurred_at",
    "event_type",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "proto",
    "app_proto",
    "signature",
    "signature_severity",
    "payload",
)


def _aware(moment: Optional[datetime]) -> datetime:
    current = moment or datetime.now(timezone.utc)
    return current if current.tzinfo else current.replace(tzinfo=timezone.utc)


async def _existing_event_ids(session: AsyncSession, event_ids: Sequence[str]) -> set[str]:
    """Which of these ``event_id`` values are already stored."""
    if not event_ids:
        return set()
    rows = (
        await session.exec(select(SensorEvent.event_id).where(SensorEvent.event_id.in_(list(event_ids))))
    ).all()
    return set(rows)


def _signature_alert(event: SensorEvent, normalized: dict) -> Alert:
    return Alert(
        source="suricata",
        event_type="signature",
        severity=severity_from_signature_level(event.signature_severity),
        src_ip=event.src_ip,
        src_port=event.src_port,
        dst_ip=event.dst_ip,
        dst_port=event.dst_port,
        proto=event.proto,
        signature=event.signature,
        detail=(
            f"Suricata signature match: {event.signature}"
            if event.signature
            else "Suricata alert with no signature"
        ),
        payload=normalized.get("payload", ""),
        dedup_key=None,  # one sensor alert = one row; Suricata owns suppression
        status="new",
    )


async def _apply_detection(
    session: AsyncSession,
    det: detection_service.Detection,
    rules: Sequence[detection_service.Rule],
    now: datetime,
) -> str:
    """Persist one detection, bumping an existing alert instead of flooding.

    Returns ``"created"`` or ``"updated"``.
    """
    window_seconds = next(
        (rule.window_seconds for rule in rules if rule.name == det.rule_name),
        det.metadata.get("window_seconds", 60),
    )
    recent_cutoff = now - timedelta(seconds=int(window_seconds))

    existing = (
        await session.exec(
            select(Alert)
            .where(Alert.dedup_key == det.dedup_key)
            .where(Alert.created_at >= recent_cutoff)
            .order_by(Alert.created_at.desc())
        )
    ).first()

    if existing is not None:
        # The activity is still going on: one alert, a rising counter. An alert
        # already acknowledged stays acknowledged — a human accepted it.
        existing.occurrences = (existing.occurrences or 1) + 1
        existing.confidence = max(existing.confidence or 0.0, det.confidence)
        existing.detail = det.detail
        session.add(existing)
        return "updated"

    session.add(
        Alert(
            source="rule",
            event_type=det.kind,
            severity=det.severity,
            src_ip=det.src_ip,
            src_port=None,
            dst_ip=det.dst_ip,
            dst_port=det.dst_port,
            proto=det.proto,
            rule_name=det.rule_name,
            confidence=det.confidence,
            occurrences=1,
            dedup_key=det.dedup_key,
            detail=det.detail,
            payload=json.dumps(det.metadata, ensure_ascii=False, sort_keys=True),
            status="new",
        )
    )
    return "created"


async def ingest_events(
    session: AsyncSession,
    events: Sequence[dict],
    rules: Optional[Sequence[detection_service.Rule]] = None,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Ingest normalized sensor events and (re)evaluate the detection rules."""
    moment = _aware(now)
    active_rules = list(rules) if rules is not None else detection_service.load_rules()

    incoming_ids = [event["event_id"] for event in events if event.get("event_id")]
    already_stored = await _existing_event_ids(session, incoming_ids)

    stored = 0
    duplicates = 0
    signature_alerts = 0
    batch_ids: set[str] = set()

    for normalized in events:
        event_id = normalized.get("event_id")
        if not event_id or event_id in already_stored or event_id in batch_ids:
            duplicates += 1
            continue
        batch_ids.add(event_id)

        event = SensorEvent(**{name: normalized.get(name) for name in _SENSOR_EVENT_FIELDS})
        session.add(event)
        stored += 1

        if normalized.get("event_type") == "alert":
            alert = _signature_alert(event, normalized)
            session.add(alert)
            metrics.record_alert(alert.source, alert.severity)
            signature_alerts += 1

    await session.flush()

    # --- local detection over the trailing window ------------------------- #
    window_seconds = max((rule.window_seconds for rule in active_rules), default=60)
    window_start = moment - timedelta(seconds=window_seconds)
    recent = (
        await session.exec(
            select(SensorEvent)
            .where(SensorEvent.occurred_at >= window_start)
            .where(SensorEvent.occurred_at <= moment)
            .order_by(SensorEvent.occurred_at.desc())
        )
    ).all()

    detections = detection_service.evaluate(recent, rules=active_rules, now=moment)
    metrics.record_detections(detections)

    created = 0
    updated = 0
    for det in detections:
        outcome = await _apply_detection(session, det, active_rules, moment)
        if outcome == "created":
            metrics.record_alert("rule", det.severity)
            created += 1
        else:
            updated += 1

    await session.commit()

    result = {
        "received": len(events),
        "stored": stored,
        "duplicates": duplicates,
        "signature_alerts": signature_alerts,
        "detections": len(detections),
        "rule_alerts_created": created,
        "rule_alerts_updated": updated,
    }
    if stored or detections:
        logger.info("sensor ingest: %s", result)
    return result


async def count_sensor_events(session: AsyncSession) -> int:
    """Total number of stored sensor events (used by the dashboard/metrics)."""
    return (await session.exec(select(func.count()).select_from(SensorEvent))).one()
