"""Persistence helpers for threat intel — upserts with cross-source de-duplication.

Two invariants this module exists to guarantee:

1. **One indicator = one row.** An IP present in both MISP and OTX is stored once,
   with both provenances merged into ``sources`` and the earliest ``first_seen``
   kept. Without this the correlator would alert twice for the same thing.
2. **Re-syncing is safe.** Polling a feed again refreshes ``last_seen`` and merges
   metadata; it never duplicates. Re-running a sync is therefore the normal case,
   not an exceptional one.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import IntelFeedItem, Ioc

logger = logging.getLogger(__name__)

#: Ordered, so "escalate" means "take the most serious of the two".
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _aware(moment: Optional[datetime]) -> datetime:
    current = moment or datetime.now(timezone.utc)
    return current if current.tzinfo else current.replace(tzinfo=timezone.utc)


def _naive_to_utc(value: Optional[datetime]) -> datetime:
    """Dates read back from SQLite are naive; comparisons must be homogeneous.

    SQLite stores ``DateTime`` as a string without the offset, so a value that
    went in UTC-aware comes back naive. Re-attaching UTC is correct because that
    is precisely how it was written (see tests/test_migrations.py).
    """
    return _aware(value)


def escalate_severity(current: str, candidate: str) -> str:
    """Keep the most severe of two severities."""
    left = SEVERITY_ORDER.index(current) if current in SEVERITY_ORDER else 1
    right = SEVERITY_ORDER.index(candidate) if candidate in SEVERITY_ORDER else 1
    return SEVERITY_ORDER[max(left, right)]


def merge_sources(current: str, incoming: str) -> str:
    """Union of two comma-separated source lists, sorted and deduplicated."""
    values = {part.strip() for part in (current or "").split(",") if part.strip()}
    values.update(part.strip() for part in (incoming or "").split(",") if part.strip())
    return ",".join(sorted(values))


async def _existing_iocs(session: AsyncSession, pairs: set[tuple[str, str]]) -> dict[tuple[str, str], Ioc]:
    """Preload the IoCs among ``pairs`` in one query per indicator type."""
    found: dict[tuple[str, str], Ioc] = {}
    for ioc_type in {pair[0] for pair in pairs}:
        values = [value for kind, value in pairs if kind == ioc_type]
        if not values:
            continue
        rows = await session.exec(
            select(Ioc).where(Ioc.type == ioc_type).where(Ioc.value.in_(values))
        )
        for row in rows.all():
            found[(row.type, row.value)] = row
    return found


async def upsert_iocs(
    session: AsyncSession,
    candidates: Sequence[dict],
    now: Optional[datetime] = None,
) -> dict[str, int]:
    """Insert new indicators, merge the known ones. Returns per-bucket counters."""
    moment = _aware(now)
    pairs = {(item["type"], item["value"]) for item in candidates}
    existing = await _existing_iocs(session, pairs)

    created = 0
    updated = 0
    for item in candidates:
        key = (item["type"], item["value"])
        row = existing.get(key)
        if row is None:
            row = Ioc(
                type=item["type"],
                value=item["value"],
                sources=item["source"],
                severity=item.get("severity", "medium"),
                first_seen=item.get("first_seen") or moment,
                last_seen=item.get("last_seen") or moment,
                metadata_json=_dump_metadata(item.get("metadata")),
                created_at=moment,
                updated_at=moment,
            )
            session.add(row)
            existing[key] = row
            created += 1
            continue

        row.sources = merge_sources(row.sources, item["source"])
        row.severity = escalate_severity(row.severity, item.get("severity", "medium"))
        row.first_seen = min(_naive_to_utc(row.first_seen), item.get("first_seen") or moment)
        row.last_seen = max(_naive_to_utc(row.last_seen), item.get("last_seen") or moment)
        row.metadata_json = _merge_metadata(row.metadata_json, item.get("metadata"))
        row.updated_at = moment
        session.add(row)
        updated += 1

    try:
        await session.commit()
    except IntegrityError:
        # Two syncs raced on the same indicator: the unique constraint is the
        # source of truth, so drop the conflicting insert and keep going.
        await session.rollback()
        logger.info("intel: race on the iocs unique constraint during upsert")

    return {"created": created, "updated": updated, "received": len(candidates)}


async def upsert_feed_items(
    session: AsyncSession,
    items: Sequence[dict],
    now: Optional[datetime] = None,
) -> dict[str, int]:
    """Insert new advisory items, deduplicated on the feed GUID."""
    moment = _aware(now)
    guids = [item["guid"] for item in items]
    known: set[str] = set()
    if guids:
        rows = await session.exec(select(IntelFeedItem.guid).where(IntelFeedItem.guid.in_(guids)))
        known = {row for row in rows.all()}

    created = 0
    for item in items:
        if item["guid"] in known:
            continue
        known.add(item["guid"])
        session.add(
            IntelFeedItem(
                guid=item["guid"],
                source=item["source"],
                title=item["title"],
                link=item["link"],
                summary=item.get("summary", ""),
                published_at=item.get("published_at") or moment,
                fetched_at=moment,
            )
        )
        created += 1

    await session.commit()
    return {"created": created, "duplicates": len(items) - created, "received": len(items)}


def _dump_metadata(metadata: Optional[dict]) -> str:
    try:
        return json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return "{}"


def _merge_metadata(current: str, incoming: Optional[dict]) -> str:
    """Merge feed metadata, the fresher value winning on a key collision."""
    try:
        merged: dict[str, Any] = json.loads(current or "{}")
    except ValueError:
        merged = {}
    for key, value in (incoming or {}).items():
        if value in (None, "", [], {}):
            continue
        merged[key] = value
    return _dump_metadata(merged)
