"""Read-side aggregation for the Renseignement page (v0.4, issue #10).

One function assembles everything the page renders, so the front-end makes a
single call and the shaping logic is testable server-side rather than spread
across React components.

The map (#10) is deliberately built **only** from coordinates the feeds already
provided: no indicator is ever sent to a geolocation service just to be plotted.
Indicators without coordinates simply do not appear on the map.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlmodel import func, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Alert, IntelFeedItem, Ioc
from app.services.intel.normalize import geo_from_metadata

#: Bounds on the payload — the page is a dashboard, not an export.
RECENT_IOC_LIMIT = 50
FEED_LIMIT = 30
MATCH_LIMIT = 30
GEO_LIMIT = 300
#: "Recent" window used by the counters.
ACTIVITY_WINDOW_DAYS = 7


def _metadata(raw: str) -> dict:
    try:
        loaded = json.loads(raw or "{}")
    except ValueError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def ioc_to_dict(ioc: Ioc) -> dict[str, Any]:
    """Serialise an IoC for the API, including any plume the feed provided."""
    metadata = _metadata(ioc.metadata_json)
    coordinates = geo_from_metadata(metadata)
    return {
        "id": ioc.id,
        "type": ioc.type,
        "value": ioc.value,
        "sources": [part for part in (ioc.sources or "").split(",") if part],
        "severity": ioc.severity,
        "first_seen": ioc.first_seen,
        "last_seen": ioc.last_seen,
        "name": metadata.get("name", ""),
        "tags": metadata.get("tags", [])[:8] if isinstance(metadata.get("tags"), list) else [],
        "targeted_countries": metadata.get("targeted_countries", []),
        "latitude": coordinates[0] if coordinates else None,
        "longitude": coordinates[1] if coordinates else None,
    }


def geo_points(iocs: list[Ioc]) -> list[dict[str, Any]]:
    """Coordinates for the campaign map, one point per indicator."""
    points: list[dict[str, Any]] = []
    for ioc in iocs:
        metadata = _metadata(ioc.metadata_json)
        coordinates = geo_from_metadata(metadata)
        if coordinates is None:
            continue
        points.append(
            {
                "label": ioc.value,
                "type": ioc.type,
                "severity": ioc.severity,
                "sources": ioc.sources,
                "latitude": coordinates[0],
                "longitude": coordinates[1],
                "name": metadata.get("name", ""),
                "targeted_countries": metadata.get("targeted_countries", []),
            }
        )
        if len(points) >= GEO_LIMIT:
            break
    return points


async def build_overview(
    session: AsyncSession,
    now: Optional[datetime] = None,
    *,
    ioc_limit: int = RECENT_IOC_LIMIT,
) -> dict[str, Any]:
    """Everything the Renseignement page needs, in one round trip."""
    moment = now or datetime.now(timezone.utc)
    window_start = moment - timedelta(days=ACTIVITY_WINDOW_DAYS)

    recent_iocs = list(
        (
            await session.exec(
                select(Ioc).order_by(Ioc.last_seen.desc(), Ioc.id.desc()).limit(ioc_limit)
            )
        ).all()
    )
    feed_items = list(
        (
            await session.exec(
                select(IntelFeedItem)
                .order_by(IntelFeedItem.published_at.desc(), IntelFeedItem.id.desc())
                .limit(FEED_LIMIT)
            )
        ).all()
    )
    matches = list(
        (
            await session.exec(
                select(Alert)
                .where(Alert.source == "intel")
                .order_by(Alert.created_at.desc(), Alert.id.desc())
                .limit(MATCH_LIMIT)
            )
        ).all()
    )

    # Every stored indicator is scanned for coordinates, not just the recent page:
    # a plume is rare, so restricting to the last 50 would usually show an empty map.
    all_iocs = list((await session.exec(select(Ioc).order_by(Ioc.last_seen.desc()))).all())

    total_iocs = (await session.exec(select(func.count()).select_from(Ioc))).one()
    total_feed = (await session.exec(select(func.count()).select_from(IntelFeedItem))).one()
    total_matches = (
        await session.exec(select(func.count()).select_from(Alert).where(Alert.source == "intel"))
    ).one()
    recent_matches_count = (
        await session.exec(
            select(func.count())
            .select_from(Alert)
            .where(Alert.source == "intel")
            .where(Alert.created_at >= window_start)
        )
    ).one()

    by_source: dict[str, int] = {}
    for sources in (await session.exec(select(Ioc.sources))).all():
        for name in (sources or "").split(","):
            cleaned = name.strip()
            if cleaned:
                by_source[cleaned] = by_source.get(cleaned, 0) + 1

    type_rows = (await session.exec(select(Ioc.type, func.count()).group_by(Ioc.type))).all()

    return {
        "counts": {
            "iocs": total_iocs,
            "feed_items": total_feed,
            "matches": total_matches,
            "matches_recent": recent_matches_count,
        },
        "by_source": by_source,
        "by_type": {ioc_type: count for ioc_type, count in type_rows},
        "iocs": [ioc_to_dict(ioc) for ioc in recent_iocs],
        "feed": [
            {
                "id": item.id,
                "guid": item.guid,
                "source": item.source,
                "title": item.title,
                "link": item.link,
                "summary": item.summary,
                "published_at": item.published_at,
            }
            for item in feed_items
        ],
        "matches": [
            {
                "id": alert.id,
                "created_at": alert.created_at,
                "severity": alert.severity,
                "event_type": alert.event_type,
                "detail": alert.detail,
                "status": alert.status,
            }
            for alert in matches
        ],
        "geo": geo_points(all_iocs),
    }
