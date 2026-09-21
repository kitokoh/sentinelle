"""Intel persistence tests (v0.4) — cross-source de-duplication and idempotency.

The property that matters: an indicator reported by two feeds is **one** row, and
re-syncing never duplicates anything.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import select

from app.db import async_session
from app.models import IntelFeedItem, Ioc
from app.services.intel import store
from app.services.intel.normalize import candidate

NOW = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _schema(client):
    """The migrations run during the API lifespan; direct-DB tests need them too."""
    return client


def ip_candidate(value: str, source: str, **overrides) -> dict:
    """Deterministic candidate: never relies on the wall clock."""
    overrides.setdefault("first_seen", NOW - timedelta(days=1))
    overrides.setdefault("last_seen", NOW)
    item = candidate("ip", value, source, **overrides)
    assert item is not None
    return item


async def _rows() -> list[Ioc]:
    async with async_session() as session:
        return list((await session.exec(select(Ioc).order_by(Ioc.id))).all())


# --------------------------------------------------------------------------- #
# Severity / source merging helpers
# --------------------------------------------------------------------------- #


def test_escalate_severity_keeps_the_most_serious():
    assert store.escalate_severity("low", "critical") == "critical"
    assert store.escalate_severity("high", "medium") == "high"
    # An unknown severity degrades to medium rather than crashing.
    assert store.escalate_severity("weird", "low") == "low"


def test_merge_sources_unions_and_sorts():
    assert store.merge_sources("misp", "otx") == "misp,otx"
    assert store.merge_sources("misp,otx", "otx") == "misp,otx"
    assert store.merge_sources("", "cert") == "cert"


# --------------------------------------------------------------------------- #
# Upserts
# --------------------------------------------------------------------------- #


async def test_a_new_indicator_is_inserted_once():
    async with async_session() as session:
        counters = await store.upsert_iocs(
            session, [ip_candidate("203.0.113.201", "misp")], now=NOW
        )

    assert counters["created"] >= 1
    matching = [row for row in await _rows() if row.value == "203.0.113.201"]
    assert len(matching) == 1
    assert matching[0].sources == "misp"


async def test_resyncing_the_same_source_updates_instead_of_duplicating():
    later = NOW + timedelta(hours=1)
    async with async_session() as session:
        await store.upsert_iocs(
            session, [ip_candidate("203.0.113.202", "misp", last_seen=NOW)], now=NOW
        )
    async with async_session() as session:
        counters = await store.upsert_iocs(
            session,
            [ip_candidate("203.0.113.202", "misp", last_seen=later)],
            now=later,
        )

    assert counters["created"] == 0
    assert counters["updated"] == 1

    matching = [row for row in await _rows() if row.value == "203.0.113.202"]
    assert len(matching) == 1
    # SQLite returns naive datetimes; the stored wall clock is UTC by construction.
    assert matching[0].last_seen.replace(tzinfo=timezone.utc) == later


async def test_the_same_indicator_from_two_feeds_becomes_one_row_with_both_sources():
    """This is what "dédup avec MISP" buys: one indicator, two provenances."""
    async with async_session() as session:
        await store.upsert_iocs(
            session,
            [
                ip_candidate(
                    "203.0.113.203",
                    "misp",
                    severity="medium",
                    first_seen="2026-09-01T00:00:00Z",
                    metadata={"name": "first sighting"},
                )
            ],
            now=NOW,
        )
    async with async_session() as session:
        counters = await store.upsert_iocs(
            session,
            [
                ip_candidate(
                    "203.0.113.203",
                    "otx",
                    severity="critical",
                    last_seen="2026-09-20T00:00:00Z",
                    metadata={"name": "second sighting", "tags": ["ransomware"]},
                )
            ],
            now=NOW,
        )

    assert counters["created"] == 0
    row = [item for item in await _rows() if item.value == "203.0.113.203"][0]
    assert row.sources == "misp,otx"
    # The most serious severity wins...
    assert row.severity == "critical"
    # ...the earliest sighting is kept...
    assert row.first_seen.replace(tzinfo=timezone.utc) == datetime(2026, 9, 1, tzinfo=timezone.utc)
    # ...and metadata is merged, the fresher value winning on a collision.
    metadata = json.loads(row.metadata_json)
    assert metadata["name"] == "second sighting"
    assert metadata["tags"] == ["ransomware"]


async def test_upsert_of_nothing_is_a_no_op():
    async with async_session() as session:
        counters = await store.upsert_iocs(session, [], now=NOW)
    assert counters == {"created": 0, "updated": 0, "received": 0}


async def test_feed_items_are_deduplicated_on_guid():
    items = [
        {
            "guid": "urn:cert:2026-001",
            "source": "CERT-FR",
            "title": "Avis 1",
            "link": "https://example.org/1",
            "summary": "résumé",
            "published_at": NOW,
        }
    ]

    async with async_session() as session:
        first = await store.upsert_feed_items(session, items, now=NOW)
    async with async_session() as session:
        second = await store.upsert_feed_items(session, items, now=NOW)

    assert first["created"] == 1
    assert second["created"] == 0
    assert second["duplicates"] == 1

    async with async_session() as session:
        stored = list(
            (await session.exec(select(IntelFeedItem).where(IntelFeedItem.guid == "urn:cert:2026-001"))).all()
        )
    assert len(stored) == 1
    assert stored[0].title == "Avis 1"


async def test_metadata_that_is_not_json_does_not_break_a_merge():
    async with async_session() as session:
        session.add(
            Ioc(
                type="domain",
                value="broken-metadata.example",
                sources="misp",
                severity="low",
                first_seen=NOW,
                last_seen=NOW,
                metadata_json="{not json",
            )
        )
        await session.commit()

    async with async_session() as session:
        await store.upsert_iocs(
            session, [candidate("domain", "broken-metadata.example", "otx", metadata={"a": 1})], now=NOW
        )

    row = [item for item in await _rows() if item.value == "broken-metadata.example"][0]
    assert json.loads(row.metadata_json) == {"a": 1}
    assert row.sources == "misp,otx"
