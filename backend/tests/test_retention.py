"""Retention & purge tests (v0.3, issue #5).

The acceptance criterion is explicit: "données anciennes purgées, récentes
conservées". Two properties are pinned beyond that, because silently deleting
the audit record would be far worse than keeping too much:

* ``scans`` and ``targets`` are never purged;
* ``RETENTION_DAYS <= 0`` disables purging entirely.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import select

from app.db import async_session
from app.models import Alert, Finding, Scan, SensorEvent, Target
from app.services.retention import purge_expired


@pytest.fixture(autouse=True)
def _schema(client):
    """The migrations run during the API lifespan; direct-DB tests need them too."""
    return client

NOW = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)


def _create_target(client, headers, value: str) -> int:
    response = client.post(
        "/api/targets",
        json={"name": "Retention VM", "value": value, "kind": "ip"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


async def _seed_scan(target_id: int, created_at: datetime, marker: str) -> int:
    async with async_session() as session:
        scan = Scan(target_id=target_id, profile="quick", status="done", created_at=created_at)
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        session.add(
            Finding(
                scan_id=scan.id,
                source="nmap",
                port=22,
                protocol="tcp",
                service=marker,
                version="",
                severity="low",
                detail=f"finding for {marker}",
            )
        )
        await session.commit()
        return scan.id


async def _seed_alert(created_at: datetime, marker: str) -> int:
    async with async_session() as session:
        alert = Alert(
            source="rule",
            event_type="port_scan",
            severity="high",
            rule_name=marker,
            detail=f"alert for {marker}",
            created_at=created_at,
        )
        session.add(alert)
        await session.commit()
        await session.refresh(alert)
        return alert.id


async def _seed_event(occurred_at: datetime, marker: str) -> int:
    async with async_session() as session:
        event = SensorEvent(
            event_id=marker,
            occurred_at=occurred_at,
            event_type="flow",
            src_ip="203.0.113.99",
            payload="{}",
        )
        session.add(event)
        await session.commit()
        await session.refresh(event)
        return event.id


async def _exists(model, row_id: int) -> bool:
    async with async_session() as session:
        return await session.get(model, row_id) is not None


async def test_old_rows_are_purged_and_recent_rows_are_kept(client, auth_headers):
    target_id = _create_target(client, auth_headers, "10.77.0.10")
    old_moment = NOW - timedelta(days=60)
    recent_moment = NOW - timedelta(days=1)

    old_scan = await _seed_scan(target_id, old_moment, "old-scan")
    recent_scan = await _seed_scan(target_id, recent_moment, "recent-scan")
    old_alert = await _seed_alert(old_moment, "old-alert")
    recent_alert = await _seed_alert(recent_moment, "recent-alert")
    old_event = await _seed_event(old_moment, "retention-old-event")
    recent_event = await _seed_event(recent_moment, "retention-recent-event")

    async with async_session() as session:
        counters = await purge_expired(session, retention_days=30, now=NOW)

    assert counters["enabled"] is True
    # The suite shares one database, so the global counters only need to prove
    # that a purge happened; the row-level assertions below are the strict part.
    assert counters["findings"] >= 1
    assert counters["alerts"] >= 1
    assert counters["sensor_events"] >= 1

    # Expired rows are gone...
    assert not await _exists(Alert, old_alert)
    assert not await _exists(SensorEvent, old_event)
    async with async_session() as session:
        old_findings = (
            await session.exec(select(Finding).where(Finding.scan_id == old_scan))
        ).all()
        assert list(old_findings) == []

    # ...recent ones are untouched...
    assert await _exists(Alert, recent_alert)
    assert await _exists(SensorEvent, recent_event)
    async with async_session() as session:
        recent_findings = (
            await session.exec(select(Finding).where(Finding.scan_id == recent_scan))
        ).all()
        assert len(list(recent_findings)) == 1

    # ...and the audit record itself is never purged.
    assert await _exists(Scan, old_scan)
    assert await _exists(Target, target_id)


async def test_retention_zero_disables_purging(client, auth_headers):
    target_id = _create_target(client, auth_headers, "10.77.0.11")
    ancient = NOW - timedelta(days=3650)
    alert_id = await _seed_alert(ancient, "disabled-retention-alert")
    event_id = await _seed_event(ancient, "disabled-retention-event")

    async with async_session() as session:
        counters = await purge_expired(session, retention_days=0, now=NOW)

    assert counters["enabled"] is False
    assert counters["alerts"] == 0
    assert await _exists(Alert, alert_id)
    assert await _exists(SensorEvent, event_id)
    assert await _exists(Target, target_id)


async def test_purge_is_idempotent(client, auth_headers):
    target_id = _create_target(client, auth_headers, "10.77.0.12")
    await _seed_alert(NOW - timedelta(days=90), "idempotent-alert")

    async with async_session() as session:
        first = await purge_expired(session, retention_days=30, now=NOW)
    async with async_session() as session:
        second = await purge_expired(session, retention_days=30, now=NOW)

    assert first["alerts"] >= 1
    assert second["alerts"] == 0
    assert target_id is not None


async def test_cutoff_boundary_keeps_rows_exactly_at_the_limit(client, auth_headers):
    _create_target(client, auth_headers, "10.77.0.13")
    on_the_edge = await _seed_alert(NOW - timedelta(days=30), "boundary-alert")

    async with async_session() as session:
        counters = await purge_expired(session, retention_days=30, now=NOW)

    # Strictly older than the cutoff is purged; the boundary itself is kept.
    assert counters["alerts"] == 0
    assert await _exists(Alert, on_the_edge)
