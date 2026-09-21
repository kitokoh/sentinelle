"""Ingestion pipeline tests (v0.3, issue #1) — EVE fixtures against a real DB.

Acceptance criterion: "fixture EVE → alertes insérées et filtrables". These
tests drive the real ``ingest_events`` against the temp SQLite database, so the
unique ``event_id`` constraint, the detection window and the alert de-duplication
are all exercised end to end.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import select

from app.db import async_session
from app.models import Alert, SensorEvent
from app.services.detection import load_rules
from app.services.ingest import ingest_events
from app.services.suricata import normalize_events


@pytest.fixture(autouse=True)
def _schema(client):
    """The migrations run during the API lifespan; direct-DB tests need them too."""
    return client


def flow_record(now: datetime, seconds_ago: float, **overrides) -> dict:
    """A Suricata ``flow`` record, timestamped relative to ``now``."""
    record = {
        "timestamp": (now - timedelta(seconds=seconds_ago)).isoformat(),
        "flow_id": 7000 + int(seconds_ago),
        "event_type": "flow",
        "src_ip": "198.51.100.7",
        "src_port": 45000,
        "dest_ip": "10.20.30.10",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
    }
    record.update(overrides)
    return record


def alert_record(now: datetime, seconds_ago: float = 1, **overrides) -> dict:
    record = flow_record(
        now,
        seconds_ago,
        event_type="alert",
        flow_id=99001,
        alert={"signature": "ET SCAN Potential SSH Scan", "severity": 1},
    )
    record.update(overrides)
    return record


def port_scan_lines(now: datetime, src_ip: str, ports: int = 25) -> list[str]:
    """EVE lines describing one port scan from ``src_ip``."""
    return [
        json.dumps(
            flow_record(
                now,
                seconds_ago=index,
                src_ip=src_ip,
                src_port=50000,
                dest_port=1000 + index,
            )
        )
        for index in range(ports)
    ]


async def _alerts_for(src_ip: str) -> list[Alert]:
    async with async_session() as session:
        result = await session.exec(
            select(Alert).where(Alert.src_ip == src_ip).order_by(Alert.id)
        )
        return list(result.all())


async def _events_for(src_ip: str) -> list[SensorEvent]:
    async with async_session() as session:
        result = await session.exec(select(SensorEvent).where(SensorEvent.src_ip == src_ip))
        return list(result.all())


# --------------------------------------------------------------------------- #
# Events are persisted, then detected
# --------------------------------------------------------------------------- #


async def test_eve_fixture_is_persisted_and_raises_a_rule_alert():
    """"Un scan génère des alertes visibles via l'API" — the whole point of #1."""
    now = datetime.now(timezone.utc)
    src_ip = "198.51.100.7"
    events = normalize_events(port_scan_lines(now, src_ip))

    async with async_session() as session:
        summary = await ingest_events(session, events, rules=load_rules(), now=now)

    assert summary["received"] == 25
    assert summary["stored"] == 25
    assert summary["duplicates"] == 0
    assert summary["rule_alerts_created"] == 1

    stored = await _events_for(src_ip)
    assert len(stored) == 25
    assert all(event.event_type == "flow" for event in stored)
    assert {event.dst_port for event in stored} == {1000 + index for index in range(25)}
    # The raw EVE record survives for forensics.
    assert json.loads(stored[0].payload)["src_ip"] == src_ip

    alerts = await _alerts_for(src_ip)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.source == "rule"
    assert alert.rule_name == "port_scan"
    assert alert.event_type == "port_scan"
    assert alert.severity == "high"
    assert alert.status == "new"
    assert alert.occurrences == 1
    assert alert.confidence == 0.625
    assert alert.dedup_key == f"port_scan|{src_ip}|-|-"


async def test_reingesting_the_same_events_is_idempotent():
    """Restarting the worker must not replay the past — the cursor guarantees it."""
    now = datetime.now(timezone.utc)
    src_ip = "198.51.100.8"
    lines = port_scan_lines(now, src_ip)

    async with async_session() as session:
        await ingest_events(session, normalize_events(lines), rules=load_rules(), now=now)
    async with async_session() as session:
        summary = await ingest_events(session, normalize_events(lines), rules=load_rules(), now=now)

    assert summary["stored"] == 0
    assert summary["duplicates"] == 25
    assert len(await _events_for(src_ip)) == 25

    # The ongoing scan bumps the counter instead of creating a second alert.
    alerts = await _alerts_for(src_ip)
    assert len(alerts) == 1
    assert alerts[0].occurrences == 2


async def test_an_ongoing_scan_keeps_bumping_the_same_alert():
    """Alert storms are the failure mode this dedup exists to prevent."""
    now = datetime.now(timezone.utc)
    src_ip = "198.51.100.9"

    # Three consecutive sweeps of the same 25 ports (only the source port
    # changes, so every EVE record keeps a distinct event_id).
    for round_index in range(3):
        lines = [
            json.dumps(
                flow_record(
                    now,
                    seconds_ago=index,
                    src_ip=src_ip,
                    src_port=50000 + round_index,
                    dest_port=3000 + index,
                )
            )
            for index in range(25)
        ]
        async with async_session() as session:
            await ingest_events(session, normalize_events(lines), rules=load_rules(), now=now)

    alerts = await _alerts_for(src_ip)
    assert len(alerts) == 1
    # One alert, three occurrences, evidence refreshed on every sweep.
    assert alerts[0].occurrences == 3
    assert alerts[0].confidence == 0.625


async def test_a_suricata_signature_record_becomes_a_suricata_alert():
    now = datetime.now(timezone.utc)
    src_ip = "198.51.100.10"
    events = normalize_events([json.dumps(alert_record(now, src_ip=src_ip))])

    async with async_session() as session:
        summary = await ingest_events(session, events, rules=load_rules(), now=now)

    assert summary["stored"] == 1
    assert summary["signature_alerts"] == 1

    alerts = await _alerts_for(src_ip)
    assert len(alerts) == 1
    assert alerts[0].source == "suricata"
    assert alerts[0].event_type == "signature"
    assert alerts[0].signature == "ET SCAN Potential SSH Scan"
    # Suricata severity 1 -> high.
    assert alerts[0].severity == "high"
    assert alerts[0].rule_name is None


async def test_acknowledged_alerts_are_not_reopened_by_new_traffic(client, auth_headers):
    now = datetime.now(timezone.utc)
    src_ip = "198.51.100.11"
    lines = port_scan_lines(now, src_ip)

    async with async_session() as session:
        await ingest_events(session, normalize_events(lines), rules=load_rules(), now=now)

    alert = (await _alerts_for(src_ip))[0]
    response = client.patch(f"/api/alerts/{alert.id}", json={"status": "ack"}, headers=auth_headers)
    assert response.status_code == 200, response.text

    more = [
        json.dumps(flow_record(now, seconds_ago=index, src_ip=src_ip, dest_port=4000 + index))
        for index in range(25)
    ]
    async with async_session() as session:
        await ingest_events(session, normalize_events(more), rules=load_rules(), now=now)

    alerts = await _alerts_for(src_ip)
    assert len(alerts) == 1
    # A human accepted it: the counter rises, but the status is left alone.
    assert alerts[0].status == "ack"
    assert alerts[0].occurrences == 2


async def test_ingesting_nothing_is_a_no_op():
    """An empty batch stores nothing and cannot create a duplicate.

    The detection counters are deliberately not asserted here: the suite shares
    one database, so a previous test's live window legitimately re-fires.
    """
    async with async_session() as session:
        summary = await ingest_events(session, [], rules=load_rules())

    assert summary["received"] == 0
    assert summary["stored"] == 0
    assert summary["duplicates"] == 0


async def test_alerts_are_visible_and_filterable_through_the_api(client, auth_headers):
    """"alertes visibles via l'API", with the severity/source filters of #1."""
    now = datetime.now(timezone.utc)
    src_ip = "198.51.100.12"
    events = normalize_events(port_scan_lines(now, src_ip))

    async with async_session() as session:
        await ingest_events(session, events, rules=load_rules(), now=now)

    response = client.get("/api/alerts", params={"src_ip": src_ip}, headers=auth_headers)
    assert response.status_code == 200, response.text
    alerts = response.json()
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "port_scan"

    filtered = client.get(
        "/api/alerts",
        params={"severity": "high", "source": "rule"},
        headers=auth_headers,
    )
    assert filtered.status_code == 200
    assert any(alert["src_ip"] == src_ip for alert in filtered.json())

    excluded = client.get(
        "/api/alerts",
        params={"src_ip": src_ip, "severity": "low"},
        headers=auth_headers,
    )
    assert excluded.status_code == 200
    assert excluded.json() == []


async def test_period_filter_excludes_old_alerts(client, auth_headers):
    now = datetime.now(timezone.utc)
    src_ip = "198.51.100.13"
    async with async_session() as session:
        await ingest_events(
            session, normalize_events(port_scan_lines(now, src_ip)), rules=load_rules(), now=now
        )

    future = (now + timedelta(hours=1)).isoformat()
    response = client.get("/api/alerts", params={"src_ip": src_ip, "since": future}, headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == []
