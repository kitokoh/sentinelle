"""Alert API tests (v0.3, issues #1 & #3) — listing, filtering, acknowledgement.

Alerts are seeded straight into the database with a unique ``rule_name`` marker
so each test is independent from the ingestion tests' fixtures.
"""

from datetime import datetime, timedelta, timezone

from sqlmodel import select

from app.db import async_session
from app.models import Alert

MARKERS = (
    "test-listing",
    "test-filters",
    "test-ack",
    "test-detail",
    "test-order",
    "test-pagination",
)


async def _seed_alert(**overrides) -> Alert:
    values = {
        "source": "rule",
        "event_type": "port_scan",
        "severity": "high",
        "src_ip": "203.0.113.5",
        "dst_ip": "10.0.0.10",
        "dst_port": 22,
        "proto": "TCP",
        "rule_name": "test-listing",
        "confidence": 0.8,
        "detail": "seeded alert",
        "payload": "{}",
        "status": "new",
    }
    values.update(overrides)
    async with async_session() as session:
        alert = Alert(**values)
        session.add(alert)
        await session.commit()
        await session.refresh(alert)
        return alert


async def _fetch(alert_id: int) -> Alert | None:
    async with async_session() as session:
        return await session.get(Alert, alert_id)


# --------------------------------------------------------------------------- #
# Listing & filtering
# --------------------------------------------------------------------------- #


async def test_listing_returns_alerts_newest_first(client, auth_headers):
    first = await _seed_alert(rule_name="test-order", created_at=datetime.now(timezone.utc) - timedelta(hours=1), src_ip="203.0.113.31")
    second = await _seed_alert(rule_name="test-order", created_at=datetime.now(timezone.utc), src_ip="203.0.113.31")

    response = client.get("/api/alerts", params={"rule_name": "test-order"}, headers=auth_headers)

    assert response.status_code == 200, response.text
    ids = [alert["id"] for alert in response.json()]
    assert ids == [second.id, first.id]


async def test_filters_combine_severity_source_and_status(client, auth_headers):
    await _seed_alert(rule_name="test-filters", severity="critical", source="rule", src_ip="203.0.113.6")
    await _seed_alert(rule_name="test-filters", severity="low", source="suricata", src_ip="203.0.113.6", status="ack")

    by_severity = client.get(
        "/api/alerts", params={"rule_name": "test-filters", "severity": "critical"}, headers=auth_headers
    )
    assert [alert["severity"] for alert in by_severity.json()] == ["critical"]

    by_source = client.get(
        "/api/alerts", params={"rule_name": "test-filters", "source": "suricata"}, headers=auth_headers
    )
    assert [alert["source"] for alert in by_source.json()] == ["suricata"]

    by_status = client.get(
        "/api/alerts", params={"rule_name": "test-filters", "status": "ack"}, headers=auth_headers
    )
    assert [alert["status"] for alert in by_status.json()] == ["ack"]

    combined = client.get(
        "/api/alerts",
        params={"rule_name": "test-filters", "severity": "critical", "source": "suricata"},
        headers=auth_headers,
    )
    assert combined.json() == []


async def test_severity_accepts_comma_separated_and_repeated_values(client, auth_headers):
    await _seed_alert(rule_name="test-filters", severity="high", src_ip="203.0.113.7")
    await _seed_alert(rule_name="test-filters", severity="medium", src_ip="203.0.113.7")

    comma = client.get(
        "/api/alerts", params={"rule_name": "test-filters", "severity": "high,medium"}, headers=auth_headers
    )
    assert len(comma.json()) == 2

    repeated = client.get(
        "/api/alerts",
        params=[("rule_name", "test-filters"), ("severity", "high"), ("severity", "medium")],
        headers=auth_headers,
    )
    assert len(repeated.json()) == 2


async def test_pagination_is_bounded(client, auth_headers):
    for index in range(3):
        await _seed_alert(
            rule_name="test-pagination",
            src_ip="203.0.113.40",
            created_at=datetime.now(timezone.utc) + timedelta(seconds=index),
        )

    page = client.get(
        "/api/alerts", params={"rule_name": "test-pagination", "limit": 2}, headers=auth_headers
    )
    assert len(page.json()) == 2

    next_page = client.get(
        "/api/alerts",
        params={"rule_name": "test-pagination", "limit": 2, "offset": 2},
        headers=auth_headers,
    )
    assert len(next_page.json()) == 1

    # The limit is capped: an operator cannot accidentally request everything.
    too_big = client.get("/api/alerts", params={"limit": 10_000}, headers=auth_headers)
    assert too_big.status_code == 422


async def test_listing_requires_authentication(client):
    assert client.get("/api/alerts").status_code == 401


# --------------------------------------------------------------------------- #
# Detail & acknowledgement
# --------------------------------------------------------------------------- #


async def test_detail_exposes_the_raw_payload(client, auth_headers):
    alert = await _seed_alert(rule_name="test-detail", payload='{"signature": "ET SCAN"}')

    response = client.get(f"/api/alerts/{alert.id}", headers=auth_headers)

    assert response.status_code == 200
    assert response.json()["payload"] == '{"signature": "ET SCAN"}'


async def test_unknown_alert_returns_404(client, auth_headers):
    assert client.get("/api/alerts/9999999", headers=auth_headers).status_code == 404
    assert (
        client.patch("/api/alerts/9999999", json={"status": "ack"}, headers=auth_headers).status_code
        == 404
    )


async def test_acknowledgement_records_who_and_when(client, auth_headers):
    alert = await _seed_alert(rule_name="test-ack")

    response = client.patch(f"/api/alerts/{alert.id}", json={"status": "ack"}, headers=auth_headers)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ack"
    assert body["acknowledged_by"] is not None
    assert body["acknowledged_at"] is not None

    me = client.get("/api/auth/me", headers=auth_headers).json()
    assert body["acknowledged_by"] == me["id"]
    assert (await _fetch(alert.id)).status == "ack"


async def test_reopening_an_alert_clears_the_acknowledgement(client, auth_headers):
    alert = await _seed_alert(rule_name="test-ack")
    client.patch(f"/api/alerts/{alert.id}", json={"status": "ack"}, headers=auth_headers)

    response = client.patch(f"/api/alerts/{alert.id}", json={"status": "new"}, headers=auth_headers)

    assert response.status_code == 200
    assert response.json()["status"] == "new"
    assert response.json()["acknowledged_at"] is None
    assert response.json()["acknowledged_by"] is None


async def test_only_the_lifecycle_field_is_writable(client, auth_headers):
    """An alert is evidence: the API must refuse to rewrite its content."""
    alert = await _seed_alert(rule_name="test-ack")

    response = client.patch(
        f"/api/alerts/{alert.id}",
        json={"status": "ack", "severity": "info", "detail": "tampered"},
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.json()["severity"] == "high"
    assert response.json()["detail"] == "seeded alert"


async def test_invalid_status_is_rejected(client, auth_headers):
    alert = await _seed_alert(rule_name="test-ack")

    response = client.patch(f"/api/alerts/{alert.id}", json={"status": "closed"}, headers=auth_headers)

    assert response.status_code == 422


async def test_acknowledgement_requires_authentication(client):
    assert client.patch("/api/alerts/1", json={"status": "ack"}).status_code == 401


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #


async def test_stats_expose_the_unacknowledged_counter(client, auth_headers):
    before = client.get("/api/alerts/stats", headers=auth_headers).json()
    assert before["unacknowledged"] <= before["total"]
    assert set(before["by_severity"]) == {"info", "low", "medium", "high", "critical"}

    await _seed_alert(rule_name="test-listing", src_ip="203.0.113.60", status="new")

    after = client.get("/api/alerts/stats", headers=auth_headers).json()
    assert after["total"] == before["total"] + 1
    assert after["unacknowledged"] == before["unacknowledged"] + 1
    assert after["by_source"]["rule"] >= 1


async def test_stats_require_authentication(client):
    assert client.get("/api/alerts/stats").status_code == 401


async def test_alert_counters_survive_a_round_trip_through_the_db(client, auth_headers):
    alert = await _seed_alert(rule_name="test-listing", src_ip="203.0.113.61", confidence=0.42, occurrences=7)

    async with async_session() as session:
        stored = (await session.exec(select(Alert).where(Alert.id == alert.id))).one()

    assert stored.confidence == 0.42
    assert stored.occurrences == 7
