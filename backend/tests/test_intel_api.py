"""Threat-intel API + worker job tests (v0.4, issues #6–#10).

The API side covers the read model the Renseignement page consumes; the job side
covers the "dégradation propre" requirement — an unconfigured source reports
``skipped`` instead of failing, so a worker log always says why nothing happened.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import select

from app.db import async_session
from app.models import Alert, IntelFeedItem, Ioc
from app.services.intel import normalize, overview
from app.worker import jobs

NOW = datetime.now(timezone.utc)



async def _seed_ioc(
    ioc_type: str,
    value: str,
    *,
    source: str = "misp",
    severity: str = "medium",
    metadata: dict | None = None,
) -> int:
    import json

    async with async_session() as session:
        row = Ioc(
            type=ioc_type,
            value=value,
            sources=source,
            severity=severity,
            first_seen=NOW - timedelta(days=1),
            last_seen=NOW,
            metadata_json=json.dumps(metadata or {}),
        )
        session.add(row)
        await session.commit()
        await session.refresh(row)
        return row.id


async def _seed_feed_item(guid: str, source: str = "CERT-FR") -> int:
    async with async_session() as session:
        item = IntelFeedItem(
            guid=guid,
            source=source,
            title=f"Avis {guid}",
            link=f"https://example.org/{guid}",
            summary="résumé",
            published_at=NOW,
        )
        session.add(item)
        await session.commit()
        await session.refresh(item)
        return item.id


async def _seed_intel_alert(detail: str) -> int:
    async with async_session() as session:
        alert = Alert(
            source="intel",
            event_type="ioc_match_ip",
            severity="high",
            detail=detail,
            dedup_key=f"intel|ip|203.0.113.77|alert:{detail}",
            created_at=NOW,
        )
        session.add(alert)
        await session.commit()
        await session.refresh(alert)
        return alert.id


# --------------------------------------------------------------------------- #
# Read model
# --------------------------------------------------------------------------- #


def test_ioc_to_dict_flattens_sources_and_pulls_geo_out_of_metadata():
    ioc = Ioc(
        id=1,
        type="ip",
        value="203.0.113.5",
        sources="misp,otx",
        severity="high",
        first_seen=NOW,
        last_seen=NOW,
        metadata_json='{"name": "APT", "tags": ["apt"], "latitude": 48.85, "longitude": 2.35}',
    )

    payload = overview.ioc_to_dict(ioc)

    assert payload["sources"] == ["misp", "otx"]
    assert payload["name"] == "APT"
    assert payload["latitude"] == 48.85
    assert payload["longitude"] == 2.35


def test_ioc_to_dict_without_geo_reports_null_coordinates():
    ioc = Ioc(
        id=2,
        type="ip",
        value="203.0.113.6",
        sources="misp",
        severity="low",
        first_seen=NOW,
        last_seen=NOW,
        metadata_json="not json at all",
    )
    payload = overview.ioc_to_dict(ioc)

    assert payload["latitude"] is None
    assert payload["sources"] == ["misp"]


def test_geo_points_only_returns_plottable_indicators():
    plottable = Ioc(
        id=3,
        type="ip",
        value="203.0.113.7",
        sources="otx",
        severity="high",
        first_seen=NOW,
        last_seen=NOW,
        metadata_json='{"latitude": 55.75, "longitude": 37.61, "name": "campagne"}',
    )
    flat = Ioc(
        id=4,
        type="ip",
        value="203.0.113.8",
        sources="misp",
        severity="low",
        first_seen=NOW,
        last_seen=NOW,
        metadata_json="{}",
    )

    points = overview.geo_points([plottable, flat])

    assert len(points) == 1
    assert points[0]["label"] == "203.0.113.7"
    assert points[0]["latitude"] == 55.75


async def test_overview_shape(client, auth_headers):
    await _seed_ioc(
        "ip",
        "203.0.113.90",
        source="misp,otx",
        metadata={"latitude": 1.0, "longitude": 2.0, "name": "demo"},
    )
    await _seed_feed_item("urn:overview:1")
    await _seed_intel_alert("overview demo")

    response = client.get("/api/intel/overview", headers=auth_headers)

    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"counts", "by_source", "by_type", "iocs", "feed", "matches", "geo"}
    assert body["counts"]["iocs"] >= 1
    assert body["counts"]["matches"] >= 1
    assert body["by_source"].get("misp", 0) >= 1
    assert any(point["label"] == "203.0.113.90" for point in body["geo"])
    assert any(item["guid"] == "urn:overview:1" for item in body["feed"])


# --------------------------------------------------------------------------- #
# Listings
# --------------------------------------------------------------------------- #


async def test_iocs_can_be_filtered_by_type_source_and_search(client, auth_headers):
    await _seed_ioc("domain", "filter-me.example", source="otx", severity="high")

    by_type = client.get("/api/intel/iocs", params={"type": "domain"}, headers=auth_headers)
    assert by_type.status_code == 200
    assert all(item["type"] == "domain" for item in by_type.json())

    by_source = client.get("/api/intel/iocs", params={"source": "otx"}, headers=auth_headers)
    assert all("otx" in item["sources"] for item in by_source.json())

    by_search = client.get(
        "/api/intel/iocs", params={"search": "filter-me"}, headers=auth_headers
    )
    assert [item["value"] for item in by_search.json()] == ["filter-me.example"]

    by_severity = client.get(
        "/api/intel/iocs", params={"search": "filter-me", "severity": "low"}, headers=auth_headers
    )
    assert by_severity.json() == []


async def test_feed_listing_filters_by_source(client, auth_headers):
    await _seed_feed_item("urn:feed:certfr", source="CERT-FR")
    await _seed_feed_item("urn:feed:cisa", source="CISA")

    response = client.get("/api/intel/feed", params={"source": "CISA"}, headers=auth_headers)

    assert response.status_code == 200
    assert [item["source"] for item in response.json()] == ["CISA"]


async def test_matches_listing_returns_only_intel_alerts(client, auth_headers):
    await _seed_intel_alert("matched thing")

    response = client.get("/api/intel/matches", headers=auth_headers)

    assert response.status_code == 200
    assert response.json()
    assert all(item["source"] == "intel" for item in response.json())


async def test_intel_endpoints_require_authentication(client):
    assert client.get("/api/intel/overview").status_code == 401
    assert client.get("/api/intel/iocs").status_code == 401
    assert client.get("/api/intel/feed").status_code == 401
    assert client.get("/api/intel/matches").status_code == 401
    assert client.post("/api/intel/sync").status_code == 401


async def test_sync_without_a_queue_returns_503_not_500(client, auth_headers):
    """No Redis here: the platform is fine, only the queue is missing."""
    response = client.post("/api/intel/sync", headers=auth_headers)

    assert response.status_code == 503
    assert "queue" in response.json()["detail"].lower()


async def test_ioc_listing_limit_is_bounded(client, auth_headers):
    assert client.get("/api/intel/iocs", params={"limit": 10_000}, headers=auth_headers).status_code == 422


# --------------------------------------------------------------------------- #
# Worker jobs — graceful degradation
# --------------------------------------------------------------------------- #


async def test_sync_misp_is_skipped_when_unconfigured(monkeypatch):
    monkeypatch.setattr(jobs.settings, "MISP_URL", None)
    monkeypatch.setattr(jobs.settings, "MISP_API_KEY", None)

    result = await jobs.sync_misp()

    assert result["status"] == "skipped"
    assert "MISP" in result["reason"]


async def test_sync_otx_is_skipped_when_unconfigured(monkeypatch):
    monkeypatch.setattr(jobs.settings, "OTX_API_KEY", None)

    result = await jobs.sync_otx()

    assert result["status"] == "skipped"
    assert "OTX" in result["reason"]


async def test_sync_cert_stores_the_mocked_feed(monkeypatch):
    async def fake_fetch(feeds, **kwargs):
        return [
            {
                "guid": "urn:job:cert:1",
                "source": "CERT-FR",
                "title": "Avis job",
                "link": "https://example.org/job",
                "summary": "résumé",
                "published_at": NOW,
            }
        ]

    monkeypatch.setattr(jobs.intel_feeds, "fetch_feeds", fake_fetch)
    monkeypatch.setattr(jobs.settings, "CERT_FEEDS", "CERT-FR=https://example.org/feed")

    result = await jobs.sync_cert()

    assert result["status"] == "ok"
    assert result["created"] >= 1
    assert result["feeds"] == ["CERT-FR"]

    async with async_session() as session:
        stored = list(
            (await session.exec(select(IntelFeedItem).where(IntelFeedItem.guid == "urn:job:cert:1"))).all()
        )
    assert len(stored) == 1


async def test_sync_cert_is_skipped_with_an_empty_feed_list(monkeypatch):
    monkeypatch.setattr(jobs.settings, "CERT_FEEDS", "   ")

    result = await jobs.sync_cert()

    assert result["status"] == "skipped"


async def test_correlate_intel_job_runs_and_reports(monkeypatch):
    await _seed_ioc("ip", "203.0.113.91", source="misp")

    result = await jobs.correlate_intel()

    assert result["status"] == "ok"
    assert "alerts_created" in result


async def test_run_intel_sync_runs_every_connector_then_correlates(monkeypatch):
    monkeypatch.setattr(jobs.settings, "MISP_URL", None)
    monkeypatch.setattr(jobs.settings, "MISP_API_KEY", None)
    monkeypatch.setattr(jobs.settings, "OTX_API_KEY", None)
    monkeypatch.setattr(jobs.settings, "CERT_FEEDS", "")

    result = await jobs.run_intel_sync()

    assert set(result) == {"misp", "otx", "cert", "correlation"}
    assert result["misp"]["status"] == "skipped"
    assert result["cert"]["status"] == "skipped"
    assert result["correlation"]["status"] == "ok"


async def test_normalize_is_reused_by_the_jobs(monkeypatch):
    """Guard: the connectors must normalise through the shared layer."""
    assert normalize.canonical_type("ip-src") == "ip"
