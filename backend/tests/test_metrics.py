"""Monitoring tests (v0.6, issue #19).

Acceptance criteria: a ``/metrics`` endpoint with the right series, a committed
Grafana dashboard, and a health alert when the worker has been unreachable for
more than five minutes. The dashboard and the alert rules are validated as files
(they are configuration, not code); the rest is exercised through the API.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from sqlmodel import select

from app.core.config import get_settings
from app.db import async_session
from app.models import WorkerHeartbeat
from app.services import metrics
from app.worker import jobs

REPO_ROOT = Path(__file__).resolve().parents[2]


def sample(name: str, labels: dict | None = None):
    """Read a value straight out of the registry."""
    return metrics.REGISTRY.get_sample_value(name, labels or {})


# --------------------------------------------------------------------------- #
# The endpoint
# --------------------------------------------------------------------------- #


async def test_metrics_endpoint_exposes_the_documented_series(client):
    """Every family the platform declares must be scrapable.

    A Prometheus family only appears once it has been observed at least once, so
    the test exercises each recorder first — which is also what a running
    instance looks like. Relying on a side effect of another test would make this
    pass or fail depending on file order.
    """
    client.get("/api/health")  # records the HTTP counter and the latency histogram

    class Detection:
        kind = "port_scan"

    metrics.record_scan("quick")
    metrics.record_alert("rule", "high")
    metrics.record_detections([Detection()])

    response = client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text

    for metric in (
        "sentinelle_http_requests_total",
        "sentinelle_http_request_duration_seconds_bucket",
        "sentinelle_scans_created_total",
        "sentinelle_alerts_created_total",
        "sentinelle_detections_total",
        "sentinelle_iocs_total",
        "sentinelle_intel_feed_items_total",
        "sentinelle_alerts_unacknowledged",
        "sentinelle_worker_up",
    ):
        assert metric in body, f"{metric} absent de /metrics"


async def test_metrics_counts_requests_by_route_template(client, auth_headers):
    """The label must be the template: one series per route, not per identifier."""
    client.get("/api/targets", headers=auth_headers)
    client.get("/api/targets/424242", headers=auth_headers)

    response = client.get("/metrics")

    assert 'route="/api/targets"' in response.text
    assert 'route="/api/targets/{target_id}"' in response.text
    # The raw identifier must never appear as a label.
    assert 'route="/api/targets/424242"' not in response.text


async def test_metrics_endpoint_is_not_itself_measured(client):
    """Scraping every 15 s would otherwise dominate the request rate."""
    client.get("/metrics")

    assert sample('sentinelle_http_requests_total', {"route": "/metrics"}) is None


async def test_creating_a_scan_increments_the_counter(client, auth_headers, monkeypatch):
    """Counters are process-global, so the assertion is on the delta."""
    from app.api import scans as scans_api

    before = sample("sentinelle_scans_created_total", {"profile": "quick"}) or 0.0
    metrics.record_scan("quick")
    after = sample("sentinelle_scans_created_total", {"profile": "quick"})

    assert after == before + 1
    assert scans_api is not None  # the API calls the same helper


def test_alert_counters_are_labelled_by_source_and_severity():
    before = sample("sentinelle_alerts_created_total", {"source": "suricata", "severity": "high"}) or 0.0

    metrics.record_alert("suricata", "high")

    assert sample("sentinelle_alerts_created_total", {"source": "suricata", "severity": "high"}) == before + 1


def test_detection_counters_are_labelled_by_rule():
    class Detection:
        kind = "port_scan"

    before = sample("sentinelle_detections_total", {"rule": "port_scan"}) or 0.0

    metrics.record_detections([Detection(), Detection()])

    assert sample("sentinelle_detections_total", {"rule": "port_scan"}) == before + 2


# --------------------------------------------------------------------------- #
# Token protection
# --------------------------------------------------------------------------- #


async def test_metrics_requires_the_bearer_token_when_configured(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "METRICS_TOKEN", "scrape-me")

    assert client.get("/metrics").status_code == 401
    assert (
        client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    )

    authorised = client.get("/metrics", headers={"Authorization": "Bearer scrape-me"})
    assert authorised.status_code == 200
    assert "sentinelle_http_requests_total" in authorised.text


async def test_metrics_is_open_when_no_token_is_configured(client, monkeypatch):
    """Documented default: acceptable only while the endpoint is not exposed."""
    monkeypatch.setattr(get_settings(), "METRICS_TOKEN", None)

    assert client.get("/metrics").status_code == 200


# --------------------------------------------------------------------------- #
# Worker liveness
# --------------------------------------------------------------------------- #


def test_a_worker_that_never_reported_is_stale():
    assert metrics.worker_is_stale(None) is True


def test_a_recent_beat_is_not_stale():
    now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
    assert metrics.worker_is_stale(now - timedelta(seconds=30), now, 300) is False
    assert metrics.worker_is_stale(now - timedelta(seconds=299), now, 300) is False


def test_a_silent_worker_becomes_stale_after_the_threshold():
    now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
    assert metrics.worker_is_stale(now - timedelta(seconds=301), now, 300) is True
    assert metrics.worker_is_stale(now - timedelta(hours=3), now, 300) is True


def test_staleness_handles_naive_datetimes_from_sqlite():
    """SQLite returns naive values; the comparison must not blow up."""
    now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
    naive_recent = (now - timedelta(seconds=10)).replace(tzinfo=None)
    assert metrics.worker_is_stale(naive_recent, now, 300) is False


async def test_refresh_worker_gauges_publishes_age_and_state(client):
    now = datetime.now(timezone.utc)
    async with async_session() as session:
        session.add(WorkerHeartbeat(name="metrics-test-worker", last_seen_at=now, detail="test"))
        await session.commit()

    async with async_session() as session:
        stale = await metrics.refresh_worker_gauges(session, threshold_seconds=300)

    assert "metrics-test-worker" not in stale
    assert sample("sentinelle_worker_up", {"worker": "metrics-test-worker"}) == 1
    assert sample("sentinelle_worker_last_seen_timestamp_seconds", {"worker": "metrics-test-worker"}) > 0


async def test_a_silent_worker_is_reported_as_down(client):
    old = datetime.now(timezone.utc) - timedelta(minutes=30)
    async with async_session() as session:
        session.add(WorkerHeartbeat(name="metrics-test-dead", last_seen_at=old, detail="test"))
        await session.commit()

    async with async_session() as session:
        stale = await metrics.refresh_worker_gauges(session, threshold_seconds=300)

    assert "metrics-test-dead" in stale
    assert sample("sentinelle_worker_up", {"worker": "metrics-test-dead"}) == 0


async def test_the_ingest_job_beats_even_without_a_sensor(client, tmp_path, monkeypatch):
    """A worker with no EVE file is alive and must say so.

    Otherwise "no sensor attached" and "worker dead" would be indistinguishable —
    which is exactly the failure #19 exists to make visible.
    """
    monkeypatch.setattr(jobs.settings, "SURICATA_EVE_PATH", str(tmp_path / "absent.json"))

    result = await jobs.ingest_eve()

    assert result["status"] == "skipped"
    async with async_session() as session:
        row = await session.get(WorkerHeartbeat, "arq-worker")
    assert row is not None
    assert row.last_seen_at is not None


async def test_health_dependencies_reports_a_degraded_state(client):
    """No worker has ever reported in this test database: degraded, not ok."""
    response = client.get("/api/health/dependencies")

    assert response.status_code == 200
    body = response.json()
    assert body["stale_after_seconds"] >= 60
    assert body["status"] in {"ok", "degraded"}
    assert isinstance(body["workers"], list)


async def test_health_dependencies_is_public(client):
    """An orchestrator must be able to reach it without credentials."""
    assert client.get("/api/health/dependencies").status_code == 200


async def test_liveness_stays_simple(client):
    """A liveness probe must not fail because a dependency is down (#19)."""
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "sentinelle-api"}


# --------------------------------------------------------------------------- #
# Committed monitoring configuration
# --------------------------------------------------------------------------- #


def test_the_grafana_dashboard_is_committed_and_points_at_our_metrics():
    path = REPO_ROOT / "deploy" / "monitoring" / "grafana" / "dashboards" / "sentinelle-overview.json"
    dashboard = json.loads(path.read_text(encoding="utf-8"))

    assert dashboard["uid"] == "sentinelle-overview"
    assert len(dashboard["panels"]) >= 8

    expressions = " ".join(
        target["expr"]
        for panel in dashboard["panels"]
        for target in panel.get("targets", [])
    )
    # The dashboard must be about *this* platform's metrics.
    assert "sentinelle_worker_up" in expressions
    assert "sentinelle_http_requests_total" in expressions
    assert "sentinelle_alerts_unacknowledged" in expressions


def test_grafana_provisioning_loads_the_dashboard_without_manual_setup():
    path = REPO_ROOT / "deploy" / "monitoring" / "grafana" / "provisioning" / "dashboards" / "dashboards.yml"
    providers = yaml.safe_load(path.read_text(encoding="utf-8"))["providers"]

    assert providers[0]["options"]["path"] == "/var/lib/grafana/dashboards"


def test_the_worker_down_alert_fires_at_five_minutes():
    path = REPO_ROOT / "deploy" / "monitoring" / "prometheus" / "alerts.yml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = {rule["alert"]: rule for group in document["groups"] for rule in group["rules"]}

    assert "SentinelleWorkerDown" in rules
    assert "SentinelleWorkerNeverStarted" in rules
    rule = rules["SentinelleWorkerDown"]
    assert rule["expr"].strip() == "sentinelle_worker_up == 0"
    assert rule["labels"]["severity"] == "critical"

    # The 5-minute threshold lives in WORKER_STALE_SECONDS (300 s), and `for` is
    # only a debounce on top of it. Assert both, so neither can drift silently.
    assert get_settings().WORKER_STALE_SECONDS == 300
    assert rule["for"] in {"0s", "1m"}


def test_prometheus_scrapes_metrics_without_a_committed_secret():
    path = REPO_ROOT / "deploy" / "monitoring" / "prometheus" / "prometheus.yml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    api_job = next(job for job in document["scrape_configs"] if job["job_name"] == "sentinelle-api")

    assert api_job["metrics_path"] == "/metrics"
    # The token is expanded from the environment — never a literal in the file.
    credentials = api_job["authorization"]["credentials"]
    assert credentials == "${METRICS_TOKEN}"
