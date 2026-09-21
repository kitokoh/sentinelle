"""Worker job tests beyond the happy path (v0.7, issue #21).

The coverage target of #21 has a purpose beyond the number: the worker is where a
silent failure costs the most — a job that stops consuming leaks nothing into the
API's logs and looks exactly like "no traffic". These tests therefore exercise the
paths that only appear *after* something goes wrong, plus the intel connectors
with a configured source (the degraded path was already covered).
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlmodel import select

from app.db import async_session
from app.models import Ioc, SensorEvent, WorkerHeartbeat
from app.worker import jobs, settings as worker_settings

REPO_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- #
# NVD enrichment selection
# --------------------------------------------------------------------------- #


def test_nvd_pairs_keeps_only_distinct_service_version_pairs():
    raw = [
        {"service": "ssh", "version": "OpenSSH 8.9"},
        {"service": "SSH", "version": "openssh 8.9"},  # same pair, different case
        {"service": "nginx", "version": "1.18"},
        {"service": "", "version": "1.0"},  # missing service
        {"service": "redis", "version": ""},  # missing version
        {"service": "mysql", "version": "5.7"},
    ]

    pairs = jobs._nvd_pairs(raw)

    assert pairs == [("ssh", "OpenSSH 8.9"), ("nginx", "1.18"), ("mysql", "5.7")]


def test_nvd_pairs_is_capped():
    """Unbounded enrichment would turn one scan into hundreds of API calls."""
    raw = [{"service": f"svc{i}", "version": "1.0"} for i in range(50)]

    pairs = jobs._nvd_pairs(raw)

    assert len(pairs) == jobs._NVD_ENRICHMENT_LIMIT == 5


def test_nvd_pairs_tolerates_missing_keys():
    assert jobs._nvd_pairs([{}, {"service": None, "version": None}]) == []


# --------------------------------------------------------------------------- #
# EVE ingestion through the job (the happy path)
# --------------------------------------------------------------------------- #


async def test_ingest_eve_reads_a_real_file_and_advances_its_cursor(client, tmp_path, monkeypatch):
    """End-to-end: file → normalized events → cursor → no re-read."""
    eve_path = tmp_path / "eve.json"
    monkeypatch.setattr(jobs.settings, "SURICATA_EVE_PATH", str(eve_path))

    now = datetime.now(timezone.utc)
    records = [
        {
            "timestamp": (now - timedelta(seconds=index)).isoformat(),
            "flow_id": 5000 + index,
            "event_type": "flow",
            "src_ip": "198.51.100.31",
            "src_port": 40000 + index,
            "dest_ip": "10.70.0.1",
            "dest_port": 80,
            "proto": "TCP",
            "app_proto": "http",
        }
        for index in range(3)
    ]
    eve_path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")

    first = await jobs.ingest_eve()

    assert first["status"] == "ok"
    assert first["stored"] == 3
    assert first["cursor"] > 0

    # A second cycle with nothing new must store nothing and keep the cursor.
    second = await jobs.ingest_eve()
    assert second["stored"] == 0
    assert second["cursor"] == first["cursor"]

    async with async_session() as session:
        stored = list(
            (
                await session.exec(select(SensorEvent).where(SensorEvent.src_ip == "198.51.100.31"))
            ).all()
        )
    assert len(stored) == 3


async def test_ingest_eve_reports_a_missing_file_without_failing(client, tmp_path, monkeypatch):
    monkeypatch.setattr(jobs.settings, "SURICATA_EVE_PATH", str(tmp_path / "absent.json"))

    result = await jobs.ingest_eve()

    assert result["status"] == "skipped"
    assert result["path"].endswith("absent.json")


async def test_ingest_eve_beats_before_looking_for_the_sensor(client, tmp_path, monkeypatch):
    """The heartbeat is unconditional: a worker without a sensor is still alive."""
    monkeypatch.setattr(jobs.settings, "SURICATA_EVE_PATH", str(tmp_path / "absent.json"))

    await jobs.ingest_eve()

    async with async_session() as session:
        heartbeat = await session.get(WorkerHeartbeat, "arq-worker")
    assert heartbeat is not None
    assert heartbeat.detail and heartbeat.detail.startswith("ingest:")


# --------------------------------------------------------------------------- #
# Intel connectors with a configured source
# --------------------------------------------------------------------------- #


async def test_sync_misp_persists_what_the_connector_returns(client, monkeypatch):
    async def fake_fetch(base_url, api_key, **kwargs):
        assert base_url == "https://misp.lab"
        assert api_key == "key"
        return [
            {
                "type": "ip",
                "value": "203.0.113.150",
                "source": "misp",
                "severity": "high",
                "first_seen": datetime.now(timezone.utc),
                "last_seen": datetime.now(timezone.utc),
                "metadata": {"name": "worker test"},
            }
        ]

    monkeypatch.setattr(jobs.settings, "MISP_URL", "https://misp.lab")
    monkeypatch.setattr(jobs.settings, "MISP_API_KEY", "key")
    monkeypatch.setattr(jobs.intel_misp, "fetch_attributes", fake_fetch)

    result = await jobs.sync_misp()

    assert result["status"] == "ok"
    assert result["created"] >= 1

    async with async_session() as session:
        stored = list((await session.exec(select(Ioc).where(Ioc.value == "203.0.113.150"))).all())
    assert len(stored) == 1
    assert stored[0].sources == "misp"


async def test_sync_otx_persists_what_the_connector_returns(client, monkeypatch):
    async def fake_fetch(api_key, **kwargs):
        assert api_key == "otx-key"
        return [
            {
                "type": "domain",
                "value": "worker-test.example",
                "source": "otx",
                "severity": "medium",
                "first_seen": datetime.now(timezone.utc),
                "last_seen": datetime.now(timezone.utc),
                "metadata": {"name": "otx worker test"},
            }
        ]

    monkeypatch.setattr(jobs.settings, "OTX_API_KEY", "otx-key")
    monkeypatch.setattr(jobs.intel_otx, "fetch_pulses", fake_fetch)

    result = await jobs.sync_otx()

    assert result["status"] == "ok"
    assert result["created"] >= 1

    async with async_session() as session:
        stored = list(
            (await session.exec(select(Ioc).where(Ioc.value == "worker-test.example"))).all()
        )
    assert len(stored) == 1
    assert stored[0].sources == "otx"


async def test_sync_misp_with_no_indicator_is_still_ok(client, monkeypatch):
    """An empty source is a normal outcome, not a failure — and it says so."""
    async def empty_fetch(*args, **kwargs):
        return []

    monkeypatch.setattr(jobs.settings, "MISP_URL", "https://misp.lab")
    monkeypatch.setattr(jobs.settings, "MISP_API_KEY", "key")
    monkeypatch.setattr(jobs.intel_misp, "fetch_attributes", empty_fetch)

    result = await jobs.sync_misp()

    assert result["status"] == "ok"
    assert result["created"] == 0
    assert result["received"] == 0


async def test_run_intel_sync_runs_every_connector_in_order(client, monkeypatch):
    order: list[str] = []

    async def fake_misp(*args, **kwargs):
        order.append("misp")
        return []

    async def fake_otx(*args, **kwargs):
        order.append("otx")
        return []

    async def fake_feeds(*args, **kwargs):
        order.append("cert")
        return []

    monkeypatch.setattr(jobs.settings, "MISP_URL", "https://misp.lab")
    monkeypatch.setattr(jobs.settings, "MISP_API_KEY", "key")
    monkeypatch.setattr(jobs.settings, "OTX_API_KEY", "otx-key")
    monkeypatch.setattr(jobs.settings, "CERT_FEEDS", "CERT-FR=https://example.org/feed")
    monkeypatch.setattr(jobs.intel_misp, "fetch_attributes", fake_misp)
    monkeypatch.setattr(jobs.intel_otx, "fetch_pulses", fake_otx)
    monkeypatch.setattr(jobs.intel_feeds, "fetch_feeds", fake_feeds)

    result = await jobs.run_intel_sync()

    assert order == ["misp", "otx", "cert"]
    assert result["correlation"]["status"] == "ok"


async def test_purge_expired_data_job_reports_its_counters(client):
    """The nightly job must return something an operator can read in the logs."""
    result = await jobs.purge_expired_data()

    assert "enabled" in result
    assert "findings" in result and "alerts" in result and "sensor_events" in result


# --------------------------------------------------------------------------- #
# Worker registration (app/worker/settings.py)
# --------------------------------------------------------------------------- #


def test_every_job_is_registered_on_the_worker():
    functions = {function.__name__ for function in worker_settings.WorkerSettings.functions}

    assert functions == {
        "run_scan",
        "ingest_eve",
        "purge_expired_data",
        "sync_misp",
        "sync_otx",
        "sync_cert",
        "correlate_intel",
        "run_intel_sync",
    }


def _cron_by_job_name() -> dict:
    """arq names cron jobs ``cron:<function>`` — strip the prefix to compare."""
    return {
        job.name.removeprefix("cron:"): job for job in worker_settings.WorkerSettings.cron_jobs
    }


def test_the_scheduled_jobs_are_the_documented_ones():
    """A cron job that silently disappears is a feature that silently stops."""
    assert set(_cron_by_job_name()) == {
        "ingest_eve",
        "purge_expired_data",
        "sync_misp",
        "sync_otx",
        "sync_cert",
        "correlate_intel",
    }


def test_ingestion_runs_at_startup():
    """A worker restart must not wait a full cycle before seeing EVE traffic."""
    assert _cron_by_job_name()["ingest_eve"].run_at_startup is True


def test_the_worker_reads_its_redis_url_from_the_configuration():
    from app.core.config import get_settings

    assert worker_settings.redis_settings.host == get_settings().REDIS_URL.split("//")[1].split(":")[0]
