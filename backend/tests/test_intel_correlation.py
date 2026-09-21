"""IoC ↔ observed correlation tests (v0.4, issue #9).

Acceptance criterion: "Tests de corrélation sur jeux synthétiques". Everything
here is synthetic — indicators, alerts and findings are seeded directly — and the
properties pinned are the ones that decide whether the feature is usable:

* a match **creates an alert** with severity ≥ high and ``source="intel"``;
* a match is raised **once, ever** (§ "le nerf de la guerre" is worthless if it
  repeats the same finding every cycle);
* a local alert that is *itself* intel must not match intel (no self-correlation).
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import select

from app.db import async_session
from app.models import Alert, Finding, Ioc, Scan, Target
from app.services.intel import correlation
from app.services.intel.normalize import candidate

NOW = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)



async def _seed_ioc(ioc_type: str, value: str, source: str = "misp", severity: str = "medium") -> int:
    item = candidate(ioc_type, value, source, severity=severity, metadata={"name": "synthetic"})
    async with async_session() as session:
        row = Ioc(
            type=item["type"],
            value=item["value"],
            sources=item["source"],
            severity=item["severity"],
            first_seen=item["first_seen"],
            last_seen=item["last_seen"],
            metadata_json="{}",
        )
        session.add(row)
        await session.commit()
        await session.refresh(row)
        return row.id


async def _seed_alert(**overrides) -> int:
    values = {
        "source": "rule",
        "event_type": "port_scan",
        "severity": "high",
        "detail": "synthetic alert",
        "payload": "{}",
        "status": "new",
        "created_at": NOW,
    }
    values.update(overrides)
    async with async_session() as session:
        alert = Alert(**values)
        session.add(alert)
        await session.commit()
        await session.refresh(alert)
        return alert.id


async def _seed_finding(detail: str) -> int:
    async with async_session() as session:
        target = Target(name="Corr VM", value="10.90.0.1", kind="ip", owner_id=1)
        session.add(target)
        await session.commit()
        await session.refresh(target)
        scan = Scan(target_id=target.id, profile="quick", status="done")
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        finding = Finding(
            scan_id=scan.id,
            port=80,
            protocol="tcp",
            service="http",
            version="",
            severity="medium",
            detail=detail,
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)
        return finding.id


# --------------------------------------------------------------------------- #
# Severity policy
# --------------------------------------------------------------------------- #


def test_intel_matches_are_never_below_high():
    assert correlation._severity_for("info") == "high"
    assert correlation._severity_for("medium") == "high"
    assert correlation._severity_for("high") == "high"
    # A critical indicator is not downgraded.
    assert correlation._severity_for("critical") == "critical"
    assert correlation._severity_for("nonsense") == "high"


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


async def test_an_ip_indicator_matching_an_alert_raises_a_high_intel_alert():
    await _seed_alert(
        src_ip="198.51.100.201",
        dst_ip="10.0.0.5",
        src_port=40000,
        dst_port=22,
        detail="SSH brute force suspected",
    )
    await _seed_ioc("ip", "198.51.100.201", source="misp")

    async with async_session() as session:
        counters = await correlation.correlate_iocs(session, now=NOW)

    assert counters["alert_matches"] >= 1
    assert counters["alerts_created"] >= 1

    async with async_session() as session:
        matches = list(
            (
                await session.exec(
                    select(Alert)
                    .where(Alert.source == "intel")
                    .where(Alert.src_ip == "198.51.100.201")
                )
            ).all()
        )
    assert len(matches) == 1
    assert matches[0].severity == "high"  # medium IoC escalated to the floor
    assert matches[0].event_type == "ioc_match_ip"
    assert matches[0].status == "new"
    assert matches[0].confidence == 1.0
    assert "198.51.100.201" in matches[0].detail


async def test_a_domain_indicator_matches_a_finding_on_its_detail():
    await _seed_finding(detail="http://evil-c2.example/gate.php responded 200")
    await _seed_ioc("domain", "evil-c2.example", source="otx")

    async with async_session() as session:
        counters = await correlation.correlate_iocs(session, now=NOW)

    assert counters["finding_matches"] >= 1
    async with async_session() as session:
        matches = list(
            (
                await session.exec(
                    select(Alert)
                    .where(Alert.source == "intel")
                    .where(Alert.detail.like("%evil-c2.example%"))
                )
            ).all()
        )
    assert matches
    assert matches[0].severity == "high"
    assert matches[0].dedup_key.startswith("intel|domain|evil-c2.example|finding:")


async def test_a_hash_indicator_matches_a_finding():
    await _seed_finding(detail="file downloaded, sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    await _seed_ioc("sha256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", source="misp")

    async with async_session() as session:
        await correlation.correlate_iocs(session, now=NOW)

    async with async_session() as session:
        matches = list(
            (
                await session.exec(
                    select(Alert).where(Alert.dedup_key.like("intel|sha256|%"))
                )
            ).all()
        )
    assert matches


async def test_an_indicator_that_matches_nothing_creates_nothing():
    await _seed_ioc("ip", "198.51.100.240", source="misp")

    async with async_session() as session:
        await correlation.correlate_iocs(session, now=NOW)

    # The correlator walks every stored indicator, so the assertion targets this
    # one rather than a global counter shared with the rest of the suite.
    async with async_session() as session:
        matches = list(
            (
                await session.exec(
                    select(Alert).where(Alert.dedup_key.like("intel|ip|198.51.100.240|%"))
                )
            ).all()
        )
    assert matches == []


# --------------------------------------------------------------------------- #
# Once, ever
# --------------------------------------------------------------------------- #


async def test_a_match_is_reported_only_once_whatever_the_time_window():
    """Re-running correlation must not re-alert on an already-reported match."""
    await _seed_alert(src_ip="198.51.100.202", detail="synthetic")
    await _seed_ioc("ip", "198.51.100.202", source="misp")

    async with async_session() as session:
        first = await correlation.correlate_iocs(session, now=NOW)
    assert first["alerts_created"] >= 1

    async with async_session() as session:
        second = await correlation.correlate_iocs(session, now=NOW + timedelta(days=30))

    assert second["alerts_created"] == 0

    async with async_session() as session:
        matches = list(
            (
                await session.exec(
                    select(Alert)
                    .where(Alert.source == "intel")
                    .where(Alert.src_ip == "198.51.100.202")
                )
            ).all()
        )
    assert len(matches) == 1


async def test_a_new_alert_on_a_known_indicator_is_a_new_match():
    """The indicator is known, but this particular entity was never matched."""
    await _seed_ioc("ip", "198.51.100.203", source="misp")
    await _seed_alert(src_ip="198.51.100.203", detail="first occurrence")

    async with async_session() as session:
        await correlation.correlate_iocs(session, now=NOW)

    await _seed_alert(src_ip="198.51.100.203", detail="second occurrence")

    async with async_session() as session:
        counters = await correlation.correlate_iocs(session, now=NOW + timedelta(minutes=5))

    assert counters["alerts_created"] >= 1
    async with async_session() as session:
        matches = list(
            (
                await session.exec(
                    select(Alert)
                    .where(Alert.source == "intel")
                    .where(Alert.src_ip == "198.51.100.203")
                )
            ).all()
        )
    assert len(matches) == 2


async def test_intel_alerts_never_correlate_with_themselves():
    seeded = await _seed_alert(
        source="intel",
        src_ip="198.51.100.204",
        detail="already an intel match",
        dedup_key="intel|ip|198.51.100.204|alert:1",
    )
    await _seed_ioc("ip", "198.51.100.204", source="misp")

    async with async_session() as session:
        await correlation.correlate_iocs(session, now=NOW)

    # Only the seeded alert exists: correlation never feeds on its own output.
    async with async_session() as session:
        rows = list(
            (
                await session.exec(
                    select(Alert)
                    .where(Alert.source == "intel")
                    .where(Alert.src_ip == "198.51.100.204")
                )
            ).all()
        )
    assert [row.id for row in rows] == [seeded]


# --------------------------------------------------------------------------- #
# Guards
# --------------------------------------------------------------------------- #


async def test_correlation_with_no_indicator_reports_zero_and_does_not_raise():
    """An empty intel store is a normal state, not an error."""
    async with async_session() as session:
        counters = await correlation.correlate_iocs(session, now=NOW, ioc_limit=0)
    assert counters["iocs_evaluated"] == 0
    assert counters["alerts_created"] == 0


async def test_the_number_of_alerts_created_per_run_is_capped():
    """A pathological feed must not be able to flood the alert stream."""
    for index in range(5):
        await _seed_alert(src_ip="198.51.100.250", detail=f"synthetic {index}")
    await _seed_ioc("ip", "198.51.100.250", source="misp")

    # A zero budget means "report nothing this cycle", whatever else is stored.
    async with async_session() as session:
        blocked = await correlation.correlate_iocs(session, now=NOW, max_alerts=0)
    assert blocked["alerts_created"] == 0
    assert blocked["alerts_skipped"] >= 1

    async with async_session() as session:
        capped = await correlation.correlate_iocs(session, now=NOW, max_alerts=2)
    assert capped["alerts_created"] <= 2
