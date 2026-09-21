"""arq worker jobs. Uses its own async engine/session, separate from the API's."""

import logging
from datetime import datetime, timezone

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import get_settings
from app.models import Finding, IngestState, Scan, Target, utcnow
from app.services import nvd, retention, scanner
from app.services.ingest import ingest_events
from app.services.intel import correlation as intel_correlation
from app.services.intel import feeds as intel_feeds
from app.services.intel import misp as intel_misp
from app.services.intel import otx as intel_otx
from app.services.intel import store as intel_store
from app.services.risk import compute_risk_score
from app.services.suricata import normalize_events, read_new_lines

logger = logging.getLogger(__name__)

settings = get_settings()

connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

_engine = create_async_engine(settings.DATABASE_URL, echo=False, connect_args=connect_args)
_WorkerSession = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)

# v0.2 — at most this many distinct (service, version) pairs get NVD-enriched per scan.
_NVD_ENRICHMENT_LIMIT = 5


def _nvd_pairs(raw_findings: list[dict]) -> list[tuple[str, str]]:
    """Up to 5 distinct non-empty (service, version) pairs from nmap findings."""
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw in raw_findings:
        service = (raw.get("service") or "").strip()
        version = (raw.get("version") or "").strip()
        if not service or not version:
            continue
        key = (service.lower(), version.lower())
        if key in seen:
            continue
        seen.add(key)
        pairs.append((service, version))
        if len(pairs) >= _NVD_ENRICHMENT_LIMIT:
            break
    return pairs


async def run_scan(ctx: dict, scan_id: int) -> str:
    """Execute one scan: nmap + nuclei + NVD enrichment, risk score, update status."""
    async with _WorkerSession() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return f"scan {scan_id} not found"
        target = await session.get(Target, scan.target_id)
        if target is None:
            scan.status = "failed"
            scan.error = "Target no longer exists"
            scan.finished_at = datetime.now(timezone.utc)
            session.add(scan)
            await session.commit()
            return scan.status

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        session.add(scan)
        await session.commit()

        try:
            raw_findings = await scanner.run_nmap_scan(target.value, scan.profile)
            # Replace any previous findings for this scan.
            await session.execute(delete(Finding).where(Finding.scan_id == scan.id))

            severities: list[str] = []
            for raw in raw_findings:
                session.add(Finding(scan_id=scan.id, source="nmap", org_id=scan.org_id, **raw))
                severities.append(raw["severity"])

            # (a) nuclei — NON-fatal: a missing binary or failed run never
            # breaks the scan; scan.error stays reserved for fatal nmap failure.
            try:
                nuclei_findings = await scanner.run_nuclei_scan(target.value, scan.profile)
            except RuntimeError as exc:
                logger.info("nuclei skipped for scan %s: %s", scan.id, exc)
                nuclei_findings = []
            for raw in nuclei_findings:
                session.add(Finding(scan_id=scan.id, source="nuclei", org_id=scan.org_id, **raw))
                severities.append(raw["severity"])

            # (b) NVD enrichment — best-effort; lookup_cves never raises.
            for service, version in _nvd_pairs(raw_findings):
                for cve in await nvd.lookup_cves(service, version):
                    severity = nvd.severity_from_cvss(cve["cvss"])
                    session.add(
                        Finding(
                            scan_id=scan.id,
                            source="nvd",
                            org_id=scan.org_id,
                            port=0,
                            protocol="tcp",
                            service=cve["cve_id"],
                            version="",
                            severity=severity,
                            detail=f"{cve['description']} (CVSS {cve['cvss']})",
                        )
                    )
                    severities.append(severity)

            # (c) + (d) risk score for the scan, mirrored onto the target.
            scan.risk_score = compute_risk_score(severities)
            target.risk_score = scan.risk_score
            session.add(target)

            scan.status = "done"
            scan.error = None
        except Exception as exc:  # noqa: BLE001 — any nmap/parsing failure marks the scan failed
            scan.status = "failed"
            scan.error = str(exc)[:2000]

        scan.finished_at = datetime.now(timezone.utc)
        session.add(scan)
        await session.commit()
        return scan.status


# --------------------------------------------------------------------------- #
# v0.3 "Défense" jobs — sensor ingestion (#1) and retention purge (#5)
# --------------------------------------------------------------------------- #


def _ingest_state_key(eve_path: str) -> str:
    """Cursor identity: one offset per EVE file."""
    return f"suricata:eve:{eve_path}"


async def ingest_eve(ctx: dict | None = None, path: str | None = None) -> dict:
    """Tail the Suricata EVE file, persist new events and run detection.

    Designed to be called every 15 s by the worker cron. It is safe to call on
    a machine with no sensor at all: a missing file is reported, not raised.
    """
    eve_path = path or settings.SURICATA_EVE_PATH
    key = _ingest_state_key(eve_path)

    async with _WorkerSession() as session:
        state = await session.get(IngestState, key)
        result = read_new_lines(
            eve_path,
            offset=state.offset if state else 0,
            inode=state.inode if state else 0,
        )

        if result.missing:
            return {"status": "skipped", "reason": "eve file not found", "path": eve_path}

        events = normalize_events(result.lines)
        summary = await ingest_events(session, events)

        if state is None:
            state = IngestState(key=key, offset=result.offset, inode=result.inode)
        else:
            state.offset = result.offset
            state.inode = result.inode
            state.updated_at = utcnow()
        session.add(state)
        await session.commit()

    summary.update(
        {
            "status": "ok",
            "path": eve_path,
            "rotated": result.rotated,
            "cursor": result.offset,
        }
    )
    return summary


async def purge_expired_data(ctx: dict | None = None, retention_days: int | None = None) -> dict:
    """Delete findings/alerts/sensor events older than ``RETENTION_DAYS`` (#5)."""
    days = settings.RETENTION_DAYS if retention_days is None else retention_days
    async with _WorkerSession() as session:
        return await retention.purge_expired(session, days)


# --------------------------------------------------------------------------- #
# v0.4 "Renseignement" jobs — connectors (#6, #7, #8) and correlation (#9)
# --------------------------------------------------------------------------- #


def _disabled(reason: str) -> dict:
    """Uniform "nothing to do" result, so a skipped job is visible in the logs."""
    return {"status": "skipped", "reason": reason}


async def sync_misp(ctx: dict | None = None) -> dict:
    """Pull indicators from the configured MISP instance (#6)."""
    if not settings.MISP_URL or not settings.MISP_API_KEY:
        return _disabled("MISP_URL/MISP_API_KEY not configured")

    candidates = await intel_misp.fetch_attributes(
        settings.MISP_URL,
        settings.MISP_API_KEY,
        lookback_days=settings.MISP_LOOKBACK_DAYS,
        limit=settings.MISP_ATTRIBUTE_LIMIT,
    )
    async with _WorkerSession() as session:
        counters = await intel_store.upsert_iocs(session, candidates)
    counters.update({"status": "ok", "source": "misp"})
    return counters


async def sync_otx(ctx: dict | None = None) -> dict:
    """Pull subscribed AlienVault OTX pulses (#7)."""
    if not settings.OTX_API_KEY:
        return _disabled("OTX_API_KEY not configured")

    candidates = await intel_otx.fetch_pulses(
        settings.OTX_API_KEY, limit=settings.OTX_PULSE_LIMIT
    )
    async with _WorkerSession() as session:
        counters = await intel_store.upsert_iocs(session, candidates)
    counters.update({"status": "ok", "source": "otx"})
    return counters


async def sync_cert(ctx: dict | None = None) -> dict:
    """Aggregate the configured CERT advisory feeds (#8)."""
    feeds = intel_feeds.parse_feed_spec(settings.CERT_FEEDS)
    if not feeds:
        return _disabled("no CERT feed configured")

    items = await intel_feeds.fetch_feeds(feeds, per_feed_limit=settings.CERT_ITEMS_PER_FEED)
    async with _WorkerSession() as session:
        counters = await intel_store.upsert_feed_items(session, items)
    counters.update({"status": "ok", "feeds": [name for name, _ in feeds]})
    return counters


async def correlate_intel(ctx: dict | None = None) -> dict:
    """Match stored indicators against local alerts and findings (#9)."""
    async with _WorkerSession() as session:
        counters = await intel_correlation.correlate_iocs(
            session, ioc_limit=settings.INTEL_IOC_LIMIT
        )
    counters["status"] = "ok"
    return counters


async def run_intel_sync(ctx: dict | None = None) -> dict:
    """Full intel cycle: every connector, then correlation.

    Enqueued by ``POST /api/intel/sync`` so a demo instance can refresh its
    intelligence on demand instead of waiting for the cron.
    """
    result = {
        "misp": await sync_misp(ctx),
        "otx": await sync_otx(ctx),
        "cert": await sync_cert(ctx),
    }
    result["correlation"] = await correlate_intel(ctx)
    return result
