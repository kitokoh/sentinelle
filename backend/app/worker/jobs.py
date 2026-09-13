"""arq worker jobs. Uses its own async engine/session, separate from the API's."""

import logging
from datetime import datetime, timezone

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import get_settings
from app.models import Finding, Scan, Target
from app.services import nvd, scanner
from app.services.risk import compute_risk_score

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
                session.add(Finding(scan_id=scan.id, source="nmap", **raw))
                severities.append(raw["severity"])

            # (a) nuclei — NON-fatal: a missing binary or failed run never
            # breaks the scan; scan.error stays reserved for fatal nmap failure.
            try:
                nuclei_findings = await scanner.run_nuclei_scan(target.value, scan.profile)
            except RuntimeError as exc:
                logger.info("nuclei skipped for scan %s: %s", scan.id, exc)
                nuclei_findings = []
            for raw in nuclei_findings:
                session.add(Finding(scan_id=scan.id, source="nuclei", **raw))
                severities.append(raw["severity"])

            # (b) NVD enrichment — best-effort; lookup_cves never raises.
            for service, version in _nvd_pairs(raw_findings):
                for cve in await nvd.lookup_cves(service, version):
                    severity = nvd.severity_from_cvss(cve["cvss"])
                    session.add(
                        Finding(
                            scan_id=scan.id,
                            source="nvd",
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
