"""arq worker jobs. Uses its own async engine/session, separate from the API's."""

from datetime import datetime, timezone

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import get_settings
from app.models import Finding, Scan, Target
from app.services import scanner

settings = get_settings()

connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

_engine = create_async_engine(settings.DATABASE_URL, echo=False, connect_args=connect_args)
_WorkerSession = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)


async def run_scan(ctx: dict, scan_id: int) -> str:
    """Execute one scan: nmap the target, replace its findings, update status."""
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
            for raw in raw_findings:
                session.add(Finding(scan_id=scan.id, **raw))
            scan.status = "done"
            scan.error = None
        except Exception as exc:  # noqa: BLE001 — any nmap/parsing failure marks the scan failed
            scan.status = "failed"
            scan.error = str(exc)[:2000]

        scan.finished_at = datetime.now(timezone.utc)
        session.add(scan)
        await session.commit()
        return scan.status
