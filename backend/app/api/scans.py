"""Scan routes: enqueue nmap jobs (in-scope targets only), read results, export.

v0.5 additions:

* every query is scoped to the caller's **organization** (#15) on top of the
  existing per-owner scoping — closing either door alone is not enough;
* reads require the ``viewer`` role, launching a scan requires ``analyst`` (#12);
* ``GET /api/scans/{id}/report.pdf`` renders the client-facing report (#11).
"""

import csv
import io
from datetime import datetime
from typing import Literal, Optional

import arq
from arq.connections import RedisSettings
from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.api.deps import analyst_required, get_current_org_id, get_current_user, viewer_required
from app.core.config import get_settings
from app.db import get_session
from app.models import Finding, Scan, Target, User
from app.services import reports

router = APIRouter(prefix="/scans", tags=["scans"])


class ScanCreate(BaseModel):
    target_id: int
    profile: Literal["quick", "full"] = "quick"


class ScanRead(BaseModel):
    id: int
    target_id: int
    org_id: int
    profile: str
    status: str
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    error: Optional[str]
    risk_score: float


class ScanWithTarget(ScanRead):
    target_name: str
    target_value: str


class FindingRead(BaseModel):
    id: int
    port: int
    protocol: str
    service: str
    version: str
    severity: str
    detail: str
    source: str


class ScanDetail(ScanRead):
    target_name: str
    target_value: str
    findings: list[FindingRead]


async def _get_scoped_scan(scan_id: int, session: AsyncSession, user: User, org_id: int) -> tuple[Scan, Target]:
    """Load a scan the caller is allowed to see, or raise 404.

    A 404 (not a 403) for another organization's scan: the caller must not even
    learn that the identifier exists.
    """
    scan = await session.get(Scan, scan_id)
    if scan is None or scan.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    target = await session.get(Target, scan.target_id)
    if target is None or target.org_id != org_id or target.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan, target


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(analyst_required),
    org_id: int = Depends(get_current_org_id),
) -> Scan:
    """Create a scan and enqueue it on the arq worker.

    Hard guardrail: targets whose scope_status is "denied" are refused with 403.
    """
    target = await session.get(Target, payload.target_id)
    if target is None or target.owner_id != current_user.id or target.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    if target.scope_status == "denied":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Target is outside the authorized scope. Provide a valid "
                "authorization_reference on the target to scan public assets."
            ),
        )

    scan = Scan(
        target_id=target.id,
        profile=payload.profile,
        status="pending",
        org_id=target.org_id,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    redis = await arq.create_pool(RedisSettings.from_dsn(get_settings().REDIS_URL))
    try:
        await redis.enqueue_job("run_scan", scan.id)
    finally:
        await redis.close()

    return scan


@router.get("", response_model=list[ScanWithTarget])
async def list_scans(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(viewer_required),
    org_id: int = Depends(get_current_org_id),
) -> list[ScanWithTarget]:
    """List the current user's scans, newest first, with target info embedded."""
    result = await session.exec(
        select(Scan, Target)
        .join(Target, Scan.target_id == Target.id)
        .where(Target.owner_id == current_user.id)
        .where(Scan.org_id == org_id)
        .where(Target.org_id == org_id)
        .order_by(Scan.created_at.desc())
    )
    return [
        ScanWithTarget(
            **scan.model_dump(),
            target_name=target.name,
            target_value=target.value,
        )
        for scan, target in result.all()
    ]


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(viewer_required),
    org_id: int = Depends(get_current_org_id),
) -> ScanDetail:
    """Fetch one owned scan including its findings."""
    scan, target = await _get_scoped_scan(scan_id, session, current_user, org_id)

    result = await session.exec(
        select(Finding)
        .where(Finding.scan_id == scan.id)
        .where(Finding.org_id == org_id)
        .order_by(Finding.port)
    )
    return ScanDetail(
        **scan.model_dump(),
        target_name=target.name,
        target_value=target.value,
        findings=[FindingRead(**finding.model_dump()) for finding in result.all()],
    )


CSV_HEADER = ["source", "port", "protocol", "service", "version", "severity", "detail"]


@router.get("/{scan_id}/export")
async def export_scan_findings(
    scan_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(viewer_required),
    org_id: int = Depends(get_current_org_id),
) -> StreamingResponse:
    """Export one owned scan's findings as a CSV attachment (v0.2)."""
    scan, _ = await _get_scoped_scan(scan_id, session, current_user, org_id)

    result = await session.exec(
        select(Finding)
        .where(Finding.scan_id == scan.id)
        .where(Finding.org_id == org_id)
        .order_by(Finding.source, Finding.port, Finding.id)
    )

    # The csv module handles quoting of fields containing commas/quotes/newlines.
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_HEADER)
    for finding in result.all():
        writer.writerow(
            [
                finding.source,
                finding.port,
                finding.protocol,
                finding.service,
                finding.version,
                finding.severity,
                finding.detail,
            ]
        )

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_findings.csv"'},
    )


@router.get("/{scan_id}/report.pdf")
async def download_scan_report(
    scan_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(viewer_required),
    org_id: int = Depends(get_current_org_id),
) -> Response:
    """Render the audit report for one owned scan (v0.5, issue #11).

    The report carries the actor's email: an audit deliverable must say who
    produced it.
    """
    scan, target = await _get_scoped_scan(scan_id, session, current_user, org_id)

    findings = (
        await session.exec(
            select(Finding)
            .where(Finding.scan_id == scan.id)
            .where(Finding.org_id == org_id)
            .order_by(Finding.port, Finding.id)
        )
    ).all()

    payload = reports.build_scan_report(
        scan, target, list(findings), generated_by=current_user.email
    )
    return Response(
        content=payload,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="rapport_scan_{scan_id}.pdf"',
            # The report is generated from live data: never serve it from a cache.
            "Cache-Control": "no-store",
        },
    )
