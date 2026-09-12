"""Scan routes: enqueue nmap jobs (only for in-scope targets) and read results."""

from datetime import datetime
from typing import Literal, Optional

import arq
from arq.connections import RedisSettings
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.db import get_session
from app.models import Finding, Scan, Target, User

router = APIRouter(prefix="/scans", tags=["scans"])


class ScanCreate(BaseModel):
    target_id: int
    profile: Literal["quick", "full"] = "quick"


class ScanRead(BaseModel):
    id: int
    target_id: int
    profile: str
    status: str
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    error: Optional[str]


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


class ScanDetail(ScanRead):
    target_name: str
    target_value: str
    findings: list[FindingRead]


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> Scan:
    """Create a scan and enqueue it on the arq worker.

    Hard guardrail: targets whose scope_status is "denied" are refused with 403.
    """
    target = await session.get(Target, payload.target_id)
    if target is None or target.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    if target.scope_status == "denied":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Target is outside the authorized scope. Provide a valid "
                "authorization_reference on the target to scan public assets."
            ),
        )

    scan = Scan(target_id=target.id, profile=payload.profile, status="pending")
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
    current_user: User = Depends(get_current_user),
) -> list[ScanWithTarget]:
    """List the current user's scans, newest first, with target info embedded."""
    result = await session.exec(
        select(Scan, Target)
        .join(Target, Scan.target_id == Target.id)
        .where(Target.owner_id == current_user.id)
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
    current_user: User = Depends(get_current_user),
) -> ScanDetail:
    """Fetch one owned scan including its findings."""
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    target = await session.get(Target, scan.target_id)
    if target is None or target.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    result = await session.exec(
        select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.port)
    )
    return ScanDetail(
        **scan.model_dump(),
        target_name=target.name,
        target_value=target.value,
        findings=[FindingRead(**finding.model_dump()) for finding in result.all()],
    )
