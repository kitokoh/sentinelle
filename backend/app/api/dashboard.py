"""Dashboard aggregate stats for the current user."""

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.api.deps import get_current_user
from app.db import get_session
from app.models import Finding, Scan, Target, User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

SEVERITIES = ("info", "low", "medium", "high", "critical")


@router.get("/stats")
async def get_stats(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return counts of targets/scans/findings, findings by severity, last 5 scans."""
    targets_count = (
        await session.exec(
            select(func.count()).select_from(Target).where(Target.owner_id == current_user.id)
        )
    ).one()

    scans_count = (
        await session.exec(
            select(func.count())
            .select_from(Scan)
            .join(Target, Scan.target_id == Target.id)
            .where(Target.owner_id == current_user.id)
        )
    ).one()

    findings_count = (
        await session.exec(
            select(func.count())
            .select_from(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .join(Target, Scan.target_id == Target.id)
            .where(Target.owner_id == current_user.id)
        )
    ).one()

    severity_rows = (
        await session.exec(
            select(Finding.severity, func.count())
            .select_from(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .join(Target, Scan.target_id == Target.id)
            .where(Target.owner_id == current_user.id)
            .group_by(Finding.severity)
        )
    ).all()
    findings_by_severity = {severity: 0 for severity in SEVERITIES}
    findings_by_severity.update({severity: count for severity, count in severity_rows})

    last_scans_rows = (
        await session.exec(
            select(Scan, Target)
            .join(Target, Scan.target_id == Target.id)
            .where(Target.owner_id == current_user.id)
            .order_by(Scan.created_at.desc())
            .limit(5)
        )
    ).all()
    last_scans = [
        {
            "id": scan.id,
            "target_id": scan.target_id,
            "target_name": target.name,
            "target_value": target.value,
            "profile": scan.profile,
            "status": scan.status,
            "created_at": scan.created_at,
            "finished_at": scan.finished_at,
        }
        for scan, target in last_scans_rows
    ]

    return {
        "targets_count": targets_count,
        "scans_count": scans_count,
        "findings_count": findings_count,
        "findings_by_severity": findings_by_severity,
        "last_scans": last_scans,
    }
