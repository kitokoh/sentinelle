"""Dashboard aggregate stats, scoped to the caller's organization (v0.5, #15)."""

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.api.deps import get_current_org_id, get_current_user, viewer_required
from app.db import get_session
from app.models import Alert, Finding, Scan, Target, User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

SEVERITIES = ("info", "low", "medium", "high", "critical")


@router.get("/stats")
async def get_stats(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(viewer_required),
    org_id: int = Depends(get_current_org_id),
) -> dict:
    """Return counts of targets/scans/findings/alerts, severities, and last 5 scans."""
    targets_count = (
        await session.exec(
            select(func.count())
            .select_from(Target)
            .where(Target.owner_id == current_user.id)
            .where(Target.org_id == org_id)
        )
    ).one()

    scans_count = (
        await session.exec(
            select(func.count())
            .select_from(Scan)
            .join(Target, Scan.target_id == Target.id)
            .where(Target.owner_id == current_user.id)
            .where(Scan.org_id == org_id)
        )
    ).one()

    findings_count = (
        await session.exec(
            select(func.count())
            .select_from(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .join(Target, Scan.target_id == Target.id)
            .where(Target.owner_id == current_user.id)
            .where(Finding.org_id == org_id)
        )
    ).one()

    severity_rows = (
        await session.exec(
            select(Finding.severity, func.count())
            .select_from(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .join(Target, Scan.target_id == Target.id)
            .where(Target.owner_id == current_user.id)
            .where(Finding.org_id == org_id)
            .group_by(Finding.severity)
        )
    ).all()
    findings_by_severity = {severity: 0 for severity in SEVERITIES}
    findings_by_severity.update({severity: count for severity, count in severity_rows})

    # Alerts: the organization's own, plus the platform-wide feed (org_id NULL).
    alerts_count = (
        await session.exec(
            select(func.count())
            .select_from(Alert)
            .where((Alert.org_id == org_id) | (Alert.org_id.is_(None)))
        )
    ).one()
    unacknowledged = (
        await session.exec(
            select(func.count())
            .select_from(Alert)
            .where((Alert.org_id == org_id) | (Alert.org_id.is_(None)))
            .where(Alert.status == "new")
        )
    ).one()

    last_scans_rows = (
        await session.exec(
            select(Scan, Target)
            .join(Target, Scan.target_id == Target.id)
            .where(Target.owner_id == current_user.id)
            .where(Scan.org_id == org_id)
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
            "risk_score": scan.risk_score,
        }
        for scan, target in last_scans_rows
    ]

    return {
        "targets_count": targets_count,
        "scans_count": scans_count,
        "findings_count": findings_count,
        "findings_by_severity": findings_by_severity,
        "alerts_count": alerts_count,
        "alerts_unacknowledged": unacknowledged,
        "last_scans": last_scans,
    }
