"""Target CRUD, scoped to the current user *and* their organization.

Every create goes through the scope guardrail; every read is filtered on the
tenant (v0.5, #15). Creating and deleting are ``analyst`` operations (#12).
"""

from datetime import datetime
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.api.deps import analyst_required, get_current_org_id, viewer_required
from app.db import get_session
from app.models import Target, User
from app.services.scope import validate_target

router = APIRouter(prefix="/targets", tags=["targets"])


class TargetCreate(BaseModel):
    name: str
    value: str
    kind: Literal["ip", "hostname", "cidr"]
    authorization_reference: Optional[str] = None


class TargetRead(BaseModel):
    id: int
    name: str
    value: str
    kind: str
    scope_status: str
    authorization_reference: Optional[str]
    org_id: int
    created_at: datetime
    risk_score: float


@router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
async def create_target(
    payload: TargetCreate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(analyst_required),
    org_id: int = Depends(get_current_org_id),
) -> Target:
    """Register a target. Its scope_status is computed by the guardrail, never by the client."""
    try:
        scope_status = validate_target(payload.value, payload.kind, payload.authorization_reference)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    target = Target(
        name=payload.name,
        value=payload.value.strip(),
        kind=payload.kind,
        scope_status=scope_status,
        authorization_reference=(
            payload.authorization_reference.strip() if payload.authorization_reference else None
        ),
        owner_id=current_user.id,
        org_id=org_id,
    )
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target


@router.get("", response_model=list[TargetRead])
async def list_targets(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(viewer_required),
    org_id: int = Depends(get_current_org_id),
) -> list[Target]:
    """List the current user's targets."""
    result = await session.exec(
        select(Target)
        .where(Target.owner_id == current_user.id)
        .where(Target.org_id == org_id)
        .order_by(Target.created_at.desc())
    )
    return list(result.all())


async def _get_owned_target(target_id: int, session: AsyncSession, current_user: User, org_id: int) -> Target:
    """Another tenant's target is a 404, never a 403 — do not confirm it exists."""
    target = await session.get(Target, target_id)
    if target is None or target.owner_id != current_user.id or target.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    return target


@router.get("/{target_id}", response_model=TargetRead)
async def get_target(
    target_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(viewer_required),
    org_id: int = Depends(get_current_org_id),
) -> Target:
    """Fetch one owned target."""
    return await _get_owned_target(target_id, session, current_user, org_id)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(analyst_required),
    org_id: int = Depends(get_current_org_id),
) -> None:
    """Delete one owned target."""
    target = await _get_owned_target(target_id, session, current_user, org_id)
    await session.delete(target)
    await session.commit()
