"""User administration — the ``admin``-only surface (v0.5, issues #12, #15).

Deliberately small: list the members of your organization, and change a role.
Everything here is scoped to the caller's organization — an administrator of one
tenant can never even see, let alone modify, a member of another.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.api.deps import admin_required, get_current_org_id, viewer_required
from app.core.roles import ROLES, label as role_label, normalise
from app.db import get_session
from app.models import Organization, User
from app.services import audit

router = APIRouter(prefix="/users", tags=["users"])


class UserRead(BaseModel):
    id: int
    email: str
    role: str
    role_label: str
    org_id: int
    sso_subject: Optional[str]
    created_at: datetime


class RoleUpdate(BaseModel):
    role: str


class OrganizationRead(BaseModel):
    id: int
    name: str
    slug: str
    members: int


def _to_read(user: User) -> UserRead:
    return UserRead(
        id=user.id or 0,
        email=user.email,
        role=normalise(user.role),
        role_label=role_label(user.role),
        org_id=user.org_id,
        sso_subject=user.sso_subject,
        created_at=user.created_at,
    )


@router.get("", response_model=list[UserRead])
async def list_users(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(admin_required),
    org_id: int = Depends(get_current_org_id),
) -> list[UserRead]:
    """List the members of the caller's organization."""
    rows = await session.exec(
        select(User).where(User.org_id == org_id).order_by(User.created_at)
    )
    return [_to_read(user) for user in rows.all()]


@router.patch("/{user_id}/role", response_model=UserRead)
async def change_role(
    user_id: int,
    payload: RoleUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(admin_required),
    org_id: int = Depends(get_current_org_id),
) -> UserRead:
    """Change a member's role.

    Two guardrails, both about not locking a tenant out of its own account:

    * the role must exist — a typo would otherwise be stored and, at
      authorisation time, silently downgraded to ``viewer``;
    * an administrator cannot demote themselves, which is the classic way to end
      up with nobody able to administer the organization.
    """
    if payload.role not in ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown role '{payload.role}'. Expected one of: {', '.join(ROLES)}.",
        )

    user = await session.get(User, user_id)
    if user is None or user.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.id == current_user.id and payload.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot remove your own administrator role — ask another administrator.",
        )

    previous = normalise(user.role)
    user.role = payload.role
    session.add(user)
    await session.commit()
    await session.refresh(user)

    # The URL cannot express "analyst -> admin"; the journal should still say it.
    audit.attach_detail(request, f"role de {user.email} : {previous} -> {payload.role}")
    return _to_read(user)


@router.get("/organization", response_model=OrganizationRead)
async def read_organization(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(viewer_required),
    org_id: int = Depends(get_current_org_id),
) -> OrganizationRead:
    """Describe the caller's organization (shown in the interface header)."""
    organization = await session.get(Organization, org_id)
    if organization is None:  # pragma: no cover - protected by the foreign key
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Organization not found",
        )
    members = await session.exec(select(User).where(User.org_id == org_id))
    return OrganizationRead(
        id=organization.id or org_id,
        name=organization.name,
        slug=organization.slug,
        members=len(list(members.all())),
    )
