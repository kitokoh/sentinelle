"""Test helpers shared by the v0.5 suites (RBAC, audit, tenancy, reports).

Kept out of ``conftest.py`` so the original session fixtures stay untouched: a
test that needs a second organization or a specific role builds it explicitly,
which is also what makes the isolation tests readable.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import select

from app.core.security import create_access_token, hash_password
from app.db import async_session
from app.models import Organization, User

DEFAULT_PASSWORD = "SupportPass2026!"


async def create_organization(slug: str, name: Optional[str] = None) -> int:
    """Create a tenant and return its id."""
    async with async_session() as session:
        existing = (
            await session.exec(select(Organization).where(Organization.slug == slug))
        ).first()
        if existing is not None:
            return existing.id
        org = Organization(name=name or slug.title(), slug=slug)
        session.add(org)
        await session.commit()
        await session.refresh(org)
        return org.id


async def create_user(
    email: str,
    *,
    role: str = "analyst",
    org_id: int = 1,
    password: str = DEFAULT_PASSWORD,
) -> User:
    """Create (or fetch) a user with an explicit role and tenant."""
    async with async_session() as session:
        existing = (await session.exec(select(User).where(User.email == email))).first()
        if existing is not None:
            return existing
        user = User(
            email=email,
            hashed_password=hash_password(password),
            role=role,
            org_id=org_id,
            created_at=datetime.now(timezone.utc),
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


async def token_for(
    email: str,
    *,
    role: str = "analyst",
    org_id: int = 1,
    password: str = DEFAULT_PASSWORD,
) -> tuple[int, dict[str, str]]:
    """Create the user if needed and return ``(user_id, auth headers)``."""
    user = await create_user(email, role=role, org_id=org_id, password=password)
    return user.id, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def create_target(client, headers, value: str, name: str = "Support VM") -> int:
    response = client.post(
        "/api/targets", json={"name": name, "value": value, "kind": "ip"}, headers=headers
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]
