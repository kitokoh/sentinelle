"""Shared API dependencies — authentication, authorisation and tenant scope.

Three things are resolved here, and every route depends on at least one:

* :func:`get_current_user` — who is calling (Bearer JWT → ``User`` row).
* :func:`require_min_role` — is that role sufficient (v0.5, #12).
* :func:`get_current_org_id` — which tenant they belong to (v0.5, #15).

Authorisation is **fail closed**: an unknown role ranks as ``viewer``, so a bad
value in the database loses privileges rather than gaining them.
"""

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.roles import label as role_label
from app.core.roles import normalise, role_at_least
from app.core.security import decode_access_token
from app.db import get_session
from app.models import User
from app.models.user import DEFAULT_ORG_ID

bearer_scheme = HTTPBearer(auto_error=False)

_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Resolve the JWT in the Authorization: Bearer header to a User row."""
    if credentials is None:
        raise _CREDENTIALS_EXCEPTION
    try:
        payload = decode_access_token(credentials.credentials)
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise _CREDENTIALS_EXCEPTION from None

    user = await session.get(User, user_id)
    if user is None:
        raise _CREDENTIALS_EXCEPTION
    return user


def _insufficient_role(minimum: str, current: User) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            f"This action requires the '{minimum}' role or higher. "
            f"Your role is '{normalise(current.role)}' ({role_label(current.role)})."
        ),
    )


def require_min_role(minimum: str):
    """Build a dependency that only lets through ``minimum`` or stronger roles.

    Returned dependencies are module-level singletons below, so the closure is
    built once at import rather than on every request.
    """

    async def dependency(current_user: User = Depends(get_current_user)) -> User:
        if not role_at_least(current_user.role, minimum):
            raise _insufficient_role(minimum, current_user)
        return current_user

    dependency.__name__ = f"require_{minimum}_role"
    return dependency


#: Read-only access — any authenticated member of the organization.
viewer_required = require_min_role("viewer")
#: Anything that changes the platform: targets, scans, acknowledgements, syncs.
analyst_required = require_min_role("analyst")
#: User administration and the audit trail.
admin_required = require_min_role("admin")


async def get_current_org_id(current_user: User = Depends(get_current_user)) -> int:
    """Tenant of the caller, falling back to the default organization (#15)."""
    return current_user.org_id or DEFAULT_ORG_ID


async def get_current_org(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """The :class:`Organization` row of the caller (used by the admin views)."""
    from app.models import Organization

    org_id = current_user.org_id or DEFAULT_ORG_ID
    org = await session.get(Organization, org_id)
    if org is None:  # pragma: no cover - protected by the foreign key
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Your organization could not be resolved — contact an administrator.",
        )
    return org
