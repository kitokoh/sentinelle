"""Shared API dependencies — current-user resolution from a Bearer token."""

from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.security import decode_access_token
from app.db import get_session
from app.models import User

bearer_scheme = HTTPBearer(auto_error=False)

_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
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
