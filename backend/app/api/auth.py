"""Authentication routes: register, login, me."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.api.deps import get_current_user
from app.core.security import create_access_token, hash_password, verify_password
from app.db import get_session
from app.models import User

router = APIRouter(prefix="/auth", tags=["auth"])


class AuthPayload(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserRead(BaseModel):
    id: int
    email: str
    role: str
    created_at: datetime


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: AuthPayload, session: AsyncSession = Depends(get_session)) -> TokenResponse:
    """Create an analyst account and return an access token."""
    existing = await session.exec(select(User).where(User.email == payload.email))
    if existing.first() is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email already exists",
        )
    if not payload.password:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Password must not be empty")

    user = User(email=payload.email, hashed_password=hash_password(payload.password))
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return TokenResponse(access_token=create_access_token(str(user.id)))


@router.post("/login", response_model=TokenResponse)
async def login(payload: AuthPayload, session: AsyncSession = Depends(get_session)) -> TokenResponse:
    """Exchange email + password for a JWT access token."""
    result = await session.exec(select(User).where(User.email == payload.email))
    user = result.first()
    if user is None or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    return TokenResponse(access_token=create_access_token(str(user.id)))


@router.get("/me", response_model=UserRead)
async def me(current_user: User = Depends(get_current_user)) -> User:
    """Return the currently authenticated user."""
    return current_user
