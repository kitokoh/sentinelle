"""Password hashing (bcrypt via passlib) and JWT helpers (pyjwt)."""

from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from app.core.config import get_settings

ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plaintext password."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check a plaintext password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(subject: str) -> str:
    """Create a signed JWT whose `sub` claim is the given subject (user id)."""
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {"sub": str(subject), "exp": expire}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT. Raises jwt.PyJWTError on any failure."""
    settings = get_settings()
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[ALGORITHM])
