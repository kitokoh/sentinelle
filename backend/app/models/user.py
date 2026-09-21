"""User model."""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel
from app.models.columns import utc_datetime_column

#: Default organization new users land in (issue #15). See app.models.organization.
DEFAULT_ORG_ID = 1


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    #: viewer | analyst | admin — see app/core/roles.py. Unknown values are
    #: treated as the weakest role at authorisation time.
    role: str = Field(default="analyst")
    #: Tenant the user belongs to (v0.5, #15).
    org_id: int = Field(default=DEFAULT_ORG_ID, foreign_key="organizations.id", index=True)
    #: Set when the account was created through SSO (#14), for traceability.
    sso_subject: Optional[str] = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=utcnow, sa_column=utc_datetime_column())
