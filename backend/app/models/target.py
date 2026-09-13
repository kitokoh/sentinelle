"""Target model — an asset a user wants to audit (ip | hostname | cidr)."""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Target(SQLModel, table=True):
    __tablename__ = "targets"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    value: str
    kind: str  # ip | hostname | cidr
    scope_status: str = Field(default="denied")  # allowed | denied
    authorization_reference: Optional[str] = None
    owner_id: int = Field(foreign_key="users.id", index=True)
    created_at: datetime = Field(default_factory=utcnow)
    # v0.2 — risk score of the latest completed scan against this target.
    risk_score: float = Field(default=0.0)
