"""Target model — an asset a user wants to audit (ip | hostname | cidr)."""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel

from app.models.user import DEFAULT_ORG_ID, utcnow
from app.models.columns import utc_datetime_column


class Target(SQLModel, table=True):
    __tablename__ = "targets"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    value: str
    kind: str  # ip | hostname | cidr
    scope_status: str = Field(default="denied")  # allowed | denied
    authorization_reference: Optional[str] = None
    owner_id: int = Field(foreign_key="users.id", index=True)
    #: Tenant boundary (v0.5, #15) — every read path filters on it.
    org_id: int = Field(default=DEFAULT_ORG_ID, foreign_key="organizations.id", index=True)
    created_at: datetime = Field(default_factory=utcnow, sa_column=utc_datetime_column())
    # v0.2 — risk score of the latest completed scan against this target.
    risk_score: float = Field(default=0.0)
