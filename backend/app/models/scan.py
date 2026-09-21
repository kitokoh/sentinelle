"""Scan model — one nmap run against a target."""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel

from app.models.user import DEFAULT_ORG_ID, utcnow
from app.models.columns import utc_datetime_column


class Scan(SQLModel, table=True):
    __tablename__ = "scans"

    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="targets.id", index=True)
    #: Tenant boundary (v0.5, #15) — copied from the target at creation time.
    org_id: int = Field(default=DEFAULT_ORG_ID, foreign_key="organizations.id", index=True)
    profile: str = Field(default="quick")  # quick | full
    status: str = Field(default="pending")  # pending | running | done | failed | denied
    created_at: datetime = Field(default_factory=utcnow, sa_column=utc_datetime_column())
    started_at: Optional[datetime] = Field(default=None, sa_column=utc_datetime_column(nullable=True))
    finished_at: Optional[datetime] = Field(default=None, sa_column=utc_datetime_column(nullable=True))
    error: Optional[str] = None
    # v0.2 — aggregate severity score over all findings of this scan (0-100).
    risk_score: float = Field(default=0.0)
