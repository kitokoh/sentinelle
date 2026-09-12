"""Scan model — one nmap run against a target."""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(SQLModel, table=True):
    __tablename__ = "scans"

    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="targets.id", index=True)
    profile: str = Field(default="quick")  # quick | full
    status: str = Field(default="pending")  # pending | running | done | failed | denied
    created_at: datetime = Field(default_factory=utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
