"""Organization — the tenant boundary (v0.5, issue #15).

Every row that belongs to a customer carries an ``org_id`` pointing here, and
every read path filters on it. The row with ``id = 1`` is the **default
organization**, created by migration ``0004_governance`` and used for data that
predates multi-tenancy (and for anyone registering without an invitation).

Tenancy lives in the database *and* in the queries: a foreign key alone would
not prevent one tenant from reading another's scans.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


#: ``id`` of the organization every pre-existing row is backfilled into.
DEFAULT_ORG_ID = 1
DEFAULT_ORG_SLUG = "default"


class Organization(SQLModel, table=True):
    __tablename__ = "organizations"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    slug: str = Field(index=True, unique=True)
    created_at: datetime = Field(default_factory=utcnow)
