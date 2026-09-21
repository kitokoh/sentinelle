"""IntelFeedItem — one watch item pulled from a CERT advisory feed.

v0.4 (#8). Feeds are merged into a single stream, deduplicated on the feed's own
GUID (falling back to the link) so re-polling an Atom/RSS document never
duplicates an advisory.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel
from app.models.columns import utc_datetime_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IntelFeedItem(SQLModel, table=True):
    __tablename__ = "intel_feed_items"

    id: Optional[int] = Field(default=None, primary_key=True)
    #: Feed GUID when provided, otherwise the link — the dedup key.
    guid: str = Field(index=True, unique=True)
    #: Human name of the feed, e.g. "CERT-FR".
    source: str = Field(index=True)
    title: str = Field(default="")
    link: str = Field(default="")
    summary: str = Field(default="", sa_column=Column(Text))
    published_at: datetime = Field(default_factory=utcnow, sa_column=utc_datetime_column(index=True))
    fetched_at: datetime = Field(default_factory=utcnow, sa_column=utc_datetime_column())
