"""IoC — one indicator of compromise, deduplicated across intel sources.

v0.4 (#6, #7). A given indicator is very often present in several feeds at once
(a MISP event and an AlienVault OTX pulse routinely overlap), so the row is keyed
on ``(type, value)`` and keeps *every* provenance in ``sources``. Re-ingesting an
indicator refreshes ``last_seen`` and merges the source list instead of creating
a duplicate — that is what "dédup avec MISP" means in practice.

``metadata_json`` keeps whatever the feed gave us (pulse name, TLP, tags,
country/latitude/longitude when available) so the map (#10) and the analyst view
have something to show without re-querying the source.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

#: Indicator families we normalise every feed into.
IOC_TYPES = ("ip", "domain", "url", "md5", "sha1", "sha256", "email")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Ioc(SQLModel, table=True):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_iocs_type_value"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    #: ip | domain | url | md5 | sha1 | sha256 | email
    type: str = Field(index=True)
    value: str = Field(index=True)
    #: Comma-separated, sorted: "misp,otx".
    sources: str = Field(default="")

    severity: str = Field(default="medium", index=True)  # info | low | medium | high | critical
    #: When the source first/last reported the indicator.
    first_seen: datetime = Field(default_factory=utcnow, index=True)
    last_seen: datetime = Field(default_factory=utcnow, index=True)

    #: Feed-specific payload (pulse name, tags, TLP, country, lat/lon…).
    metadata_json: str = Field(default="{}", sa_column=Column(Text))

    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
