"""Alert model — a normalized defensive event surfaced in the SOC dashboard.

Three sources feed this table (v0.3):

  * ``suricata`` — a signature match straight out of the Suricata EVE stream.
  * ``rule``     — the local detection engine (see app/services/detection.py):
                   port scan, SSH brute force, beaconing.
  * ``intel``    — reserved for the v0.4 threat-intel correlation (#9).

An alert starts as ``new`` and can be acknowledged once (``ack``), which is
what the front-end counter and the ``PATCH /api/alerts/{id}`` route act upon.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel
from app.models.columns import utc_datetime_column

#: Lifecycle of an alert. Kept as plain strings so the column stays portable.
ALERT_STATUSES = ("new", "ack")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Alert(SQLModel, table=True):
    __tablename__ = "alerts"

    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=utcnow, sa_column=utc_datetime_column(index=True))

    #: suricata | rule | intel
    source: str = Field(default="suricata", index=True)
    #: Free-form classifier: ``signature`` for Suricata, the rule kind for the
    #: detection engine (port_scan | ssh_bruteforce | beaconing).
    event_type: str = Field(default="", index=True)
    severity: str = Field(default="info", index=True)  # info | low | medium | high | critical

    #: Network 4-tuple, when the alert can be attributed to one.
    src_ip: Optional[str] = Field(default=None, index=True)
    src_port: Optional[int] = None
    dst_ip: Optional[str] = Field(default=None, index=True)
    dst_port: Optional[int] = None
    proto: Optional[str] = None

    #: v0.3 — detection-engine enrichment (issue #2).
    rule_name: Optional[str] = Field(default=None, index=True)
    #: 0.0–1.0, how sure the engine is (threshold margin / interval regularity).
    confidence: Optional[float] = None
    #: How many raw events backed this alert; bumped instead of duplicating.
    occurrences: int = Field(default=1)
    #: Stable identity of the detection, used to avoid alert storms.
    dedup_key: Optional[str] = Field(default=None, index=True)

    signature: Optional[str] = None
    detail: str = Field(default="")
    #: Raw source event (JSON text) kept for forensics/investigation.
    payload: str = Field(default="", sa_column=Column(Text))

    status: str = Field(default="new", index=True)
    acknowledged_at: Optional[datetime] = Field(default=None, sa_column=utc_datetime_column(nullable=True))
    acknowledged_by: Optional[int] = Field(default=None, foreign_key="users.id")

    #: Tenant boundary (v0.5, #15). ``None`` means **platform-wide**: the sensor
    #: feed and threat-intel matches belong to the platform, not to one customer,
    #: so every organization sees them. A non-null value is a hard boundary —
    #: an alert scoped to an organization is invisible to any other.
    org_id: Optional[int] = Field(default=None, foreign_key="organizations.id", index=True)
