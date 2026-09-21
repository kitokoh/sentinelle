"""SensorEvent — one normalized event ingested from a network sensor.

v0.3 keeps every Suricata EVE record (not only the alerts) so the detection
engine (#2) can reason over a window of raw activity — that is what makes
port-scan, brute-force and beaconing detection possible at all.

Rows are deduplicated on ``event_id`` (Suricata's ``flow_id`` + timestamp),
which makes the EVE tailer idempotent across restarts.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SensorEvent(SQLModel, table=True):
    __tablename__ = "sensor_events"

    id: Optional[int] = Field(default=None, primary_key=True)
    #: Stable identity in the source stream — enforces idempotent ingestion.
    event_id: str = Field(index=True, unique=True)
    #: When the sensor observed it (Suricata ``timestamp``).
    occurred_at: datetime = Field(index=True)
    ingested_at: datetime = Field(default_factory=utcnow)

    #: alert | flow | dns | http | tls | ssh | fileinfo | …
    event_type: str = Field(default="", index=True)
    src_ip: Optional[str] = Field(default=None, index=True)
    src_port: Optional[int] = None
    dst_ip: Optional[str] = Field(default=None, index=True)
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    app_proto: Optional[str] = None
    signature: Optional[str] = None
    #: Suricata severity 1..3 (1 = most severe); null for non-alert events.
    signature_severity: Optional[int] = None

    #: Raw EVE record (JSON text) — the evidence, never re-parsed downstream.
    payload: str = Field(default="", sa_column=Column(Text))
