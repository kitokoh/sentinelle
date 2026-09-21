"""IngestState — tiny key/value cursor so file tailing survives restarts.

The Suricata tailer (#1) records the byte offset it has already consumed for a
given EVE file. Re-reading an EVE file therefore never duplicates rows, which
matters because Suricata truncates or rotates its log on restart.
"""

from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IngestState(SQLModel, table=True):
    __tablename__ = "ingest_state"

    #: Identifies the stream, e.g. ``suricata:eve:/var/log/suricata/eve.json``.
    key: str = Field(primary_key=True)
    #: Number of bytes already consumed from the source file.
    offset: int = Field(default=0)
    #: Inode of the consumed file — a change means rotation, so the offset resets.
    inode: int = Field(default=0)
    updated_at: datetime = Field(default_factory=utcnow)
