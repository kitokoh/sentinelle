"""Suricata EVE JSON handling: normalization + incremental file tailing.

Kept free of database and FastAPI imports so it can be unit-tested on plain
fixtures (``tests/test_suricata.py``) and reused by the worker job.

Two responsibilities:

* :func:`normalize_events` — turn raw EVE records into the flat shape stored in
  ``sensor_events`` (and used by the detection engine).
* :func:`read_new_lines` — read only what is new in an EVE file, surviving
  rotation and truncation. This is what makes ingestion idempotent: combined
  with the ``ingest_state`` cursor and the unique ``event_id`` column, a restart
  never duplicates an event.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

#: Suricata classifies signature severity 1..3; 1 is the most severe.
SEVERITY_BY_SIGNATURE_LEVEL = {1: "high", 2: "medium", 3: "low"}

DEFAULT_SEVERITY = "info"


@dataclass
class TailResult:
    """Outcome of one incremental read of an EVE file."""

    lines: list[str] = field(default_factory=list)
    offset: int = 0
    inode: int = 0
    rotated: bool = False
    missing: bool = False


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse Suricata's ISO-8601 timestamp (``2026-09-21T03:14:15.123456+0000``)."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    # Suricata writes +0000 (no colon) which fromisoformat accepts since 3.11
    # only — normalize it for the 3.10 baseline.
    if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
        text = f"{text[:-2]}:{text[-2:]}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def severity_from_signature_level(level: Any) -> str:
    """Map a Suricata signature severity level to our severity vocabulary."""
    try:
        return SEVERITY_BY_SIGNATURE_LEVEL.get(int(level), DEFAULT_SEVERITY)
    except (TypeError, ValueError):
        return DEFAULT_SEVERITY


def build_event_id(record: dict, occurred_at: datetime, event_type: str) -> str:
    """Stable identity of an EVE record.

    EVE has no primary key. ``flow_id`` identifies a flow but is shared by every
    record of that flow, so the timestamp, the event type and — for signature
    hits — the signature itself are folded in as well.
    """
    signature = ((record.get("alert") or {}).get("signature")) or ""
    parts = [
        str(record.get("flow_id") or "nofid"),
        occurred_at.isoformat(),
        event_type or "unknown",
        signature,
        str(record.get("src_port") or ""),
        str(record.get("dest_port") or ""),
    ]
    return "|".join(parts)


def normalize_event(record: dict) -> Optional[dict]:
    """Flatten one EVE record. Returns ``None`` when it cannot be dated."""
    if not isinstance(record, dict):
        return None
    occurred_at = parse_timestamp(record.get("timestamp"))
    if occurred_at is None:
        return None

    event_type = str(record.get("event_type") or "")
    alert = record.get("alert") or {}

    return {
        "event_id": build_event_id(record, occurred_at, event_type),
        "occurred_at": occurred_at,
        "event_type": event_type,
        "src_ip": record.get("src_ip"),
        "src_port": record.get("src_port"),
        "dst_ip": record.get("dest_ip"),
        "dst_port": record.get("dest_port"),
        "proto": record.get("proto"),
        "app_proto": record.get("app_proto"),
        "signature": alert.get("signature"),
        "signature_severity": alert.get("severity"),
        # Raw record kept verbatim — the evidence an analyst will ask for.
        "payload": json.dumps(record, ensure_ascii=False, sort_keys=True),
    }


def normalize_events(lines: Sequence[str]) -> list[dict]:
    """Normalize raw EVE JSON lines, skipping blanks and malformed records.

    Two byte-identical records inside the same batch (which Suricata can emit)
    would collide on the unique ``event_id``; a ``#n`` suffix disambiguates them
    within the batch without affecting idempotency across restarts.
    """
    events: list[dict] = []
    seen: dict[str, int] = {}
    for line in lines:
        text = line.strip()
        if not text:
            continue
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            continue
        normalized = normalize_event(record)
        if normalized is None:
            continue
        key = normalized["event_id"]
        if key in seen:
            seen[key] += 1
            normalized["event_id"] = f"{key}#{seen[key]}"
        else:
            seen[key] = 0
        events.append(normalized)
    return events


def read_new_lines(path: str | os.PathLike, offset: int = 0, inode: int = 0) -> TailResult:
    """Read the bytes added to ``path`` since ``offset``.

    Handles the two ways a log file betrays a tailer:

    * **rotation** — a different inode means the file was replaced, so reading
      resumes from the beginning of the new file;
    * **truncation** — a size smaller than the stored offset means the file was
      emptied, so the offset resets to 0.

    Only complete lines are consumed: a half-written JSON object stays in the
    file and is picked up on the next cycle.
    """
    try:
        stat = os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return TailResult(offset=offset, inode=inode, missing=True)

    current_inode = stat.st_ino
    rotated = inode not in (0, current_inode)
    start = 0 if (rotated or stat.st_size < offset) else offset

    try:
        with open(path, "rb") as handle:
            handle.seek(start)
            chunk = handle.read()
    except (FileNotFoundError, NotADirectoryError):
        return TailResult(offset=offset, inode=inode, missing=True)

    if not chunk:
        return TailResult(offset=start, inode=current_inode, rotated=rotated)

    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        # Nothing complete yet — do not consume the partial record.
        return TailResult(offset=start, inode=current_inode, rotated=rotated)

    complete = chunk[: last_newline + 1]
    consumed = start + len(complete)
    lines = complete.decode("utf-8", errors="replace").splitlines()
    return TailResult(lines=lines, offset=consumed, inode=current_inode, rotated=rotated)
