"""UTC columns get a timezone — ``timestamp with time zone`` where it exists

Revision ID: 0005_utc_timestamps
Revises: 0004_governance
Create Date: 2026-09-21

Fixes a latent production bug that only PostgreSQL could reveal.

The application produces **aware** UTC datetimes everywhere (``utcnow()``,
Suricata/MISP/OIDC timestamps normalised to UTC). The columns were declared
``DateTime()``, i.e. ``timestamp without time zone``. SQLite silently drops the
offset, so every test passed; PostgreSQL — via asyncpg — refuses the value
outright::

    asyncpg.exceptions.DataError: invalid input for query argument $4:
    datetime.datetime(2026, 9, 21, 4, 0, 51, ...)
    (can't subtract offset-naive and offset-aware datetimes)

The first place it surfaced was the default organization inserted by
``0004_governance``; the same failure awaited every insert and every time-bounded
query (alerts ``since``/``until``, the detection window, the retention cutoff,
the audit filters). The whole platform was unusable on PostgreSQL.

**SQLite is deliberately skipped.** It has no timezone-aware type at all: its
declared type is cosmetic, values are stored as text, and re-declaring the
columns would rebuild fourteen tables for no observable change. Reflecting the
schema back shows no difference either, so ``alembic check`` stays clean on both
backends. The change below is what makes PostgreSQL store a real
``timestamptz``.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005_utc_timestamps"
down_revision: Union[str, None] = "0004_governance"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

#: ``(table, column, nullable)`` for every UTC instant in the schema.
UTC_COLUMNS: tuple[tuple[str, str, bool], ...] = (
    ("users", "created_at", False),
    ("targets", "created_at", False),
    ("scans", "created_at", False),
    ("scans", "started_at", True),
    ("scans", "finished_at", True),
    ("alerts", "created_at", False),
    ("alerts", "acknowledged_at", True),
    ("sensor_events", "occurred_at", False),
    ("sensor_events", "ingested_at", False),
    ("ingest_state", "updated_at", False),
    ("iocs", "first_seen", False),
    ("iocs", "last_seen", False),
    ("iocs", "created_at", False),
    ("iocs", "updated_at", False),
    ("intel_feed_items", "published_at", False),
    ("intel_feed_items", "fetched_at", False),
    ("audit_logs", "created_at", False),
    # ``organizations.created_at`` is absent on purpose: 0004 creates it as
    # timestamptz directly, because it inserts a row into it in the same revision.
)


def upgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        # Nothing to do: SQLite has no timezone-aware type and stores text as-is.
        return

    for table, column, nullable in UTC_COLUMNS:
        op.alter_column(
            table,
            column,
            existing_type=sa.DateTime(),
            type_=sa.DateTime(timezone=True),
            existing_nullable=nullable,
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        return

    for table, column, nullable in UTC_COLUMNS:
        op.alter_column(
            table,
            column,
            existing_type=sa.DateTime(timezone=True),
            type_=sa.DateTime(),
            existing_nullable=nullable,
        )
