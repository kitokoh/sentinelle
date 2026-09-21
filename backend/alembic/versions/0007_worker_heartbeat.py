"""worker heartbeat — liveness proof for the queue consumer

Revision ID: 0007_worker_heartbeat
Revises: 0006_encrypt_fields
Create Date: 2026-09-21

One row per worker job family, refreshed on every cycle (issue #19). It exists so
that "the worker stopped consuming" is an observable fact rather than a silent
failure: the API keeps answering and the queue keeps filling in that scenario,
and nothing else in the schema would show it.
"""

from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007_worker_heartbeat"
down_revision: Union[str, None] = "0006_encrypt_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "worker_heartbeats",
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detail", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.PrimaryKeyConstraint("name"),
    )
    op.create_index(
        "ix_worker_heartbeats_last_seen_at", "worker_heartbeats", ["last_seen_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_worker_heartbeats_last_seen_at", table_name="worker_heartbeats")
    op.drop_table("worker_heartbeats")
