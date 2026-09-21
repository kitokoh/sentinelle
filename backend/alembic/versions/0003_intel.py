"""v0.4 intel — IoC store and CERT feed items

Revision ID: 0003_intel
Revises: 0002_defense
Create Date: 2026-09-21

Additive migration for the v0.4 "Renseignement" milestone (issues #6–#10):

  * ``iocs``             — indicators of compromise, unique on ``(type, value)``
                           so one indicator stays one row even when several
                           feeds report it (``sources`` keeps every provenance).
  * ``intel_feed_items`` — CERT advisories, deduplicated on the feed GUID.
"""

from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003_intel"
down_revision: Union[str, None] = "0002_defense"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "iocs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("type", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("value", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("sources", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("severity", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("type", "value", name="uq_iocs_type_value"),
    )
    op.create_index("ix_iocs_type", "iocs", ["type"], unique=False)
    op.create_index("ix_iocs_value", "iocs", ["value"], unique=False)
    op.create_index("ix_iocs_severity", "iocs", ["severity"], unique=False)
    op.create_index("ix_iocs_first_seen", "iocs", ["first_seen"], unique=False)
    op.create_index("ix_iocs_last_seen", "iocs", ["last_seen"], unique=False)

    op.create_table(
        "intel_feed_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("guid", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("source", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("title", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("link", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("published_at", sa.DateTime(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_intel_feed_items_guid", "intel_feed_items", ["guid"], unique=True)
    op.create_index(
        "ix_intel_feed_items_source", "intel_feed_items", ["source"], unique=False
    )
    op.create_index(
        "ix_intel_feed_items_published_at", "intel_feed_items", ["published_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_intel_feed_items_published_at", table_name="intel_feed_items")
    op.drop_index("ix_intel_feed_items_source", table_name="intel_feed_items")
    op.drop_index("ix_intel_feed_items_guid", table_name="intel_feed_items")
    op.drop_table("intel_feed_items")

    op.drop_index("ix_iocs_last_seen", table_name="iocs")
    op.drop_index("ix_iocs_first_seen", table_name="iocs")
    op.drop_index("ix_iocs_severity", table_name="iocs")
    op.drop_index("ix_iocs_value", table_name="iocs")
    op.drop_index("ix_iocs_type", table_name="iocs")
    op.drop_table("iocs")
