"""v0.3 defense — alerts, sensor events, ingest cursor

Revision ID: 0002_defense
Revises: 0001_initial
Create Date: 2026-09-21

Purely additive migration for the v0.3 "Défense" milestone (issues #1, #2, #5):

  * ``alerts``        — normalized defensive alerts (Suricata signatures, local
                        detection rules, and — from v0.4 — threat intel).
  * ``sensor_events`` — every ingested sensor event, kept raw so the detection
                        engine can reason over a time window.
  * ``ingest_state``  — byte-offset cursor making the EVE tailer idempotent.
"""

from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_defense"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ingest_state",
        sa.Column("key", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("offset", sa.Integer(), nullable=False),
        sa.Column("inode", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )

    op.create_table(
        "sensor_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("ingested_at", sa.DateTime(), nullable=False),
        sa.Column("event_type", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("src_ip", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_ip", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("proto", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("app_proto", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("signature", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("signature_severity", sa.Integer(), nullable=True),
        sa.Column("payload", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sensor_events_event_id", "sensor_events", ["event_id"], unique=True)
    op.create_index("ix_sensor_events_occurred_at", "sensor_events", ["occurred_at"], unique=False)
    op.create_index("ix_sensor_events_event_type", "sensor_events", ["event_type"], unique=False)
    op.create_index("ix_sensor_events_src_ip", "sensor_events", ["src_ip"], unique=False)
    op.create_index("ix_sensor_events_dst_ip", "sensor_events", ["dst_ip"], unique=False)

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("source", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("event_type", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("severity", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("src_ip", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_ip", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("proto", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("rule_name", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("occurrences", sa.Integer(), nullable=False),
        sa.Column("dedup_key", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("signature", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("detail", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=True),
        sa.Column("status", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledged_by", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["acknowledged_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"], unique=False)
    op.create_index("ix_alerts_source", "alerts", ["source"], unique=False)
    op.create_index("ix_alerts_event_type", "alerts", ["event_type"], unique=False)
    op.create_index("ix_alerts_severity", "alerts", ["severity"], unique=False)
    op.create_index("ix_alerts_src_ip", "alerts", ["src_ip"], unique=False)
    op.create_index("ix_alerts_dst_ip", "alerts", ["dst_ip"], unique=False)
    op.create_index("ix_alerts_rule_name", "alerts", ["rule_name"], unique=False)
    op.create_index("ix_alerts_dedup_key", "alerts", ["dedup_key"], unique=False)
    op.create_index("ix_alerts_status", "alerts", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_alerts_status", table_name="alerts")
    op.drop_index("ix_alerts_dedup_key", table_name="alerts")
    op.drop_index("ix_alerts_rule_name", table_name="alerts")
    op.drop_index("ix_alerts_dst_ip", table_name="alerts")
    op.drop_index("ix_alerts_src_ip", table_name="alerts")
    op.drop_index("ix_alerts_severity", table_name="alerts")
    op.drop_index("ix_alerts_event_type", table_name="alerts")
    op.drop_index("ix_alerts_source", table_name="alerts")
    op.drop_index("ix_alerts_created_at", table_name="alerts")
    op.drop_table("alerts")

    op.drop_index("ix_sensor_events_dst_ip", table_name="sensor_events")
    op.drop_index("ix_sensor_events_src_ip", table_name="sensor_events")
    op.drop_index("ix_sensor_events_event_type", table_name="sensor_events")
    op.drop_index("ix_sensor_events_occurred_at", table_name="sensor_events")
    op.drop_index("ix_sensor_events_event_id", table_name="sensor_events")
    op.drop_table("sensor_events")

    op.drop_table("ingest_state")
