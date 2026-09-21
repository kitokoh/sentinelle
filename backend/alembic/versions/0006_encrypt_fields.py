"""Encrypt sensitive fields at rest

Revision ID: 0006_encrypt_fields
Revises: 0005_utc_timestamps
Create Date: 2026-09-21

Data migration for issue #18: existing rows of ``findings.detail`` and
``alerts.payload`` are encrypted in place. New writes are encrypted by the
``EncryptedText`` column type (see app/models/columns.py), so this revision only
has to deal with what was already stored.

Two properties make it safe to run on a live deployment:

* **idempotent** — an already-prefixed value is skipped, so a re-run (or a run
  after a partial failure) encrypts nothing twice;
* **reversible** — ``downgrade`` decrypts the rows it can, so a rollback does not
  leave unreadable data behind.

It reads the key from the application settings, exactly like the API does: the
migration and the running service must share the same key material
(``FIELD_ENCRYPTION_KEY``, or the ``JWT_SECRET`` fallback used in development).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006_encrypt_fields"
down_revision: Union[str, None] = "0005_utc_timestamps"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

#: Sensitive free-text columns, per issue #18.
ENCRYPTED_COLUMNS = (("findings", "detail"), ("alerts", "payload"))


def _rewrite(transform) -> None:
    """Apply ``transform`` to every non-empty value of the targeted columns."""
    bind = op.get_bind()
    for table, column in ENCRYPTED_COLUMNS:
        rows = bind.execute(
            sa.text(
                f"SELECT id, {column} FROM {table} "
                f"WHERE {column} IS NOT NULL AND {column} <> ''"
            )
        ).fetchall()
        for row_id, value in rows:
            updated = transform(value)
            if updated == value:
                continue
            bind.execute(
                sa.text(f"UPDATE {table} SET {column} = :value WHERE id = :row_id"),
                {"value": updated, "row_id": row_id},
            )


def upgrade() -> None:
    from app.services import crypto

    _rewrite(crypto.encrypt_text)


def downgrade() -> None:
    from app.services import crypto

    _rewrite(crypto.decrypt_text)
