"""Shared column definitions.

Why this module exists (and why it is not over-engineering):

The platform stores UTC instants as Python **aware** datetimes — every helper
produces ``datetime.now(timezone.utc)``, and incoming timestamps (Suricata,
MISP, OIDC) are normalised to UTC on the way in. Declaring the columns as plain
``DateTime()`` (i.e. ``timestamp without time zone``) works on SQLite, which
silently drops the offset, but **PostgreSQL rejects it outright** through
asyncpg::

    asyncpg.exceptions.DataError: invalid input for query argument $4:
    datetime.datetime(2026, 9, 21, 4, 0, 51, ...)
    (can't subtract offset-naive and offset-aware datetimes)

The failure is invisible in development because SQLite is permissive, and a test
suite that only ever runs on SQLite will never see it. Declaring
``DateTime(timezone=True)`` (``timestamp with time zone`` on PostgreSQL) makes
the column match what the code actually produces, on both backends.

Reads still need care: SQLite has no timezone support and returns naive values,
so comparisons with a freshly computed ``now`` must normalise — see
``app.services.detection._as_datetime`` and
``app.services.intel.store._naive_to_utc``.
"""

from sqlalchemy import Column, DateTime, Text
from sqlalchemy.types import TypeDecorator


def utc_datetime_column(*, nullable: bool = False, index: bool = False) -> Column:
    """A ``DateTime`` column that accepts aware UTC datetimes on every backend.

    Returns a fresh :class:`~sqlalchemy.Column` on each call — columns are
    stateful and must never be shared between models.

    Usage::

        created_at: datetime = Field(
            default_factory=utcnow,
            sa_column=utc_datetime_column(index=True),
        )
    """
    return Column(DateTime(timezone=True), nullable=nullable, index=index)


class EncryptedText(TypeDecorator):
    """A ``TEXT`` column whose content is encrypted at rest (v0.6, #18).

    Transparent by design: the model, the API and every caller keep reading and
    writing plain strings, while the row on disk holds Fernet ciphertext. That is
    what makes the change safe to introduce on an existing deployment — no call
    site had to change, and values written before the feature stay readable (see
    :func:`app.services.crypto.decrypt_text`).

    ``impl`` stays ``Text``: the column type is unchanged, only its content is.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: ANN001 - SQLAlchemy signature
        from app.services import crypto

        return crypto.encrypt_text(value)

    def process_result_value(self, value, dialect):  # noqa: ANN001 - SQLAlchemy signature
        from app.services import crypto

        return crypto.decrypt_text(value)
