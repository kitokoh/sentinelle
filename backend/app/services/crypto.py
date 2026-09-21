"""Field-level encryption at rest (v0.6, issue #18).

Two fields carry the substance of what the platform knows and are the ones worth
protecting on disk: the free-text ``detail`` of a finding (which contains
banners, URLs, credentials sometimes) and the raw ``payload`` of an alert (the
whole EVE record). They are encrypted with **Fernet** (AES-128-CBC + HMAC), which
gives confidentiality *and* integrity, and is authenticated — a tampered value
fails to decrypt instead of silently returning garbage.

Three properties this module is built around:

* **Backwards compatible.** Ciphertext carries an explicit ``enc:v1:`` prefix, so
  a plaintext value written before this feature is still readable and simply gets
  encrypted on its next write. No flag day, no downtime.
* **Never crash the interface.** A value that cannot be decrypted (key rotated
  without re-encrypting) yields a visible placeholder and an ``error`` log, not a
  500. Losing the key must not make the platform unusable — and the placeholder
  leaks nothing.
* **Key from outside.** ``FIELD_ENCRYPTION_KEY`` is never committed. Without it,
  a deterministic key is derived from ``JWT_SECRET`` so development and tests work
  out of the box; that fallback is logged loudly and is **not** acceptable in
  production (rotating ``JWT_SECRET`` would make stored data unreadable).
"""

import base64
import hashlib
import logging
from functools import lru_cache
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings

logger = logging.getLogger(__name__)

#: Marks a ciphertext and versions the scheme, so a future algorithm can coexist.
PREFIX = "enc:v1:"

#: Returned instead of a value that cannot be decrypted. Deliberately not empty:
#: an analyst must see that something is there but unreadable.
UNDECRYPTABLE = "[chiffré — clé indisponible]"

_warned_about_fallback = False


def _derive_key(secret: str) -> bytes:
    """Derive a Fernet key from a secret (development fallback only)."""
    digest = hashlib.sha256(f"sentinelle-field-encryption:{secret}".encode()).digest()
    return base64.urlsafe_b64encode(digest)


@lru_cache(maxsize=4)
def _fernet_for(key: str) -> Fernet:
    return Fernet(key.encode() if isinstance(key, str) else key)


def key() -> str:
    """Resolve the encryption key, warning once when falling back."""
    global _warned_about_fallback
    settings = get_settings()
    explicit = settings.FIELD_ENCRYPTION_KEY
    if explicit:
        # Fail fast on a malformed key rather than at the first write.
        _fernet_for(explicit)
        return explicit

    if not _warned_about_fallback:
        logger.warning(
            "FIELD_ENCRYPTION_KEY is not set: deriving a key from JWT_SECRET. "
            "Fine for development, NOT for production — rotating JWT_SECRET would "
            "make encrypted data unreadable."
        )
        _warned_about_fallback = True
    return _derive_key(settings.JWT_SECRET).decode()


def fernet(field_key: Optional[str] = None) -> Fernet:
    """The Fernet instance for ``field_key`` (or the configured key)."""
    return _fernet_for(field_key or key())


def is_encrypted(value: Optional[str]) -> bool:
    """Does this stored value already carry the ciphertext prefix?"""
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt_text(plaintext: Optional[str], field_key: Optional[str] = None) -> Optional[str]:
    """Encrypt a value. Empty and already-encrypted values are returned unchanged."""
    if plaintext is None or plaintext == "":
        return plaintext
    if is_encrypted(plaintext):
        # Idempotent: re-encrypting a ciphertext would double-wrap it.
        return plaintext
    token = fernet(field_key).encrypt(plaintext.encode("utf-8")).decode("ascii")
    return f"{PREFIX}{token}"


def decrypt_text(stored: Optional[str], field_key: Optional[str] = None) -> Optional[str]:
    """Decrypt a value, or return it as-is when it was stored in plaintext.

    Never raises: an undecryptable value yields :data:`UNDECRYPTABLE` so a key
    problem degrades one field instead of breaking the whole page.
    """
    if stored is None or stored == "":
        return stored
    if not is_encrypted(stored):
        # Written before encryption was introduced — still readable, and it will
        # be encrypted the next time the row is written.
        return stored

    token = stored[len(PREFIX) :]
    try:
        return fernet(field_key).decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        logger.error(
            "field decryption failed: the value was encrypted with another key "
            "(FIELD_ENCRYPTION_KEY changed?) — returning a placeholder"
        )
        return UNDECRYPTABLE


def looks_encrypted_value(stored: Optional[str]) -> bool:
    """Alias kept explicit for tests and read-side checks."""
    return is_encrypted(stored)


#: Sensitive columns, per issue #18.
ENCRYPTED_COLUMNS = (("findings", "detail"), ("alerts", "payload"))


async def reencrypt_rows(
    session,
    old_key: str,
    new_key: str,
    *,
    dry_run: bool = False,
) -> dict[str, int]:
    """Re-encrypt every protected column from ``old_key`` to ``new_key``.

    Rotating ``FIELD_ENCRYPTION_KEY`` without this step silently makes the data
    unreadable — the exact footgun this function exists to remove. Rotating *in
    place* (read with the old key, write with the new one) is what keeps the
    operation possible without a maintenance window: a row is never left
    unreadable, even if the script is interrupted, because each row is rewritten
    in its own statement.

    Raw SQL is used on purpose: the ORM would transparently decrypt with the
    *configured* key, which is precisely what we are changing.

    Returns per-table counters, and changes nothing when ``dry_run`` is set.
    """
    from sqlalchemy import text

    counters = {"scanned": 0, "reencrypted": 0, "skipped": 0}

    for table, column in ENCRYPTED_COLUMNS:
        rows = (
            await session.execute(
                text(f"SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL AND {column} <> ''")
            )
        ).fetchall()
        for row_id, stored in rows:
            counters["scanned"] += 1
            if not is_encrypted(stored):
                # A legacy plaintext row: it must be encrypted with the *new* key.
                if not dry_run:
                    await session.execute(
                        text(f"UPDATE {table} SET {column} = :value WHERE id = :row_id"),
                        {"value": encrypt_text(stored, new_key), "row_id": row_id},
                    )
                counters["reencrypted"] += 1
                continue

            plaintext = decrypt_text(stored, old_key)
            if plaintext == UNDECRYPTABLE:
                # The old key does not open this row. Refuse rather than destroy.
                raise ValueError(
                    f"{table}.{column} id={row_id}: the old key does not decrypt this value. "
                    "Check FIELD_ENCRYPTION_KEY_OLD before rotating."
                )
            if not dry_run:
                await session.execute(
                    text(f"UPDATE {table} SET {column} = :value WHERE id = :row_id"),
                    {"value": encrypt_text(plaintext, new_key), "row_id": row_id},
                )
            counters["reencrypted"] += 1

    if not dry_run:
        await session.commit()
    return counters
