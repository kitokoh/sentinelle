"""Rotation de FIELD_ENCRYPTION_KEY (v0.6, issue #17).

    cd backend
    FIELD_ENCRYPTION_KEY_OLD=<ancienne> FIELD_ENCRYPTION_KEY_NEW=<nouvelle> \\
        python scripts/rotate_field_key.py [--dry-run]

Pourquoi des variables d'environnement et non des arguments : un secret passé en
ligne de commande finit dans `ps` et dans l'historique du shell.

L'ordre compte. Le script **re-chiffre en place** (déchiffre avec l'ancienne clé,
écrit avec la nouvelle) : aucune fenêtre pendant laquelle les données sont
illisibles, et une interruption ne casse qu'à partir de la ligne en cours. Le
service peut rester en marche, mais redémarrez API et worker une fois la rotation
terminée pour qu'ils prennent la nouvelle clé en mémoire.
"""

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import get_settings  # noqa: E402
from app.db import build_engine  # noqa: E402
from app.services import crypto  # noqa: E402


async def main(dry_run: bool) -> int:
    old_key = os.environ.get("FIELD_ENCRYPTION_KEY_OLD", "").strip()
    new_key = os.environ.get("FIELD_ENCRYPTION_KEY_NEW", "").strip()
    if not old_key or not new_key:
        print(
            "FIELD_ENCRYPTION_KEY_OLD et FIELD_ENCRYPTION_KEY_NEW sont requis.\n"
            "  python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"",
            file=sys.stderr,
        )
        return 2
    if old_key == new_key:
        print("Les deux clés sont identiques : rien à faire.", file=sys.stderr)
        return 2

    engine = build_engine(get_settings().DATABASE_URL)
    try:
        from sqlalchemy.ext.asyncio import async_sessionmaker
        from sqlmodel.ext.asyncio.session import AsyncSession

        session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with session_factory() as session:
            counters = await crypto.reencrypt_rows(
                session, old_key, new_key, dry_run=dry_run
            )
    finally:
        await engine.dispose()

    verb = "à re-chiffrer (simulation)" if dry_run else "re-chiffrées"
    print(f"{counters['reencrypted']} valeur(s) {verb} sur {counters['scanned']} inspectée(s).")
    if not dry_run:
        print(
            "Rotation terminée. Définissez FIELD_ENCRYPTION_KEY sur la nouvelle clé, "
            "puis redémarrez l'API et le worker."
        )
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="compter les valeurs concernées sans rien modifier",
    )
    arguments = parser.parse_args()
    raise SystemExit(asyncio.run(main(arguments.dry_run)))
