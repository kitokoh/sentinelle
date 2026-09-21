"""Programmatic Alembic entry point.

``app.db.init_db()`` calls :func:`upgrade_to_head` with the *synchronous*
connection SQLAlchemy hands to ``run_sync``, so the API brings the schema up to
date on startup without shelling out (issue #4).

The CLI remains available for operators: ``cd backend && alembic upgrade head``.
"""

from pathlib import Path
from typing import Optional

from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Connection

BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
SCRIPT_LOCATION = BACKEND_DIR / "alembic"


def alembic_config(connection: Optional[Connection] = None) -> Config:
    """Build an Alembic config pointing at this backend's migration scripts.

    When ``connection`` is given it is handed to ``alembic/env.py`` through
    ``config.attributes``, which makes the environment reuse that connection
    instead of opening its own.
    """
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(SCRIPT_LOCATION))
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def upgrade_to_head(connection: Connection) -> None:
    """Apply every pending revision on an open synchronous connection."""
    command.upgrade(alembic_config(connection), "head")
