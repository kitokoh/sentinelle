"""Alembic environment — async-capable and sharing the app's SQLModel metadata.

Three ways it is driven (see issue #4):

  * CLI — ``alembic upgrade head`` builds its own async engine from app settings.
  * Programmatic — ``app.db.init_db()`` passes a live *synchronous* connection
    through ``config.attributes["connection"]`` so migrations run on the exact
    connection the API already owns.
  * Tests — same programmatic path, against a throwaway SQLite database.

The database URL always comes from ``app.core.config`` (env var / .env), never
from a hard-coded value, so the same revision serves SQLite and PostgreSQL.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config
from sqlmodel import SQLModel

from app import models  # noqa: F401  — registers every table on the metadata
from app.core.config import get_settings

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

#: Single source of truth for autogenerate / `alembic check`.
target_metadata = SQLModel.metadata


def get_url() -> str:
    """Database URL, resolved from application settings at runtime."""
    return get_settings().DATABASE_URL


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of running against a live database."""
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Run the migration series on an already-open (sync) connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # SQLite cannot ALTER most columns in place; batch mode rewrites the table.
        render_as_batch=connection.dialect.name == "sqlite",
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """CLI path: build a short-lived async engine from the configured URL."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()
    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """Online path: reuse a supplied connection, otherwise create one."""
    supplied = config.attributes.get("connection")
    if supplied is not None:
        do_run_migrations(supplied)
        return
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
