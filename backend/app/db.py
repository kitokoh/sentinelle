"""Async database engine, session dependency and table initialisation."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import get_settings

settings = get_settings()


def build_engine(url: str) -> AsyncEngine:
    """Create an async engine for ``url`` with the right pooling for the context.

    In the **test** environment the pool is disabled on purpose. The suite drives
    the API through ``TestClient`` — which runs the app in its own event loop —
    *and* talks to the database directly from pytest-asyncio's loop. A pooled
    connection belongs to the loop that opened it: aiosqlite tolerates being
    handed across loops, asyncpg does not and fails with
    ``got Future attached to a different loop``. One connection per checkout
    keeps every acquisition loop-local, so the same suite runs on SQLite and on
    PostgreSQL (see the CI matrix).

    Production keeps the default pool: a worker or an API process owns a single
    loop for its whole life.
    """
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    if settings.ENV == "test":
        return create_async_engine(url, echo=False, connect_args=connect_args, poolclass=NullPool)
    return create_async_engine(url, echo=False, connect_args=connect_args)


engine = build_engine(settings.DATABASE_URL)

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an async SQLModel session."""
    async with async_session() as session:
        yield session


async def init_db() -> None:
    """Bring the schema up to date by running Alembic migrations.

    Since v0.3 (#4) the schema is owned by Alembic rather than
    ``metadata.create_all``, so an upgrade is replayable everywhere. The
    migration series is executed on the very connection this engine owns.
    """
    from app import models  # noqa: F401  (registers tables on SQLModel.metadata)
    from app.migrations import upgrade_to_head

    async with engine.begin() as conn:
        await conn.run_sync(upgrade_to_head)
