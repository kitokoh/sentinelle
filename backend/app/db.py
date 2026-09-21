"""Async database engine, session dependency and table initialisation."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import get_settings

settings = get_settings()

connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_async_engine(settings.DATABASE_URL, echo=False, connect_args=connect_args)

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
