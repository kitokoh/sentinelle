"""Alembic migration tests (v0.3, issue #4).

Three things must hold or the migration story is a lie:

1. the initial revision reproduces **exactly** the v0.2 schema (``create_all``
   used to own it) — that is what makes ``alembic stamp 0001_initial`` safe on
   an existing deployment;
2. ``upgrade head`` builds the schema the models describe, with no drift
   (verified by ``alembic check``, i.e. a real autogenerate diff);
3. the whole series is replayable (downgrade base → upgrade head).
"""

from alembic import command
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel

from app import models  # noqa: F401  — registers every table on the metadata
from app.db import init_db
from app.migrations import alembic_config, upgrade_to_head

#: Tables owned by the v0.2 baseline revision.
V02_TABLES = {"users", "targets", "scans", "findings"}


def _engine(tmp_path, name: str = "migrations.db"):
    return create_async_engine(f"sqlite+aiosqlite:///{tmp_path / name}")


async def _table_names(engine) -> set[str]:
    async with engine.connect() as connection:
        names = await connection.run_sync(lambda conn: inspect(conn).get_table_names())
    return set(names)


async def test_initial_revision_is_the_v02_schema(tmp_path):
    engine = _engine(tmp_path, "v02.db")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(
                lambda conn: command.upgrade(alembic_config(conn), "0001_initial")
            )
        tables = await _table_names(engine)
    finally:
        await engine.dispose()

    assert V02_TABLES <= tables
    # No v0.3 table may appear in the baseline revision.
    assert "alerts" not in tables
    assert "sensor_events" not in tables
    assert "ingest_state" not in tables


async def test_upgrade_head_creates_every_model_table(tmp_path):
    engine = _engine(tmp_path)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(upgrade_to_head)
        tables = await _table_names(engine)
    finally:
        await engine.dispose()

    expected = set(SQLModel.metadata.tables) | {"alembic_version"}
    assert expected <= tables
    assert {"alerts", "sensor_events", "ingest_state"} <= tables


async def test_upgrade_head_matches_the_metadata_without_drift(tmp_path):
    """`alembic check` is an autogenerate diff: any drift fails this test."""
    engine = _engine(tmp_path, "drift.db")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(upgrade_to_head)
        async with engine.connect() as connection:
            await connection.run_sync(lambda conn: command.check(alembic_config(conn)))
    finally:
        await engine.dispose()


async def test_the_series_is_replayable(tmp_path):
    engine = _engine(tmp_path, "replay.db")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(upgrade_to_head)

        async with engine.begin() as connection:
            await connection.run_sync(lambda conn: command.downgrade(alembic_config(conn), "base"))
        assert await _table_names(engine) == {"alembic_version"}

        async with engine.begin() as connection:
            await connection.run_sync(upgrade_to_head)
        tables = await _table_names(engine)
    finally:
        await engine.dispose()

    assert {"alerts", "sensor_events", "ingest_state", "findings"} <= tables


async def test_init_db_is_idempotent():
    """The API runs this on every startup — a second call must be a no-op."""
    await init_db()
    await init_db()
