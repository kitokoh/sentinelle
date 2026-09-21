"""Pytest fixtures. Points the app at a temporary database before importing it."""

import os
import tempfile

from cryptography.fernet import Fernet

# Must be set BEFORE app modules are imported (the engine is built at import time).
#
# `setdefault`, not assignment: CI runs this same suite against PostgreSQL as
# well as SQLite. The bug that made that necessary — aware datetimes written to
# `timestamp without time zone` columns — was invisible for exactly one reason:
# only SQLite ever ran these tests. See app/models/columns.py.
_TMPDIR = tempfile.mkdtemp(prefix="sentinelle-test-")
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{_TMPDIR}/test.db")
os.environ["JWT_SECRET"] = "test-secret-not-for-production"
os.environ["ENV"] = "test"
# One encryption key for the whole session (#18). Rows written by one test must be
# readable by the next: a per-test key would make the shared database a jumble of
# mutually unreadable ciphertexts, and the key-rotation tests impossible.
os.environ.setdefault("FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    """TestClient against the app with tables created in a temp SQLite DB."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def _schema(client):
    """Guarantee the schema exists for every test.

    The migrations are applied by the API lifespan, which only runs once the
    ``client`` fixture is instantiated. Tests that talk to the database directly
    (without going through the API) would otherwise run against an empty file.
    Depending on ``client`` here makes the whole suite order-independent.
    """
    return client


@pytest.fixture(scope="session")
def auth_headers(client):
    """Register a throwaway user and return Authorization headers for it."""
    response = client.post(
        "/api/auth/register",
        json={"email": "fixture-user@sentinelle.dev", "password": "FixturePass2026!"},
    )
    assert response.status_code == 201, response.text
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
