"""Pytest fixtures. Points the app at a temporary SQLite DB before importing it."""

import os
import tempfile

# Must be set BEFORE app modules are imported (engine is built at import time).
_TMPDIR = tempfile.mkdtemp(prefix="sentinelle-test-")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_TMPDIR}/test.db"
os.environ["JWT_SECRET"] = "test-secret-not-for-production"
os.environ["ENV"] = "test"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    """TestClient against the app with tables created in a temp SQLite DB."""
    with TestClient(app) as test_client:
        yield test_client


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
