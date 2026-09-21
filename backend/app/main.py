"""Sentinelle API — FastAPI application entrypoint.

Sovereign security-audit & cyber-defense demo platform. Authorized targets
only: every target passes through the scope guardrail (app/services/scope.py)
before a scan can ever be queued.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import alerts, auth, dashboard, scans, targets
from app.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Bring the schema up to date by running the Alembic migrations (#4).
    await init_db()
    yield


app = FastAPI(
    title="Sentinelle API",
    description="Sovereign security-audit & cyber-defense demo platform (authorized targets only).",
    version="0.1.0",
    docs_url="/docs",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite dev frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(targets.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")


@app.get("/api/health", tags=["health"])
async def health() -> dict:
    """Liveness probe."""
    return {"status": "ok", "service": "sentinelle-api"}
