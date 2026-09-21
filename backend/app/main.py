"""Sentinelle API — FastAPI application entrypoint.

Sovereign security-audit & cyber-defense demo platform. Authorized targets
only: every target passes through the scope guardrail (app/services/scope.py)
before a scan can ever be queued.

v0.5 adds two cross-cutting concerns that are registered here rather than
sprinkled across routes:

* the **audit middleware** (#13) — one row per mutating request, written after
  the response, so no route can forget to log;
* the **RBAC dependencies** (#12) and **tenant scoping** (#15), applied per route
  in ``app/api/*`` through ``app.api.deps``.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api import alerts, audit, auth, dashboard, intel, oidc, scans, targets, users
from app.db import init_db
from app.services import audit as audit_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Bring the schema up to date by running the Alembic migrations (#4).
    await init_db()
    yield


app = FastAPI(
    title="Sentinelle API",
    description="Sovereign security-audit & cyber-defense demo platform (authorized targets only).",
    version="0.5.0",
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


@app.middleware("http")
async def audit_trail(request: Request, call_next):
    """Record every mutating API request in the audit trail (#13).

    Runs *after* the handler so the status code is known. ``record_request``
    never raises: a broken journal must not break the request it describes.
    """
    response = await call_next(request)
    await audit_service.record_request(request, response.status_code)
    return response


app.include_router(auth.router, prefix="/api")
app.include_router(oidc.router, prefix="/api")
app.include_router(targets.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(intel.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(audit.router, prefix="/api")


@app.get("/api/health", tags=["health"])
async def health() -> dict:
    """Liveness probe."""
    return {"status": "ok", "service": "sentinelle-api"}
