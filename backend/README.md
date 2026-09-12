# Sentinelle — Backend

Sovereign security-audit & cyber-defense **demo** platform. Authorized targets
only: a scope guardrail decides what may ever be scanned (see below).

Stack: FastAPI + SQLModel + pydantic-settings, SQLite (aiosqlite) by default
(`DATABASE_URL` also accepts `postgresql+asyncpg://...`), JWT auth
(pyjwt + passlib/bcrypt), arq + Redis job queue, nmap as the scan engine.

## Run locally

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # optional, defaults work out of the box
uvicorn app.main:app --reload   # API on http://localhost:8000
```

- REST API lives under `/api` (health: `GET /api/health`)
- OpenAPI docs: http://localhost:8000/docs
- Seed a demo account + sample target:

```bash
python seed.py    # admin@sentinelle.local / Sentinelle2026!  (+ target 192.168.56.10)
```

## Run the tests

```bash
pytest -q        # uses a temporary SQLite DB, no Redis needed
```

## Run the worker

Scans are executed asynchronously by an arq worker (needs Redis and nmap):

```bash
redis-server &                     # or point REDIS_URL at an existing instance
arq app.worker.settings.WorkerSettings
```

Docker: `Dockerfile` builds the API image, `Dockerfile.worker` builds the
worker image (includes nmap).

## The scope guardrail (`app/services/scope.py`)

Every target is classified at creation time, and scans on `denied` targets are
refused with **403**:

- **Allowed**: RFC1918 / loopback / link-local IPs, CIDRs fully contained in
  those ranges, and hostnames ending in `.lab`, `.local`, `.test`, `.internal`,
  `.example`.
- **Denied**: anything public — *unless* a non-empty `authorization_reference`
  is supplied (e.g. an engagement-letter ID), which is then stored on the
  target for audit.
- The guardrail **never performs DNS resolution**; hostnames are checked by
  suffix only.

## Layout

```
app/
  main.py            FastAPI app, CORS (localhost:5173), routers, /api/health
  core/config.py     pydantic-settings (DATABASE_URL, REDIS_URL, JWT_*, ENV)
  core/security.py   bcrypt password hashing, JWT create/decode
  db.py              async engine, get_session dependency, init_db
  models/            User, Target, Scan, Finding (SQLModel tables)
  services/scope.py  THE GUARDRAIL — validate_target()
  services/scanner.py async nmap wrapper (XML stdout -> findings)
  api/               auth, targets, scans, dashboard routers + deps
  worker/            arq settings + run_scan job
seed.py              demo data
tests/               pytest suite (guardrail, auth, targets/scans)
```
