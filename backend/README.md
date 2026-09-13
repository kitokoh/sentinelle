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
worker image (includes nmap and nuclei).

## v0.2 — audit de vulnérabilités

On top of the nmap port scan, the worker now enriches every scan with:

- **nuclei** template findings (`source: "nuclei"`) — severity-filtered by
  profile (`quick`: critical+high, `full`: all severities).
- **NVD CVE enrichment** (`source: "nvd"`) — up to 5 distinct
  `(service, version)` pairs from the nmap findings are looked up against the
  NVD API 2.0 (top 3 CVEs each, cached in-process).
- **Risk scoring** — `scan.risk_score` (0-100: critical 15, high 8, medium 3,
  low 1, info 0, capped at 100) is computed over all findings and mirrored
  onto `target.risk_score`.
- **CSV export** — `GET /api/scans/{id}/export` downloads
  `scan_<id>_findings.csv` (owner-only, auth required).

Local-dev notes:

- **nuclei is optional locally.** If the `nuclei` binary is not on `PATH`, the
  step is skipped and scans still succeed (the worker logs
  "nuclei not installed"). The Docker worker image ships nuclei v3.3.7 pinned,
  with templates pre-fetched at build time.
- **`NVD_API_KEY` is optional.** Without it, NVD lookups run anonymously
  (lower rate limits). Any NVD failure (network, rate limit, parse) is
  silently ignored — NVD can never break a scan.
- **DB reset after pulling v0.2.** The dev DB is created via `create_all`
  (no Alembic yet), so the new columns require a fresh database:

  ```bash
  rm -f sentinelle.db
  ```

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
  services/scanner.py async nmap + nuclei wrappers (XML/JSONL stdout -> findings)
  services/nvd.py    NVD API 2.0 client (best-effort CVE lookup, cached)
  services/risk.py   severity weights -> 0-100 risk score
  api/               auth, targets, scans (incl. CSV export), dashboard routers + deps
  worker/            arq settings + run_scan job (nmap, nuclei, NVD, scoring)
seed.py              demo data
tests/               pytest suite (guardrail, auth, targets, nvd, nuclei, risk, export, worker)
```
