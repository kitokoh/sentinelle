"""arq WorkerSettings — run with: arq app.worker.settings.WorkerSettings

Jobs, by milestone:

* v0.1/v0.2 — :func:`~app.worker.jobs.run_scan`, on demand from the API.
* v0.3 — :func:`~app.worker.jobs.ingest_eve` (every 15 s) and
  :func:`~app.worker.jobs.purge_expired_data` (daily, off-peak).
* v0.4 — the intel connectors and the correlator. Each is scheduled separately so
  a slow or unreachable source never delays the others; ``run_intel_sync`` exists
  for on-demand refreshes.
"""

from arq import cron
from arq.connections import RedisSettings

from app.core.config import get_settings
from app.worker.jobs import (
    correlate_intel,
    ingest_eve,
    purge_expired_data,
    run_intel_sync,
    run_scan,
    sync_cert,
    sync_misp,
    sync_otx,
)

redis_settings = RedisSettings.from_dsn(get_settings().REDIS_URL)


class WorkerSettings:
    functions = [
        run_scan,
        ingest_eve,
        purge_expired_data,
        sync_misp,
        sync_otx,
        sync_cert,
        correlate_intel,
        run_intel_sync,
    ]

    cron_jobs = [
        # Sensor ingestion: every 15 seconds.
        cron(ingest_eve, second={0, 15, 30, 45}, run_at_startup=True),
        # Retention purge: daily at 03:15 UTC (off-peak).
        cron(purge_expired_data, hour=3, minute=15),
        # Threat intel pull connectors: four times a day, staggered so two
        # sources never hit the same minute.
        cron(sync_misp, hour={0, 6, 12, 18}, minute=20),
        cron(sync_otx, hour={0, 6, 12, 18}, minute=35),
        # CERT advisories: hourly — they are cheap and time-sensitive.
        cron(sync_cert, minute=25),
        # Correlation: every 15 minutes, just after ingestion cycles.
        cron(correlate_intel, minute={5, 20, 35, 50}),
    ]

    redis_settings = redis_settings
