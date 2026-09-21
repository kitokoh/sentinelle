"""arq WorkerSettings — run with: arq app.worker.settings.WorkerSettings

Beyond the on-demand scan job (v0.1/v0.2), v0.3 adds two periodic jobs:

* :func:`~app.worker.jobs.ingest_eve` — tails the Suricata EVE stream every 15 s
  and feeds the detection engine (#1, #2). ``run_at_startup`` means a worker
  restart never waits a full cycle before it starts seeing traffic.
* :func:`~app.worker.jobs.purge_expired_data` — applies the retention policy
  once a day, off-peak (#5).
"""

from arq import cron
from arq.connections import RedisSettings

from app.core.config import get_settings
from app.worker.jobs import ingest_eve, purge_expired_data, run_scan

redis_settings = RedisSettings.from_dsn(get_settings().REDIS_URL)


class WorkerSettings:
    functions = [run_scan, ingest_eve, purge_expired_data]

    cron_jobs = [
        # Sensor ingestion: every 15 seconds.
        cron(ingest_eve, second={0, 15, 30, 45}, run_at_startup=True),
        # Retention purge: daily at 03:15 UTC (off-peak).
        cron(purge_expired_data, hour=3, minute=15),
    ]

    redis_settings = redis_settings
