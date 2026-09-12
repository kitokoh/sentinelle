"""arq WorkerSettings — run with: arq app.worker.settings.WorkerSettings"""

from arq.connections import RedisSettings

from app.core.config import get_settings
from app.worker.jobs import run_scan

redis_settings = RedisSettings.from_dsn(get_settings().REDIS_URL)


class WorkerSettings:
    functions = [run_scan]
    redis_settings = redis_settings
