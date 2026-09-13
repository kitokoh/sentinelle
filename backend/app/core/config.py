"""Application configuration via pydantic-settings (env vars / .env file)."""

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings. Every value can be overridden with an environment variable."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Async SQLAlchemy URL. SQLite by default; postgresql+asyncpg also supported.
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinelle.db"
    # Redis instance used by arq (scan job queue).
    REDIS_URL: str = "redis://localhost:6379"
    # Secret used to sign JWT access tokens. MUST be overridden in production.
    JWT_SECRET: str = "change-me-in-production"
    JWT_EXPIRE_MINUTES: int = 60
    ENV: str = "dev"
    # v0.2 — optional NVD API key (raises rate limits; lookups work without it).
    NVD_API_KEY: Optional[str] = None


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
