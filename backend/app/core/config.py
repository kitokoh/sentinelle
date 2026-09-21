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

    # --- v0.3 "Défense" (#1, #2, #5) -------------------------------------
    #: Suricata EVE JSON stream tailed by the worker's ingest job.
    SURICATA_EVE_PATH: str = "/var/log/suricata/eve.json"
    #: Declarative detection rules. Empty -> the packaged rules/detection.yaml.
    DETECTION_RULES_PATH: Optional[str] = None
    #: Days of findings / alerts / sensor events kept before the purge job runs.
    #: <= 0 disables purging entirely (retention for ever — e.g. a lab demo).
    RETENTION_DAYS: int = 90
    #: How many sensor events the ingest job pulls back from the DB to evaluate
    #: detection rules over (a safety cap on the sliding window query).
    DETECTION_WINDOW_MAX_EVENTS: int = 5000

    # --- v0.4 "Renseignement" (#6–#9) -------------------------------------
    #: MISP instance used by the pull connector (#6). Unset -> job skipped.
    MISP_URL: Optional[str] = None
    MISP_API_KEY: Optional[str] = None
    MISP_LOOKBACK_DAYS: int = 30
    MISP_ATTRIBUTE_LIMIT: int = 500
    #: AlienVault OTX API key (#7). Unset -> job skipped. Never hard-coded.
    OTX_API_KEY: Optional[str] = None
    OTX_PULSE_LIMIT: int = 20
    #: CERT advisory feeds (#8), as "NAME=URL" entries separated by commas.
    CERT_FEEDS: str = "CERT-FR=https://www.cert.ssi.gouv.fr/feed/"
    CERT_ITEMS_PER_FEED: int = 50
    #: Bound on the indicators considered by one correlation run (#9).
    INTEL_IOC_LIMIT: int = 1000

    # --- v0.6 "Durcissement production" (#16–#20) -------------------------
    #: Fernet key encrypting sensitive fields at rest (#18). Generate with:
    #: ``python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"``
    #: Never committed. Unset -> derived from JWT_SECRET (development only).
    FIELD_ENCRYPTION_KEY: Optional[str] = None
    #: Bearer token protecting ``/metrics`` (#19). Unset -> the endpoint is open,
    #: which is only acceptable when it is not reachable from outside.
    METRICS_TOKEN: Optional[str] = None
    #: A worker is considered down when its heartbeat is older than this (#19).
    WORKER_STALE_SECONDS: int = 300
    #: Where the SPA is served from, for the SSO redirect (#14).

    # --- v0.5 "Rapports & gouvernance" (#12–#15) --------------------------
    #: OIDC / Keycloak single sign-on (#14). All three of the first settings are
    #: required to enable SSO; the rest fall back to sensible defaults.
    OIDC_ISSUER: Optional[str] = None
    OIDC_CLIENT_ID: Optional[str] = None
    OIDC_CLIENT_SECRET: Optional[str] = None
    OIDC_REDIRECT_URI: str = "http://localhost:8000/api/auth/oidc/callback"
    OIDC_SCOPES: str = "openid profile email"
    #: Claim holding the provider's roles (Keycloak: ``realm_access.roles``).
    OIDC_ROLE_CLAIM: str = "realm_access.roles"
    #: Provider roles mapped onto each platform role. Highest privilege wins.
    OIDC_ADMIN_ROLES: str = "sentinelle-admin,admin"
    OIDC_ANALYST_ROLES: str = "sentinelle-analyst,analyst"
    #: Role granted to an identity with no recognisable role (least privilege).
    OIDC_DEFAULT_ROLE: str = "viewer"
    #: Where the browser is sent back after login (the SPA).
    FRONTEND_URL: str = "http://localhost:5173"


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
