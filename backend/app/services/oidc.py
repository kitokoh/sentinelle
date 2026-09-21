"""OIDC / Keycloak integration (v0.5, issue #14).

Authorization Code flow, driven by :mod:`authlib`, with three deliberate choices:

* **Stateless ``state``.** The CSRF token is a short-lived JWT signed with the
  platform's own secret rather than a server-side session. No session store to
  keep coherent across workers, and the check still holds.
* **Claims read from the token we just received over TLS.** The access token
  comes back from the IdP's token endpoint on a verified TLS connection, so its
  payload is decoded *without* re-verifying the signature — verifying it again
  would mean fetching and rotating the realm's JWKS for no security gain in this
  flow. Provider discovery, however, is fetched over HTTPS and cached.
* **Unconfigured means disabled, not broken.** With no issuer/client, the local
  password login stays the only door, and the SSO endpoint says so plainly.

Roles are mapped from a configurable claim (``realm_access.roles`` by default):
the highest privilege found wins, so a member of ``admin`` and ``viewer`` is an
administrator.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Optional
from urllib.parse import urlencode

import httpx
import jwt
from authlib.integrations.httpx_client import AsyncOAuth2Client

from app.core.config import get_settings

logger = logging.getLogger(__name__)

DISCOVERY_TIMEOUT = 10.0
TOKEN_TIMEOUT = 15.0
STATE_TTL_MINUTES = 10
STATE_SUBJECT = "sentinelle-oidc-state"


class OidcNotConfigured(RuntimeError):
    """Raised when an SSO endpoint is called while OIDC is not configured."""


@dataclass(frozen=True)
class OidcConfig:
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: str
    frontend_url: str
    role_claim: str
    admin_roles: tuple[str, ...]
    analyst_roles: tuple[str, ...]
    default_role: str

    @property
    def provider_name(self) -> str:
        """Human label shown on the login button."""
        return "Keycloak" if "keycloak" in self.issuer.lower() else "SSO"


def _split(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in (value or "").split(",") if part.strip())


def is_enabled() -> bool:
    """SSO is on only when an issuer, a client id and a secret are all present."""
    settings = get_settings()
    return bool(settings.OIDC_ISSUER and settings.OIDC_CLIENT_ID and settings.OIDC_CLIENT_SECRET)


def config() -> OidcConfig:
    """Current OIDC configuration. Raises when SSO is not configured."""
    settings = get_settings()
    if not is_enabled():
        raise OidcNotConfigured(
            "OIDC is not configured — set OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET."
        )
    return OidcConfig(
        issuer=settings.OIDC_ISSUER.rstrip("/"),
        client_id=settings.OIDC_CLIENT_ID,
        client_secret=settings.OIDC_CLIENT_SECRET,
        redirect_uri=settings.OIDC_REDIRECT_URI,
        scopes=settings.OIDC_SCOPES,
        frontend_url=settings.FRONTEND_URL.rstrip("/"),
        role_claim=settings.OIDC_ROLE_CLAIM,
        admin_roles=_split(settings.OIDC_ADMIN_ROLES) or ("admin",),
        analyst_roles=_split(settings.OIDC_ANALYST_ROLES) or ("analyst",),
        default_role=settings.OIDC_DEFAULT_ROLE or "viewer",
    )


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=4)
def _discovery_sync(issuer: str) -> dict:
    """Fetch and cache the provider's ``.well-known`` document.

    Synchronous on purpose: ``httpx`` is used directly and the result is cached
    for the process lifetime, so a login storm does not become a discovery storm.
    """
    url = f"{issuer}/.well-known/openid-configuration"
    with httpx.Client(timeout=DISCOVERY_TIMEOUT, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
        document = response.json()
    for required in ("authorization_endpoint", "token_endpoint"):
        if required not in document:
            raise OidcNotConfigured(f"Provider discovery at {url} is missing '{required}'.")
    return document


async def discovery(issuer: str) -> dict:
    """Async wrapper around the cached discovery document."""
    import asyncio

    return await asyncio.to_thread(_discovery_sync, issuer)


def clear_discovery_cache() -> None:
    """Drop the cached discovery document (used by the tests)."""
    _discovery_sync.cache_clear()


# --------------------------------------------------------------------------- #
# State (stateless CSRF token)
# --------------------------------------------------------------------------- #


def create_state() -> str:
    """A short-lived signed token used as the OAuth ``state`` parameter."""
    settings = get_settings()
    payload = {
        "sub": STATE_SUBJECT,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=STATE_TTL_MINUTES),
        "nonce": datetime.now(timezone.utc).timestamp(),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def verify_state(state: Optional[str]) -> bool:
    """Is this ``state`` one we issued, and still valid?"""
    if not state:
        return False
    settings = get_settings()
    try:
        payload = jwt.decode(state, settings.JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return False
    return payload.get("sub") == STATE_SUBJECT


def authorization_url(authorization_endpoint: str, cfg: OidcConfig, state: str) -> str:
    """Build the redirect the browser is sent to."""
    params = {
        "client_id": cfg.client_id,
        "response_type": "code",
        "scope": cfg.scopes,
        "redirect_uri": cfg.redirect_uri,
        "state": state,
    }
    separator = "&" if "?" in authorization_endpoint else "?"
    return f"{authorization_endpoint}{separator}{urlencode(params)}"


# --------------------------------------------------------------------------- #
# Token exchange & claims
# --------------------------------------------------------------------------- #


async def exchange_code(code: str, token_endpoint: str, cfg: OidcConfig) -> dict[str, Any]:
    """Exchange an authorization code for tokens, through authlib."""
    async with AsyncOAuth2Client(
        client_id=cfg.client_id,
        client_secret=cfg.client_secret,
        redirect_uri=cfg.redirect_uri,
        timeout=TOKEN_TIMEOUT,
    ) as oauth:
        token = await oauth.fetch_token(token_endpoint, code=code, grant_type="authorization_code")
    return dict(token)


def decode_token_payload(token: Optional[str]) -> dict[str, Any]:
    """Read a JWT's payload without re-verifying its signature.

    Safe in this flow: the token was just received from the provider's token
    endpoint over a verified TLS connection. Re-verifying would require managing
    the realm's JWKS for no additional guarantee here.
    """
    if not token:
        return {}
    try:
        return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    except jwt.PyJWTError:
        return {}


def _claim_value(claims: dict[str, Any], path: str) -> list[str]:
    """Read a possibly nested claim (``realm_access.roles``) as a list of strings."""
    current: Any = claims
    for part in path.split("."):
        if not isinstance(current, dict):
            return []
        current = current.get(part)
    if isinstance(current, str):
        return [current]
    if isinstance(current, (list, tuple)):
        return [str(item) for item in current]
    return []


def map_role(claims: dict[str, Any], cfg: Optional[OidcConfig] = None) -> str:
    """Map the provider's roles onto a Sentinelle role.

    Highest privilege wins. An identity with no recognisable role gets the
    ``default_role`` (``viewer`` by default) — least privilege for an unknown
    account is the only defensible default.
    """
    resolved = cfg or config()
    roles = {role.lower() for role in _claim_value(claims, resolved.role_claim)}
    if roles & {role.lower() for role in resolved.admin_roles}:
        return "admin"
    if roles & {role.lower() for role in resolved.analyst_roles}:
        return "analyst"
    return resolved.default_role


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class OidcIdentity:
    subject: str
    email: str
    role: str


def identity_from_tokens(token: dict[str, Any], cfg: Optional[OidcConfig] = None) -> OidcIdentity:
    """Derive ``(subject, email, role)`` from a token response.

    The id token is preferred for the identity (that is its purpose), the access
    token for the roles (that is where Keycloak puts them).
    """
    resolved = cfg or config()
    id_claims = decode_token_payload(token.get("id_token"))
    access_claims = decode_token_payload(token.get("access_token"))

    subject = str(id_claims.get("sub") or access_claims.get("sub") or "").strip()
    email = str(
        id_claims.get("email")
        or id_claims.get("preferred_username")
        or access_claims.get("email")
        or access_claims.get("preferred_username")
        or ""
    ).strip()

    if not subject:
        raise ValueError("The identity provider returned no subject — check the client's scopes.")
    if not email:
        # Without an e-mail there is no stable account key we can trust.
        email = f"{subject}@sso.invalid"

    role = map_role({**access_claims, **id_claims}, resolved)
    return OidcIdentity(subject=subject, email=email.lower(), role=role)


def success_redirect(cfg: OidcConfig, access_token: str) -> str:
    """Where the browser lands after a successful login.

    The token travels in the URL **fragment**: fragments are not sent to the
    server, so the token does not end up in the reverse proxy's access log.
    """
    return f"{cfg.frontend_url}/auth/callback#token={access_token}"


def failure_redirect(cfg: OidcConfig, reason: str) -> str:
    return f"{cfg.frontend_url}/login#sso_error={reason}"
