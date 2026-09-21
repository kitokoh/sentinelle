"""SSO / OIDC routes (v0.5, issue #14).

Three public endpoints complete the Authorization Code flow:

``GET /api/auth/oidc/config``    is SSO available? (drives the login button)
``GET /api/auth/oidc/login``     redirect the browser to the provider
``GET /api/auth/oidc/callback``  exchange the code, map the role, issue our JWT

The local password login stays available throughout: SSO is an addition, never a
replacement, and losing the identity provider must not lock an administrator out
of their own platform.
"""

import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import get_settings
from app.core.security import create_access_token, hash_password
from app.db import get_session
from app.models import User
from app.models.user import DEFAULT_ORG_ID
from app.services import oidc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/oidc", tags=["auth"])


@router.get("/config")
async def oidc_config() -> dict:
    """Public: lets the login page decide whether to show the SSO button.

    Each enabled setting is reported individually so an operator can see *which*
    variable is missing without reading the logs.
    """
    settings = get_settings()
    present = {
        "issuer": bool(settings.OIDC_ISSUER),
        "client_id": bool(settings.OIDC_CLIENT_ID),
        "client_secret": bool(settings.OIDC_CLIENT_SECRET),
    }
    enabled = oidc.is_enabled()
    return {
        "enabled": enabled,
        "provider": oidc.config().provider_name if enabled else None,
        "issuer": settings.OIDC_ISSUER if enabled else None,
        "login_url": "/api/auth/oidc/login" if enabled else None,
        "configured": present,
        "local_login_available": True,
    }


@router.get("/login")
async def oidc_login() -> RedirectResponse:
    """Send the browser to the identity provider."""
    if not oidc.is_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "SSO is not configured on this instance. Set OIDC_ISSUER, OIDC_CLIENT_ID "
                "and OIDC_CLIENT_SECRET — or sign in with an e-mail and password."
            ),
        )

    cfg = oidc.config()
    try:
        document = await oidc.discovery(cfg.issuer)
    except Exception as exc:  # noqa: BLE001 — any discovery failure is a plain 502
        logger.warning("OIDC discovery failed for %s: %s", cfg.issuer, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "The identity provider could not be reached. Local sign-in remains available."
            ),
        ) from exc

    url = oidc.authorization_url(document["authorization_endpoint"], cfg, oidc.create_state())
    return RedirectResponse(url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


async def _upsert_user(session: AsyncSession, identity: oidc.OidcIdentity) -> User:
    """Find or create the account behind an SSO identity.

    Two decisions worth knowing:

    * **An SSO account never has a usable password.** A random secret is hashed
      and stored, so the local login route can never authenticate it — the only
      door is the provider.
    * **An existing local account with the same e-mail is linked**, not
      duplicated, and its role is refreshed from the provider. This assumes the
      provider verifies e-mail addresses, which is why it is documented.
    """
    user = (
        await session.exec(select(User).where(User.sso_subject == identity.subject))
    ).first()
    if user is None:
        user = (await session.exec(select(User).where(User.email == identity.email))).first()

    if user is None:
        user = User(
            email=identity.email,
            # Unusable by construction: nobody knows this string.
            hashed_password=hash_password(secrets.token_urlsafe(48)),
            role=identity.role,
            org_id=DEFAULT_ORG_ID,
            sso_subject=identity.subject,
        )
    else:
        user.sso_subject = identity.subject
        user.role = identity.role

    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@router.get("/callback")
async def oidc_callback(
    code: str | None = Query(None),
    state: str | None = Query(None),
    error: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """Complete the flow and hand a platform JWT back to the front-end."""
    if not oidc.is_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="SSO is not configured."
        )

    cfg = oidc.config()

    if error:
        # The provider refused (user cancelled, consent denied…).
        logger.info("OIDC provider returned an error: %s", error)
        return RedirectResponse(oidc.failure_redirect(cfg, error))

    if not code or not oidc.verify_state(state):
        return RedirectResponse(oidc.failure_redirect(cfg, "invalid_state"))

    try:
        document = await oidc.discovery(cfg.issuer)
        token = await oidc.exchange_code(code, document["token_endpoint"], cfg)
        identity = oidc.identity_from_tokens(token, cfg)
    except Exception as exc:  # noqa: BLE001 — never leak provider internals to the browser
        logger.warning("OIDC callback failed: %s", exc)
        return RedirectResponse(oidc.failure_redirect(cfg, "exchange_failed"))

    user = await _upsert_user(session, identity)
    access_token = create_access_token(str(user.id))
    logger.info("OIDC login: %s (role %s)", user.email, user.role)
    return RedirectResponse(oidc.success_redirect(cfg, access_token))
