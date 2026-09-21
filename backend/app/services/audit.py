"""Audit trail service (v0.5, issue #13).

Responsibilities, in order of importance:

1. :func:`classify` turns a request into a stable ``(action, entity, entity_id)``
   triple so the journal is queryable and not just a list of URLs.
2. :func:`record_request` writes one row per mutating request. It is called by
   the middleware, never by a route.
3. Both are **failure-tolerant**: an audit write that fails must not fail the
   request it describes... but it must also be *loud*. A silently broken audit
   trail is worse than a noisy one, so failures are logged at ``error``.

The actor is resolved by decoding the bearer token without raising: an
unauthenticated request (a failed login, typically) is still worth recording,
with a null actor.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import Request
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.security import decode_access_token
from app.db import async_session
from app.models import AuditLog, User

logger = logging.getLogger(__name__)

#: Methods that change something. GET/HEAD/OPTIONS are reads and are not audited.
AUDITED_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_VERBS = {"POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete"}

#: Sub-resources that name an *action* rather than a noun. ``POST /api/auth/login``
#: reads as ``auth.login``, not ``auth.create.login`` — the journal is read by
#: humans, and an operator filters on ``auth.*`` to find login attempts.
_ACTION_SUBRESOURCES = frozenset(
    {"login", "logout", "register", "refresh", "revoke", "sync", "run", "trigger", "ack"}
)


def classify(method: str, path: str) -> tuple[str, Optional[str], Optional[int]]:
    """Derive ``(action, entity, entity_id)`` from a request.

    ``/api/alerts/42``        -> ``("alerts.update", "alerts", 42)``
    ``/api/users/3/role``     -> ``("users.update.role", "users", 3)``
    ``/api/auth/login``       -> ``("auth.login", "auth", None)``

    A creation carries no identifier: the new id is not in the URL, so
    ``entity_id`` stays ``None`` for ``*.create`` rows. A route that needs it can
    attach one through :func:`attach_detail`.
    """
    parts = [part for part in path.split("/") if part]
    if parts and parts[0] == "api":
        parts = parts[1:]

    entity = parts[0] if parts else "root"
    entity_id: Optional[int] = None
    sub: Optional[str] = None

    if len(parts) > 1:
        if parts[1].isdigit():
            entity_id = int(parts[1])
            if len(parts) > 2:
                sub = ".".join(parts[2:])
        else:
            sub = ".".join(parts[1:])

    verb = _VERBS.get(method, method.lower())
    if sub and sub.split(".")[0] in _ACTION_SUBRESOURCES:
        action = f"{entity}.{sub}"
    else:
        action = f"{entity}.{verb}" + (f".{sub}" if sub else "")
    return action, entity, entity_id


def _client_ip(request: Request) -> Optional[str]:
    """Source IP, honouring a reverse proxy's forwarding header."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip() or None
    return request.client.host if request.client else None


async def _resolve_actor(session: AsyncSession, request: Request) -> tuple[Optional[int], Optional[str], Optional[int]]:
    """Best-effort ``(actor_id, actor_email, org_id)`` from the bearer token."""
    header = request.headers.get("authorization") or ""
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None, None, None
    try:
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        return None, None, None

    user = await session.get(User, user_id)
    if user is None:
        return user_id, None, None
    return user.id, user.email, getattr(user, "org_id", None)


async def record_request(request: Request, status_code: int) -> Optional[AuditLog]:
    """Persist one audit row for a mutating request. Never raises."""
    if request.method not in AUDITED_METHODS:
        return None

    path = request.url.path
    if not path.startswith("/api") or path == "/api/health":
        return None

    action, entity, entity_id = classify(request.method, path)
    detail = getattr(request.state, "audit_detail", "") or ""

    try:
        async with async_session() as session:
            actor_id, actor_email, org_id = await _resolve_actor(session, request)
            row = AuditLog(
                actor_id=actor_id,
                actor_email=actor_email,
                org_id=org_id,
                action=action,
                method=request.method,
                path=path,
                status_code=status_code,
                entity=entity,
                entity_id=entity_id,
                ip=_client_ip(request),
                user_agent=(request.headers.get("user-agent") or "")[:300] or None,
                detail=detail,
                created_at=datetime.now(timezone.utc),
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row
    except Exception:  # noqa: BLE001 — the request must not fail because of the journal
        logger.exception("audit: could not record %s %s", request.method, path)
        return None


def attach_detail(request: Request, detail: str) -> None:
    """Let a route enrich the row the middleware is about to write.

    Used when the *meaning* of a change matters (``role: analyst -> admin``) and
    the URL alone cannot express it. Falls back to a no-op if the request state
    is unavailable.
    """
    try:
        request.state.audit_detail = detail
    except AttributeError:  # pragma: no cover - defensive
        pass
