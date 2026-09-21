"""OIDC / Keycloak tests (v0.5, issue #14).

The provider is mocked throughout: no Keycloak instance is needed to prove the
role mapping, the account provisioning and the guardrails. The flow's security
properties are checked too — a forged ``state`` is refused, and an SSO account
can never be authenticated through the local password route.
"""

import jwt
import pytest
from sqlmodel import select

from app.core.config import get_settings
from app.db import async_session
from app.models import User
from app.services import oidc


ISSUER = "https://keycloak.lab/realms/sentinelle"
AUTHORIZATION_ENDPOINT = f"{ISSUER}/protocol/openid-connect/auth"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"


def unsigned_token(claims: dict) -> str:
    """A JWT the flow will decode without verifying the signature (as designed)."""
    return jwt.encode(claims, "irrelevant-for-this-flow", algorithm="HS256")


@pytest.fixture
def sso_enabled(monkeypatch):
    """Configure SSO on the cached Settings singleton for one test."""
    settings = get_settings()
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", "sentinelle")
    monkeypatch.setattr(settings, "OIDC_CLIENT_SECRET", "not-a-real-secret")
    monkeypatch.setattr(
        settings, "OIDC_REDIRECT_URI", "http://localhost:8000/api/auth/oidc/callback"
    )
    monkeypatch.setattr(settings, "FRONTEND_URL", "http://localhost:5173")
    return settings


@pytest.fixture
def provider(monkeypatch):
    """Mock the provider's discovery and token endpoints."""

    async def fake_discovery(issuer: str) -> dict:
        assert issuer == ISSUER
        return {
            "authorization_endpoint": AUTHORIZATION_ENDPOINT,
            "token_endpoint": TOKEN_ENDPOINT,
        }

    monkeypatch.setattr(oidc, "discovery", fake_discovery)
    return monkeypatch


# --------------------------------------------------------------------------- #
# Configuration gating
# --------------------------------------------------------------------------- #


def test_sso_is_disabled_by_default():
    assert oidc.is_enabled() is False


def test_sso_requires_all_three_settings(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)
    assert oidc.is_enabled() is False  # client id and secret still missing

    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", "sentinelle")
    assert oidc.is_enabled() is False

    monkeypatch.setattr(settings, "OIDC_CLIENT_SECRET", "secret")
    assert oidc.is_enabled() is True


def test_config_requires_configuration_to_be_read():
    with pytest.raises(oidc.OidcNotConfigured):
        oidc.config()


# --------------------------------------------------------------------------- #
# Role mapping
# --------------------------------------------------------------------------- #


def test_realm_roles_map_onto_platform_roles(sso_enabled):
    cfg = oidc.config()

    assert oidc.map_role({"realm_access": {"roles": ["sentinelle-admin"]}}, cfg) == "admin"
    assert oidc.map_role({"realm_access": {"roles": ["sentinelle-analyst"]}}, cfg) == "analyst"
    # An identity with no recognisable role gets least privilege.
    assert oidc.map_role({"realm_access": {"roles": ["offline_access"]}}, cfg) == "viewer"
    assert oidc.map_role({}, cfg) == "viewer"


def test_the_highest_privilege_wins(sso_enabled):
    cfg = oidc.config()
    claims = {"realm_access": {"roles": ["sentinelle-analyst", "sentinelle-admin", "viewer"]}}
    assert oidc.map_role(claims, cfg) == "admin"


def test_role_mapping_is_case_insensitive_but_not_guesswork(sso_enabled):
    cfg = oidc.config()
    assert oidc.map_role({"realm_access": {"roles": ["Sentinelle-ADMIN"]}}, cfg) == "admin"
    assert oidc.map_role({"realm_access": {"roles": ["admin-ish"]}}, cfg) == "viewer"


def test_role_claim_path_is_configurable(sso_enabled, monkeypatch):
    monkeypatch.setattr(sso_enabled, "OIDC_ROLE_CLAIM", "resource_access.sentinelle.roles")
    cfg = oidc.config()

    claims = {"resource_access": {"sentinelle": {"roles": ["sentinelle-analyst"]}}}
    assert oidc.map_role(claims, cfg) == "analyst"


# --------------------------------------------------------------------------- #
# Identity extraction
# --------------------------------------------------------------------------- #


def test_identity_comes_from_the_tokens(sso_enabled):
    token = {
        "id_token": unsigned_token({"sub": "abc-123", "email": "Agent.Public@Gov.FR"}),
        "access_token": unsigned_token({"sub": "abc-123", "realm_access": {"roles": ["sentinelle-analyst"]}}),
    }

    identity = oidc.identity_from_tokens(token)

    assert identity.subject == "abc-123"
    assert identity.email == "agent.public@gov.fr"
    assert identity.role == "analyst"


def test_identity_falls_back_to_preferred_username(sso_enabled):
    token = {
        "id_token": unsigned_token({"sub": "abc-123", "preferred_username": "AgentPublic"}),
        "access_token": unsigned_token({"sub": "abc-123"}),
    }
    identity = oidc.identity_from_tokens(token)
    assert identity.email == "agentpublic"


def test_identity_without_a_subject_is_refused(sso_enabled):
    """Without a subject there is no stable account key — better to fail than to guess."""
    with pytest.raises(ValueError):
        oidc.identity_from_tokens({"access_token": unsigned_token({"email": "x@y.z"})})


def test_state_tokens_are_signed_and_short_lived():
    state = oidc.create_state()
    assert oidc.verify_state(state) is True
    assert oidc.verify_state("forged") is False
    assert oidc.verify_state("") is False
    assert oidc.verify_state(None) is False

    # A token signed with another secret must not be accepted.
    forged = jwt.encode({"sub": "sentinelle-oidc-state"}, "wrong-secret", algorithm="HS256")
    assert oidc.verify_state(forged) is False


def test_authorization_url_carries_every_required_parameter(sso_enabled):
    cfg = oidc.config()
    url = oidc.authorization_url(AUTHORIZATION_ENDPOINT, cfg, "state-value")

    assert url.startswith(AUTHORIZATION_ENDPOINT)
    assert "response_type=code" in url
    assert "client_id=sentinelle" in url
    assert "state=state-value" in url
    assert "scope=openid" in url
    assert "redirect_uri=" in url


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #


async def test_config_endpoint_reports_what_is_missing(client):
    response = client.get("/api/auth/oidc/config")

    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is False
    assert body["configured"] == {"issuer": False, "client_id": False, "client_secret": False}
    # The local login stays the reference path.
    assert body["local_login_available"] is True


async def test_login_is_unavailable_when_unconfigured(client):
    response = client.get("/api/auth/oidc/login", follow_redirects=False)

    assert response.status_code == 503
    assert "OIDC_ISSUER" in response.json()["detail"]


async def test_callback_is_unavailable_when_unconfigured(client):
    assert client.get("/api/auth/oidc/callback", follow_redirects=False).status_code == 503


async def test_login_redirects_to_the_provider(client, sso_enabled, provider):
    response = client.get("/api/auth/oidc/login", follow_redirects=False)

    assert response.status_code == 307
    location = response.headers["location"]
    assert location.startswith(AUTHORIZATION_ENDPOINT)
    assert "state=" in location


async def test_config_endpoint_reports_sso_when_enabled(client, sso_enabled):
    response = client.get("/api/auth/oidc/config")

    assert response.json()["enabled"] is True
    assert response.json()["login_url"] == "/api/auth/oidc/login"


async def test_a_forged_state_is_refused(client, sso_enabled, provider):
    response = client.get(
        "/api/auth/oidc/callback",
        params={"code": "whatever", "state": "forged-state"},
        follow_redirects=False,
    )

    assert response.status_code == 307
    assert "sso_error=invalid_state" in response.headers["location"]


async def test_a_provider_error_is_reported_back_to_the_front(client, sso_enabled, provider):
    response = client.get(
        "/api/auth/oidc/callback",
        params={"error": "access_denied", "state": oidc.create_state()},
        follow_redirects=False,
    )

    assert response.status_code == 307
    assert "sso_error=access_denied" in response.headers["location"]


async def test_a_successful_callback_provisions_the_account(client, sso_enabled, provider, monkeypatch):
    async def fake_exchange(code, token_endpoint, cfg):
        assert code == "auth-code"
        assert token_endpoint == TOKEN_ENDPOINT
        return {
            "id_token": unsigned_token({"sub": "kc-user-1", "email": "sso-agent@gov.fr"}),
            "access_token": unsigned_token(
                {"sub": "kc-user-1", "realm_access": {"roles": ["sentinelle-analyst"]}}
            ),
        }

    monkeypatch.setattr(oidc, "exchange_code", fake_exchange)

    response = client.get(
        "/api/auth/oidc/callback",
        params={"code": "auth-code", "state": oidc.create_state()},
        follow_redirects=False,
    )

    assert response.status_code == 307
    location = response.headers["location"]
    assert location.startswith("http://localhost:5173/auth/callback#token=")
    token = location.split("#token=", 1)[1]
    # The token travels in the fragment, so it never reaches a server log.
    assert "?" not in location

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200, me.text
    assert me.json()["email"] == "sso-agent@gov.fr"
    assert me.json()["role"] == "analyst"

    async with async_session() as session:
        stored = (
            await session.exec(select(User).where(User.email == "sso-agent@gov.fr"))
        ).one()
    assert stored.sso_subject == "kc-user-1"


async def test_an_sso_account_cannot_log_in_with_a_password(client, sso_enabled, provider, monkeypatch):
    """The provisioned hash is random: the only door is the identity provider."""

    async def fake_exchange(code, token_endpoint, cfg):
        return {
            "id_token": unsigned_token({"sub": "kc-user-2", "email": "no-password@gov.fr"}),
            "access_token": unsigned_token({"sub": "kc-user-2", "realm_access": {"roles": ["viewer"]}}),
        }

    monkeypatch.setattr(oidc, "exchange_code", fake_exchange)
    client.get(
        "/api/auth/oidc/callback",
        params={"code": "c", "state": oidc.create_state()},
        follow_redirects=False,
    )

    for guess in ("", "password", "no-password@gov.fr"):
        attempt = client.post(
            "/api/auth/login", json={"email": "no-password@gov.fr", "password": guess}
        )
        assert attempt.status_code == 401


async def test_logging_in_twice_reuses_the_account_and_refreshes_the_role(
    client, sso_enabled, provider, monkeypatch
):
    tokens = {"roles": ["sentinelle-analyst"]}

    async def fake_exchange(code, token_endpoint, cfg):
        return {
            "id_token": unsigned_token({"sub": "kc-user-3", "email": "twice@gov.fr"}),
            "access_token": unsigned_token({"sub": "kc-user-3", "realm_access": {"roles": tokens["roles"]}}),
        }

    monkeypatch.setattr(oidc, "exchange_code", fake_exchange)

    client.get(
        "/api/auth/oidc/callback",
        params={"code": "c1", "state": oidc.create_state()},
        follow_redirects=False,
    )

    # The provider promotes the account.
    tokens["roles"] = ["sentinelle-admin"]
    response = client.get(
        "/api/auth/oidc/callback",
        params={"code": "c2", "state": oidc.create_state()},
        follow_redirects=False,
    )

    token = response.headers["location"].split("#token=", 1)[1]
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["role"] == "admin"

    async with async_session() as session:
        rows = list((await session.exec(select(User).where(User.email == "twice@gov.fr"))).all())
    assert len(rows) == 1


async def test_an_exchange_failure_does_not_leak_provider_details(
    client, sso_enabled, provider, monkeypatch
):
    async def failing_exchange(code, token_endpoint, cfg):
        raise RuntimeError("connection refused to internal-idp.local:8443")

    monkeypatch.setattr(oidc, "exchange_code", failing_exchange)

    response = client.get(
        "/api/auth/oidc/callback",
        params={"code": "c", "state": oidc.create_state()},
        follow_redirects=False,
    )

    assert response.status_code == 307
    location = response.headers["location"]
    assert "sso_error=exchange_failed" in location
    assert "internal-idp" not in location
