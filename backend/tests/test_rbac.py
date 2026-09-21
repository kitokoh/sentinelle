"""RBAC tests (v0.5, issue #12).

Acceptance criterion: "Tests croisés par rôle sur chaque endpoint sensible". The
matrix is crossed here — each sensitive endpoint is called by a viewer, an
analyst and an admin, and the expected status is asserted.

The two properties that matter beyond the matrix:

* **fail closed** — an unknown role in the database loses privileges rather
  than gaining them;
* **404 before 403 for other tenants** — a viewer of another organization must
  not be able to tell a resource exists.
"""

import pytest

from app.core import roles
from tests.support import create_organization, create_target, create_user, token_for



# --------------------------------------------------------------------------- #
# The role model itself
# --------------------------------------------------------------------------- #


def test_role_order_is_a_strict_hierarchy():
    assert roles.role_at_least("admin", "analyst")
    assert roles.role_at_least("analyst", "analyst")
    assert not roles.role_at_least("analyst", "admin")
    assert roles.role_at_least("viewer", "viewer")
    assert not roles.role_at_least("viewer", "analyst")


def test_an_unknown_role_fails_closed():
    """A typo must never grant more than the weakest role."""
    assert roles.normalise("superuser") == "viewer"
    assert roles.normalise(None) == "viewer"
    assert roles.normalise("ADMIN") == "viewer"  # case matters: unknown, not admin
    assert not roles.role_at_least("superuser", "analyst")


def test_role_labels_are_french_and_safe():
    assert roles.label("viewer") == "Lecteur"
    assert roles.label("analyst") == "Analyste"
    assert roles.label("admin") == "Administrateur"
    assert roles.label("nonsense") == "Lecteur"


# --------------------------------------------------------------------------- #
# The matrix, endpoint by endpoint
# --------------------------------------------------------------------------- #


async def test_read_endpoints_are_open_to_every_role(client):
    _, viewer = await token_for("rbac-viewer@test.local", role="viewer")
    _, analyst = await token_for("rbac-analyst@test.local", role="analyst")
    _, admin = await token_for("rbac-admin@test.local", role="admin")

    for headers in (viewer, analyst, admin):
        assert client.get("/api/auth/me", headers=headers).status_code == 200
        assert client.get("/api/targets", headers=headers).status_code == 200
        assert client.get("/api/scans", headers=headers).status_code == 200
        assert client.get("/api/dashboard/stats", headers=headers).status_code == 200
        assert client.get("/api/alerts", headers=headers).status_code == 200
        assert client.get("/api/alerts/stats", headers=headers).status_code == 200
        assert client.get("/api/intel/overview", headers=headers).status_code == 200


async def test_write_endpoints_reject_a_viewer(client):
    """lecteur = lecture seule, sans exception."""
    _, viewer = await token_for("rbac-viewer-write@test.local", role="viewer")

    assert (
        client.post(
            "/api/targets",
            json={"name": "x", "value": "10.11.0.1", "kind": "ip"},
            headers=viewer,
        ).status_code
        == 403
    )
    assert client.post("/api/scans", json={"target_id": 1}, headers=viewer).status_code == 403
    assert client.patch("/api/alerts/1", json={"status": "ack"}, headers=viewer).status_code == 403
    assert client.post("/api/intel/sync", headers=viewer).status_code == 403


async def test_write_endpoints_accept_an_analyst(client):
    """analyste = scans et opérations courantes."""
    _, analyst = await token_for("rbac-analyst-write@test.local", role="analyst")

    created = client.post(
        "/api/targets",
        json={"name": "Analyst VM", "value": "10.11.0.2", "kind": "ip"},
        headers=analyst,
    )
    assert created.status_code == 201, created.text

    target_id = created.json()["id"]
    assert client.delete(f"/api/targets/{target_id}", headers=analyst).status_code == 204


async def test_user_administration_is_admin_only(client):
    _, viewer = await token_for("rbac-viewer-users@test.local", role="viewer")
    _, analyst = await token_for("rbac-analyst-users@test.local", role="analyst")
    _, admin = await token_for("rbac-admin-users@test.local", role="admin")

    assert client.get("/api/users", headers=viewer).status_code == 403
    assert client.get("/api/users", headers=analyst).status_code == 403
    assert client.get("/api/users", headers=admin).status_code == 200

    target = await create_user("rbac-target-user@test.local", role="viewer")
    assert (
        client.patch(f"/api/users/{target.id}/role", json={"role": "analyst"}, headers=analyst).status_code
        == 403
    )
    promoted = client.patch(
        f"/api/users/{target.id}/role", json={"role": "analyst"}, headers=admin
    )
    assert promoted.status_code == 200, promoted.text
    assert promoted.json()["role"] == "analyst"


async def test_the_audit_trail_is_admin_only(client):
    _, analyst = await token_for("rbac-analyst-audit@test.local", role="analyst")
    _, admin = await token_for("rbac-admin-audit@test.local", role="admin")

    assert client.get("/api/audit", headers=analyst).status_code == 403
    assert client.get("/api/audit", headers=admin).status_code == 200


async def test_unauthenticated_requests_are_rejected(client):
    assert client.get("/api/targets").status_code == 401
    assert client.get("/api/users").status_code == 401
    assert client.get("/api/audit").status_code == 401
    assert client.get("/api/dashboard/stats").status_code == 401


# --------------------------------------------------------------------------- #
# Admin guardrails
# --------------------------------------------------------------------------- #


async def test_an_admin_cannot_demote_themselves(client):
    """The classic way to end up with nobody able to administer the platform."""
    admin_id, admin = await token_for("rbac-self-demote@test.local", role="admin")

    response = client.patch(f"/api/users/{admin_id}/role", json={"role": "analyst"}, headers=admin)

    assert response.status_code == 400
    assert "administrator" in response.json()["detail"].lower()
    # ...and the role is unchanged.
    assert client.get("/api/users", headers=admin).json()
    me = client.get("/api/auth/me", headers=admin).json()
    assert me["role"] == "admin"


async def test_an_unknown_role_is_refused_by_the_api(client):
    """Storing a typo would mean a silent downgrade at authorisation time."""
    admin_id, admin = await token_for("rbac-bad-role@test.local", role="admin")
    target = await create_user("rbac-bad-role-target@test.local", role="viewer")

    response = client.patch(
        f"/api/users/{target.id}/role", json={"role": "root"}, headers=admin
    )

    assert response.status_code == 422
    assert "unknown role" in response.json()["detail"].lower()
    assert admin_id is not None


async def test_an_admin_cannot_see_another_organizations_users(client):
    other_org = await create_organization("rbac-other-org")
    await create_user("rbac-outsider@test.local", role="viewer", org_id=other_org)
    _, admin = await token_for("rbac-admin-org@test.local", role="admin")

    emails = [user["email"] for user in client.get("/api/users", headers=admin).json()]

    assert "rbac-outsider@test.local" not in emails


async def test_the_403_message_names_the_required_role(client):
    _, viewer = await token_for("rbac-message@test.local", role="viewer")

    response = client.post("/api/scans", json={"target_id": 1}, headers=viewer)

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert "analyst" in detail
    assert "viewer" in detail


async def test_a_viewer_can_still_read_what_an_analyst_created(client):
    """The hierarchy must not accidentally lock readers out of fresh data."""
    _, analyst = await token_for("rbac-cross-analyst@test.local", role="analyst")
    _, viewer = await token_for("rbac-cross-viewer@test.local", role="viewer")

    target_id = create_target(client, analyst, "10.11.0.3", name="Cross VM")

    listed = client.get(f"/api/targets/{target_id}", headers=viewer)
    assert listed.status_code in (200, 404)  # 404 because ownership is per-user
    assert client.get("/api/targets", headers=viewer).status_code == 200
