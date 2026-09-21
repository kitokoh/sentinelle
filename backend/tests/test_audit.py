"""Audit trail tests (v0.5, issue #13).

Acceptance criterion: "une mutation = une ligne de journal". The four properties
pinned here are what make the trail usable — and what makes it safe:

* a mutation writes exactly one row, a read writes none;
* the actor, the status and the source IP are captured;
* a **failed** login is recorded (that is the event an investigator looks for);
* **no request body is ever stored** — passwords must not leak into the journal.
"""

import pytest
from sqlmodel import select

from app.db import async_session
from app.models import AuditLog
from tests.support import create_target, token_for



async def _rows(action: str, actor: str | None = None) -> list[AuditLog]:
    async with async_session() as session:
        query = select(AuditLog).where(AuditLog.action == action)
        if actor:
            query = query.where(AuditLog.actor_email == actor)
        rows = await session.exec(query.order_by(AuditLog.id))
        return list(rows.all())


async def test_a_mutation_writes_exactly_one_row(client):
    email = "audit-create@test.local"
    _, headers = await token_for(email)

    target_id = create_target(client, headers, "10.30.0.1", name="Audited VM")

    rows = await _rows("targets.create", actor=email)
    assert len(rows) == 1
    row = rows[0]
    assert row.method == "POST"
    assert row.path == "/api/targets"
    assert row.status_code == 201
    assert row.entity == "targets"
    # A creation has no id in the URL: the journal says what was created, by whom.
    # (The new id is only knowable for updates/deletes — see audit.classify.)
    assert row.entity_id is None
    assert row.actor_email == email
    assert target_id > 0
    assert row.ip is not None  # TestClient reports "testclient"


async def test_a_read_does_not_write_anything(client):
    email = "audit-read@test.local"
    _, headers = await token_for(email)

    client.get("/api/targets", headers=headers)
    client.get("/api/dashboard/stats", headers=headers)
    client.get("/api/alerts", headers=headers)
    client.get(f"/api/auth/me", headers=headers)

    async with async_session() as session:
        rows = await session.exec(select(AuditLog).where(AuditLog.actor_email == email))
        assert list(rows.all()) == []


async def test_a_failed_mutation_is_recorded_with_its_status(client):
    """A 403 is exactly what an administrator needs to see."""
    _, viewer = await token_for("audit-forbidden@test.local", role="viewer")

    response = client.post(
        "/api/targets", json={"name": "x", "value": "10.30.0.2", "kind": "ip"}, headers=viewer
    )
    assert response.status_code == 403

    rows = await _rows("targets.create", actor="audit-forbidden@test.local")
    assert len(rows) == 1
    assert rows[0].status_code == 403


async def test_a_failed_login_is_recorded_without_an_actor(client):
    client.post(
        "/api/auth/login", json={"email": "audit-nobody@test.local", "password": "wrong-password"}
    )

    rows = await _rows("auth.login")
    assert rows
    assert rows[-1].status_code == 401
    assert rows[-1].actor_email is None


async def test_the_request_body_is_never_stored(client):
    """A journal that captures passwords becomes a liability, not an asset."""
    secret = "SuperSecretPassword!2026"
    email = "audit-secret@test.local"
    await token_for(email, password=secret)

    response = client.post("/api/auth/login", json={"email": email, "password": secret})
    assert response.status_code == 200

    async with async_session() as session:
        rows = await session.exec(select(AuditLog))
        for row in rows.all():
            blob = f"{row.detail}{row.path}{row.action}{row.user_agent or ''}"
            assert secret not in blob


async def test_a_route_can_enrich_the_row_it_causes(client):
    """Role transitions are not expressible in a URL; the detail field carries them."""
    admin_id, admin = await token_for("audit-admin@test.local", role="admin")
    victim = await token_for("audit-victim@test.local", role="viewer")
    victim_id, _ = victim
    assert admin_id is not None

    response = client.patch(
        f"/api/users/{victim_id}/role", json={"role": "analyst"}, headers=admin
    )
    assert response.status_code == 200, response.text

    rows = await _rows("users.update.role", actor="audit-admin@test.local")
    assert rows
    assert "viewer -> analyst" in rows[-1].detail
    assert "audit-victim@test.local" in rows[-1].detail


async def test_the_journal_is_filterable_by_actor_action_and_entity(client):
    _, admin = await token_for("audit-filter-admin@test.local", role="admin")
    actor_email = "audit-filter-worker@test.local"
    _, worker = await token_for(actor_email)
    create_target(client, worker, "10.30.0.3", name="Filtered VM")

    by_actor = client.get("/api/audit", params={"actor": actor_email}, headers=admin)
    assert by_actor.status_code == 200
    assert by_actor.json()
    assert all(actor_email in row["actor_email"] for row in by_actor.json())

    by_action = client.get("/api/audit", params={"action": "targets."}, headers=admin)
    assert all(row["action"].startswith("targets.") for row in by_action.json())

    by_entity = client.get(
        "/api/audit", params={"entity": "targets", "limit": 5}, headers=admin
    )
    assert all(row["entity"] == "targets" for row in by_entity.json())


async def test_the_journal_is_append_only(client):
    """There is no write endpoint: the only way to add a line is to act."""
    _, admin = await token_for("audit-append-admin@test.local", role="admin")

    # No write route exists at all — 405 when the path exists for another verb,
    # 404 when it does not exist for any verb. Never a success.
    assert client.post("/api/audit", json={"action": "fake"}, headers=admin).status_code in (404, 405)
    assert client.delete("/api/audit/1", headers=admin).status_code in (404, 405)
    assert client.patch("/api/audit/1", json={"action": "fake"}, headers=admin).status_code in (404, 405)


async def test_action_names_are_derived_reliably():
    from app.services import audit

    assert audit.classify("POST", "/api/targets") == ("targets.create", "targets", None)
    assert audit.classify("PATCH", "/api/alerts/42") == ("alerts.update", "alerts", 42)
    assert audit.classify("DELETE", "/api/targets/7") == ("targets.delete", "targets", 7)
    assert audit.classify("POST", "/api/scans/7/report.pdf") == (
        "scans.create.report.pdf",
        "scans",
        7,
    )
    assert audit.classify("POST", "/api/intel/sync") == ("intel.sync", "intel", None)
    assert audit.classify("POST", "/api/auth/login") == ("auth.login", "auth", None)
    assert audit.classify("POST", "/api/auth/register") == ("auth.register", "auth", None)


async def test_listing_returns_the_newest_first(client):
    _, admin = await token_for("audit-order-admin@test.local", role="admin")
    _, worker = await token_for("audit-order-worker@test.local")
    create_target(client, worker, "10.30.0.4")
    create_target(client, worker, "10.30.0.5")

    rows = client.get(
        "/api/audit", params={"actor": "audit-order-worker@test.local"}, headers=admin
    ).json()

    assert len(rows) >= 2
    assert rows[0]["created_at"] >= rows[-1]["created_at"]


async def test_the_action_list_helps_an_operator_filter(client):
    _, admin = await token_for("audit-actions-admin@test.local", role="admin")

    response = client.get("/api/audit/actions", headers=admin)

    assert response.status_code == 200
    assert "auth.login" in response.json()
