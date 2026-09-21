"""Multi-tenant isolation tests (v0.5, issue #15).

Acceptance criterion: "aucune fuite cross-tenant (cas négatifs explicites)". Every
test here is a negative one: the assertion is that a tenant *cannot* reach
another tenant's data.

Two distinct boundaries are exercised, because either alone would be a hole:

* **tenant** — ``org_id`` filtering (this file);
* **ownership** — per-user scoping on top of it.

A missing resource answers **404, never 403**: a 403 would confirm that the
identifier exists, which is itself a leak.
"""

from datetime import datetime, timezone

import pytest
from sqlmodel import select

from app.db import async_session
from app.models import Alert, Finding, Scan, Target, User
from tests.support import create_organization, create_target, create_user, token_for



async def _second_tenant(prefix: str) -> tuple[int, dict[str, str]]:
    org_id = await create_organization(f"{prefix}-org", f"{prefix.title()} Org")
    _, headers = await token_for(f"{prefix}-analyst@test.local", role="admin", org_id=org_id)
    return org_id, headers


async def test_targets_do_not_leak_between_organizations(client):
    org_a, tenant_a = await _second_tenant("iso-a")
    org_b, tenant_b = await _second_tenant("iso-b")

    target_id = create_target(client, tenant_a, "10.40.0.1", name="A only")

    assert client.get(f"/api/targets/{target_id}", headers=tenant_b).status_code == 404
    assert client.delete(f"/api/targets/{target_id}", headers=tenant_b).status_code == 404
    assert all(item["id"] != target_id for item in client.get("/api/targets", headers=tenant_b).json())
    assert any(item["id"] == target_id for item in client.get("/api/targets", headers=tenant_a).json())
    assert org_a != org_b


async def test_scans_and_findings_do_not_leak_between_organizations(client):
    org_a, tenant_a = await _second_tenant("scan-a")
    org_b, tenant_b = await _second_tenant("scan-b")

    target_id = create_target(client, tenant_a, "10.41.0.1", name="A scan target")
    async with async_session() as session:
        target = await session.get(Target, target_id)
        scan = Scan(target_id=target_id, profile="quick", status="done", org_id=target.org_id)
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        session.add(
            Finding(
                scan_id=scan.id,
                org_id=org_a,
                port=443,
                protocol="tcp",
                service="https",
                version="",
                severity="low",
                detail="tenant A only",
            )
        )
        await session.commit()
        scan_id = scan.id

    assert client.get(f"/api/scans/{scan_id}", headers=tenant_b).status_code == 404
    assert client.get(f"/api/scans/{scan_id}/export", headers=tenant_b).status_code == 404
    assert client.get(f"/api/scans/{scan_id}/report.pdf", headers=tenant_b).status_code == 404
    assert all(item["id"] != scan_id for item in client.get("/api/scans", headers=tenant_b).json())
    assert client.get(f"/api/scans/{scan_id}", headers=tenant_a).status_code == 200
    assert org_b != org_a


async def test_a_scan_cannot_be_launched_against_another_tenants_target(client):
    _, tenant_a = await _second_tenant("launch-a")
    _, tenant_b = await _second_tenant("launch-b")

    target_id = create_target(client, tenant_a, "10.42.0.1", name="A launch target")

    response = client.post("/api/scans", json={"target_id": target_id}, headers=tenant_b)

    assert response.status_code == 404


async def test_tenant_scoped_alerts_are_invisible_to_other_tenants(client):
    org_a, tenant_a = await _second_tenant("alert-a")
    _, tenant_b = await _second_tenant("alert-b")

    async with async_session() as session:
        alert = Alert(
            source="rule",
            event_type="port_scan",
            severity="high",
            rule_name="iso-test",
            detail="tenant A only",
            org_id=org_a,
            created_at=datetime.now(timezone.utc),
        )
        session.add(alert)
        await session.commit()
        await session.refresh(alert)
        alert_id = alert.id

    assert client.get(f"/api/alerts/{alert_id}", headers=tenant_b).status_code == 404
    assert client.patch(f"/api/alerts/{alert_id}", json={"status": "ack"}, headers=tenant_b).status_code == 404
    visible_to_b = [row["id"] for row in client.get("/api/alerts", headers=tenant_b).json()]
    assert alert_id not in visible_to_b
    assert client.get(f"/api/alerts/{alert_id}", headers=tenant_a).status_code == 200


async def test_platform_wide_alerts_are_shared_on_purpose(client):
    """``org_id IS NULL`` is the sensor feed and threat intel: platform-wide by design."""
    _, tenant_a = await _second_tenant("platform-a")
    _, tenant_b = await _second_tenant("platform-b")

    async with async_session() as session:
        alert = Alert(
            source="suricata",
            event_type="signature",
            severity="high",
            detail="platform-wide sensor alert",
            org_id=None,
            created_at=datetime.now(timezone.utc),
        )
        session.add(alert)
        await session.commit()
        await session.refresh(alert)
        alert_id = alert.id

    assert client.get(f"/api/alerts/{alert_id}", headers=tenant_a).status_code == 200
    assert client.get(f"/api/alerts/{alert_id}", headers=tenant_b).status_code == 200


async def test_the_dashboard_counters_stay_within_the_tenant(client):
    org_a, tenant_a = await _second_tenant("dash-a")
    _, tenant_b = await _second_tenant("dash-b")

    create_target(client, tenant_a, "10.43.0.1", name="A dash")
    create_target(client, tenant_a, "10.43.0.2", name="A dash 2")

    stats_a = client.get("/api/dashboard/stats", headers=tenant_a).json()
    stats_b = client.get("/api/dashboard/stats", headers=tenant_b).json()

    assert stats_a["targets_count"] == 2
    assert stats_b["targets_count"] == 0
    assert org_a is not None


async def test_the_api_reports_the_tenant_of_the_caller(client):
    org_id, headers = await _second_tenant("whoami")

    me = client.get("/api/auth/me", headers=headers)

    assert me.status_code == 200
    assert me.json()["org_id"] == org_id

    organization = client.get("/api/users/organization", headers=headers)
    assert organization.status_code == 200
    assert organization.json()["id"] == org_id
    assert organization.json()["members"] >= 1


async def test_a_self_service_account_lands_in_the_default_organization(client):
    response = client.post(
        "/api/auth/register",
        json={"email": "iso-selfservice@test.local", "password": "SelfService2026!"},
    )

    assert response.status_code == 201, response.text
    headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    me = client.get("/api/auth/me", headers=headers).json()

    assert me["org_id"] == 1
    assert me["role"] == "analyst"


async def test_an_admin_cannot_touch_a_user_from_another_tenant(client):
    other_org = await create_organization("iso-touch-org")
    outsider = await create_user("iso-touch-outsider@test.local", role="viewer", org_id=other_org)
    _, admin = await token_for("iso-touch-admin@test.local", role="admin")

    response = client.patch(
        f"/api/users/{outsider.id}/role", json={"role": "admin"}, headers=admin
    )

    assert response.status_code == 404

    async with async_session() as session:
        stored = (await session.exec(select(User).where(User.id == outsider.id))).one()
    assert stored.role == "viewer"  # unchanged
