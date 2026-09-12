"""Target CRUD + guardrail enforcement on scan creation."""


def test_create_private_target_allowed(client, auth_headers):
    response = client.post(
        "/api/targets",
        json={"name": "Lab VM", "value": "192.168.56.10", "kind": "ip"},
        headers=auth_headers,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["scope_status"] == "allowed"

    # It shows up in the list and get-by-id.
    listing = client.get("/api/targets", headers=auth_headers)
    assert listing.status_code == 200
    assert any(t["id"] == body["id"] for t in listing.json())

    fetched = client.get(f"/api/targets/{body['id']}", headers=auth_headers)
    assert fetched.status_code == 200
    assert fetched.json()["value"] == "192.168.56.10"


def test_denied_public_target_scan_returns_403(client, auth_headers):
    # A public IP without an authorization reference is stored as denied.
    response = client.post(
        "/api/targets",
        json={"name": "Public DNS", "value": "8.8.8.8", "kind": "ip"},
        headers=auth_headers,
    )
    assert response.status_code == 201, response.text
    target = response.json()
    assert target["scope_status"] == "denied"

    # Scanning it must be refused with 403 — the guardrail holds at scan time too.
    scan_response = client.post(
        "/api/scans",
        json={"target_id": target["id"], "profile": "quick"},
        headers=auth_headers,
    )
    assert scan_response.status_code == 403, scan_response.text


def test_delete_target(client, auth_headers):
    response = client.post(
        "/api/targets",
        json={"name": "Temp", "value": "10.10.10.10", "kind": "ip"},
        headers=auth_headers,
    )
    assert response.status_code == 201
    target_id = response.json()["id"]

    assert client.delete(f"/api/targets/{target_id}", headers=auth_headers).status_code == 204
    assert client.get(f"/api/targets/{target_id}", headers=auth_headers).status_code == 404


def test_targets_require_auth(client):
    assert client.get("/api/targets").status_code == 401
