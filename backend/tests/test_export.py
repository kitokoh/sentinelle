"""CSV export endpoint + risk_score serialization tests (v0.2).

Scans/findings are seeded directly in the DB (no Redis/nmap needed); the
export endpoint is then exercised through the API with real auth.
"""

import csv
import io

from app.db import async_session
from app.models import Finding, Scan

_EXPORT_DETAIL = 'Open port 80/tcp — "web", plain (nginx, 1.18)'  # comma + quotes -> must be CSV-escaped


def _create_target(client, headers, name="Export VM", value="192.168.56.77") -> int:
    response = client.post(
        "/api/targets",
        json={"name": name, "value": value, "kind": "ip"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


async def _seed_scan(target_id: int, risk_score: float = 27.0) -> int:
    """Insert a done scan with one finding per source; return the scan id."""
    async with async_session() as session:
        scan = Scan(target_id=target_id, profile="quick", status="done", risk_score=risk_score)
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        for finding in (
            Finding(
                scan_id=scan.id, source="nmap", port=22, protocol="tcp",
                service="ssh", version="OpenSSH 8.9p1", severity="low",
                detail="Open port 22/tcp — service: ssh",
            ),
            Finding(
                scan_id=scan.id, source="nmap", port=80, protocol="tcp",
                service="http", version="nginx 1.18", severity="low",
                detail=_EXPORT_DETAIL,
            ),
            Finding(
                scan_id=scan.id, source="nuclei", port=0, protocol="http",
                service="CVE-2021-41773", version="", severity="critical",
                detail="http://192.168.56.77/cgi-bin/ — passwd-file",
            ),
            Finding(
                scan_id=scan.id, source="nvd", port=0, protocol="tcp",
                service="CVE-2023-38408", version="", severity="critical",
                detail="OpenSSH agent forwarding RCE (CVSS 9.8)",
            ),
        ):
            session.add(finding)
        await session.commit()
        return scan.id


async def test_export_csv_happy_path(client, auth_headers):
    target_id = _create_target(client, auth_headers)
    scan_id = await _seed_scan(target_id)

    response = client.get(f"/api/scans/{scan_id}/export", headers=auth_headers)

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    disposition = response.headers["content-disposition"]
    assert "attachment" in disposition
    assert f"scan_{scan_id}_findings.csv" in disposition

    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[0] == ["source", "port", "protocol", "service", "version", "severity", "detail"]
    assert len(rows) == 5  # header + 4 findings

    # Ordered by source then port: nmap(22), nmap(80), nuclei, nvd.
    body = rows[1:]
    assert [row[0] for row in body] == ["nmap", "nmap", "nuclei", "nvd"]
    assert body[0] == [
        "nmap", "22", "tcp", "ssh", "OpenSSH 8.9p1", "low", "Open port 22/tcp — service: ssh"
    ]
    assert body[2] == [
        "nuclei", "0", "http", "CVE-2021-41773", "", "critical",
        "http://192.168.56.77/cgi-bin/ — passwd-file",
    ]
    assert body[3][0] == "nvd"
    assert body[3][3] == "CVE-2023-38408"

    # The comma/quote-laden detail round-trips through the CSV intact.
    assert ["nmap", "80", "tcp", "http", "nginx 1.18", "low", _EXPORT_DETAIL] in body
    # ...and was actually quoted/escaped in the raw payload.
    assert '"Open port 80/tcp — ""web"", plain (nginx, 1.18)"' in response.text


async def test_export_other_users_scan_returns_404(client, auth_headers):
    target_id = _create_target(client, auth_headers, name="Victim VM", value="10.9.9.9")
    scan_id = await _seed_scan(target_id)

    other = client.post(
        "/api/auth/register",
        json={"email": "other@sentinelle.dev", "password": "OtherPass2026!"},
    )
    assert other.status_code == 201, other.text
    other_headers = {"Authorization": f"Bearer {other.json()['access_token']}"}

    response = client.get(f"/api/scans/{scan_id}/export", headers=other_headers)
    assert response.status_code == 404


def test_export_requires_auth(client):
    assert client.get("/api/scans/1/export").status_code == 401


async def test_export_missing_scan_returns_404(client, auth_headers):
    assert client.get("/api/scans/999999/export", headers=auth_headers).status_code == 404


async def test_risk_score_serialization(client, auth_headers):
    """risk_score is exposed everywhere scans/targets are returned (v0.2)."""
    target_id = _create_target(client, auth_headers, name="Risk VM", value="10.8.8.8")
    scan_id = await _seed_scan(target_id, risk_score=42.0)

    detail = client.get(f"/api/scans/{scan_id}", headers=auth_headers)
    assert detail.status_code == 200
    assert detail.json()["risk_score"] == 42.0
    # Findings expose their source too.
    assert {f["source"] for f in detail.json()["findings"]} == {"nmap", "nuclei", "nvd"}

    listing = client.get("/api/scans", headers=auth_headers)
    assert listing.status_code == 200
    mine = [s for s in listing.json() if s["id"] == scan_id]
    assert mine and mine[0]["risk_score"] == 42.0

    targets = client.get("/api/targets", headers=auth_headers)
    assert targets.status_code == 200
    mine = [t for t in targets.json() if t["id"] == target_id]
    assert mine and "risk_score" in mine[0]

    fetched = client.get(f"/api/targets/{target_id}", headers=auth_headers)
    assert fetched.status_code == 200
    assert "risk_score" in fetched.json()
