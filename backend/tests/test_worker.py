"""Worker run_scan wiring tests — nmap + nuclei + NVD are all mocked.

Verifies the v0.2 enrichment pipeline end to end against a real (temp) DB:
finding sources, non-fatal nuclei failure, and risk score persistence.
"""

from sqlmodel import select

from app.db import async_session
from app.models import Finding, Scan, Target
from app.services import nvd, scanner
from app.worker import jobs

NMAP_FINDINGS = [
    {
        "port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.9p1",
        "severity": "low", "detail": "Open port 22/tcp — service: ssh (OpenSSH 8.9p1)",
    },
    {
        "port": 80, "protocol": "tcp", "service": "http", "version": "nginx 1.18.0",
        "severity": "low", "detail": "Open port 80/tcp — service: http (nginx 1.18.0)",
    },
    {
        "port": 3306, "protocol": "tcp", "service": "mysql", "version": "MySQL 5.7.44",
        "severity": "medium", "detail": "Open port 3306/tcp — service: mysql (MySQL 5.7.44)",
    },
]

NUCLEI_FINDINGS = [
    {
        "port": 0, "protocol": "http", "service": "CVE-2021-41773", "version": "",
        "severity": "critical", "detail": "http://10.20.30.40/cgi-bin/ — passwd-file",
    },
]

SSH_CVES = [
    {
        "cve_id": "CVE-2023-38408", "severity": "critical", "cvss": 9.8,
        "description": "OpenSSH agent forwarding RCE",
    },
]


def _patch_scanners(monkeypatch, nuclei_error: RuntimeError | None = None):
    async def fake_nmap(target_value, profile="quick"):
        return [dict(f) for f in NMAP_FINDINGS]

    async def fake_nuclei(target_value, profile="quick"):
        if nuclei_error is not None:
            raise nuclei_error
        return [dict(f) for f in NUCLEI_FINDINGS]

    async def fake_lookup(service, version, api_key=None):
        # Only the ssh pair yields a CVE; nginx/mysql return nothing.
        return [dict(c) for c in SSH_CVES] if service == "ssh" else []

    monkeypatch.setattr(scanner, "run_nmap_scan", fake_nmap)
    monkeypatch.setattr(scanner, "run_nuclei_scan", fake_nuclei)
    monkeypatch.setattr(nvd, "lookup_cves", fake_lookup)


async def _create_pending_scan(client, auth_headers, value: str) -> tuple[int, int]:
    response = client.post(
        "/api/targets",
        json={"name": "Worker VM", "value": value, "kind": "ip"},
        headers=auth_headers,
    )
    assert response.status_code == 201, response.text
    target_id = response.json()["id"]

    async with async_session() as session:
        scan = Scan(target_id=target_id, profile="quick", status="pending")
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        return scan.id, target_id


async def _fetch(scan_id: int, target_id: int):
    async with async_session() as session:
        scan = await session.get(Scan, scan_id)
        target = await session.get(Target, target_id)
        findings = (
            await session.exec(select(Finding).where(Finding.scan_id == scan_id))
        ).all()
        return scan, target, list(findings)


async def test_run_scan_full_pipeline(client, auth_headers, monkeypatch):
    _patch_scanners(monkeypatch)
    scan_id, target_id = await _create_pending_scan(client, auth_headers, "10.20.30.40")

    status = await jobs.run_scan({}, scan_id)

    assert status == "done"
    scan, target, findings = await _fetch(scan_id, target_id)
    assert scan.error is None

    # Findings: 3 nmap + 1 nuclei + 1 NVD CVE (ssh only).
    by_source = {}
    for finding in findings:
        by_source.setdefault(finding.source, []).append(finding)
    assert sorted(by_source) == ["nmap", "nuclei", "nvd"]
    assert len(by_source["nmap"]) == 3
    assert by_source["nuclei"][0].service == "CVE-2021-41773"
    assert by_source["nvd"][0].service == "CVE-2023-38408"
    assert by_source["nvd"][0].severity == "critical"
    assert "CVSS 9.8" in by_source["nvd"][0].detail

    # Risk: nmap low+low+medium = 5, nuclei critical = 15, nvd critical = 15 -> 35.
    assert scan.risk_score == 35.0
    assert target.risk_score == 35.0


async def test_run_scan_nuclei_failure_is_non_fatal(client, auth_headers, monkeypatch):
    _patch_scanners(monkeypatch, nuclei_error=RuntimeError("nuclei not installed"))
    scan_id, target_id = await _create_pending_scan(client, auth_headers, "10.20.30.41")

    status = await jobs.run_scan({}, scan_id)

    assert status == "done"
    scan, target, findings = await _fetch(scan_id, target_id)
    # scan.error stays reserved for fatal nmap failure only.
    assert scan.error is None
    assert {f.source for f in findings} == {"nmap", "nvd"}
    # Risk: nmap 5 + nvd critical 15 = 20.
    assert scan.risk_score == 20.0
    assert target.risk_score == 20.0


async def test_run_scan_nmap_failure_still_marks_failed(client, auth_headers, monkeypatch):
    async def fake_nmap(target_value, profile="quick"):
        raise RuntimeError("nmap exited with code 1: permission denied")

    monkeypatch.setattr(scanner, "run_nmap_scan", fake_nmap)
    scan_id, _ = await _create_pending_scan(client, auth_headers, "10.20.30.42")

    status = await jobs.run_scan({}, scan_id)

    assert status == "failed"
    async with async_session() as session:
        scan = await session.get(Scan, scan_id)
        assert "permission denied" in (scan.error or "")
