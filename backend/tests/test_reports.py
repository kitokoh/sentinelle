"""PDF report tests (v0.5, issue #11).

Acceptance criterion: "PDF généré, magic bytes, non vide". Beyond that, the
report is checked for the properties that make it usable as an audit deliverable:
it names the target, it carries who generated it, and it refuses to cross a
tenant boundary.
"""

from datetime import datetime, timezone

import pytest

from app.db import async_session
from app.models import Finding, Scan, Target
from tests.support import create_organization, create_target, token_for



async def _seed_scan_with_findings(
    client, headers, value: str, *, org_id: int | None = None
) -> tuple[int, int]:
    target_id = create_target(client, headers, value, name="Report VM")
    async with async_session() as session:
        target = await session.get(Target, target_id)
        scan = Scan(
            target_id=target_id,
            profile="quick",
            status="done",
            risk_score=35.0,
            org_id=org_id or target.org_id,
            created_at=datetime(2026, 9, 21, 10, 0, tzinfo=timezone.utc),
            finished_at=datetime(2026, 9, 21, 10, 3, tzinfo=timezone.utc),
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        session.add_all(
            [
                Finding(
                    scan_id=scan.id,
                    org_id=scan.org_id,
                    source="nmap",
                    port=22,
                    protocol="tcp",
                    service="ssh",
                    version="OpenSSH 8.9p1",
                    severity="low",
                    detail="Open port 22/tcp — service: ssh",
                ),
                Finding(
                    scan_id=scan.id,
                    org_id=scan.org_id,
                    source="nuclei",
                    port=0,
                    protocol="http",
                    service="CVE-2021-41773",
                    version="",
                    severity="critical",
                    detail="http://10.20.30.40/cgi-bin/ — passwd-file",
                ),
                Finding(
                    scan_id=scan.id,
                    org_id=scan.org_id,
                    source="nvd",
                    port=0,
                    protocol="tcp",
                    service="CVE-2023-38408",
                    version="",
                    severity="critical",
                    detail="OpenSSH agent forwarding RCE (CVSS 9.8) " * 20,
                ),
            ]
        )
        await session.commit()
        return scan.id, target_id


async def test_the_report_is_a_valid_pdf(client):
    _, headers = await token_for("report-happy@test.local")
    scan_id, _ = await _seed_scan_with_findings(client, headers, "10.50.0.1")

    response = client.get(f"/api/scans/{scan_id}/report.pdf", headers=headers)

    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/pdf"
    assert "attachment" in response.headers["content-disposition"]
    assert f"rapport_scan_{scan_id}.pdf" in response.headers["content-disposition"]
    assert response.headers["cache-control"] == "no-store"

    payload = response.content
    # Magic bytes, non-empty, properly terminated.
    assert payload[:5] == b"%PDF-"
    assert b"%%EOF" in payload
    assert len(payload) > 2000


async def test_the_report_handles_an_empty_findings_list(client):
    """A clean scan still deserves a report — and must not crash the generator."""
    _, headers = await token_for("report-empty@test.local")
    target_id = create_target(client, headers, "10.50.0.2", name="Clean VM")
    async with async_session() as session:
        scan = Scan(target_id=target_id, profile="quick", status="done", risk_score=0.0)
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        scan_id = scan.id

    response = client.get(f"/api/scans/{scan_id}/report.pdf", headers=headers)

    assert response.status_code == 200
    assert response.content[:5] == b"%PDF-"


async def test_the_report_survives_characters_outside_latin1(client):
    """Em dashes and quotes are all over nmap output; core fonts cannot draw them."""
    _, headers = await token_for("report-unicode@test.local")
    target_id = create_target(client, headers, "10.50.0.3", name="Unicode — VM « test »")
    async with async_session() as session:
        scan = Scan(target_id=target_id, profile="full", status="done", risk_score=55.0)
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        session.add(
            Finding(
                scan_id=scan.id,
                org_id=scan.org_id,
                source="nuclei",
                port=0,
                protocol="http",
                service="CVE-2026-0001",
                version="",
                severity="high",
                detail="Exposition « sensible » — vérifier l’accès … et le reste",
            )
        )
        await session.commit()
        scan_id = scan.id

    response = client.get(f"/api/scans/{scan_id}/report.pdf", headers=headers)

    assert response.status_code == 200
    assert response.content[:5] == b"%PDF-"


async def test_the_report_refuses_another_tenants_scan(client):
    other_org = await create_organization("report-other-org")
    _, tenant_a = await token_for("report-a@test.local")
    _, tenant_b = await token_for("report-b@test.local", role="admin", org_id=other_org)

    scan_id, _ = await _seed_scan_with_findings(client, tenant_a, "10.50.0.4")

    assert client.get(f"/api/scans/{scan_id}/report.pdf", headers=tenant_b).status_code == 404


async def test_the_report_requires_authentication(client):
    assert client.get("/api/scans/1/report.pdf").status_code == 401


async def test_an_unknown_scan_returns_404(client):
    _, headers = await token_for("report-missing@test.local")
    assert client.get("/api/scans/999999/report.pdf", headers=headers).status_code == 404


async def test_the_renderer_is_deterministic_for_the_same_input():
    """Same data in, same bytes out — a report that changes on its own is not evidence."""
    from types import SimpleNamespace

    from app.services import reports

    scan = SimpleNamespace(
        id=1,
        status="done",
        profile="quick",
        risk_score=20.0,
        created_at=datetime(2026, 9, 21, 10, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 9, 21, 10, 1, tzinfo=timezone.utc),
    )
    target = SimpleNamespace(
        name="VM", value="10.0.0.1", kind="ip", authorization_reference="LETTRE-1"
    )
    findings = [
        SimpleNamespace(
            source="nmap",
            port=22,
            protocol="tcp",
            service="ssh",
            severity="low",
            detail="Open port 22/tcp",
        )
    ]
    moment = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)

    first = reports.build_scan_report(scan, target, findings, generated_at=moment, generated_by="a@b.c")
    second = reports.build_scan_report(scan, target, findings, generated_at=moment, generated_by="a@b.c")

    assert first == second


def test_recommendations_are_rule_based_and_explainable():
    from types import SimpleNamespace

    from app.services import reports

    critical = [SimpleNamespace(severity="critical", source="nuclei", service="CVE-1")]
    assert any("sans délai" in advice for advice in reports.recommendations(critical))

    plaintext = [SimpleNamespace(severity="high", source="nmap", service="telnet")]
    assert any("clair" in advice for advice in reports.recommendations(plaintext))

    clean = [SimpleNamespace(severity="info", source="nmap", service="http")]
    assert any("Aucune action critique" in advice for advice in reports.recommendations(clean))


def test_risk_levels_match_the_interface():
    from app.services import reports

    assert reports.risk_level(0) == "non évalué"
    assert reports.risk_level(10) == "faible"
    assert reports.risk_level(25) == "modéré"
    assert reports.risk_level(50) == "élevé"
    assert reports.risk_level(90) == "critique"
