"""Jeu de données de démonstration — cibles, scans, constats, alertes, renseignement.

    cd backend && python seed_demo.py

Différence avec `seed.py` : `seed.py` crée le strict minimum pour démarrer
(un compte, une cible). Celui-ci remplit les **écrans** — il produit de quoi
regarder le tableau de bord, la page Alertes, la page Renseignement et le rapport
PDF sans lancer une seule commande nmap.

C'est ce qui rend les captures d'écran et la démonstration reproductibles : mêmes
données, même rendu. Toutes les valeurs sont fictives et utilisent les plages
IPv4 réservées à la documentation (RFC 5737) et les domaines `.example`.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlmodel import select

from app.core.security import hash_password
from app.db import async_session, init_db
from app.models import (
    Alert,
    AuditLog,
    Finding,
    IntelFeedItem,
    Ioc,
    Organization,
    Scan,
    Target,
    User,
)
from app.models.user import DEFAULT_ORG_ID
from app.services.scope import validate_target

DEMO_EMAIL = "admin@sentinelle.local"
DEMO_PASSWORD = "Sentinelle2026!"
NOW = datetime.now(timezone.utc)


def _scan_findings() -> list[dict]:
    """Constats d'un scan « complet » : trois sources, toutes sévérités."""
    return [
        {
            "source": "nmap",
            "port": 22,
            "protocol": "tcp",
            "service": "ssh",
            "version": "OpenSSH 8.9p1 Ubuntu 3ubuntu0.4",
            "severity": "low",
            "detail": "Open port 22/tcp — service: ssh (OpenSSH 8.9p1 Ubuntu 3ubuntu0.4)",
        },
        {
            "source": "nmap",
            "port": 80,
            "protocol": "tcp",
            "service": "http",
            "version": "nginx 1.18.0",
            "severity": "low",
            "detail": 'Open port 80/tcp — service: http (nginx 1.18.0), titre « Intranet RH »',
        },
        {
            "source": "nmap",
            "port": 3306,
            "protocol": "tcp",
            "service": "mysql",
            "version": "MySQL 5.7.44",
            "severity": "medium",
            "detail": "Open port 3306/tcp — service: mysql (MySQL 5.7.44)",
        },
        {
            "source": "nmap",
            "port": 5900,
            "protocol": "tcp",
            "service": "vnc",
            "version": "RealVNC 5.3",
            "severity": "medium",
            "detail": "Open port 5900/tcp — service: vnc (RealVNC 5.3), authentification VNC seule",
        },
        {
            "source": "nuclei",
            "port": 0,
            "protocol": "http",
            "service": "CVE-2021-41773",
            "version": "",
            "severity": "critical",
            "detail": "http://10.20.30.40/cgi-bin/.%2e/.%2e/etc/passwd — lecture de fichier arbitraire",
        },
        {
            "source": "nuclei",
            "port": 0,
            "protocol": "http",
            "service": "http-missing-security-headers",
            "version": "",
            "severity": "low",
            "detail": "http://10.20.30.40/ — en-têtes de sécurité absents (CSP, HSTS, X-Frame-Options)",
        },
        {
            "source": "nvd",
            "port": 0,
            "protocol": "tcp",
            "service": "CVE-2023-38408",
            "version": "",
            "severity": "critical",
            "detail": "OpenSSH agent forwarding RCE via le socket PKCS#11 (CVSS 9.8)",
        },
        {
            "source": "nvd",
            "port": 0,
            "protocol": "tcp",
            "service": "CVE-2022-31144",
            "version": "",
            "severity": "high",
            "detail": "Redis Lua sandbox escape, exécution de code arbitraire (CVSS 7.5)",
        },
    ]


async def _organisation(session) -> Organization:
    organization = await session.get(Organization, DEFAULT_ORG_ID)
    if organization is None:
        organization = Organization(id=DEFAULT_ORG_ID, name="Organisation par défaut", slug="default")
        session.add(organization)
        await session.commit()
        await session.refresh(organization)
    return organization


async def _utilisateur(session) -> User:
    user = (await session.exec(select(User).where(User.email == DEMO_EMAIL))).first()
    if user is None:
        user = User(
            email=DEMO_EMAIL,
            hashed_password=hash_password(DEMO_PASSWORD),
            role="admin",
            org_id=DEFAULT_ORG_ID,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        print(f"Compte de démonstration créé : {DEMO_EMAIL} / {DEMO_PASSWORD}")
    return user


async def _cible(session, user: User, name: str, value: str, kind: str, reference: Optional[str]) -> Target:
    target = (
        await session.exec(
            select(Target).where(Target.value == value, Target.owner_id == user.id)
        )
    ).first()
    if target is not None:
        return target
    target = Target(
        name=name,
        value=value,
        kind=kind,
        scope_status=validate_target(value, kind, reference),
        authorization_reference=reference,
        owner_id=user.id,
        org_id=user.org_id,
    )
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target


async def _scan(session, target: Target, *, profile: str, age_hours: int, findings: list[dict]) -> Scan:
    created = NOW - timedelta(hours=age_hours)
    done = (
        await session.exec(select(Scan).where(Scan.target_id == target.id, Scan.profile == profile))
    ).first()
    if done is not None:
        return done

    severity_weights = {"critical": 15, "high": 8, "medium": 3, "low": 1, "info": 0}
    score = min(100.0, float(sum(severity_weights.get(f["severity"], 0) for f in findings)))

    scan = Scan(
        target_id=target.id,
        org_id=target.org_id,
        profile=profile,
        status="done",
        risk_score=score,
        created_at=created,
        started_at=created + timedelta(seconds=4),
        finished_at=created + timedelta(seconds=96),
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    for finding in findings:
        session.add(Finding(scan_id=scan.id, org_id=scan.org_id, **finding))
    target.risk_score = score
    session.add(target)
    await session.commit()
    return scan


async def _alertes(session, org_id: int) -> None:
    existing = (await session.exec(select(Alert).where(Alert.rule_name == "port_scan"))).first()
    if existing is not None:
        return

    session.add_all(
        [
            Alert(
                source="rule",
                event_type="port_scan",
                severity="high",
                src_ip="198.51.100.23",
                dst_ip="192.168.56.10",
                proto="TCP",
                rule_name="port_scan",
                confidence=0.62,
                occurrences=3,
                dedup_key="port_scan|198.51.100.23|-|-",
                detail=(
                    "Port scan detected: 198.51.100.23 contacted 25 distinct destination "
                    "ports within 60s (threshold 20)."
                ),
                payload=json.dumps({"distinct_ports": [21, 22, 23, 25, 53, 80, 110, 443, 3306]}),
                created_at=NOW - timedelta(minutes=42),
            ),
            Alert(
                source="rule",
                event_type="ssh_bruteforce",
                severity="high",
                src_ip="203.0.113.77",
                dst_ip="192.168.56.10",
                dst_port=22,
                proto="tcp",
                rule_name="ssh_bruteforce",
                confidence=0.6,
                occurrences=1,
                dedup_key="ssh_bruteforce|203.0.113.77|192.168.56.10|22",
                detail=(
                    "SSH brute force suspected: 12 connection attempts from 203.0.113.77 "
                    "to 192.168.56.10 within 300s (threshold 10)."
                ),
                payload=json.dumps({"attempts": 12}),
                created_at=NOW - timedelta(minutes=17),
            ),
            Alert(
                source="suricata",
                event_type="signature",
                severity="high",
                src_ip="198.51.100.23",
                dst_ip="192.168.56.10",
                dst_port=80,
                proto="TCP",
                signature="ET WEB_SERVER Possible SQL Injection Attempt",
                detail="Suricata signature match: ET WEB_SERVER Possible SQL Injection Attempt",
                payload=json.dumps({"alert": {"signature": "ET WEB_SERVER Possible SQL Injection Attempt"}}),
                created_at=NOW - timedelta(hours=3),
            ),
            Alert(
                source="intel",
                event_type="ioc_match_ip",
                severity="critical",
                src_ip="198.51.100.23",
                confidence=1.0,
                dedup_key="intel|ip|198.51.100.23|alert:seed",
                detail=(
                    "Indicator ip 198.51.100.23 (source: misp,otx, severity critical) matched "
                    "alert #seed: Port scan detected"
                ),
                payload=json.dumps({"ioc": {"type": "ip", "value": "198.51.100.23", "sources": "misp,otx"}}),
                created_at=NOW - timedelta(minutes=39),
            ),
        ]
    )
    await session.commit()


async def _renseignement(session) -> None:
    existing = (await session.exec(select(Ioc))).first()
    if existing is not None:
        return

    def ioc(ioc_type, value, sources, severity, metadata, days_ago=2):
        return Ioc(
            type=ioc_type,
            value=value,
            sources=sources,
            severity=severity,
            first_seen=NOW - timedelta(days=days_ago + 5),
            last_seen=NOW - timedelta(days=days_ago),
            metadata_json=json.dumps(metadata),
        )

    session.add_all(
        [
            ioc(
                "ip", "198.51.100.23", "misp,otx", "critical",
                {"name": "Campagne de reconnaissance ciblant les PME", "tags": ["apt", "scanning"],
                 "targeted_countries": ["France"], "latitude": 55.75, "longitude": 37.61},
            ),
            ioc(
                "ip", "203.0.113.77", "misp", "high",
                {"name": "Serveur de commande et contrôle", "tags": ["c2", "ransomware"],
                 "latitude": 39.9, "longitude": 116.4},
            ),
            ioc(
                "domain", "encrypted-c2.example", "otx", "high",
                {"name": "Balise HTTPS périodique", "tags": ["c2"], "latitude": 37.77, "longitude": -122.42},
            ),
            ioc(
                "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "misp,otx", "medium", {"name": "Charge utile de rançon", "tags": ["ransomware"]},
            ),
            ioc("url", "http://malicious.example/payload.bin", "otx", "medium",
                {"name": "Point de téléchargement", "tags": ["dropper"]}),
            ioc("email", "support@phishing.example", "misp", "medium",
                {"name": "Adresse d'hameçonnage", "tags": ["phishing"]}),
        ]
    )

    session.add_all(
        [
            IntelFeedItem(
                guid="urn:demo:certfr:2026-avi-0001",
                source="CERT-FR",
                title="Multiples vulnérabilités dans Apache HTTP Server",
                link="https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0001/",
                summary=(
                    "Le 21 septembre 2026, l'éditeur a publié des correctifs pour plusieurs "
                    "vulnérabilités affectant Apache HTTP Server. Le CERT-FR recommande "
                    "l'application des mises à jour dans les meilleurs délais."
                ),
                published_at=NOW - timedelta(hours=6),
            ),
            IntelFeedItem(
                guid="urn:demo:certfr:2026-avi-0002",
                source="CERT-FR",
                title="Vulnérabilité dans les équipements de virtualisation",
                link="https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0002/",
                summary="Exécution de code à distance sur l'interface d'administration des hôtes.",
                published_at=NOW - timedelta(days=1),
            ),
        ]
    )
    await session.commit()


async def _journal(session, user: User) -> None:
    """Quelques lignes de journal, pour que la page ne soit pas vide en démonstration."""
    existing = (await session.exec(select(AuditLog))).first()
    if existing is not None:
        return

    rows = [
        ("auth.login", "POST", "/api/auth/login", 200, None, None, 3),
        ("targets.create", "POST", "/api/targets", 201, "targets", None, 2),
        ("scans.create", "POST", "/api/scans", 201, "scans", None, 2),
        ("alerts.update", "PATCH", "/api/alerts/1", 200, "alerts", 1, 1),
        ("intel.sync", "POST", "/api/intel/sync", 202, "intel", None, 1),
        ("users.update.role", "PATCH", "/api/users/2/role", 200, "users", 2, 1),
    ]
    for action, method, path, status, entity, entity_id, hours_ago in rows:
        session.add(
            AuditLog(
                actor_id=user.id,
                actor_email=user.email,
                org_id=user.org_id,
                action=action,
                method=method,
                path=path,
                status_code=status,
                entity=entity,
                entity_id=entity_id,
                ip="192.168.56.1",
                user_agent="Mozilla/5.0 (démonstration)",
                detail="role de analyste@exemple.fr : viewer -> analyst" if action == "users.update.role" else "",
                created_at=NOW - timedelta(hours=hours_ago),
            )
        )
    await session.commit()


async def main() -> None:
    await init_db()
    async with async_session() as session:
        await _organisation(session)
        user = await _utilisateur(session)

        # 1. Le parc cible : deux actifs internes, une cible publique autorisée,
        #    une cible refusée (pour montrer le garde-fou à l'écran).
        principal = await _cible(session, user, "Serveur intranet RH", "192.168.56.10", "ip", None)
        await _cible(session, user, "Poste comptabilité", "192.168.56.24", "ip", None)
        await _cible(
            session, user, "Portail exposé", "portal.example", "hostname", "LETTRE-2026-014"
        )
        await _cible(session, user, "Cible non autorisée", "93.184.216.34", "ip", None)

        # 2. Deux scans terminés : l'un complet, l'autre plus léger.
        findings = _scan_findings()
        await _scan(session, principal, profile="full", age_hours=5, findings=findings)
        await _scan(
            session,
            principal,
            profile="quick",
            age_hours=29,
            findings=[f for f in findings if f["source"] != "nuclei"],
        )

        # 3. Alertes, renseignement et journal.
        await _alertes(session, user.org_id)
        await _renseignement(session)
        await _journal(session, user)

    print(
        "\nDémonstration prête.\n"
        f"  Compte   : {DEMO_EMAIL} / {DEMO_PASSWORD}\n"
        "  Contenu  : 4 cibles (dont une refusée), 2 scans terminés, 8 constats,\n"
        "             4 alertes, 6 indicateurs, 2 avis CERT, 6 lignes de journal.\n"
    )


if __name__ == "__main__":
    asyncio.run(main())
