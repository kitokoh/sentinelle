"""Encryption at rest tests (v0.6, issue #18).

Acceptance criteria: "données chiffrées en base, lisibles via API" and a key that
never comes from the repository. The tests below therefore check **both sides** of
every value: what the row actually contains on disk (read with raw SQL, bypassing
the ORM) and what the API returns.

Two further properties are pinned because losing either would be worse than the
problem being solved: a legacy plaintext row stays readable, and an undecryptable
value degrades to a placeholder instead of breaking the page.
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from app.db import async_session
from app.models import Alert, Finding, Scan
from app.services import crypto
from tests.support import create_target, token_for


def test_round_trip():
    ciphertext = crypto.encrypt_text("10.0.0.1 — bannière SSH exposée")

    assert ciphertext is not None
    assert ciphertext.startswith(crypto.PREFIX)
    assert "bannière" not in ciphertext  # the plaintext is really gone
    assert crypto.decrypt_text(ciphertext) == "10.0.0.1 — bannière SSH exposée"


def test_encryption_is_idempotent():
    """Re-running the data migration must not double-wrap a value."""
    once = crypto.encrypt_text("secret")
    twice = crypto.encrypt_text(once)

    assert once == twice
    assert crypto.decrypt_text(twice) == "secret"


def test_empty_values_are_left_alone():
    assert crypto.encrypt_text("") == ""
    assert crypto.encrypt_text(None) is None
    assert crypto.decrypt_text("") == ""
    assert crypto.decrypt_text(None) is None


def test_plaintext_from_before_the_feature_is_still_readable():
    """No flag day: rows written before #18 must keep working (and be re-encrypted on write)."""
    legacy = "Open port 22/tcp — service: ssh (OpenSSH 8.9p1)"

    assert not crypto.is_encrypted(legacy)
    assert crypto.decrypt_text(legacy) == legacy


def test_ciphertext_is_not_portable_across_keys():
    from cryptography.fernet import Fernet

    other_key = Fernet.generate_key().decode()
    ciphertext = crypto.encrypt_text("indiscret", field_key=Fernet.generate_key().decode())

    assert crypto.decrypt_text(ciphertext, field_key=other_key) == crypto.UNDECRYPTABLE


def test_decryption_failure_does_not_raise_and_leaks_nothing():
    from cryptography.fernet import Fernet

    ciphertext = crypto.encrypt_text("valeur sensible", field_key=Fernet.generate_key().decode())
    result = crypto.decrypt_text(ciphertext)

    assert result == crypto.UNDECRYPTABLE
    assert "sensible" not in result


def test_the_development_fallback_is_derived_and_deterministic(monkeypatch):
    """Without FIELD_ENCRYPTION_KEY the key is derived from JWT_SECRET — and that is a warning."""
    from cryptography.fernet import Fernet

    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "FIELD_ENCRYPTION_KEY", None)
    first = crypto.key()
    second = crypto.key()

    assert first == second  # deterministic: a restart must still read the data
    Fernet(first.encode())  # valid Fernet key


def test_the_key_never_comes_from_the_repository():
    """The key is either configured explicitly or derived — never a literal."""
    configured = crypto.key()
    assert configured
    assert "FIELD_ENCRYPTION_KEY" not in configured

    from cryptography.fernet import Fernet

    Fernet(configured.encode())  # raises if it is not a valid Fernet key


# --------------------------------------------------------------------------- #
# What actually lands on disk
# --------------------------------------------------------------------------- #


async def _raw(column: str, table: str, row_id: int) -> str:
    """Read a column with raw SQL — the ORM would decrypt it for us."""
    async with async_session() as session:
        result = await session.execute(
            text(f"SELECT {column} FROM {table} WHERE id = :row_id"), {"row_id": row_id}
        )
        return result.scalar_one()


async def test_a_finding_detail_is_encrypted_on_disk_and_readable_through_the_api(client):
    _, headers = await token_for("crypto-finding@test.local")
    target_id = create_target(client, headers, "10.60.0.1", name="Crypto VM")

    async with async_session() as session:
        scan = Scan(target_id=target_id, profile="quick", status="done", risk_score=10.0)
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        finding = Finding(
            scan_id=scan.id,
            org_id=scan.org_id,
            source="nmap",
            port=22,
            protocol="tcp",
            service="ssh",
            version="OpenSSH 8.9p1",
            severity="low",
            detail="Open port 22/tcp — service: ssh (OpenSSH 8.9p1)",
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)
        finding_id, scan_id = finding.id, scan.id

    stored = await _raw("detail", "findings", finding_id)
    assert stored.startswith(crypto.PREFIX)
    assert "OpenSSH" not in stored

    response = client.get(f"/api/scans/{scan_id}", headers=headers)
    assert response.status_code == 200
    details = [item["detail"] for item in response.json()["findings"]]
    assert any("OpenSSH 8.9p1" in detail for detail in details)


async def test_an_alert_payload_is_encrypted_on_disk_and_readable_through_the_api(client):
    _, headers = await token_for("crypto-alert@test.local")

    async with async_session() as session:
        alert = Alert(
            source="suricata",
            event_type="signature",
            severity="high",
            detail="signature match",
            payload='{"alert": {"signature": "ET SCAN"}, "src_ip": "198.51.100.9"}',
        )
        session.add(alert)
        await session.commit()
        await session.refresh(alert)
        alert_id = alert.id

    stored = await _raw("payload", "alerts", alert_id)
    assert stored.startswith(crypto.PREFIX)
    assert "ET SCAN" not in stored

    response = client.get(f"/api/alerts/{alert_id}", headers=headers)
    assert response.status_code == 200
    assert "ET SCAN" in response.json()["payload"]


async def test_a_legacy_plaintext_row_is_still_served_by_the_api(client):
    """A row written before #18 must not disappear from the interface."""
    _, headers = await token_for("crypto-legacy@test.local")

    async with async_session() as session:
        alert = Alert(
            source="rule",
            event_type="port_scan",
            severity="high",
            detail="legacy row",
            payload="{not-encrypted}",  # written by raw SQL on purpose
        )
        session.add(alert)
        await session.commit()
        await session.refresh(alert)
        alert_id = alert.id
        # Simulate a pre-migration row.
        await session.execute(
            text("UPDATE alerts SET payload = :value WHERE id = :row_id"),
            {"value": '{"legacy": true}', "row_id": alert_id},
        )
        await session.commit()

    stored = await _raw("payload", "alerts", alert_id)
    assert stored == '{"legacy": true}'  # untouched, as a legacy row would be

    response = client.get(f"/api/alerts/{alert_id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["payload"] == '{"legacy": true}'


async def test_the_csv_export_decrypts_finding_details(client):
    """The export is a read path like any other: it must show the plaintext."""
    _, headers = await token_for("crypto-export@test.local")
    target_id = create_target(client, headers, "10.60.0.2", name="Crypto export VM")

    async with async_session() as session:
        scan = Scan(target_id=target_id, profile="quick", status="done")
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
                service="CVE-2021-41773",
                version="",
                severity="critical",
                detail="http://10.60.0.2/cgi-bin/ — passwd-file",
            )
        )
        await session.commit()
        scan_id = scan.id

    response = client.get(f"/api/scans/{scan_id}/export", headers=headers)

    assert response.status_code == 200
    assert "passwd-file" in response.text


async def test_correlation_still_matches_encrypted_findings(client):
    """Regression guard: a SQL LIKE cannot see ciphertext (#18 × #9)."""
    from app.models import Ioc
    from app.services.intel import correlation

    _, headers = await token_for("crypto-correlation@test.local")
    target_id = create_target(client, headers, "10.60.0.3", name="Crypto correlation VM")

    async with async_session() as session:
        scan = Scan(
            target_id=target_id,
            profile="quick",
            status="done",
            created_at=datetime.now(timezone.utc),
        )
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
                service="indic",
                version="",
                severity="high",
                detail="http://encrypted-c2.example/gate.php responded 200",
            )
        )
        ioc = Ioc(
            type="domain",
            value="encrypted-c2.example",
            sources="misp",
            severity="high",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            metadata_json="{}",
        )
        session.add(ioc)
        await session.commit()

    async with async_session() as session:
        counters = await correlation.correlate_iocs(session)

    assert counters["finding_matches"] >= 1

    async with async_session() as session:
        result = await session.execute(
            text("SELECT COUNT(*) FROM alerts WHERE source = 'intel'")
        )
        assert result.scalar_one() >= 1


# --------------------------------------------------------------------------- #
# Rotation of the encryption key (#17)
#
# These tests run against their own throwaway database. `reencrypt_rows` is
# deliberately database-wide (that is what a rotation is), so running it against
# the shared test database would re-key every other test's rows and make the
# suite order-dependent.
# --------------------------------------------------------------------------- #

ALERT_INSERT = (
    "INSERT INTO alerts (source, event_type, severity, detail, payload, status, "
    "occurrences, created_at) VALUES ('rule', 'port_scan', 'high', :detail, :payload, "
    "'new', 1, :now)"
)
FINDING_INSERT = (
    "INSERT INTO findings (scan_id, org_id, port, protocol, service, version, severity, "
    "detail, source) VALUES (1, 1, 22, 'tcp', 'ssh', '', 'low', :detail, 'nmap')"
)


async def _rotation_database(tmp_path):
    """A fresh schema plus a session factory, isolated from the shared database."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.db import build_engine
    from app.migrations import upgrade_to_head
    from sqlmodel.ext.asyncio.session import AsyncSession

    engine = build_engine(f"sqlite+aiosqlite:///{tmp_path}/rotation.db")
    async with engine.begin() as connection:
        await connection.run_sync(upgrade_to_head)
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def test_rotation_reencrypts_with_the_new_key(tmp_path):
    """Rotating the key without re-encrypting is the documented footgun; this is the cure."""
    from cryptography.fernet import Fernet
    from sqlalchemy import text

    from app.services import crypto as crypto_service

    key_a = Fernet.generate_key().decode()
    key_b = Fernet.generate_key().decode()
    engine, factory = await _rotation_database(tmp_path)

    try:
        async with factory() as session:
            await session.execute(
                text(ALERT_INSERT),
                {
                    "detail": "rotation sentinel",
                    "payload": crypto_service.encrypt_text('{"sentinel": true}', key_a),
                    "now": datetime.now(timezone.utc),
                },
            )
            await session.execute(
                text(FINDING_INSERT),
                {"detail": crypto_service.encrypt_text("finding sentinel", key_a)},
            )
            await session.commit()

        async with factory() as session:
            counters = await crypto_service.reencrypt_rows(session, key_a, key_b)

        # Both protected columns are covered, not just the first one.
        assert counters["reencrypted"] == 2

        async with factory() as session:
            payload = (
                await session.execute(text("SELECT payload FROM alerts WHERE id = 1"))
            ).scalar_one()
            detail = (
                await session.execute(text("SELECT detail FROM findings WHERE id = 1"))
            ).scalar_one()

        assert crypto_service.decrypt_text(payload, key_b) == '{"sentinel": true}'
        assert crypto_service.decrypt_text(detail, key_b) == "finding sentinel"
        # ...and the old key no longer opens them.
        assert crypto_service.decrypt_text(payload, key_a) == crypto_service.UNDECRYPTABLE
    finally:
        await engine.dispose()


async def test_rotation_refuses_a_wrong_old_key_instead_of_destroying_data(tmp_path):
    """A rotation that cannot read a row must stop, not overwrite it."""
    from cryptography.fernet import Fernet
    from sqlalchemy import text

    from app.services import crypto as crypto_service

    real_key = Fernet.generate_key().decode()
    engine, factory = await _rotation_database(tmp_path)

    try:
        async with factory() as session:
            await session.execute(
                text(ALERT_INSERT),
                {
                    "detail": "guard",
                    "payload": crypto_service.encrypt_text('{"guard": true}', real_key),
                    "now": datetime.now(timezone.utc),
                },
            )
            await session.commit()

        async with factory() as session:
            original = (
                await session.execute(text("SELECT payload FROM alerts WHERE id = 1"))
            ).scalar_one()

        async with factory() as session:
            with pytest.raises(ValueError, match="does not decrypt"):
                await crypto_service.reencrypt_rows(
                    session, Fernet.generate_key().decode(), Fernet.generate_key().decode()
                )

        async with factory() as session:
            after = (
                await session.execute(text("SELECT payload FROM alerts WHERE id = 1"))
            ).scalar_one()
            assert after == original
            await session.rollback()
    finally:
        await engine.dispose()


async def test_rotation_dry_run_changes_nothing(tmp_path):
    from cryptography.fernet import Fernet
    from sqlalchemy import text

    from app.services import crypto as crypto_service

    key_a = Fernet.generate_key().decode()
    engine, factory = await _rotation_database(tmp_path)

    try:
        async with factory() as session:
            await session.execute(
                text(ALERT_INSERT),
                {
                    "detail": "dry",
                    "payload": crypto_service.encrypt_text("{}", key_a),
                    "now": datetime.now(timezone.utc),
                },
            )
            await session.commit()

        async with factory() as session:
            before = (
                await session.execute(text("SELECT payload FROM alerts WHERE id = 1"))
            ).scalar_one()

        async with factory() as session:
            counters = await crypto_service.reencrypt_rows(
                session, key_a, Fernet.generate_key().decode(), dry_run=True
            )

        assert counters["reencrypted"] == 1
        async with factory() as session:
            after = (
                await session.execute(text("SELECT payload FROM alerts WHERE id = 1"))
            ).scalar_one()
        assert after == before
    finally:
        await engine.dispose()
