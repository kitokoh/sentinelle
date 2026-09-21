"""Scan API — the queue boundary (v0.7).

The happy path of ``POST /api/scans`` cannot be tested here: it enqueues a job,
and the test environment deliberately has no Redis. What *can* be tested is what
happens when the queue is missing, and that is the case worth pinning:

Until v0.7 the endpoint answered **500** and left a ``pending`` scan behind — a
row that would never run and never explain itself. It now answers **503** with a
message an operator can act on, and records the failure on the scan so the
interface shows *why* nothing happened.

The scan's *execution* is covered elsewhere, with the scanners stubbed
(`tests/test_worker.py`) — faster and more deterministic than a real nmap.
"""

from sqlmodel import select

from app.db import async_session
from app.models import Scan
from tests.support import create_target, token_for


async def _scan_rows(target_id: int) -> list[Scan]:
    async with async_session() as session:
        rows = await session.exec(select(Scan).where(Scan.target_id == target_id))
        return list(rows.all())


async def test_launching_a_scan_without_a_queue_is_a_503_not_a_500(client):
    """An unreachable queue is an infrastructure fact, not an internal error."""
    _, headers = await token_for("scan-queue@test.local")
    target_id = create_target(client, headers, "10.80.0.1", name="Queue VM")

    response = client.post("/api/scans", json={"target_id": target_id}, headers=headers)

    assert response.status_code == 503, response.text
    assert "queue" in response.json()["detail"].lower()


async def test_the_failed_scan_is_recorded_with_its_reason(client):
    """A scan that could not be queued must not vanish silently."""
    _, headers = await token_for("scan-recorded@test.local")
    target_id = create_target(client, headers, "10.80.0.2", name="Recorded VM")

    client.post("/api/scans", json={"target_id": target_id}, headers=headers)

    rows = await _scan_rows(target_id)
    assert len(rows) == 1
    assert rows[0].status == "failed"
    assert "queue" in (rows[0].error or "").lower()
    assert rows[0].finished_at is not None


async def test_the_scan_is_still_visible_after_the_queue_failure(client):
    """It is listed, so the operator sees the failed attempt instead of nothing."""
    _, headers = await token_for("scan-visible@test.local")
    target_id = create_target(client, headers, "10.80.0.3", name="Visible VM")
    client.post("/api/scans", json={"target_id": target_id}, headers=headers)

    listing = client.get("/api/scans", headers=headers)

    assert listing.status_code == 200
    mine = [scan for scan in listing.json() if scan["target_id"] == target_id]
    assert len(mine) == 1
    assert mine[0]["status"] == "failed"
    # Le nom de la cible est aplati par l'API : le front n'a pas d'objet imbriqué.
    assert mine[0]["target_name"] == "Visible VM"
    assert mine[0]["target_value"] == "10.80.0.3"


async def test_a_reader_cannot_launch_a_scan(client):
    """RBAC still comes first: the role check happens before the queue is touched."""
    _, viewer = await token_for("scan-viewer@test.local", role="viewer")

    response = client.post("/api/scans", json={"target_id": 1}, headers=viewer)

    assert response.status_code == 403


async def test_an_out_of_scope_target_is_refused_before_the_queue(client):
    """The guardrail is evaluated before anything else — 403, not 503."""
    _, headers = await token_for("scan-scope@test.local")
    response = client.post(
        "/api/targets",
        json={"name": "Publique", "value": "93.184.216.34", "kind": "ip"},
        headers=headers,
    )
    assert response.status_code == 201
    target_id = response.json()["id"]
    assert response.json()["scope_status"] == "denied"

    blocked = client.post("/api/scans", json={"target_id": target_id}, headers=headers)

    assert blocked.status_code == 403
    assert "scope" in blocked.json()["detail"].lower()
