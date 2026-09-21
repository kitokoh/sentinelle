"""IoC ↔ observed correlation (v0.4, issue #9) — "le nerf de la guerre".

Matches the indicators we hold against what the platform actually observed:
alerts (sensor + detection rules) and findings (nmap / nuclei / CVE).

Two decisions worth defending:

* **A match is always at least ``high``.** An indicator that a feed bothered to
  publish is not a low-severity observation; downgrading it below high would bury
  it in the alert stream. A more severe indicator stays more severe.
* **A match is raised once, ever.** The dedup key embeds the indicator *and* the
  matched entity, and unlike the detection engine there is no time window: a match
  that was already reported last week is not reported again. Rescanning an asset
  does not re-alert on intel it already hit.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import or_
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Alert, Finding, Ioc
from app.services.intel.store import SEVERITY_ORDER

logger = logging.getLogger(__name__)

#: Matching on free text (detail/signature) is a LIKE scan — bound it.
MAX_MATCHES_PER_IOC = 25
#: Hard ceiling on alerts created by a single correlation run.
MAX_ALERTS_PER_RUN = 200
#: The floor every intel match is raised to.
SEVERITY_FLOOR = "high"


def _severity_for(ioc_severity: str) -> str:
    """Escalate to at least ``high`` without ever downgrading a critical IoC."""
    current = ioc_severity if ioc_severity in SEVERITY_ORDER else "medium"
    floor_index = SEVERITY_ORDER.index(SEVERITY_FLOOR)
    current_index = SEVERITY_ORDER.index(current)
    return SEVERITY_ORDER[max(current_index, floor_index)]


def _alert_filters(ioc: Ioc):
    """How an indicator is looked up among alerts, per indicator type."""
    if ioc.type == "ip":
        return or_(Alert.src_ip == ioc.value, Alert.dst_ip == ioc.value)
    if ioc.type in ("domain", "url"):
        pattern = f"%{ioc.value}%"
        return or_(Alert.detail.like(pattern), Alert.signature.like(pattern))
    pattern = f"%{ioc.value}%"
    return or_(Alert.detail.like(pattern), Alert.signature.like(pattern))


def _finding_filter(ioc: Ioc):
    """Findings only carry free text, whatever the indicator type."""
    return Finding.detail.like(f"%{ioc.value}%")


def _match_detail(ioc: Ioc, entity: str, description: str) -> str:
    return (
        f"Indicator {ioc.type} {ioc.value} (source: {ioc.sources}, severity {ioc.severity}) "
        f"matched {entity}: {description}"
    )


def _payload(ioc: Ioc, entity_kind: str, entity_id: int, extra: dict) -> str:
    return json.dumps(
        {
            "ioc": {"type": ioc.type, "value": ioc.value, "sources": ioc.sources},
            "entity": entity_kind,
            "entity_id": entity_id,
            **extra,
        },
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )


def dedup_key(ioc: Ioc, entity_kind: str, entity_id: int) -> str:
    return f"intel|{ioc.type}|{ioc.value}|{entity_kind}:{entity_id}"


async def correlate_iocs(
    session: AsyncSession,
    now: Optional[datetime] = None,
    *,
    ioc_limit: int = 1000,
    max_alerts: int = MAX_ALERTS_PER_RUN,
) -> dict[str, int]:
    """Match stored indicators against local alerts and findings.

    Returns counters the worker logs — an operator must be able to tell
    "nothing matched" from "the correlator did not run".
    """
    moment = now or datetime.now(timezone.utc)

    iocs = list(
        (
            await session.exec(
                select(Ioc).order_by(Ioc.last_seen.desc()).limit(ioc_limit)
            )
        ).all()
    )

    counters = {
        "iocs_evaluated": len(iocs),
        "alert_matches": 0,
        "finding_matches": 0,
        "alerts_created": 0,
        "alerts_skipped": 0,
    }
    if not iocs:
        logger.info("intel correlation: no indicator stored yet")
        return counters

    existing_keys: set[str] = set()
    for ioc in iocs:
        severity = _severity_for(ioc.severity)

        matched_alerts = list(
            (
                await session.exec(
                    select(Alert)
                    .where(Alert.source != "intel")
                    .where(_alert_filters(ioc))
                    .order_by(Alert.created_at.desc())
                    .limit(MAX_MATCHES_PER_IOC)
                )
            ).all()
        )
        matched_findings = list(
            (
                await session.exec(
                    select(Finding).where(_finding_filter(ioc)).limit(MAX_MATCHES_PER_IOC)
                )
            ).all()
        )

        counters["alert_matches"] += len(matched_alerts)
        counters["finding_matches"] += len(matched_findings)

        for alert in matched_alerts:
            key = dedup_key(ioc, "alert", alert.id)
            if key in existing_keys or await _already_reported(session, key):
                counters["alerts_skipped"] += 1
                continue
            if counters["alerts_created"] >= max_alerts:
                counters["alerts_skipped"] += 1
                continue
            session.add(
                Alert(
                    source="intel",
                    event_type=f"ioc_match_{ioc.type}",
                    severity=severity,
                    src_ip=alert.src_ip,
                    src_port=alert.src_port,
                    dst_ip=alert.dst_ip,
                    dst_port=alert.dst_port,
                    proto=alert.proto,
                    rule_name=None,
                    confidence=1.0,
                    detail=_match_detail(ioc, f"alert #{alert.id}", alert.detail[:300]),
                    payload=_payload(
                        ioc,
                        "alert",
                        alert.id,
                        {
                            "matched_alert": {
                                "id": alert.id,
                                "source": alert.source,
                                "severity": alert.severity,
                                "detail": alert.detail[:300],
                            }
                        },
                    ),
                    status="new",
                    created_at=moment,
                    dedup_key=key,
                )
            )
            existing_keys.add(key)
            counters["alerts_created"] += 1

        for finding in matched_findings:
            key = dedup_key(ioc, "finding", finding.id)
            if key in existing_keys or await _already_reported(session, key):
                counters["alerts_skipped"] += 1
                continue
            if counters["alerts_created"] >= max_alerts:
                counters["alerts_skipped"] += 1
                continue
            session.add(
                Alert(
                    source="intel",
                    event_type=f"ioc_match_{ioc.type}",
                    severity=severity,
                    src_ip=None,
                    dst_ip=None,
                    dst_port=finding.port or None,
                    proto=finding.protocol,
                    detail=_match_detail(ioc, f"finding #{finding.id}", finding.detail[:300]),
                    payload=_payload(
                        ioc,
                        "finding",
                        finding.id,
                        {
                            "matched_finding": {
                                "id": finding.id,
                                "scan_id": finding.scan_id,
                                "source": finding.source,
                                "service": finding.service,
                                "detail": finding.detail[:300],
                            }
                        },
                    ),
                    status="new",
                    created_at=moment,
                    dedup_key=key,
                )
            )
            existing_keys.add(key)
            counters["alerts_created"] += 1

    await session.commit()
    logger.info("intel correlation: %s", counters)
    return counters


async def _already_reported(session: AsyncSession, key: str) -> bool:
    """Has this exact indicator/entity pair already produced an alert?"""
    row = await session.exec(select(Alert.id).where(Alert.dedup_key == key))
    return row.first() is not None


async def recent_matches(session: AsyncSession, limit: int = 50) -> list[Alert]:
    """Read side: the intel alerts, newest first (drives the investigation view)."""
    rows = await session.exec(
        select(Alert)
        .where(Alert.source == "intel")
        .order_by(Alert.created_at.desc(), Alert.id.desc())
        .limit(limit)
    )
    return list(rows.all())

