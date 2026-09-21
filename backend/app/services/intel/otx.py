"""AlienVault OTX connector — subscribed pulses as normalised IoCs (v0.4, #7).

OTX returns its indicators nested inside *pulses*; each indicator is normalised
through the shared layer so an IP already known to MISP merges into the same
``iocs`` row (see app/services/intel/store.py).

The API key travels in the ``X-OTX-API-KEY`` header and is never logged.
"""

import logging
from typing import Any, Optional

import httpx

from app.services.intel.normalize import candidate, severity_from_keywords

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 20.0
SUBSCRIBED_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"


def parse_pulses(payload: dict, source: str = "otx") -> list[dict]:
    """Turn an OTX ``pulses/subscribed`` response into normalised IoC candidates."""
    results: list[dict] = []

    for pulse in (payload or {}).get("results") or []:
        if not isinstance(pulse, dict):
            continue
        metadata = {
            "name": pulse.get("name", ""),
            "tags": pulse.get("tags") or [],
            "author": pulse.get("author_name", ""),
            "tlp": pulse.get("tlp", ""),
            "targeted_countries": pulse.get("targeted_countries") or [],
            "references": (pulse.get("references") or [])[:5],
        }
        severity = severity_from_keywords(metadata)
        created = pulse.get("created")
        modified = pulse.get("modified") or created

        for indicator in pulse.get("indicators") or []:
            if not isinstance(indicator, dict):
                continue
            normalized = candidate(
                indicator.get("type"),
                indicator.get("indicator"),
                source,
                severity=severity,
                first_seen=indicator.get("created") or created,
                last_seen=modified,
                metadata={
                    **metadata,
                    "pulse_id": pulse.get("id", ""),
                    # OTX sometimes ships geo information with the indicator.
                    **(indicator.get("geo") or {}),
                },
            )
            if normalized is not None:
                results.append(normalized)
    return results


async def fetch_pulses(
    api_key: str,
    *,
    limit: int = 20,
    modified_since: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    source: str = "otx",
) -> list[dict]:
    """Pull subscribed OTX pulses. Never raises — a missing key means "disabled"."""
    if not api_key:
        logger.info("OTX sync skipped: no API key configured")
        return []

    params: dict[str, Any] = {"limit": int(limit)}
    if modified_since:
        params["modified_since"] = modified_since
    headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}

    try:
        if client is not None:
            response = await client.get(SUBSCRIBED_URL, params=params, headers=headers)
        else:
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as owned:
                response = await owned.get(SUBSCRIBED_URL, params=params, headers=headers)
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("OTX sync skipped: %s", exc)
        return []

    candidates = parse_pulses(payload, source=source)
    logger.info("OTX sync: %s indicator(s) retrieved", len(candidates))
    return candidates
