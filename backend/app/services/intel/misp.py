"""MISP connector — pull attributes as normalised IoCs (v0.4, issue #6).

Design constraints worth stating:

* **No connectivity must be survivable.** Every function returns a (possibly
  empty) list and logs; a MISP instance that is down or misconfigured can never
  take the worker down with it. That is the "dégradation propre" criterion.
* **Unconfigured = disabled.** With no ``MISP_URL``/``MISP_API_KEY`` the sync
  job reports ``skipped`` instead of failing.
* The REST search is POSTed with the key in the ``Authorization`` header (MISP
  supports both header and body auth; the header keeps the key out of logs).
"""

import logging
from typing import Any, Optional

import httpx

from app.services.intel.normalize import candidate, severity_from_misp_threat_level

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15.0

#: MISP attribute types we ask for explicitly — narrowing the search server-side
#: keeps the payload small on a busy instance.
REQUESTED_TYPES = [
    "ip-src",
    "ip-dst",
    "domain",
    "hostname",
    "url",
    "md5",
    "sha1",
    "sha256",
    "email-src",
]


def _event_metadata(event: dict, attribute: dict) -> dict:
    """Metadata carried onto the IoC — pulse/event context the analyst will want."""
    return {
        "name": (event or {}).get("info") or attribute.get("comment") or "",
        "category": attribute.get("category", ""),
        "tags": [
            tag.get("name")
            for tag in ((event or {}).get("Tag") or [])
            if isinstance(tag, dict) and tag.get("name")
        ],
        "threat_level_id": (event or {}).get("threat_level_id"),
        "to_ids": attribute.get("to_ids"),
        "misp_type": attribute.get("type"),
    }


def parse_attributes(payload: dict, source: str = "misp") -> list[dict]:
    """Turn a MISP ``restSearch`` response into normalised IoC candidates.

    Split out from the HTTP call so tests can drive it with a mocked payload —
    which is exactly what the acceptance criterion asks for.
    """
    attributes = ((payload or {}).get("response") or {}).get("Attribute") or []
    results: list[dict] = []

    for attribute in attributes:
        if not isinstance(attribute, dict):
            continue
        event = attribute.get("Event") or {}
        metadata = _event_metadata(event, attribute)
        normalized = candidate(
            attribute.get("type"),
            attribute.get("value"),
            source,
            severity=severity_from_misp_threat_level(metadata.get("threat_level_id")),
            first_seen=attribute.get("first_seen") or attribute.get("timestamp"),
            last_seen=attribute.get("last_seen") or attribute.get("timestamp"),
            metadata=metadata,
        )
        if normalized is not None:
            results.append(normalized)
    return results


async def fetch_attributes(
    base_url: str,
    api_key: str,
    *,
    lookback_days: int = 30,
    limit: int = 500,
    client: Optional[httpx.AsyncClient] = None,
    source: str = "misp",
) -> list[dict]:
    """Pull recent attributes from MISP. Never raises."""
    url = f"{base_url.rstrip('/')}/attributes/restSearch"
    body: dict[str, Any] = {
        "returnFormat": "json",
        "type": REQUESTED_TYPES,
        "last": f"{int(lookback_days)}d",
        "limit": int(limit),
        "to_ids": True,
        "includeContext": True,
    }
    headers = {"Authorization": api_key, "Accept": "application/json"}

    try:
        if client is not None:
            response = await client.post(url, json=body, headers=headers)
        else:
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as owned:
                response = await owned.post(url, json=body, headers=headers)
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        # Degradation propre: log and continue with nothing.
        logger.warning("MISP sync skipped (%s): %s", base_url, exc)
        return []

    candidates = parse_attributes(payload, source=source)
    logger.info("MISP sync: %s attribute(s) retrieved from %s", len(candidates), base_url)
    return candidates
