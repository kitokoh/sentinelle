"""Shared normalisation for threat-intel sources (v0.4, issues #6–#9).

Every connector — MISP, AlienVault OTX, a CERT feed — speaks its own dialect.
This module is the single place that turns those dialects into one shape:

    {"type", "value", "source", "severity", "first_seen", "last_seen", "metadata"}

Keeping it here (rather than duplicated in each connector) is what makes
cross-source de-duplication possible at all: two feeds agree only if they are
canonicalised the same way.
"""

from datetime import datetime, timezone
from typing import Any, Optional

#: Canonical indicator families.
IOC_TYPES = ("ip", "domain", "url", "md5", "sha1", "sha256", "email")

#: Every source-specific label mapped onto a canonical type. A type we do not
#: know is dropped, never guessed — a wrong normalisation poisons the correlation.
_TYPE_ALIASES: dict[str, str] = {
    # MISP attribute types
    "ip": "ip",
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip-src|port": "ip",
    "ip-dst|port": "ip",
    "domain": "domain",
    "hostname": "domain",
    "domain|ip": "domain",
    "url": "url",
    "uri": "url",
    "link": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email": "email",
    "email-src": "email",
    # AlienVault OTX indicator types
    "ipv4": "ip",
    "ipv6": "ip",
    "filehash-md5": "md5",
    "filehash-sha1": "sha1",
    "filehash-sha256": "sha256",
    "filepath": "url",
    "mutex": "domain",
}

#: MISP event threat levels.
_MISP_THREAT_LEVELS = {1: "high", 2: "medium", 3: "low", 4: "info"}

#: Keywords that justify raising an otherwise unqualified indicator.
_SEVERE_KEYWORDS = ("ransomware", "apt", "backdoor", "rat", "exploit", "zero-day", "0day")


def canonical_type(raw: Any) -> Optional[str]:
    """Map a source-specific type label to a canonical one (or ``None``)."""
    if not isinstance(raw, str):
        return None
    return _TYPE_ALIASES.get(raw.strip().lower())


def canonical_value(ioc_type: str, value: Any) -> Optional[str]:
    """Clean up an indicator value so identical indicators compare equal."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    # Domains, URLs and emails are case-insensitive; hashes are conventionally
    # lower-cased; IPs are normalised. Everything else is left alone.
    if ioc_type in ("domain", "url", "email", "md5", "sha1", "sha256"):
        return text.lower()
    if ioc_type == "ip":
        return text.lower().strip("[]")
    return text


def parse_datetime(value: Any) -> Optional[datetime]:
    """Best-effort ISO-8601 / epoch parsing, always returning an aware datetime."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        # OTX mixes epochs (seconds) and ISO strings.
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip().replace("Z", "+00:00")
    if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
        text = f"{text[:-2]}:{text[-2:]}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def severity_from_keywords(metadata: dict, default: str = "medium") -> str:
    """Raise the severity when the feed's own tags say something serious."""
    haystack = " ".join(
        str(part)
        for part in (
            metadata.get("tags", []),
            metadata.get("name", ""),
            metadata.get("category", ""),
            metadata.get("description", ""),
        )
    ).lower()
    return "high" if any(keyword in haystack for keyword in _SEVERE_KEYWORDS) else default


def severity_from_misp_threat_level(level: Any, default: str = "medium") -> str:
    try:
        return _MISP_THREAT_LEVELS.get(int(level), default)
    except (TypeError, ValueError):
        return default


def geo_from_metadata(metadata: dict) -> Optional[tuple[float, float]]:
    """Extract a ``(latitude, longitude)`` pair when the feed provides one.

    The map in #10 is built only from what the sources give us — no geolocation
    service is called, so no indicator is ever sent to a third party just to be
    plotted.
    """
    candidates = (
        ("latitude", "longitude"),
        ("lat", "lon"),
        ("lat", "lng"),
    )
    for lat_key, lon_key in candidates:
        try:
            lat = float(metadata[lat_key])
            lon = float(metadata[lon_key])
        except (KeyError, TypeError, ValueError):
            continue
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            return lat, lon

    geo = metadata.get("geo")
    if isinstance(geo, dict):
        return geo_from_metadata(geo)
    return None


def candidate(
    ioc_type: Any,
    value: Any,
    source: str,
    *,
    severity: str = "medium",
    first_seen: Any = None,
    last_seen: Any = None,
    metadata: Optional[dict] = None,
) -> Optional[dict]:
    """Build a normalised IoC candidate, or ``None`` if it is unusable."""
    mapped = canonical_type(ioc_type)
    if mapped is None:
        return None
    cleaned = canonical_value(mapped, value)
    if not cleaned:
        return None

    now = datetime.now(timezone.utc)
    first = parse_datetime(first_seen) or parse_datetime(last_seen) or now
    last = parse_datetime(last_seen) or first
    if last < first:
        first, last = last, first

    return {
        "type": mapped,
        "value": cleaned,
        "source": source,
        "severity": severity,
        "first_seen": first,
        "last_seen": last,
        "metadata": metadata or {},
    }
