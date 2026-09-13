"""NVD API 2.0 client — best-effort CVE lookup by service/version keyword.

Used by the worker to enrich nmap service findings with known CVEs. This is
strictly best-effort: ANY failure (network error, rate limit, malformed
payload) returns an empty list silently, so a flaky NVD can never break a
scan. Results are cached in a module-level dict keyed by
(service.lower(), version.lower()) for the lifetime of the process.
"""

import httpx

from app.core.config import get_settings

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Simple process-lifetime cache: (service.lower(), version.lower()) -> CVE list.
_CVE_CACHE: dict[tuple[str, str], list[dict]] = {}


def severity_from_cvss(cvss: float) -> str:
    """Map a CVSS base score to our severity scale."""
    if cvss >= 9:
        return "critical"
    if cvss >= 7:
        return "high"
    if cvss >= 4:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _extract_cve(cve: dict) -> dict | None:
    """Extract {cve_id, severity, cvss, description} from one NVD `cve` object.

    CVSS v3.x (baseSeverity/baseScore) is preferred, with a fallback to v2.
    """
    cve_id = cve.get("id") or ""
    if not cve_id:
        return None

    description = ""
    for entry in cve.get("descriptions") or []:
        if entry.get("lang") == "en":
            description = entry.get("value") or ""
            break

    metrics = cve.get("metrics") or {}
    severity = ""
    cvss = 0.0
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key) or []
        if not entries:
            continue
        cvss_data = entries[0].get("cvssData") or {}
        try:
            cvss = float(cvss_data.get("baseScore") or 0.0)
        except (TypeError, ValueError):
            cvss = 0.0
        # v3.x: baseSeverity lives in cvssData (and usually on the metric entry
        # too); v2: only on the metric entry.
        severity = entries[0].get("baseSeverity") or cvss_data.get("baseSeverity") or ""
        break

    severity = severity.strip().lower()
    if severity not in ("critical", "high", "medium", "low"):
        severity = severity_from_cvss(cvss)

    return {"cve_id": cve_id, "severity": severity, "cvss": cvss, "description": description}


def _parse_response(payload: dict) -> list[dict]:
    """Parse an NVD 2.0 response body into at most 3 CVE dicts."""
    results: list[dict] = []
    for item in (payload.get("vulnerabilities") or [])[:3]:
        parsed = _extract_cve(item.get("cve") or {})
        if parsed is not None:
            results.append(parsed)
    return results


async def lookup_cves(service: str, version: str, api_key: str | None = None) -> list[dict]:
    """Look up CVEs for a service/version pair via the NVD API 2.0.

    Returns the top 3 matches as {cve_id, severity, cvss, description} dicts.
    Returns [] on ANY error — NVD must never break a scan.
    """
    cache_key = (service.lower(), version.lower())
    if cache_key in _CVE_CACHE:
        return _CVE_CACHE[cache_key]

    if api_key is None:
        api_key = get_settings().NVD_API_KEY

    headers = {"apiKey": api_key} if api_key else {}
    params = {"keywordSearch": f"{service} {version}", "resultsPerPage": 5}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(NVD_API_URL, params=params, headers=headers)
            response.raise_for_status()
            payload = response.json()
        results = _parse_response(payload)
    except Exception:  # noqa: BLE001 — network / rate-limit / parse errors are non-fatal
        return []

    # Only successful round-trips are cached: a transient failure may be retried.
    _CVE_CACHE[cache_key] = results
    return results
