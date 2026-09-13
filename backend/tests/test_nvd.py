"""NVD client tests — fake NVD 2.0 payloads, monkeypatched httpx (no real network)."""

import httpx
import pytest

from app.services import nvd

FAKE_NVD_PAYLOAD = {
    "resultsPerPage": 5,
    "totalResults": 4,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [
                    {"lang": "fr", "value": "Traversée de répertoire Apache"},
                    {"lang": "en", "value": "Apache HTTP Server 2.4.49 path traversal"},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                            "baseSeverity": "CRITICAL",
                            "exploitabilityScore": 3.9,
                        }
                    ],
                    # v2 also present — v3 must win.
                    "cvssMetricV2": [
                        {
                            "type": "Secondary",
                            "cvssData": {"version": "2.0", "baseScore": 7.5},
                            "baseSeverity": "HIGH",
                        }
                    ],
                },
            }
        },
        {
            "cve": {
                "id": "CVE-2017-15710",
                "descriptions": [{"lang": "en", "value": "Apache ldap out-of-bounds write"}],
                "metrics": {
                    # v2 only — exercises the fallback path.
                    "cvssMetricV2": [
                        {
                            "type": "Primary",
                            "cvssData": {"version": "2.0", "baseScore": 5.0},
                            "baseSeverity": "MEDIUM",
                        }
                    ]
                },
            }
        },
        {
            "cve": {
                "id": "CVE-2021-44790",
                "descriptions": [{"lang": "en", "value": "mod_lua buffer overflow"}],
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.0",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                            },
                            "baseSeverity": "HIGH",
                        }
                    ]
                },
            }
        },
        {
            # 4th entry — must be cut off by the top-3 limit.
            "cve": {
                "id": "CVE-1999-0001",
                "descriptions": [{"lang": "en", "value": "ancient"}],
                "metrics": {},
            }
        },
    ],
}


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeAsyncClient:
    """Mimics the subset of httpx.AsyncClient used by app.services.nvd."""

    calls: list[dict] = []
    error: Exception | None = None
    payload: object = FAKE_NVD_PAYLOAD

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def get(self, url, params=None, headers=None):
        type(self).calls.append({"url": url, "params": params, "headers": headers})
        if type(self).error is not None:
            raise type(self).error
        return _FakeResponse(type(self).payload)


@pytest.fixture
def fake_nvd(monkeypatch):
    """Patch httpx.AsyncClient inside services/nvd and reset state per test."""
    nvd._CVE_CACHE.clear()
    _FakeAsyncClient.calls = []
    _FakeAsyncClient.error = None
    _FakeAsyncClient.payload = FAKE_NVD_PAYLOAD
    monkeypatch.setattr(nvd.httpx, "AsyncClient", _FakeAsyncClient)
    yield _FakeAsyncClient
    nvd._CVE_CACHE.clear()


async def test_lookup_returns_top3_with_severity_mapping(fake_nvd):
    results = await nvd.lookup_cves("apache httpd", "2.4.49")

    assert len(results) == 3
    # v3.1 preferred over the v2 entry on the same CVE.
    assert results[0] == {
        "cve_id": "CVE-2021-41773",
        "severity": "critical",
        "cvss": 9.8,
        "description": "Apache HTTP Server 2.4.49 path traversal",
    }
    # v2-only fallback: baseScore/baseSeverity taken from cvssMetricV2.
    assert results[1]["cve_id"] == "CVE-2017-15710"
    assert results[1]["severity"] == "medium"
    assert results[1]["cvss"] == 5.0
    # v3.0 also accepted.
    assert results[2]["cve_id"] == "CVE-2021-44790"
    assert results[2]["severity"] == "high"
    assert results[2]["cvss"] == 7.5

    # The request itself hits the NVD 2.0 API with the right query.
    assert len(fake_nvd.calls) == 1
    call = fake_nvd.calls[0]
    assert call["url"] == nvd.NVD_API_URL
    assert call["params"]["keywordSearch"] == "apache httpd 2.4.49"
    assert call["params"]["resultsPerPage"] == 5
    assert call["headers"] == {}  # no NVD_API_KEY configured in tests


async def test_lookup_sends_api_key_header_when_provided(fake_nvd):
    await nvd.lookup_cves("openssl", "1.1.1", api_key="test-key-123")
    assert fake_nvd.calls[0]["headers"] == {"apiKey": "test-key-123"}


async def test_cache_hit_avoids_second_http_call(fake_nvd):
    first = await nvd.lookup_cves("nginx", "1.18.0")
    second = await nvd.lookup_cves("NGINX", "1.18.0")  # same key after lowercasing
    third = await nvd.lookup_cves("nginx", "1.18.0")

    assert first == second == third
    assert len(fake_nvd.calls) == 1  # only one HTTP round-trip


async def test_http_error_returns_empty_list(fake_nvd):
    fake_nvd.error = httpx.ConnectError("boom")
    assert await nvd.lookup_cves("openssh", "8.9") == []
    assert len(fake_nvd.calls) == 1

    # Errors are NOT cached: a later call retries and succeeds.
    fake_nvd.error = None
    assert len(await nvd.lookup_cves("openssh", "8.9")) == 3
    assert len(fake_nvd.calls) == 2


async def test_malformed_payload_returns_empty_list(fake_nvd):
    fake_nvd.payload = ["not", "a", "dict"]
    assert await nvd.lookup_cves("mysql", "5.7") == []
