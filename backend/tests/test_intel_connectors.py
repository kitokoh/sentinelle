"""Threat-intel connectors tests (v0.4, issues #6, #7, #8).

Every connector is driven with a **mocked payload** — no network access, no MISP
instance, no OTX key — which is what the acceptance criteria ask for. The failure
paths matter as much as the happy ones: an unreachable source must degrade to
"nothing ingested", never to an exception.
"""

import json
from datetime import datetime, timezone

import pytest

from app.services.intel import feeds, misp, normalize, otx


# --------------------------------------------------------------------------- #
# Normalisation (shared by every connector)
# --------------------------------------------------------------------------- #


def test_canonical_type_maps_misp_and_otx_labels():
    assert normalize.canonical_type("ip-src") == "ip"
    assert normalize.canonical_type("ip-dst") == "ip"
    assert normalize.canonical_type("IPv4") == "ip"
    assert normalize.canonical_type("hostname") == "domain"
    assert normalize.canonical_type("FileHash-SHA256") == "sha256"
    assert normalize.canonical_type("url") == "url"


def test_canonical_type_refuses_to_guess():
    """An unknown label is dropped — a wrong mapping poisons the correlation."""
    assert normalize.canonical_type("regkey") is None
    assert normalize.canonical_type("") is None
    assert normalize.canonical_type(None) is None


def test_canonical_value_normalises_case_sensitivity_per_type():
    assert normalize.canonical_value("domain", "  EVIL.Example.COM ") == "evil.example.com"
    assert normalize.canonical_value("url", "HTTP://EVIL.EXAMPLE/X") == "http://evil.example/x"
    assert normalize.canonical_value("sha256", "AABBCC") == "aabbcc"
    # IPs keep their case-freedom but no trimming surprises.
    assert normalize.canonical_value("ip", "[2001:DB8::1]") == "2001:db8::1"
    assert normalize.canonical_value("ip", "10.0.0.1") == "10.0.0.1"


def test_candidate_builds_the_common_shape():
    item = normalize.candidate(
        "ip-dst",
        "203.0.113.7",
        "misp",
        severity="high",
        first_seen="2026-09-01T10:00:00Z",
        last_seen="2026-09-02T10:00:00Z",
        metadata={"name": "APT demo"},
    )

    assert item["type"] == "ip"
    assert item["value"] == "203.0.113.7"
    assert item["source"] == "misp"
    assert item["severity"] == "high"
    assert item["first_seen"] < item["last_seen"]
    assert item["metadata"]["name"] == "APT demo"


def test_candidate_is_none_for_unusable_input():
    assert normalize.candidate("regkey", "HKLM\\x", "misp") is None
    assert normalize.candidate("ip", "", "misp") is None
    assert normalize.candidate("ip", None, "misp") is None


def test_candidate_swaps_inverted_dates():
    item = normalize.candidate(
        "domain", "a.example", "otx", first_seen="2026-09-10T00:00:00Z", last_seen="2026-09-01T00:00:00Z"
    )
    assert item["first_seen"] < item["last_seen"]


def test_parse_datetime_handles_epochs_and_offsets():
    assert normalize.parse_datetime(1758000000) == datetime.fromtimestamp(
        1758000000, tz=timezone.utc
    )
    assert normalize.parse_datetime("2026-09-21T03:00:00+0000").tzinfo is not None
    assert normalize.parse_datetime("nonsense") is None
    assert normalize.parse_datetime(None) is None


def test_severity_helpers():
    assert normalize.severity_from_misp_threat_level(1) == "high"
    assert normalize.severity_from_misp_threat_level(3) == "low"
    assert normalize.severity_from_misp_threat_level("x", default="medium") == "medium"
    assert normalize.severity_from_keywords({"tags": ["ransomware"]}) == "high"
    assert normalize.severity_from_keywords({"tags": ["phishing"]}) == "medium"


def test_geo_from_metadata_reads_the_shapes_feeds_actually_use():
    assert normalize.geo_from_metadata({"latitude": 48.85, "longitude": 2.35}) == (48.85, 2.35)
    assert normalize.geo_from_metadata({"lat": "-33.9", "lon": "151.2"}) == (-33.9, 151.2)
    assert normalize.geo_from_metadata({"geo": {"lat": 1.0, "lng": 2.0}}) == (1.0, 2.0)
    # Out-of-range or absent coordinates must not be plotted.
    assert normalize.geo_from_metadata({"latitude": 999, "longitude": 2}) is None
    assert normalize.geo_from_metadata({}) is None


# --------------------------------------------------------------------------- #
# MISP (issue #6)
# --------------------------------------------------------------------------- #

MISP_PAYLOAD = {
    "response": {
        "Attribute": [
            {
                "type": "ip-dst",
                "value": "203.0.113.10",
                "to_ids": True,
                "category": "Network activity",
                "first_seen": "2026-09-01T08:00:00Z",
                "last_seen": "2026-09-15T08:00:00Z",
                "Event": {
                    "info": "Campagne de hameçonnage ciblant le secteur public",
                    "threat_level_id": "1",
                    "Tag": [{"name": "tlp:amber"}, {"name": "phishing"}],
                },
            },
            {
                "type": "hostname",
                "value": "Malicious.Example",
                "timestamp": "1758000000",
                "Event": {"info": "Autre événement", "threat_level_id": "3"},
            },
            # An attribute type we do not model must be ignored, not guessed.
            {"type": "regkey", "value": "HKLM\\Software\\X", "Event": {}},
        ]
    }
}


def test_misp_parses_attributes_into_normalised_iocs():
    candidates = misp.parse_attributes(MISP_PAYLOAD)

    assert len(candidates) == 2
    by_value = {item["value"]: item for item in candidates}

    ip = by_value["203.0.113.10"]
    assert ip["type"] == "ip"
    assert ip["source"] == "misp"
    # threat_level_id 1 -> high, and the event info rides along as metadata.
    assert ip["severity"] == "high"
    assert "hameçonnage" in ip["metadata"]["name"]
    assert ip["metadata"]["tags"] == ["tlp:amber", "phishing"]

    host = by_value["malicious.example"]
    assert host["type"] == "domain"
    assert host["severity"] == "low"  # threat_level_id 3


def test_misp_tolerates_an_empty_or_malformed_response():
    assert misp.parse_attributes({}) == []
    assert misp.parse_attributes({"response": {}}) == []
    assert misp.parse_attributes({"response": {"Attribute": [None, "x"]}}) == []


async def test_misp_degrades_cleanly_when_unreachable():
    """'Dégradation propre sans connectivité' — the sync must not raise."""
    class ExplodingClient:
        async def post(self, *args, **kwargs):
            raise __import__("httpx").ConnectError("no route to host")

    candidates = await misp.fetch_attributes(
        "https://misp.lab", "key", client=ExplodingClient()
    )
    assert candidates == []


async def test_misp_fetch_sends_the_key_in_the_authorization_header():
    captured: dict = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return MISP_PAYLOAD

    class FakeClient:
        async def post(self, url, json=None, headers=None):
            captured["url"] = url
            captured["headers"] = headers
            captured["body"] = json
            return FakeResponse()

    candidates = await misp.fetch_attributes(
        "https://misp.lab/", "secret-key", lookback_days=7, limit=10, client=FakeClient()
    )

    assert captured["url"] == "https://misp.lab/attributes/restSearch"
    assert captured["headers"]["Authorization"] == "secret-key"
    assert captured["body"]["last"] == "7d"
    assert captured["body"]["limit"] == 10
    assert len(candidates) == 2


# --------------------------------------------------------------------------- #
# AlienVault OTX (issue #7)
# --------------------------------------------------------------------------- #

OTX_PAYLOAD = {
    "results": [
        {
            "id": "pulse-1",
            "name": "Ransomware campaign against public sector",
            "tags": ["ransomware", "c2"],
            "author_name": "analyst",
            "targeted_countries": ["France"],
            "created": "2026-09-01T00:00:00",
            "modified": "2026-09-10T00:00:00",
            "references": ["https://example.org/report"],
            "indicators": [
                {"type": "IPv4", "indicator": "198.51.100.23", "created": "2026-09-02T00:00:00"},
                {"type": "domain", "indicator": "C2.Example", "created": "2026-09-02T00:00:00"},
                {"type": "FileHash-MD5", "indicator": "D41D8CD98F00B204E9800998ECF8427E"},
                {"type": "YARA", "indicator": "rule demo { }"},
            ],
        }
    ]
}


def test_otx_parses_pulses_into_normalised_iocs():
    candidates = otx.parse_pulses(OTX_PAYLOAD)

    assert len(candidates) == 3  # the YARA rule is not an indicator we model
    by_value = {item["value"]: item for item in candidates}

    assert by_value["198.51.100.23"]["type"] == "ip"
    assert by_value["198.51.100.23"]["source"] == "otx"
    # "ransomware" in the pulse tags escalates the whole pulse.
    assert by_value["198.51.100.23"]["severity"] == "high"
    assert by_value["c2.example"]["type"] == "domain"
    assert by_value["d41d8cd98f00b204e9800998ecf8427e"]["type"] == "md5"
    # Pulse context is preserved for the analyst.
    assert by_value["198.51.100.23"]["metadata"]["targeted_countries"] == ["France"]
    assert by_value["198.51.100.23"]["metadata"]["pulse_id"] == "pulse-1"


def test_otx_carries_indicator_geo_through():
    payload = {
        "results": [
            {
                "name": "geo pulse",
                "indicators": [
                    {"type": "IPv4", "indicator": "203.0.113.99", "geo": {"latitude": 55.75, "longitude": 37.61}}
                ],
            }
        ]
    }
    item = otx.parse_pulses(payload)[0]
    assert normalize.geo_from_metadata(item["metadata"]) == (55.75, 37.61)


def test_otx_handles_an_empty_payload():
    assert otx.parse_pulses({}) == []
    assert otx.parse_pulses({"results": []}) == []


async def test_otx_without_an_api_key_is_disabled_not_broken():
    assert await otx.fetch_pulses("") == []


async def test_otx_degrades_cleanly_on_http_errors():
    class FakeResponse:
        def raise_for_status(self):
            raise __import__("httpx").HTTPStatusError("401", request=None, response=None)

    class FakeClient:
        async def get(self, *args, **kwargs):
            return FakeResponse()

    assert await otx.fetch_pulses("bad-key", client=FakeClient()) == []


# --------------------------------------------------------------------------- #
# CERT feeds (issue #8)
# --------------------------------------------------------------------------- #

RSS_DOCUMENT = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>CERT-FR</title>
    <item>
      <title>Multiples vulnérabilités dans Apache HTTP Server</title>
      <link>https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0001/</link>
      <guid>https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0001/</guid>
      <description>&lt;p&gt;Le 21 septembre 2026, l'éditeur a publié des correctifs.&lt;/p&gt;</description>
      <pubDate>Mon, 21 Sep 2026 08:30:00 GMT</pubDate>
    </item>
    <item>
      <title>Avis sans guid</title>
      <link>https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0002/</link>
      <pubDate>Sun, 20 Sep 2026 08:30:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""

ATOM_DOCUMENT = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>CISA Advisories</title>
  <entry>
    <title>ICS Advisory Demo</title>
    <link href="https://www.cisa.gov/news-events/ics-advisories/icsa-26-001"/>
    <id>urn:cisa:icsa-26-001</id>
    <summary>An advisory summary.</summary>
    <updated>2026-09-19T12:00:00Z</updated>
  </entry>
</feed>
"""


def test_parse_feed_spec_accepts_named_and_bare_urls():
    spec = "CERT-FR=https://www.cert.ssi.gouv.fr/feed/, https://example.org/rss"
    parsed = feeds.parse_feed_spec(spec)

    assert parsed[0] == ("CERT-FR", "https://www.cert.ssi.gouv.fr/feed/")
    assert parsed[1][1] == "https://example.org/rss"
    assert parsed[1][0] == "example.org"  # name falls back to the hostname


def test_parse_feed_spec_ignores_blank_entries():
    assert feeds.parse_feed_spec("") == []
    assert feeds.parse_feed_spec("  ,  ") == []


def test_parse_rss_document():
    items = feeds.parse_feed(RSS_DOCUMENT, source="CERT-FR")

    assert len(items) == 2
    first = items[0]
    assert first["title"].startswith("Multiples vulnérabilités")
    assert first["guid"] == "https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0001/"
    assert first["source"] == "CERT-FR"
    # HTML markup is stripped from the summary, the words are kept.
    assert first["summary"].startswith("Le 21 septembre 2026")
    assert "<p>" not in first["summary"]
    # RFC 822 pubDate is parsed.
    assert first["published_at"].year == 2026
    assert first["published_at"].month == 9


def test_parse_rss_falls_back_to_the_link_as_guid():
    items = feeds.parse_feed(RSS_DOCUMENT, source="CERT-FR")
    assert items[1]["guid"] == "https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0002/"


def test_parse_atom_document():
    items = feeds.parse_feed(ATOM_DOCUMENT, source="CISA")

    assert len(items) == 1
    assert items[0]["guid"] == "urn:cisa:icsa-26-001"
    assert items[0]["link"] == "https://www.cisa.gov/news-events/ics-advisories/icsa-26-001"
    assert items[0]["summary"] == "An advisory summary."
    assert items[0]["published_at"].isoformat().startswith("2026-09-19T12:00")


def test_parse_feed_returns_empty_on_malformed_xml():
    assert feeds.parse_feed("<rss><channel><item>", "broken") == []
    assert feeds.parse_feed("", "empty") == []


async def test_fetch_feeds_skips_the_broken_one_and_keeps_the_good_one():
    """One dead feed must never stop the others from being ingested."""

    class FakeResponse:
        def __init__(self, text):
            self.text = text

        def raise_for_status(self):
            return None

    class FakeClient:
        async def get(self, url, headers=None):
            if "broken" in url:
                raise __import__("httpx").ConnectError("dns failure")
            return FakeResponse(ATOM_DOCUMENT)

    items = await feeds.fetch_feeds(
        [("CERT-FR", "https://broken.example/feed"), ("CISA", "https://ok.example/feed")],
        client=FakeClient(),
    )

    assert len(items) == 1
    assert items[0]["source"] == "CISA"


async def test_fetch_feeds_bounds_the_number_of_items_per_feed():
    class FakeResponse:
        text = ATOM_DOCUMENT

        def raise_for_status(self):
            return None

    class FakeClient:
        async def get(self, url, headers=None):
            return FakeResponse()

    items = await feeds.fetch_feeds([("CISA", "https://ok.example")], client=FakeClient(), per_feed_limit=1)
    assert len(items) == 1
