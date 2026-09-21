"""CERT advisory feeds — RSS 2.0 / Atom aggregation (v0.4, issue #8).

Parsed with the standard library only: an advisory feed is a well-formed XML
document, and pulling in a full feed-parsing dependency for two element shapes
(RSS ``item`` / Atom ``entry``) is not worth the supply-chain surface.

Supported per item: title, link, summary/description, publication date and a
dedup key (the feed's GUID, falling back to the link). Namespaces are ignored
deliberately — the element's *local* name is what matters, which keeps CERT-FR,
CISA and friends working without a per-feed mapping table.
"""

import html
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

import httpx

from app.services.intel.normalize import parse_datetime

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15.0
SUMMARY_MAX_LENGTH = 1200

_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def parse_feed_spec(spec: str) -> list[tuple[str, str]]:
    """Parse the ``CERT_FEEDS`` setting into ``[(name, url)]``.

    Format: ``NAME=URL`` entries separated by commas or newlines. Entries without
    a name fall back to the URL's hostname, so a bare URL still works.
    """
    feeds: list[tuple[str, str]] = []
    for entry in re.split(r"[,\n]", spec or ""):
        entry = entry.strip()
        if not entry:
            continue
        name, _, url = entry.partition("=")
        if not url:
            name, url = "", name
        url = url.strip()
        if not url:
            continue
        feeds.append((name.strip() or url.split("//")[-1].split("/")[0], url))
    return feeds


def _local(tag: str) -> str:
    """Element local name, lower-cased: ``{ns}entry`` -> ``entry``."""
    return tag.rsplit("}", 1)[-1].lower()


def _text(element: Optional[ET.Element]) -> str:
    if element is None:
        return ""
    return _WHITESPACE_RE.sub(" ", (element.text or "")).strip()


def _clean_html(value: str) -> str:
    """Advisories routinely ship HTML summaries; keep the words, drop the markup."""
    without_tags = _TAG_RE.sub(" ", value or "")
    text = _WHITESPACE_RE.sub(" ", html.unescape(without_tags)).strip()
    return text[:SUMMARY_MAX_LENGTH]


def _child(element: ET.Element, *names: str) -> Optional[ET.Element]:
    for child in element:
        if _local(child.tag) in names:
            return child
    return None


def _link(element: ET.Element) -> str:
    link = _child(element, "link")
    if link is None:
        return ""
    # Atom puts the URL in href=, RSS in the element text.
    return (link.get("href") or _text(link)).strip()


def _feed_datetime(element: ET.Element) -> Optional[datetime]:
    for name in ("pubdate", "published", "updated", "date", "dc:date"):
        raw = _text(_child(element, name))
        if not raw:
            continue
        # RFC 822 (RSS) first, then ISO-8601 (Atom).
        try:
            parsed = parsedate_to_datetime(raw)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            pass
        iso = parse_datetime(raw)
        if iso is not None:
            return iso
    return None


def parse_feed(xml_text: str, source: str) -> list[dict]:
    """Parse an RSS 2.0 or Atom document into feed items.

    Returns ``[]`` on malformed XML rather than raising: one broken feed must not
    stop the others from being ingested.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.warning("feed %s: unparsable XML (%s)", source, exc)
        return []

    entries = [element for element in root.iter() if _local(element.tag) in ("item", "entry")]

    items: list[dict] = []
    for entry in entries:
        title = _text(_child(entry, "title"))
        link = _link(entry)
        raw_summary = _text(_child(entry, "description", "summary", "content"))
        published = _feed_datetime(entry)
        guid = _text(_child(entry, "guid", "id")) or link or title
        if not guid:
            continue

        items.append(
            {
                "guid": guid,
                # A bare GUID that is actually a URL would be an ugly title.
                "title": title or guid,
                "link": link,
                "summary": _clean_html(raw_summary),
                "source": source,
                "published_at": published or datetime.now(timezone.utc),
            }
        )
    return items


async def fetch_feeds(
    feeds: list[tuple[str, str]],
    *,
    client: Optional[httpx.AsyncClient] = None,
    per_feed_limit: int = 50,
) -> list[dict]:
    """Fetch and parse several feeds. A failing feed is skipped, never fatal."""
    items: list[dict] = []

    owned = client is None
    http = client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
    try:
        for name, url in feeds:
            try:
                response = await http.get(url, headers={"Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml"})
                response.raise_for_status()
                parsed = parse_feed(response.text, source=name)
            except (httpx.HTTPError, UnicodeDecodeError) as exc:
                logger.warning("feed %s (%s) unreachable: %s", name, url, exc)
                continue
            logger.info("feed %s: %s item(s)", name, len(parsed))
            items.extend(parsed[:per_feed_limit])
    finally:
        if owned:
            await http.aclose()

    return items
