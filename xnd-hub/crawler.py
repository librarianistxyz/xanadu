#!/usr/bin/env python3
"""
xnd-crawler: 24/7 Real-Time News, Sports, Tech & Domain Crawler for Xanadu (.xnd).
Fetches public RSS feeds and domain homepages, extracts summaries & structured text,
and indexes them into xanadu.db so Xanadu Search returns live Google-like results.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

HUB_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(HUB_DIR))

import hub  # noqa: E402

STATUS_FILE = HUB_DIR / "crawler_status.json"
CRAWL_INTERVAL = int(os.environ.get("XND_CRAWL_INTERVAL", "300"))
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "application/rss+xml, application/xml, text/html;q=0.9, */*;q=0.8",
}

RSS_FEEDS: list[tuple[str, str]] = [
    ("News", "https://feeds.bbci.co.uk/news/world/rss.xml"),
    ("News", "https://feeds.npr.org/1001/rss.xml"),
    ("Sports", "https://feeds.bbci.co.uk/sport/rss.xml"),
    ("Sports", "https://www.espn.com/espn/rss/news"),
    ("Tech", "https://hnrss.org/frontpage"),
    ("Science", "https://feeds.npr.org/1007/rss.xml"),
]

SEED_DOMAINS: list[str] = [
    "https://example.com",
    "https://www.python.org",
    "https://www.rust-lang.org",
    "https://en.wikipedia.org/wiki/Main_Page",
    "https://news.ycombinator.com",
]


def _fetch_text(url: str, timeout: int = 8) -> str:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(512_000).decode("utf-8", errors="replace")


def _slug_domain(prefix: str, key: str) -> str:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]
    clean = re.sub(r"[^a-z0-9\-]+", "-", prefix.lower()).strip("-")[:24]
    return f"{clean}-{digest}.xnd" if clean else f"web-{digest}.xnd"


def _index_entry(domain: str, title: str, content: str) -> bool:
    if domain in hub.store.domains:
        return False
    hub.publish_document(domain, title[:100], content, bypass_short_rule=True, pinned=False)
    return True


def crawl_rss_feed(category: str, feed_url: str, limit: int = 6) -> int:
    added = 0
    try:
        xml_data = _fetch_text(feed_url, timeout=8)
        root = ET.fromstring(xml_data)
    except Exception:
        return 0

    items = root.findall(".//item")[:limit]
    for item in items:
        title = html.unescape((item.findtext("title") or "").strip())
        link = (item.findtext("link") or "").strip()
        desc = html.unescape((item.findtext("description") or "").strip())
        desc_clean = re.sub(r"<[^>]+>", " ", desc)
        desc_clean = re.sub(r"\s+", " ", desc_clean).strip()
        if not title or not link:
            continue

        xnd_dom = _slug_domain(category, link)
        body = (
            f"Archived from: {link}\n\n"
            f"# {title}\n\n"
            f"## Category: {category}\n\n"
            f"{desc_clean}\n"
        )
        if _index_entry(xnd_dom, f"[{category}] {title}", body):
            added += 1
    return added


def crawl_domain_profile(url: str) -> bool:
    try:
        raw_html = _fetch_text(url, timeout=8)
    except Exception:
        return False

    parser = hub._TextExtractor()
    parser.feed(raw_html)
    title = html.unescape("".join(parser.title_parts).strip()) or url
    body_text = html.unescape("".join(parser.text_parts))
    lines = [ln.strip() for ln in body_text.splitlines() if ln.strip()]
    clean = "\n".join(lines)[:12000]

    host = urllib.parse.urlparse(url).netloc.lower().split(":")[0]
    clean_label = re.sub(r"[^a-z0-9\-]+", "-", host).strip("-")[:63]
    xnd_dom = f"{clean_label}.xnd" if clean_label else _slug_domain("site", url)

    snapshot = f"Archived from: {url}\n\n# {title}\n\n## Domain Overview ({host})\n\n{clean}"
    return _index_entry(xnd_dom, f"[Domain] {title}", snapshot)


def run_crawl_cycle() -> dict[str, Any]:
    hub.seed_universe()

    added_feeds = 0
    for category, feed_url in RSS_FEEDS:
        added_feeds += crawl_rss_feed(category, feed_url, limit=6)

    added_domains = 0
    for dom_url in SEED_DOMAINS:
        if crawl_domain_profile(dom_url):
            added_domains += 1

    total_domains = len(hub.store.domains)
    st_info = hub.store.storage_stats()

    status = {
        "last_run": time.time(),
        "added_feeds": added_feeds,
        "added_domains": added_domains,
        "total_indexed_domains": total_domains,
        "cache_kb": st_info["cache_kb"],
        "max_cache_mb": st_info["max_cache_mb"],
        "interval_sec": CRAWL_INTERVAL,
    }
    STATUS_FILE.write_text(json.dumps(status, indent=2), encoding="utf-8")
    return status


def main() -> None:
    ap = argparse.ArgumentParser(description="24/7 Xanadu News, Sports & Domain Crawler")
    ap.add_argument("--once", action="store_true", help="Run a single crawl cycle and exit")
    args = ap.parse_args()

    if args.once:
        st = run_crawl_cycle()
        print(json.dumps(st))
        return

    while True:
        try:
            st = run_crawl_cycle()
            print(f"[xnd-crawler] cycle complete: {st}", flush=True)
        except Exception as exc:
            print(f"[xnd-crawler] cycle error: {exc}", flush=True)
        time.sleep(CRAWL_INTERVAL)


if __name__ == "__main__":
    main()
