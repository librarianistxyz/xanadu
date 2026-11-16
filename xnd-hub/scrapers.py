#!/usr/bin/env python3
"""
scrapers.py: 10 Concurrent Non-Stop Background Scraper Workers for Xanadu (.xnd).
Cross-feeds entities, news, CEOs, musicians, footballers, science, world facts,
and random Wikipedia summaries into the local RAM index & wikipedia.xnd.
"""

from __future__ import annotations

import html
import json
import queue
import random
import re
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Callable

_WIKI_ENTRIES: dict[str, dict[str, Any]] = {}
_WIKI_LOCK = threading.RLock()
_ENTITY_QUEUE: queue.Queue[str] = queue.Queue(maxsize=400)
_STARTED = False

_SEED_ENTITIES = {
    "ceos": [
        "Elon Musk", "Satya Nadella", "Sundar Pichai", "Jensen Huang", "Tim Cook",
        "Mark Zuckerberg", "Sam Altman", "Jeff Bezos", "Warren Buffett", "Peter Ndegwa",
        "Bob Collymore", "Strive Masiyiwa", "Aliko Dangote", "Mary Barra", "Lisa Su",
    ],
    "musicians": [
        "Burna Boy", "Sauti Sol", "Kendrick Lamar", "Taylor Swift", "Drake",
        "The Weeknd", "Beyoncé", "Rihanna", "Wizkid", "Diamond Platnumz",
        "Billie Eilish", "Eminem", "Ed Sheeran", "Tyla", "Adele",
    ],
    "footballers": [
        "Lionel Messi", "Cristiano Ronaldo", "Kylian Mbappé", "Erling Haaland",
        "Mohamed Salah", "Bukayo Saka", "Vinícius Júnior", "Jude Bellingham",
        "Lamine Yamal", "Victor Osimhen", "Michael Olunga", "Victor Wanyama",
        "Kevin De Bruyne", "Sadio Mané", "Neymar",
    ],
    "world": [
        "Kenya", "Nairobi", "United States", "United Kingdom", "Japan", "China",
        "India", "Germany", "France", "Brazil", "Nigeria", "South Africa",
        "Ethiopia", "Egypt", "United Arab Emirates", "William Ruto",
    ],
}

_RSS_FEEDS = {
    "world_news": [
        "https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en",
        "https://feeds.bbci.co.uk/news/world/rss.xml",
        "https://www.aljazeera.com/xml/rss/all.xml",
        "https://feeds.npr.org/1001/rss.xml",
    ],
    "tech": [
        "https://news.google.com/rss/search?q=technology+AI+software&hl=en-US&gl=US&ceid=US:en",
        "https://feeds.bbci.co.uk/news/technology/rss.xml",
        "https://techcrunch.com/feed/",
        "https://feeds.arstechnica.com/arstechnica/index",
    ],
    "science": [
        "https://feeds.bbci.co.uk/news/science_and_environment/rss.xml",
        "https://www.sciencedaily.com/rss/all.xml",
        "https://news.google.com/rss/search?q=science+space+physics&hl=en-US&gl=US&ceid=US:en",
    ],
    "sports": [
        "https://www.espn.com/espn/rss/news",
        "https://feeds.bbci.co.uk/sport/football/rss.xml",
        "https://news.google.com/rss/search?q=football+premier+league+champions+league&hl=en-US&gl=US&ceid=US:en",
    ],
}


def _http_get(url: str, timeout: float = 2.5, max_bytes: int = 160_000) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "XanaduCrawler/1.0 (+https://xanadu.local)"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(max_bytes).decode("utf-8", errors="ignore")


def _fetch_wiki_summary(title: str) -> dict[str, Any] | None:
    try:
        slug = urllib.parse.quote(title.strip().replace(" ", "_"))
        raw = _http_get(f"https://en.wikipedia.org/api/rest_v1/page/summary/{slug}", timeout=2.2)
        d = json.loads(raw)
        ext = (d.get("extract") or "").strip()
        if not ext or d.get("type") == "disambiguation":
            return None
        t = d.get("title") or title
        url = ((d.get("content_urls") or {}).get("desktop") or {}).get("page") or f"https://en.wikipedia.org/wiki/{slug}"
        return {
            "title": t,
            "summary": ext,
            "url": url,
            "qid": d.get("wikibase_item") or "",
            "ts": int(time.time()),
        }
    except Exception:
        return None


def _enqueue_entity(name: str) -> None:
    clean = (name or "").strip()
    if len(clean) < 3 or len(clean) > 80:
        return
    try:
        _ENTITY_QUEUE.put_nowait(clean)
    except queue.Full:
        pass


def _record_wiki_entry(entry: dict[str, Any], store: Any) -> None:
    t = entry["title"]
    key = t.lower()
    with _WIKI_LOCK:
        _WIKI_ENTRIES[key] = entry
        if len(_WIKI_ENTRIES) > 600:
            oldest = min(_WIKI_ENTRIES.items(), key=lambda x: x[1].get("ts", 0))[0]
            _WIKI_ENTRIES.pop(oldest, None)
    # Index into RAM crawl_cache & wikipedia.xnd tokens immediately
    try:
        store.put_crawl_cache(
            key,
            {
                "knowledge_card": {
                    "title": t,
                    "subtitle": "wikipedia.xnd · Auto-Indexed Live",
                    "summary": entry["summary"],
                    "url": entry["url"],
                    "facts": [],
                },
                "disambiguation": [
                    {
                        "title": t,
                        "category": "wikipedia.xnd · Live Encyclopedia",
                        "summary": entry["summary"][:220],
                        "url": entry["url"],
                    }
                ],
                "images": [],
                "forums": [],
            },
        )
        store._index_text_tokens("wikipedia.xnd", f"{t} {entry['summary']}")
    except Exception:
        pass


def search_wiki_ram(query: str) -> dict[str, Any] | None:
    ql = (query or "").strip().lower()
    if not ql:
        return None
    with _WIKI_LOCK:
        if ql in _WIKI_ENTRIES:
            return dict(_WIKI_ENTRIES[ql])
        for k, v in _WIKI_ENTRIES.items():
            if ql in k or k in ql:
                return dict(v)
    return None


def export_wiki_shards(limit: int = 120) -> list[dict[str, str]]:
    with _WIKI_LOCK:
        items = list(_WIKI_ENTRIES.items())[-limit:]
    return [
        {
            "key": k,
            "title": str(v.get("title", "")),
            "summary": str(v.get("summary", ""))[:600],
            "url": str(v.get("url", "")),
        }
        for k, v in items
        if v.get("title") and v.get("summary")
    ]


def import_wiki_shards(shards: list[dict[str, Any]], store: Any) -> int:
    added = 0
    for sh in shards or []:
        title = str(sh.get("title") or "").strip()
        summary = str(sh.get("summary") or "").strip()
        url = str(sh.get("url") or "").strip()
        key = str(sh.get("key") or title).strip().lower()
        if not key or not title or not summary:
            continue
        with _WIKI_LOCK:
            if key in _WIKI_ENTRIES:
                continue
            _WIKI_ENTRIES[key] = {"title": title, "summary": summary, "url": url}
            if len(_WIKI_ENTRIES) > 2500:
                oldest = next(iter(_WIKI_ENTRIES))
                _WIKI_ENTRIES.pop(oldest, None)
        try:
            store._index_text_tokens("wikipedia.xnd", f"{title} {summary}")
        except Exception:
            pass
        added += 1
    return added


def _scrape_rss_batch(feeds: list[str], category: str, store: Any) -> None:
    shuffled_feeds = list(feeds)
    random.shuffle(shuffled_feeds)
    for url in shuffled_feeds:
        try:
            xml_txt = _http_get(url, timeout=2.5, max_bytes=200_000)
            root = ET.fromstring(xml_txt)
            items = list(root.findall(".//item")[:5])
            random.shuffle(items)
            for item in items:
                title = html.unescape((item.findtext("title") or "").strip())
                link = (item.findtext("link") or "").strip()
                desc = html.unescape(re.sub(r"(?s)<[^>]+>", " ", item.findtext("description") or "")).strip()
                if not title or not link:
                    continue
                # Extract capitalized proper nouns to cross-feed entity scrapers
                for ent in re.findall(r"\b[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}\b", title)[:2]:
                    _enqueue_entity(ent)
                store._index_text_tokens("news.xnd", f"{category} {title} {desc}")
                store.put_crawl_cache(
                    title.lower(),
                    {
                        "knowledge_card": {
                            "title": title,
                            "subtitle": f"Live {category} · Auto-Indexed",
                            "summary": desc or title,
                            "url": link,
                            "facts": [],
                        },
                        "disambiguation": [
                            {"title": title, "category": f"Live {category}", "summary": desc[:200] or title, "url": link}
                        ],
                        "images": [],
                        "forums": [],
                    },
                )
        except Exception:
            pass


def start_background_scrapers(
    store: Any,
    publish_doc_fn: Callable[..., Any],
) -> None:
    global _STARTED
    if _STARTED:
        return
    _STARTED = True

    def _worker_rss(name: str, feed_key: str, label: str, interval: float) -> None:
        while True:
            _scrape_rss_batch(_RSS_FEEDS[feed_key], label, store)
            time.sleep(interval)

    def _worker_category(name: str, cat_key: str, interval: float) -> None:
        pool = list(_SEED_ENTITIES[cat_key])
        random.shuffle(pool)
        idx = 0
        while True:
            ent = pool[idx % len(pool)]
            idx += 1
            if idx % len(pool) == 0:
                random.shuffle(pool)
            res = _fetch_wiki_summary(ent)
            if res:
                _record_wiki_entry(res, store)
                for m in re.findall(r"\b[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}\b", res["summary"])[:2]:
                    _enqueue_entity(m)
            time.sleep(interval)

    def _worker_wiki_random() -> None:
        while True:
            try:
                raw = _http_get("https://en.wikipedia.org/api/rest_v1/page/random/summary", timeout=2.5)
                d = json.loads(raw)
                ext = (d.get("extract") or "").strip()
                t = (d.get("title") or "").strip()
                url = ((d.get("content_urls") or {}).get("desktop") or {}).get("page") or ""
                if t and ext and url:
                    _record_wiki_entry({"title": t, "summary": ext, "url": url, "qid": d.get("wikibase_item") or "", "ts": int(time.time())}, store)
            except Exception:
                pass
            time.sleep(12.0)

    def _worker_cross_feeder() -> None:
        while True:
            try:
                ent = _ENTITY_QUEUE.get(timeout=5.0)
                if not search_wiki_ram(ent):
                    res = _fetch_wiki_summary(ent)
                    if res:
                        _record_wiki_entry(res, store)
            except queue.Empty:
                pass
            except Exception:
                pass
            time.sleep(2.0)

    def _worker_wikipedia_xnd_publisher() -> None:
        while True:
            try:
                with _WIKI_LOCK:
                    items = sorted(_WIKI_ENTRIES.values(), key=lambda x: x.get("ts", 0), reverse=True)[:40]
                if items:
                    lines = [
                        "wikipedia.xnd — Live Sovereign Encyclopedia Index\n",
                        f"Auto-indexed entries in RAM: {len(_WIKI_ENTRIES)} (news, CEOs, musicians, footballers, countries, science & random knowledge).\n\n",
                    ]
                    for it in items:
                        lines.append(f"• {it['title']}\n  {it['summary'][:220]}\n  Source: {it['url']}\n")
                    publish_doc_fn(
                        "wikipedia.xnd",
                        "wikipedia.xnd — Live Auto-Indexed Encyclopedia",
                        "\n".join(lines),
                        bypass_short_rule=True,
                    )
            except Exception:
                pass
            time.sleep(45.0)

    workers = [
        ("scraper-1-world-news", _worker_rss, ("w1", "world_news", "World News", 25.0)),
        ("scraper-2-tech-news", _worker_rss, ("w2", "tech", "Tech News", 28.0)),
        ("scraper-3-science", _worker_rss, ("w3", "science", "Science", 32.0)),
        ("scraper-4-sports", _worker_rss, ("w4", "sports", "Sports", 26.0)),
        ("scraper-5-ceos", _worker_category, ("w5", "ceos", 14.0)),
        ("scraper-6-musicians", _worker_category, ("w6", "musicians", 15.0)),
        ("scraper-7-footballers", _worker_category, ("w7", "footballers", 15.0)),
        ("scraper-8-world", _worker_category, ("w8", "world", 16.0)),
        ("scraper-9-wiki-random", _worker_wiki_random, ()),
        ("scraper-10-cross-feed", _worker_cross_feeder, ()),
        ("scraper-wiki-xnd-pub", _worker_wikipedia_xnd_publisher, ()),
    ]
    for tname, fn, args in workers:
        th = threading.Thread(target=fn, args=args, name=tname, daemon=True)
        th.start()
