#!/usr/bin/env python3
"""
Deep Search, Entity Details + Alternatives Fan-Out, and Federated P2P Search
for Xanadu (.xnd).
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

import httpx

import ir_engine

_UA = "XanaduDeepSearch/1.0"


def _http_get_json(url: str, timeout: float = 1.5) -> dict[str, Any] | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read(512_000).decode("utf-8", errors="replace"))
    except Exception:
        return None


def _fetch_wikidata_facts(qid: str) -> list[dict[str, str]]:
    if not qid or not re.match(r"^Q\d+$", qid):
        return []
    url = (
        "https://www.wikidata.org/w/api.php?action=wbgetentities"
        f"&ids={qid}&props=claims&languages=en&format=json"
    )
    data = _http_get_json(url, timeout=1.5)
    entity = ((data or {}).get("entities") or {}).get(qid) or {}
    claims = entity.get("claims") or {}

    prop_labels = {
        "P31": "Category",
        "P178": "Developer",
        "P170": "Creator",
        "P112": "Founder",
        "P571": "Founded",
        "P856": "Website",
    }
    raw_items: list[tuple[str, str, bool]] = []
    qids_to_resolve: list[str] = []

    for prop, label in prop_labels.items():
        for cl in (claims.get(prop) or [])[:2]:
            dv = ((cl.get("mainsnak") or {}).get("datavalue") or {})
            dtype = dv.get("type")
            val = dv.get("value")
            if dtype == "wikibase-entityid" and isinstance(val, dict) and val.get("id"):
                target_q = str(val["id"])
                qids_to_resolve.append(target_q)
                raw_items.append((label, target_q, True))
            elif dtype == "time" and isinstance(val, dict) and val.get("time"):
                yr = str(val["time"]).lstrip("+").split("-", 1)[0]
                if yr:
                    raw_items.append((label, yr, False))
            elif dtype == "string" and isinstance(val, str) and val:
                raw_items.append((label, val, False))

    labels_map: dict[str, str] = {}
    if qids_to_resolve:
        uniq = "|".join(dict.fromkeys(qids_to_resolve[:12]))
        lbl_url = (
            "https://www.wikidata.org/w/api.php?action=wbgetentities"
            f"&ids={uniq}&props=labels&languages=en&format=json"
        )
        ldata = _http_get_json(lbl_url, timeout=1.2) or {}
        for q_id, ent in (ldata.get("entities") or {}).items():
            lbl = (((ent.get("labels") or {}).get("en") or {}).get("value") or "").strip()
            if lbl:
                labels_map[q_id] = lbl

    facts: list[dict[str, str]] = []
    seen_pairs: set[tuple[str, str]] = set()
    for label, val, is_q in raw_items:
        resolved = labels_map.get(val, val) if is_q else val
        if is_q and resolved == val:
            continue
        pair = (label, resolved)
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            facts.append({"label": label, "value": resolved})
    return facts[:6]


def fetch_wikipedia_rest_and_wikidata(topic: str) -> dict[str, Any] | None:
    """Fetch rich Wikipedia REST summary + thumbnail + Wikidata structured facts."""
    clean = (topic or "").strip()
    if not clean:
        return None
    slug = urllib.parse.quote(clean.replace(" ", "_"))
    data = _http_get_json(f"https://en.wikipedia.org/api/rest_v1/page/summary/{slug}", timeout=1.5)
    if not data or data.get("type") == "https://mediawiki.org/wiki/HyperSwitch/errors/not_found":
        # Fallback: opensearch for canonical title
        os_data = _http_get_json(
            "https://en.wikipedia.org/w/api.php?action=opensearch&limit=1&namespace=0&format=json&search="
            + urllib.parse.quote(clean),
            timeout=1.2,
        )
        if isinstance(os_data, list) and len(os_data) >= 2 and os_data[1]:
            best_title = str(os_data[1][0])
            data = _http_get_json(
                f"https://en.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(best_title.replace(' ', '_'))}",
                timeout=1.5,
            )
    if not data or not data.get("extract"):
        return None

    qid = str(data.get("wikibase_item") or "")
    facts = _fetch_wikidata_facts(qid) if qid else []
    thumb = ((data.get("thumbnail") or {}).get("source") or "")
    page_url = (((data.get("content_urls") or {}).get("desktop") or {}).get("page") or "")
    return {
        "title": str(data.get("title") or clean),
        "subtitle": str(data.get("description") or "Wikipedia · Verified Entity Summary"),
        "summary": str(data.get("extract") or "")[:900],
        "url": page_url,
        "thumbnail": thumb,
        "wikidata_id": qid,
        "facts": facts,
    }


def deep_fetch_live_pages(
    urls: list[str],
    query: str,
    extract_text_fn: Callable[[str], tuple[str, str]],
    max_pages: int = 3,
) -> list[dict[str, Any]]:
    """Fetch top 2-3 live URLs in parallel (1.5s timeout) and rank passages via ir_engine."""
    cand_urls = [u for u in urls if isinstance(u, str) and u.startswith(("http://", "https://"))][:max_pages]
    if not cand_urls:
        return []

    q_tokens = [t for t in re.findall(r"[a-z0-9]{2,}", (query or "").lower()) if t not in ir_engine._STOP_WORDS]
    if not q_tokens:
        q_tokens = re.findall(r"[a-z0-9]{2,}", (query or "").lower())
    qtype = ir_engine.classify_question(query)

    def _fetch_one(u: str) -> dict[str, Any] | None:
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Xanadu/1.0"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                ctype = (resp.headers.get("Content-Type") or "").lower()
                if "html" not in ctype and "text" not in ctype:
                    return None
                raw_html = resp.read(220_000).decode("utf-8", errors="replace")
            title, clean_txt = extract_text_fn(raw_html)
            if not clean_txt or len(clean_txt) < 60:
                return None

            best_p = ""
            best_score = -1.0
            for block in re.split(r"\n{2,}", clean_txt):
                p = " ".join(block.split()).strip()
                if len(p) < 40:
                    continue
                p_low = p.lower()
                hits = sum(1 for t in q_tokens if re.search(rf"\b{re.escape(t)}", p_low))
                if hits == 0:
                    continue
                sc = (hits / max(1, len(q_tokens))) * 6.0
                if qtype == "DEFINE" and re.search(r"\b(is a|is an|is the|are |refers to)\b", p_low):
                    sc += 1.5
                if sc > best_score:
                    best_score = sc
                    best_p = p[:420] + ("…" if len(p) > 420 else "")
            if not best_p:
                best_p = " ".join(clean_txt.split())[:320] + "…"
                best_score = 0.5
            return {"title": title or u, "url": u, "excerpt": best_p, "score": round(best_score, 2)}
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=len(cand_urls)) as pool:
        fetched = [r for r in pool.map(_fetch_one, cand_urls) if r is not None]
    fetched.sort(key=lambda x: x["score"], reverse=True)
    return fetched


def fetch_alternatives(topic: str, max_items: int = 8) -> list[dict[str, str]]:
    """Query-time '<topic> alternatives' fan-out via DuckDuckGo IA + RelatedTopics."""
    clean = (topic or "").strip()
    if not clean:
        return []
    alts: list[dict[str, str]] = []
    seen: set[str] = set()

    # 1. DuckDuckGo RelatedTopics for '<topic> alternatives'
    for q_str in (f"{clean} alternatives", clean):
        ddg = _http_get_json(
            "https://api.duckduckgo.com/?format=json&no_html=1&skip_disambig=0&q="
            + urllib.parse.quote(q_str),
            timeout=1.5,
        )
        if not ddg:
            continue
        for item in (ddg.get("RelatedTopics") or []):
            sub_items = item.get("Topics") if isinstance(item, dict) and "Topics" in item else [item]
            for sub in sub_items:
                if not isinstance(sub, dict):
                    continue
                txt = str(sub.get("Text") or "").strip()
                url = str(sub.get("FirstURL") or "").strip()
                if not txt or not url or url in seen:
                    continue
                name = txt.split(" - ", 1)[0].strip()[:60]
                if name.lower() == clean.lower():
                    continue
                seen.add(url)
                alts.append({"name": name, "description": txt[:160], "url": url})
                if len(alts) >= max_items:
                    return alts

    # 2. Wikipedia OpenSearch fallback for related/alternative topics
    if len(alts) < 3:
        os_data = _http_get_json(
            "https://en.wikipedia.org/w/api.php?action=opensearch&limit=6&namespace=0&format=json&search="
            + urllib.parse.quote(clean),
            timeout=1.2,
        )
        if isinstance(os_data, list) and len(os_data) >= 4:
            for t, d, u in zip(os_data[1], os_data[2], os_data[3]):
                if u in seen or str(t).lower() == clean.lower():
                    continue
                seen.add(u)
                alts.append({"name": str(t), "description": str(d)[:160], "url": str(u)})
                if len(alts) >= max_items:
                    break
    return alts


def query_federated_peers(query: str, peer_urls: list[str], limit: int = 6) -> list[dict[str, Any]]:
    """Query nearby/mesh Xanadu peers' RAM indexes in parallel (0.8s cap)."""
    urls = list(dict.fromkeys(u.rstrip("/") for u in peer_urls if u))[:4]
    if not urls or not query.strip():
        return []

    def _ask(base: str) -> list[dict[str, Any]]:
        try:
            with httpx.Client(timeout=0.8) as hc:
                r = hc.post(f"{base}/api/search/federated", json={"query": query, "limit": limit})
                if r.status_code == 200:
                    data = r.json()
                    out = []
                    for item in data.get("results") or []:
                        c = dict(item)
                        c["federated_from"] = base
                        out.append(c)
                    return out
        except Exception:
            pass
        return []

    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        batches = list(pool.map(_ask, urls))

    merged: list[dict[str, Any]] = []
    seen_doms: set[str] = set()
    for b in batches:
        for item in b:
            dom = str(item.get("domain") or "")
            if dom and dom not in seen_doms:
                seen_doms.add(dom)
                merged.append(item)
    return merged[:limit]
