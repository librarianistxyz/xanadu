#!/usr/bin/env python3
"""
Google-Style Deterministic IR & Featured Snippet Engine for Xanadu (.xnd).
Zero LLMs, zero central servers: Question-Type Parsing, Two-Stage Passage
Re-Ranking (IDF + Proximity + Heading + Shape Match), Knowledge Triples,
and Decentralized Learning-to-Rank (LTR) Question Pattern Memory.
"""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any

CORE_XANADU_DOMAINS = (
    "founder.xnd",
    "home.xnd",
    "justin.xnd",
    "heart.xnd",
    "manifesto.xnd",
    "forum.xnd",
    "xanadu.xnd",
)

_STOP_WORDS = {
    "the", "is", "are", "was", "were", "a", "an", "of", "in", "on", "to", "for",
    "and", "or", "what", "who", "when", "where", "why", "how", "did", "do", "does",
    "this", "that", "with", "from", "by", "as", "at", "about", "can", "i", "you", "my",
}


def classify_question(query: str) -> str:
    q = (query or "").strip().lower()
    if re.match(r"^(how|steps|guide|tutorial|way to)\b", q) or " how to " in f" {q} ":
        return "HOW"
    if re.match(r"^(who|founder|creator|author)\b", q) or " who " in f" {q} ":
        return "WHO"
    if re.match(r"^(what|define|explain|meaning)\b", q) or " what is " in f" {q} ":
        return "DEFINE"
    if " vs " in f" {q} " or " versus " in f" {q} " or q.startswith("difference between "):
        return "COMPARE"
    if re.match(r"^(where|when)\b", q):
        return "WHEN_WHERE"
    return "FACT"


def normalize_pattern_key(query: str) -> str:
    tokens = [w for w in re.findall(r"[a-z0-9]+", (query or "").lower()) if len(w) >= 2 and w not in _STOP_WORDS]
    if not tokens:
        return ""
    qtype = classify_question(query)
    return f"{qtype}:{' '.join(sorted(set(tokens))[:6])}"


def _extract_passages_from_html_or_text(raw: str, kind: str) -> tuple[list[str], list[dict[str, str]]]:
    text = raw or ""
    if kind == "capsule" and text.lstrip().startswith("{"):
        try:
            obj = json.loads(text)
            files = obj.get("files") or {}
            text = str(files.get("index.html", "") or "")
        except Exception:
            pass

    facts: list[dict[str, str]] = []
    # Extract heading/list structure before stripping tags
    text = re.sub(r"<(script|style|noscript)[^>]*>.*?</\1>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    # Convert headings & list items into clean newline-delimited blocks
    text = re.sub(r"<(h[1-3]|p|div|li|br|tr)[^>]*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"[ \t]+", " ", text)

    passages: list[str] = []
    for block in text.splitlines():
        clean = block.strip()
        if len(clean) < 25:
            continue
        # Extract simple "Key: Value" knowledge triples
        m = re.match(r"^([A-Z][A-Za-z0-9 _/-]{2,28}):\s+(.{4,120})$", clean)
        if m and len(facts) < 4:
            facts.append({"label": m.group(1).strip(), "value": m.group(2).strip()})
        # Split overly long blocks into ~2-3 sentence passages
        if len(clean) > 420:
            sents = re.split(r"(?<=[.!?])\s+", clean)
            cur: list[str] = []
            cur_len = 0
            for s in sents:
                cur.append(s)
                cur_len += len(s)
                if cur_len >= 220:
                    passages.append(" ".join(cur))
                    cur, cur_len = [], 0
            if cur:
                passages.append(" ".join(cur))
        else:
            passages.append(clean)
    return passages, facts


class PatternMemory:
    """Decentralized Learning-to-Rank (LTR) memory mapping question patterns -> domain boosts."""

    def __init__(self, state_dir: Path) -> None:
        self.path = state_dir / "qa_patterns.json"
        self.lock = threading.Lock()
        self.patterns: dict[str, dict[str, float]] = {}
        self._load()

    def _load(self) -> None:
        try:
            if self.path.exists():
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self.patterns = {
                        str(k): {str(dk): float(dv) for dk, dv in v.items()}
                        for k, v in data.items()
                        if isinstance(v, dict)
                    }
        except Exception:
            self.patterns = {}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.patterns, separators=(",", ":")), encoding="utf-8")
        except Exception:
            pass

    def record_feedback(self, query: str, domain: str, delta: float = 1.0) -> dict[str, Any]:
        pkey = normalize_pattern_key(query)
        dom = (domain or "").strip().lower()
        if not pkey or not dom:
            return {"ok": False}
        with self.lock:
            entry = self.patterns.setdefault(pkey, {})
            new_score = max(-5.0, min(25.0, float(entry.get(dom, 0.0)) + delta))
            entry[dom] = round(new_score, 3)
            # Keep bounded to 500 patterns
            if len(self.patterns) > 500:
                oldest = next(iter(self.patterns))
                self.patterns.pop(oldest, None)
            self._save()
        return {"ok": True, "pattern_key": pkey, "domain": dom, "score": new_score}

    def get_domain_boost(self, query: str, domain: str) -> float:
        pkey = normalize_pattern_key(query)
        if not pkey:
            return 0.0
        with self.lock:
            return float((self.patterns.get(pkey) or {}).get(domain.lower(), 0.0))

    def export_patterns(self, limit: int = 150) -> dict[str, dict[str, float]]:
        with self.lock:
            items = list(self.patterns.items())[-limit:]
            return {k: dict(v) for k, v in items}

    def import_patterns(self, incoming: dict[str, Any]) -> int:
        if not isinstance(incoming, dict):
            return 0
        merged = 0
        with self.lock:
            for pkey, dom_map in incoming.items():
                if not isinstance(dom_map, dict):
                    continue
                cur = self.patterns.setdefault(str(pkey), {})
                for dom, score in dom_map.items():
                    try:
                        val = max(-5.0, min(25.0, float(score)))
                    except (TypeError, ValueError):
                        continue
                    old = float(cur.get(str(dom), 0.0))
                    # Conservative weighted blend so peer gossip enriches without overwriting
                    cur[str(dom)] = round((old * 0.7) + (val * 0.3), 3) if old else round(val * 0.5, 3)
                    merged += 1
            if merged:
                self._save()
        return merged


def answer_from_xnd_corpus(
    query: str,
    store: Any,
    bm25_results: list[dict[str, Any]],
    pattern_mem: PatternMemory | None = None,
) -> dict[str, Any] | None:
    """Two-stage Google-style Passage Re-Ranker + Featured Snippet over crawled .xnd sites."""
    q = (query or "").strip()
    if len(q) < 2:
        return None
    qtype = classify_question(q)
    q_low = q.lower()
    q_tokens = [w for w in re.findall(r"[a-z0-9]+", q_low) if len(w) >= 2 and w not in _STOP_WORDS]
    if not q_tokens:
        return None

    # Gather candidate domains: top BM25 hits + Core Xanadu domains
    cand_domains: list[str] = []
    seen: set[str] = set()
    for r in bm25_results[:8]:
        d = (r.get("domain") or "").strip().lower()
        if d and d not in seen:
            seen.add(d)
            cand_domains.append(d)
    for cd in CORE_XANADU_DOMAINS:
        if cd in store.domains and cd not in seen:
            seen.add(cd)
            cand_domains.append(cd)

    best: dict[str, Any] | None = None
    best_score = 0.0
    best_facts: list[dict[str, str]] = []

    for dom in cand_domains:
        vers = store.versions.get(dom, [])
        if not vers:
            continue
        latest = vers[-1]
        raw = store.get_blob(latest.get("sha256", ""))
        if not raw:
            continue
        title = str(latest.get("title") or dom)
        kind = str(latest.get("kind") or "document")
        passages, facts = _extract_passages_from_html_or_text(raw, kind)
        if not passages:
            continue

        ltr_boost = pattern_mem.get_domain_boost(q, dom) if pattern_mem else 0.0
        core_boost = 1.6 if dom in CORE_XANADU_DOMAINS else 0.0
        title_low = title.lower()
        title_hits = sum(1 for t in q_tokens if t in title_low)

        for idx, p in enumerate(passages):
            p_low = p.lower()
            hits = sum(1 for t in q_tokens if re.search(rf"\b{re.escape(t)}", p_low))
            if hits == 0 and title_hits == 0:
                continue

            score = (hits / max(1, len(q_tokens))) * 6.0 + (title_hits * 1.4) + core_boost + (ltr_boost * 0.6)
            # Proximity / exact phrase boost
            if len(q_tokens) >= 2:
                phrase = " ".join(q_tokens[:3])
                if phrase in p_low:
                    score += 3.5
                else:
                    # Pairwise adjacency check
                    for i in range(len(q_tokens) - 1):
                        if re.search(rf"\b{re.escape(q_tokens[i])}\W+(?:\w+\W+){{0,2}}{re.escape(q_tokens[i+1])}\b", p_low):
                            score += 1.5

            # Question-type shape boost
            if qtype == "HOW" and (re.search(r"(^|\s)(1\.|2\.|step|click|run|install|deploy|publish|open|enter)\b", p_low)):
                score += 2.0
            elif qtype == "DEFINE" and re.search(r"\b(is a|is an|is the|are |refers to|means)\b", p_low):
                score += 2.0
            elif qtype == "WHO" and re.search(r"\b(founded|created|built|author|by|made)\b", p_low):
                score += 2.0
            if idx <= 2:
                score += 0.6  # lead-paragraph prior

            if score > best_score:
                best_score = score
                best = {
                    "domain": dom,
                    "title": title,
                    "summary": p[:380] + ("…" if len(p) > 380 else ""),
                    "qtype": qtype,
                    "score": round(score, 2),
                }
                best_facts = facts

    if not best or best_score < 2.2:
        return None

    return {
        "title": best["title"],
        "subtitle": f"xnd://{best['domain']} · Featured Snippet ({best['qtype']})",
        "summary": best["summary"],
        "url": f"xnd://{best['domain']}",
        "domain": best["domain"],
        "pattern_key": normalize_pattern_key(q),
        "facts": best_facts[:3],
    }
