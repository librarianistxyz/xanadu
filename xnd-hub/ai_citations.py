#!/usr/bin/env python3
"""
Verifiable AI Citations via Native Xanadu Transclusion.

Stage-1: Deterministic IR retrieval over locally verified (.xnd) documents
         (SHA-256 + Ed25519 signature checked).
Stage-2: Optional local Ollama or OpenAI-compatible LLM synthesis, with strict
         post-generation pointer verification so an LLM can never hallucinate
         a fake {{xnd://...}} citation.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Callable

import httpx

import e2ee_spaces
import ir_engine
import transclusion_engine


def _iter_exact_spans(raw: str) -> list[tuple[int, int, str]]:
    """Return (start, end, text) slices with exact character offsets into `raw`."""
    spans: list[tuple[int, int, str]] = []
    # Split on blank lines or sentence boundaries while preserving exact offsets.
    for m in re.finditer(r"[^\n]+(?:\n(?!\s*\n)[^\n]+)*", raw or ""):
        block = m.group(0).strip()
        if len(block) < 18:
            continue
        b_start = m.start() + (len(m.group(0)) - len(m.group(0).lstrip()))
        if len(block) <= 320:
            spans.append((b_start, b_start + len(block), block))
            continue
        # Split long paragraphs into sentence-level spans with exact offsets
        for sm in re.finditer(r"[^.!?\n]+[.!?]?", block):
            sent = sm.group(0).strip()
            if len(sent) < 18:
                continue
            lead = len(sm.group(0)) - len(sm.group(0).lstrip())
            s_start = b_start + sm.start() + lead
            s_end = s_start + len(sent)
            spans.append((s_start, s_end, sent))
    return spans


def retrieve_verified_spans(
    query: str,
    store: Any,
    verify_sig_fn: Callable[[str, str, int, str, str, str], bool],
    hash_fn: Callable[[str], str],
    pattern_mem: Any = None,
    domain_filter: str = "",
    max_spans: int = 5,
) -> list[dict[str, Any]]:
    """Stage-1 retrieval returning cryptographically verified exact-offset spans."""
    q = (query or "").strip()
    if not q:
        return []
    qtype = ir_engine.classify_question(q)
    q_tokens = [
        t for t in re.findall(r"[a-z0-9]{2,}", q.lower())
        if t not in ir_engine._STOP_WORDS
    ]
    if not q_tokens:
        q_tokens = re.findall(r"[a-z0-9]{2,}", q.lower())
    if not q_tokens:
        return []

    if domain_filter:
        cand_domains = [domain_filter.strip().lower()]
    else:
        cand_domains = list(ir_engine.CORE_XANADU_DOMAINS)
        try:
            for hit in store.search_ram(q)[:25]:
                d = str(hit.get("domain") or "")
                if d and d not in cand_domains:
                    cand_domains.append(d)
        except Exception:
            pass
        for d in list(store.domains.keys())[:40]:
            if d not in cand_domains:
                cand_domains.append(d)

    scored: list[dict[str, Any]] = []
    for dom in cand_domains:
        vers = store.versions.get(dom, [])
        if not vers:
            continue
        latest = vers[-1]
        sha = str(latest.get("sha256") or "")
        raw = store.get_blob(sha)
        if not raw or e2ee_spaces.is_encrypted_blob(raw):
            continue
        kind = str(latest.get("kind") or "document")
        if kind != "document":
            continue

        pub_hex = str(latest.get("pubkey_hex") or store.domains.get(dom, {}).get("pubkey_hex") or "")
        sig_hex = str(latest.get("signature_hex") or "")
        ver_num = int(latest.get("version_num") or 1)
        prev_sha = str(latest.get("prev_sha256") or "")
        if hash_fn(raw) != sha:
            continue
        sig_ok = verify_sig_fn(pub_hex, dom, ver_num, sha, sig_hex, prev_sha)
        if not sig_ok:
            continue

        title = str(latest.get("title") or dom)
        title_low = title.lower()
        title_hits = sum(1 for t in q_tokens if t in title_low)
        ltr_boost = pattern_mem.get_domain_boost(q, dom) if pattern_mem else 0.0
        core_boost = 1.4 if dom in ir_engine.CORE_XANADU_DOMAINS else 0.0

        best_for_dom: dict[str, Any] | None = None
        for idx, (s_start, s_end, excerpt) in enumerate(_iter_exact_spans(raw)):
            p_low = excerpt.lower()
            hits = sum(1 for t in q_tokens if re.search(rf"\b{re.escape(t)}", p_low))
            if hits == 0 and title_hits == 0:
                continue
            score = (hits / max(1, len(q_tokens))) * 6.0 + (title_hits * 1.2) + core_boost + (ltr_boost * 0.5)
            if len(q_tokens) >= 2 and " ".join(q_tokens[:3]) in p_low:
                score += 3.0
            if qtype == "DEFINE" and re.search(r"\b(is a|is an|is the|are |refers to|means)\b", p_low):
                score += 1.5
            elif qtype == "WHO" and re.search(r"\b(founded|created|built|author|by|made)\b", p_low):
                score += 1.5
            if idx <= 2:
                score += 0.5

            if best_for_dom is None or score > best_for_dom["score"]:
                pointer = transclusion_engine.format_span_pointer(dom, ver_num, sha, s_start, s_end)
                fp = f"{pub_hex[:4]}-{pub_hex[4:8]}" if len(pub_hex) >= 8 else (pub_hex or "unknown")
                best_for_dom = {
                    "domain": dom,
                    "title": title,
                    "version": ver_num,
                    "sha256": sha,
                    "pubkey": pub_hex,
                    "key_fingerprint": fp,
                    "signature_ok": True,
                    "start": s_start,
                    "end": s_end,
                    "pointer": pointer,
                    "excerpt": raw[s_start:s_end],
                    "score": round(score, 2),
                }
        if best_for_dom and best_for_dom["score"] >= 1.8:
            scored.append(best_for_dom)

    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:max_spans]


def _try_llm_synthesis(query: str, citations: list[dict[str, Any]], model_override: str = "") -> tuple[str, str] | None:
    """Optionally synthesize using local Ollama or an OpenAI-compatible endpoint."""
    sources_block = "\n".join(
        f"[{i+1}] Pointer: {c['pointer']}\n    Source: {c['domain']} (v{c['version']}, key {c['key_fingerprint']})\n    Exact Text: {c['excerpt']}"
        for i, c in enumerate(citations)
    )
    sys_prompt = (
        "You are a Xanadu (.xnd) verifiable research assistant. Answer the user's question concisely "
        "using ONLY the verified source excerpts below. Whenever you state a fact from a source, "
        "include its EXACT {{xnd://...}} transclusion pointer verbatim. Never invent or alter a pointer."
    )
    user_prompt = f"Question: {query}\n\nVerified Sources:\n{sources_block}"

    api_url = os.environ.get("XND_AI_API_URL", "").strip()
    api_key = os.environ.get("XND_AI_API_KEY", "").strip()
    if api_url and api_key:
        try:
            mdl = model_override or os.environ.get("XND_AI_MODEL", "gpt-4o-mini")
            with httpx.Client(timeout=15.0) as hc:
                r = hc.post(
                    api_url,
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json={
                        "model": mdl,
                        "messages": [
                            {"role": "system", "content": sys_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": 0.2,
                    },
                )
                if r.status_code == 200:
                    txt = r.json()["choices"][0]["message"]["content"].strip()
                    if txt:
                        return txt, f"remote_llm:{mdl}"
        except Exception:
            pass

    ollama_url = os.environ.get("XND_OLLAMA_URL", "http://127.0.0.1:11434/api/chat").strip()
    ollama_mdl = model_override or os.environ.get("XND_OLLAMA_MODEL", "llama3.2").strip()
    if ollama_url:
        try:
            with httpx.Client(timeout=6.0) as hc:
                r = hc.post(
                    ollama_url,
                    json={
                        "model": ollama_mdl,
                        "stream": False,
                        "messages": [
                            {"role": "system", "content": sys_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                    },
                )
                if r.status_code == 200:
                    txt = str((r.json().get("message") or {}).get("content") or "").strip()
                    if txt:
                        return txt, f"ollama:{ollama_mdl}"
        except Exception:
            pass

    return None


def _enforce_verified_pointers(text: str, citations: list[dict[str, Any]]) -> str:
    """Strip any hallucinated {{xnd://...}} pointers and ensure verified pointers are present."""
    valid_set = {c["pointer"] for c in citations}
    used_valid: list[str] = []

    def _check_ptr(m: re.Match[str]) -> str:
        raw_ptr = m.group(0)
        if raw_ptr in valid_set:
            if raw_ptr not in used_valid:
                used_valid.append(raw_ptr)
            return raw_ptr
        return "[unverified citation removed]"

    cleaned = transclusion_engine.TRANSCLUSION_RE.sub(_check_ptr, text).strip()
    if not used_valid and citations:
        refs = "\n\nVerified Sources:\n" + "\n".join(f"- {c['pointer']}" for c in citations)
        cleaned = cleaned + refs
    return cleaned


def synthesize_cited_answer(
    query: str,
    citations: list[dict[str, Any]],
    use_llm: bool = True,
    model: str = "",
) -> dict[str, Any]:
    if not citations:
        return {
            "ok": True,
            "query": query,
            "mode": "deterministic_ir",
            "answer_markdown": f"No cryptographically verified .xnd passages matched '{query}'.",
            "citations": [],
        }

    if use_llm:
        llm_res = _try_llm_synthesis(query, citations, model_override=model)
        if llm_res is not None:
            raw_ans, mode = llm_res
            return {
                "ok": True,
                "query": query,
                "mode": mode,
                "answer_markdown": _enforce_verified_pointers(raw_ans, citations),
                "citations": citations,
            }

    lines = [f"Verifiable Xanadu Answer for: {query}", ""]
    for c in citations:
        lines.append(f"• {c['title']} ({c['domain']} v{c['version']} · key {c['key_fingerprint']}):")
        lines.append(f"  {c['pointer']}")
        lines.append("")
    return {
        "ok": True,
        "query": query,
        "mode": "deterministic_ir",
        "answer_markdown": "\n".join(lines).strip(),
        "citations": citations,
    }
