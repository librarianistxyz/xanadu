"""E2EE Distributed Mesh Inference (offload AI citation/synthesis to a trusted node)."""

from __future__ import annotations

import json
import os
from typing import Any, Callable

import ai_citations
import e2ee_spaces


def get_node_ai_capability(node_pubkey_hex: str) -> dict[str, Any]:
    ollama_url = (os.environ.get("XND_OLLAMA_URL") or "").strip()
    return {
        "e2ee_inference": True,
        "node_pubkey_hex": node_pubkey_hex,
        "stage1_verified_citations": True,
        "llm_configured": bool(ollama_url or os.environ.get("XND_OPENAI_BASE_URL")),
        "ollama_model": os.environ.get("XND_OLLAMA_MODEL", "llama3.2"),
    }


def process_encrypted_inference(
    node_privkey_hex: str,
    node_pubkey_hex: str,
    requester_pubkey_hex: str,
    envelope_str: str,
    store: Any,
    verify_sig_fn: Callable[[str, str, int, str, str, str], bool],
    hash_fn: Callable[[str], str],
    pattern_mem: Any = None,
) -> dict[str, Any]:
    """Decrypt an E2EE query, run Stage-1 verified citation retrieval, and encrypt the reply."""
    ok, plain_json, _ = e2ee_spaces.decrypt_with_privkeys(envelope_str, [node_privkey_hex])
    if not ok:
        raise ValueError("Unable to decrypt E2EE mesh inference request with this node's key")

    req = json.loads(plain_json)
    query = str(req.get("query") or "").strip()
    if not query:
        raise ValueError("Decrypted mesh inference request missing 'query'")
    max_spans = max(1, min(10, int(req.get("max_spans") or 5)))
    domain_filter = str(req.get("domain_filter") or "").strip()

    spans = ai_citations.retrieve_verified_spans(
        query,
        store,
        verify_sig_fn,
        hash_fn,
        pattern_mem=pattern_mem,
        domain_filter=domain_filter,
        max_spans=max_spans,
    )
    answer_payload = {
        "ok": True,
        "query": query,
        "responder_pubkey": node_pubkey_hex,
        "citations_count": len(spans),
        "citations": spans,
    }
    recips = [requester_pubkey_hex.strip().lower()] if requester_pubkey_hex.strip() else []
    encrypted_reply = e2ee_spaces.encrypt_for_peers(
        json.dumps(answer_payload, separators=(",", ":")),
        node_privkey_hex,
        recips,
    )
    return {
        "ok": True,
        "responder_pubkey": node_pubkey_hex,
        "envelope": encrypted_reply,
        "citations_count": len(spans),
    }
