"""AI citations, note publishing, and MCP JSON-RPC 2.0 tool endpoints."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, HTTPException, Request

import ai_citations
import transclusion_engine

MCP_TOOLS = [
    {
        "name": "xnd_search",
        "description": "Instant local + mesh search across .xnd documents with verified citation spans.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "limit": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
    },
    {
        "name": "xnd_resolve",
        "description": "Resolve and verify a .xnd domain document, returning content, signature status, trust status, and backlinks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "version": {"type": "integer"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "xnd_slice_span",
        "description": "Slice an exact verified character span [start, end) from a .xnd document and return its transclusion pointer.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "start": {"type": "integer", "minimum": 0},
                "end": {"type": "integer", "minimum": 0},
                "version": {"type": "integer"},
            },
            "required": ["domain", "start", "end"],
        },
    },
    {
        "name": "xnd_publish",
        "description": "Publish a .xnd note or report signed by the node's dedicated AI agent Ed25519 key.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "content": {"type": "string"},
                "title": {"type": "string"},
            },
            "required": ["domain", "content"],
        },
    },
    {
        "name": "xnd_trust_status",
        "description": "Check first-seen key pinning, petname, key fingerprint, and conflicts for a .xnd domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
            },
            "required": ["domain"],
        },
    },
]


def _dispatch_mcp_tool(h: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "xnd_search":
        q = str(args.get("query") or "").strip()
        if not q:
            raise HTTPException(status_code=400, detail="query is required")
        limit = max(1, min(30, int(args.get("limit") or 10)))
        hits = h.store.search_ram(q)[:limit]
        spans = ai_citations.retrieve_verified_spans(
            q, h.store, h.verify_signature, h.rust_sha256, h.pattern_mem, "", min(5, limit)
        )
        return {"query": q, "results": hits, "verified_spans": spans}

    if name == "xnd_resolve":
        dom = h.normalize_xnd_domain(str(args.get("domain") or ""))
        ver = int(args["version"]) if args.get("version") is not None else None
        return h.resolve_domain(dom, ver)

    if name == "xnd_slice_span":
        dom = h.normalize_xnd_domain(str(args.get("domain") or ""))
        ver = int(args["version"]) if args.get("version") is not None else None
        doc = h.resolve_domain(dom, ver)
        if doc.get("kind") != "document":
            raise HTTPException(status_code=400, detail="xnd_slice_span only supports document .xnd domains")
        raw = doc.get("raw_content", "")
        s = max(0, int(args.get("start") or 0))
        e = min(len(raw), int(args.get("end") or 0))
        if e < s:
            raise HTTPException(status_code=400, detail="end must be >= start")
        ptr = transclusion_engine.format_span_pointer(dom, int(doc["version"]), str(doc.get("sha256") or ""), s, e)
        return {
            "domain": dom,
            "version": doc["version"],
            "sha256": doc["sha256"],
            "verified": doc["verified"],
            "start": s,
            "end": e,
            "pointer": ptr,
            "text": raw[s:e],
        }

    if name == "xnd_publish":
        dom = h.normalize_xnd_domain(str(args.get("domain") or ""))
        content = str(args.get("content") or "")
        title = str(args.get("title") or dom).strip()
        if not h.DOMAIN_RE.match(dom) or not content.strip():
            raise HTTPException(status_code=400, detail="Valid .xnd domain and non-empty content are required")
        agent_pub, agent_priv = h._get_or_create_ai_agent_key()
        res = h.publish_document(dom, title, content, pinned=True, privkey_hex=agent_priv)
        if not h.trust_store.get_petname(dom, agent_pub):
            h.trust_store.set_petname(dom, "AI Agent")
        return {**res, "agent_pubkey_hex": agent_pub, "agent_fingerprint": h._format_fingerprint(agent_pub)}

    if name == "xnd_trust_status":
        dom = h.normalize_xnd_domain(str(args.get("domain") or ""))
        if not h.DOMAIN_RE.match(dom):
            raise HTTPException(status_code=400, detail="Valid .xnd domain is required")
        parsed = h._parse_canonical_domain(dom)
        base = parsed[0] if parsed else dom
        local_pub = (h.store.domains.get(dom, {}).get("pubkey_hex") or "").lower()
        pinned_pub = h.trust_store.get_pinned_pubkey(base)
        return {
            "domain": dom,
            "base_domain": base,
            "pinned_pubkey": pinned_pub,
            "local_pubkey": local_pub,
            "key_fingerprint": h._format_fingerprint(pinned_pub or local_pub),
            "petname": h.trust_store.get_petname(dom, pinned_pub or local_pub),
            "conflicts": h.trust_store.get_conflicts(base),
            "blocked": dom in h.store.blocked_domains or (bool(local_pub) and local_pub in h.store.blocked_pubkeys),
        }

    raise HTTPException(status_code=404, detail=f"Unknown tool: {name}")


def create_router(h: Any) -> APIRouter:
    router = APIRouter()

    @router.post("/api/ai/cite")
    async def ai_cite(request: Request) -> dict[str, Any]:
        body = await request.json()
        query = str(body.get("query") or "").strip()
        if not query:
            raise HTTPException(status_code=400, detail="query is required")
        dom_filter = str(body.get("domain") or "").strip().lower()
        use_llm = bool(body.get("use_llm", True))
        model = str(body.get("model") or "").strip()
        max_spans = max(1, min(10, int(body.get("max_spans") or 5)))

        citations = await asyncio.to_thread(
            ai_citations.retrieve_verified_spans,
            query,
            h.store,
            h.verify_signature,
            h.rust_sha256,
            h.pattern_mem,
            dom_filter,
            max_spans,
        )
        return await asyncio.to_thread(
            ai_citations.synthesize_cited_answer,
            query,
            citations,
            use_llm,
            model,
        )

    @router.post("/api/ai/publish_note")
    async def ai_publish_note(request: Request) -> dict[str, Any]:
        body = await request.json()
        query = str(body.get("query") or "").strip()
        target_domain = h.normalize_xnd_domain(str(body.get("target_domain") or ""))
        if not query or not h.DOMAIN_RE.match(target_domain):
            raise HTTPException(status_code=400, detail="query and valid target_domain (.xnd) are required")
        use_llm = bool(body.get("use_llm", True))
        model = str(body.get("model") or "").strip()
        title = str(body.get("title") or f"AI Research Note: {query[:64]}").strip()

        citations = await asyncio.to_thread(
            ai_citations.retrieve_verified_spans,
            query,
            h.store,
            h.verify_signature,
            h.rust_sha256,
            h.pattern_mem,
            "",
            5,
        )
        synth = await asyncio.to_thread(
            ai_citations.synthesize_cited_answer,
            query,
            citations,
            use_llm,
            model,
        )
        pub_res = h.publish_document(target_domain, title, synth["answer_markdown"], pinned=True)
        return {**synth, "published": pub_res}

    @router.get("/api/ai/tools")
    def list_ai_tools() -> dict[str, Any]:
        agent_pub, _ = h._get_or_create_ai_agent_key()
        return {
            "ok": True,
            "protocol": "mcp-jsonrpc-2.0",
            "agent_pubkey_hex": agent_pub,
            "agent_fingerprint": h._format_fingerprint(agent_pub),
            "tools": MCP_TOOLS,
        }

    @router.post("/api/ai/tools")
    async def call_ai_tools(request: Request) -> dict[str, Any]:
        body = await request.json()
        rpc_id = body.get("id")
        method = str(body.get("method") or "").strip()
        params = body.get("params") if isinstance(body.get("params"), dict) else {}

        if not method and body.get("tool"):
            method = "tools/call"
            params = {"name": body.get("tool"), "arguments": body.get("arguments") or {}}

        try:
            if method == "initialize":
                result: Any = {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "xanadu-xnd-hub", "version": "1.0.0"},
                }
            elif method == "tools/list":
                result = {"tools": MCP_TOOLS}
            elif method == "tools/call":
                t_name = str(params.get("name") or "").strip()
                t_args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
                out = await asyncio.to_thread(_dispatch_mcp_tool, h, t_name, t_args)
                result = {
                    "content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}],
                    "structuredContent": out,
                    "isError": False,
                }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }
            return {"jsonrpc": "2.0", "id": rpc_id, "result": result}
        except HTTPException as exc:
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {"code": -32000, "message": str(exc.detail)},
            }

    return router
