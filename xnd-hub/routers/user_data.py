"""Bookmarks, history, and quote-clipping endpoints."""

import re
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query


def create_router(h: Any) -> APIRouter:
    router = APIRouter()
    BookmarkRequest = h.BookmarkRequest
    HistoryRequest = h.HistoryRequest
    ClipQuoteRequest = h.ClipQuoteRequest

    @router.get("/api/bookmarks")
    def api_get_bookmarks() -> dict[str, Any]:
        return {"bookmarks": h.store.get_bookmarks()}

    @router.post("/api/bookmarks")
    def api_add_bookmark(req: BookmarkRequest) -> dict[str, Any]:
        return {"ok": True, "bookmarks": h.store.add_bookmark(req.url, req.title, req.kind)}

    @router.delete("/api/bookmarks")
    def api_delete_bookmark(url: str = Query(...)) -> dict[str, Any]:
        return {"ok": True, "bookmarks": h.store.remove_bookmark(url)}

    @router.get("/api/history")
    def api_get_history(q: str = Query(default="")) -> dict[str, Any]:
        return {"history": h.store.search_history(q)}

    @router.post("/api/history")
    def api_add_history(req: HistoryRequest) -> dict[str, Any]:
        h.store.record_history(req.url, req.title, req.kind)
        return {"ok": True}

    @router.post("/api/clip")
    def api_clip_quote(req: ClipQuoteRequest) -> dict[str, Any]:
        quote = req.quote.strip()
        if not quote:
            raise HTTPException(status_code=400, detail="Selected quote text is required")
        src = req.url.strip() or "https://unknown"
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        target_domain = req.domain.strip().lower()
        if target_domain:
            if not target_domain.endswith(".xnd"):
                target_domain = re.sub(r"[^a-z0-9\-]+", "-", target_domain).strip("-")[:58] + ".xnd"
            if not h.DOMAIN_RE.match(target_domain):
                raise HTTPException(status_code=400, detail="Invalid .xnd domain")
        else:
            target_domain = f"clip-{h.rust_sha256(src + quote)[:8]}.xnd"

        existing = h.store.get_version(target_domain)
        existing_text = h.store.get_blob(existing["sha256"]) if existing else ""
        clip_block = f"Archived from: {src}\nClipped at: {ts}\n\n> {quote}\n"
        if existing_text:
            new_content = existing_text.rstrip() + "\n\n" + clip_block
        else:
            heading = req.title.strip() or src
            new_content = f"Archived from: {src}\n\n# {heading}\n\nClipped at: {ts}\n\n> {quote}\n"

        res = h.publish_document(
            target_domain,
            f"[Clip] {(req.title or src)[:70]}",
            new_content,
            bypass_short_rule=True,
            pinned=True,
        )
        return {
            "ok": True,
            **res,
            "pointer": f"{{{{xnd://{target_domain}@v{res['version']}:0-{len(new_content)}}}}}",
        }

    return router
