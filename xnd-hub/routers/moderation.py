"""Trust pinning, petnames, and moderation/blocklist endpoints."""

import re
from typing import Any

from fastapi import APIRouter, HTTPException, Request

import abuse_guard


def create_router(h: Any) -> APIRouter:
    router = APIRouter()
    ModerationRequest = h.ModerationRequest

    @router.get("/api/trust/pins")
    def get_trust_pins() -> dict[str, Any]:
        return {
            "ok": True,
            "pins": h.trust_store.pins,
            "petnames": h.trust_store.petnames,
            "conflicts": h.trust_store.conflicts,
        }

    @router.post("/api/trust/pin")
    async def pin_domain_key(request: Request) -> dict[str, Any]:
        body = await request.json()
        dom = str(body.get("domain") or "").strip().lower()
        pub = str(body.get("pubkey_hex") or "").strip().lower()
        pet = str(body.get("petname") or "").strip()
        if not h.DOMAIN_RE.match(dom) or not re.match(r"^[0-9a-f]{64}$", pub):
            raise HTTPException(status_code=400, detail="Valid .xnd domain and 64-char hex pubkey_hex are required")
        h.trust_store.set_pin(dom, pub, source="manual")
        if pet:
            h.trust_store.set_petname(dom, pet)
        return {
            "ok": True,
            "domain": dom,
            "pubkey_hex": pub,
            "key_fingerprint": h._format_fingerprint(pub),
            "canonical_domain": h._canonical_domain_for(dom, pub),
        }

    @router.post("/api/trust/petname")
    async def set_domain_petname(request: Request) -> dict[str, Any]:
        body = await request.json()
        key = str(body.get("key") or body.get("domain") or "").strip().lower()
        pet = str(body.get("petname") or "").strip()
        if not key:
            raise HTTPException(status_code=400, detail="key or domain is required")
        h.trust_store.set_petname(key, pet)
        return {"ok": True, "key": key, "petname": pet}

    @router.get("/api/moderation/blocklist/export")
    def export_signed_blocklist() -> dict[str, Any]:
        _, agent_priv = h._get_or_create_ai_agent_key()
        all_doms = list(set(h.store.blocked_domains) | h.blocklist_mgr.blocked_domains)
        all_pubs = list(set(h.store.blocked_pubkeys) | h.blocklist_mgr.blocked_pubkeys)
        return abuse_guard.sign_blocklist(agent_priv, all_doms, all_pubs)

    @router.post("/api/moderation/blocklist/import")
    async def import_signed_blocklist(request: Request) -> dict[str, Any]:
        body = await request.json()
        req_trusted = bool(body.get("require_trusted_issuer", False))
        res = h.blocklist_mgr.import_signed(body, require_trusted_issuer=req_trusted)
        if not res.get("ok"):
            raise HTTPException(status_code=403, detail=res.get("error", "Invalid blocklist"))
        for d in h.blocklist_mgr.blocked_domains:
            h.store.blocked_domains.add(d)
        for p in h.blocklist_mgr.blocked_pubkeys:
            h.store.blocked_pubkeys.add(p)
        return res

    @router.get("/api/moderation")
    def get_moderation() -> dict[str, Any]:
        return {
            "blocked_domains": sorted(h.store.blocked_domains),
            "blocked_pubkeys": sorted(h.store.blocked_pubkeys),
            "followed_pubkeys": sorted(h.store.followed_pubkeys),
        }

    @router.post("/api/moderation/block")
    def block_content(req: ModerationRequest) -> dict[str, Any]:
        dom = req.domain.strip().lower()
        pub = req.pubkey_hex.strip().lower()
        if dom:
            h.store.blocked_domains.add(dom)
            h.store.delete_domain(dom)
        if pub:
            h.store.blocked_pubkeys.add(pub)
            for d_name, d_obj in list(h.store.domains.items()):
                if d_obj.get("pubkey_hex", "").lower() == pub:
                    h.store.delete_domain(d_name)
        h.store.save_moderation()
        return {"ok": True, **get_moderation()}

    @router.post("/api/moderation/unblock")
    def unblock_content(req: ModerationRequest) -> dict[str, Any]:
        dom = req.domain.strip().lower()
        pub = req.pubkey_hex.strip().lower()
        if dom:
            h.store.blocked_domains.discard(dom)
        if pub:
            h.store.blocked_pubkeys.discard(pub)
        h.store.save_moderation()
        return {"ok": True, **get_moderation()}

    @router.post("/api/moderation/delete_domain")
    def delete_local_domain(req: ModerationRequest) -> dict[str, Any]:
        dom = req.domain.strip().lower()
        deleted = h.store.delete_domain(dom) if dom else False
        return {"ok": True, "deleted": deleted, "domain": dom}

    @router.post("/api/moderation/follow")
    def follow_pubkey(req: ModerationRequest) -> dict[str, Any]:
        pub = req.pubkey_hex.strip().lower()
        if pub:
            if pub in h.store.followed_pubkeys:
                h.store.followed_pubkeys.discard(pub)
            else:
                h.store.followed_pubkeys.add(pub)
            h.store.save_moderation()
        return {"ok": True, **get_moderation()}

    return router
