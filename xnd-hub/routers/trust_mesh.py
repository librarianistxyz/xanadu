"""Web-of-Trust PageRank & E2EE Distributed Mesh Inference routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from services import mesh_inference, trust_rank


def create_router(hub: Any) -> APIRouter:
    router = APIRouter()

    @router.get("/api/trust/rank")
    def api_trust_rank(seeds: str = Query(default="")) -> dict[str, Any]:
        seed_list = [s.strip() for s in seeds.split(",") if s.strip()]
        ranks = trust_rank.compute_trust_ranks(hub.store, seed_domains=seed_list or None)
        return {"ok": True, "ranks": ranks}

    @router.get("/api/mesh/ai/capability")
    def api_mesh_ai_capability() -> dict[str, Any]:
        pub_hex, _ = hub._get_or_create_sdk_signing_key("mesh-ai.xnd")
        return {"ok": True, **mesh_inference.get_node_ai_capability(pub_hex)}

    @router.post("/api/mesh/ai/infer")
    async def api_mesh_ai_infer(request: Request) -> dict[str, Any]:
        body = await request.json()
        envelope = str((body or {}).get("envelope") or "").strip()
        requester_pub = str((body or {}).get("requester_pubkey") or "").strip().lower()
        if not envelope:
            raise HTTPException(status_code=400, detail="Missing E2EE 'envelope'")
        pub_hex, priv_hex = hub._get_or_create_sdk_signing_key("mesh-ai.xnd")
        try:
            return mesh_inference.process_encrypted_inference(
                priv_hex,
                pub_hex,
                requester_pub,
                envelope,
                hub.store,
                hub.verify_signature,
                hub.rust_sha256,
                pattern_mem=hub.pattern_mem,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return router
