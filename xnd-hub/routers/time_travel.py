"""Time-Travel Hypertext Graph & Global Provenance Blame Explorer routes."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query

import transclusion_engine


def build_blame_payload(hub: Any, domain: str, version: int | None = None) -> dict[str, Any]:
    dom = (domain or "").strip().lower()
    row = hub.store.get_version(dom, version)
    if row is None:
        raise HTTPException(status_code=404, detail="Domain or version not found")
    content = hub.store.get_blob(row["sha256"]) or ""
    segments = transclusion_engine.build_segments(
        content,
        hub.store.get_version,
        hub.store.get_blob,
        get_latest_version_fn=lambda d: hub.store.get_version(d, None),
    )
    return {
        "ok": True,
        "domain": dom,
        "version": int(row["version_num"]),
        "sha256": row["sha256"],
        "prev_sha256": row.get("prev_sha256", ""),
        "pubkey_hex": row.get("pubkey_hex", ""),
        "created_at": float(row.get("created_at") or 0.0),
        "title": row.get("title", dom),
        "segments": segments,
    }


def build_timetravel_graph(hub: Any, ts: float | None = None) -> dict[str, Any]:
    all_ts: list[float] = []
    for vers in hub.store.versions.values():
        for v in vers:
            t = float(v.get("created_at") or 0.0)
            if t > 0:
                all_ts.append(t)
    all_ts.sort()
    min_ts = all_ts[0] if all_ts else 0.0
    max_ts = all_ts[-1] if all_ts else time.time()
    cutoff = float(ts) if ts is not None else max_ts

    nodes: list[dict[str, Any]] = []
    active_versions: dict[str, dict[str, Any]] = {}
    for name, vers in hub.store.versions.items():
        chosen = None
        for v in vers:
            if float(v.get("created_at") or 0.0) <= cutoff:
                chosen = v
        if chosen is None:
            continue
        active_versions[name] = chosen
        k = chosen.get("kind") or ("capsule" if chosen.get("is_app") else "document")
        nodes.append({
            "id": name,
            "title": chosen.get("title", name),
            "kind": k,
            "version": int(chosen.get("version_num") or 1),
            "pubkey_hex": str(chosen.get("pubkey_hex") or ""),
            "sha256": str(chosen.get("sha256") or ""),
            "created_at": float(chosen.get("created_at") or 0.0),
        })

    seen_edges: set[tuple[str, str, str]] = set()
    edges: list[dict[str, Any]] = []
    for src_dom, ver_row in active_versions.items():
        content = hub.store.get_blob(ver_row["sha256"]) or ""
        for lk in transclusion_engine.extract_transclusion_links(
            src_dom, int(ver_row["version_num"]), content, hub.store.get_version
        ):
            tgt = lk["target_domain"]
            if tgt not in active_versions:
                continue
            ek = (src_dom, tgt, "transclusion")
            if ek not in seen_edges:
                seen_edges.add(ek)
                edges.append({
                    "source": src_dom,
                    "target": tgt,
                    "link_type": "transclusion",
                    "hash_verified": lk.get("hash_verified", True),
                })

    return {
        "ok": True,
        "ts": cutoff,
        "min_ts": min_ts,
        "max_ts": max_ts,
        "timeline": all_ts[-100:],
        "nodes": nodes,
        "edges": edges,
    }


def create_router(hub: Any) -> APIRouter:
    router = APIRouter()

    @router.get("/api/blame/{domain}")
    def api_blame_domain(domain: str, version: int | None = Query(default=None)) -> dict[str, Any]:
        return build_blame_payload(hub, domain, version)

    @router.get("/api/graph/timetravel")
    def api_graph_timetravel(ts: float | None = Query(default=None)) -> dict[str, Any]:
        return build_timetravel_graph(hub, ts)

    return router
