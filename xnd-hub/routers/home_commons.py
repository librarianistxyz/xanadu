"""Transparent Web-of-Trust, Latest Citations, and Fair Interval Rotation Home endpoint."""

import hashlib
import time
from typing import Any

from fastapi import APIRouter, Query


def _fmt_age(ts: float, now: float) -> str:
    diff = max(0, int(now - ts))
    if diff < 60:
        return f"{diff}s"
    if diff < 3600:
        return f"{diff // 60}m"
    if diff < 86400:
        return f"{diff // 3600}h"
    return f"{diff // 86400}d"


def create_router(h: Any) -> APIRouter:
    router = APIRouter()

    @router.get("/api/home/commons")
    def get_home_commons(
        mode: str = Query(default="all"),
        limit: int = Query(default=24, ge=1, le=60),
    ) -> dict[str, Any]:
        now = time.time()
        bucket = int(now // 900)  # 15-minute fair rotation window
        clean_mode = (mode or "all").strip().lower()
        lan_count = len(h._LAN_PEERS)

        # 1. Latest verified two-way transclusion citations
        citations_out: list[dict[str, Any]] = []
        seen_cites: set[tuple[str, str, int, int]] = set()
        for lk in reversed(list(h.store.all_links)):
            src = str(lk.get("source_domain") or "").lower()
            tgt = str(lk.get("target_domain") or "").lower()
            if not src or not tgt or src in h.store.blocked_domains or tgt in h.store.blocked_domains:
                continue
            s_idx = int(lk.get("target_start") or 0)
            e_idx = int(lk.get("target_end") or 0)
            sig_key = (src, tgt, s_idx, e_idx)
            if sig_key in seen_cites:
                continue
            seen_cites.add(sig_key)
            quote_text = ""
            tgt_ver = h.store.get_version(tgt, lk.get("target_version"))
            if tgt_ver:
                blob = h.store.get_blob(str(tgt_ver.get("sha256") or ""))
                if blob and 0 <= s_idx < e_idx <= len(blob):
                    quote_text = blob[s_idx:e_idx].strip()[:180]
            citations_out.append({
                "source_domain": src,
                "source_version": int(lk.get("source_version") or 1),
                "target_domain": tgt,
                "target_version": int(lk.get("target_version") or 1),
                "start": s_idx,
                "end": e_idx,
                "quote": quote_text,
                "age": _fmt_age(float(lk.get("created_at") or now), now),
                "reason": f"Quoted by {src}",
            })
            if len(citations_out) >= 10:
                break

        # 2. Fair interval-rotated + provenance-labeled domain cards (max 1 per pubkey in rotation)
        candidates: list[dict[str, Any]] = []
        for dom, dom_obj in list(h.store.domains.items()):
            pub = str(dom_obj.get("pubkey_hex") or "").lower()
            if dom in h.store.blocked_domains or (pub and pub in h.store.blocked_pubkeys):
                continue
            vers = h.store.versions.get(dom, [])
            if not vers:
                continue
            latest = vers[-1]
            kind = str(latest.get("kind") or ("capsule" if latest.get("is_app") else "document"))
            bl_list = h.store.links_by_target.get(dom, [])
            bl_count = len(bl_list)
            is_followed = bool(pub and pub in h.store.followed_pubkeys)
            created_at = float(latest.get("created_at") or dom_obj.get("created_at") or now)
            age_str = _fmt_age(created_at, now)

            if clean_mode == "cited" and bl_count == 0:
                continue
            if clean_mode == "followed" and not is_followed:
                continue
            if clean_mode == "capsules" and kind != "capsule":
                continue

            if bl_count > 0:
                quoter = str(bl_list[-1].get("source_domain") or "peer.xnd")
                reason = f"Quoted by {quoter}" if bl_count == 1 else f"Quoted by {quoter} (+{bl_count - 1})"
                reason_kind = "cited"
            elif is_followed:
                reason = f"Updated {age_str} ago by a key you follow"
                reason_kind = "followed"
            elif lan_count > 0:
                reason = f"Available across {lan_count} Wi-Fi peer(s) • {age_str}"
                reason_kind = "mesh"
            else:
                reason = f"Rotation window • updated {age_str} ago"
                reason_kind = "rotation"

            rot_hash = hashlib.sha256(f"{bucket}:{dom}".encode("utf-8")).hexdigest()
            candidates.append({
                "domain": dom,
                "title": str(latest.get("title") or dom),
                "kind": kind,
                "version": int(latest.get("version_num") or 1),
                "pubkey_hex": pub,
                "fingerprint": h._format_fingerprint(pub),
                "petname": h.trust_store.get_petname(dom, pub),
                "snippet": str(h.store.doc_snippets.get(dom) or latest.get("preview") or "")[:180],
                "backlinks": bl_count,
                "followed": is_followed,
                "age": age_str,
                "reason": reason,
                "reason_kind": reason_kind,
                "_rot": rot_hash,
            })

        if clean_mode == "cited":
            candidates.sort(key=lambda x: (-x["backlinks"], x["_rot"]))
        else:
            candidates.sort(key=lambda x: (0 if x["followed"] else (1 if x["backlinks"] > 0 else 2), x["_rot"]))

        # Enforce fairness: max 1 slot per pubkey in the spotlight unless pool is tiny
        selected: list[dict[str, Any]] = []
        seen_pubs: set[str] = set()
        overflow: list[dict[str, Any]] = []
        for c in candidates:
            p = c["pubkey_hex"]
            if p and p in seen_pubs:
                overflow.append(c)
                continue
            if p:
                seen_pubs.add(p)
            c.pop("_rot", None)
            selected.append(c)
            if len(selected) >= limit:
                break
        if len(selected) < limit:
            for c in overflow:
                c.pop("_rot", None)
                selected.append(c)
                if len(selected) >= limit:
                    break

        return {
            "ok": True,
            "mode": clean_mode,
            "rotation_bucket": bucket,
            "rotation_interval_sec": 900,
            "lan_peers": lan_count,
            "latest_citations": citations_out,
            "items": selected,
        }

    return router
