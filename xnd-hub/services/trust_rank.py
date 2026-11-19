"""Personalized Web-of-Trust PageRank (Anti-SEO Search) over verified transclusions."""

from __future__ import annotations

from typing import Any


def compute_trust_ranks(
    store: Any,
    seed_domains: list[str] | None = None,
    damping: float = 0.85,
    iterations: int = 20,
) -> dict[str, float]:
    """Compute personalized PageRank [0.0..1.0] over verified transclusion links."""
    blocked_doms = {d.lower() for d in getattr(store, "blocked_domains", set())}
    blocked_pubs = {p.lower() for p in getattr(store, "blocked_pubkeys", set())}
    followed_pubs = {p.lower() for p in getattr(store, "followed_pubkeys", set())}

    nodes: list[str] = []
    for name, dom_rec in store.domains.items():
        nm = name.lower()
        pub = str(dom_rec.get("pubkey_hex") or "").lower()
        if nm in blocked_doms or (pub and pub in blocked_pubs):
            continue
        if store.versions.get(nm):
            nodes.append(nm)

    if not nodes:
        return {}

    node_set = set(nodes)
    outbound: dict[str, list[str]] = {n: [] for n in nodes}
    for lk in getattr(store, "all_links", []):
        if lk.get("hash_verified") is False:
            continue
        src = str(lk.get("source_domain") or "").lower()
        tgt = str(lk.get("target_domain") or "").lower()
        if src in node_set and tgt in node_set and src != tgt:
            outbound[src].append(tgt)

    seeds: set[str] = {s.strip().lower() for s in (seed_domains or []) if s.strip().lower() in node_set}
    if not seeds:
        for n in nodes:
            dom_rec = store.domains.get(n, {})
            pub = str(dom_rec.get("pubkey_hex") or "").lower()
            if dom_rec.get("privkey_hex") or (pub and pub in followed_pubs):
                seeds.add(n)

    n_count = len(nodes)
    if seeds:
        pers = {n: (1.0 / len(seeds) if n in seeds else 0.0) for n in nodes}
    else:
        pers = {n: 1.0 / n_count for n in nodes}

    rank = dict(pers)
    for _ in range(max(1, int(iterations))):
        nxt = {n: (1.0 - damping) * pers[n] for n in nodes}
        dangling_mass = sum(rank[n] for n in nodes if not outbound[n])
        for n in nodes:
            nxt[n] += damping * dangling_mass * pers[n]
            outs = outbound[n]
            if outs:
                share = damping * rank[n] / len(outs)
                for tgt in outs:
                    nxt[tgt] += share
        rank = nxt

    max_r = max(rank.values()) if rank else 0.0
    if max_r <= 0.0:
        return {n: 0.0 for n in nodes}
    return {n: round(rank[n] / max_r, 6) for n in sorted(nodes, key=lambda x: (-rank[x], x))}
