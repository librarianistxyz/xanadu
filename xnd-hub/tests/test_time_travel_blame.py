"""Tests for Time-Travel Hypertext Graph & Global Provenance Blame Explorer."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

HUB_DIR = Path(__file__).resolve().parent.parent
if str(HUB_DIR) not in sys.path:
    sys.path.insert(0, str(HUB_DIR))

os.environ.setdefault("XND_DATA_DIR", tempfile.mkdtemp(prefix="xnd_timetravel_pytest_"))
os.environ.setdefault("XND_RATE_LIMIT", "0")

import hub  # noqa: E402
from routers import time_travel  # noqa: E402


def test_blame_detects_unchanged_edited_and_retracted_sources() -> None:
    pub, priv = hub.generate_keypair()

    # Source A: published at v1, then edited at v2
    src_a = "blame-src-a.xnd"
    r_a1 = hub.publish_document(src_a, "Source A", "Original claim about decentralized hypertext.", privkey_hex=priv)
    # Source B: published at v1, then retracted (emptied) at v2
    src_b = "blame-src-b.xnd"
    r_b1 = hub.publish_document(src_b, "Source B", "Temporary statement that gets retracted.", privkey_hex=priv)
    # Source C: stays unchanged at v1
    src_c = "blame-src-c.xnd"
    r_c1 = hub.publish_document(src_c, "Source C", "Immutable anchor sentence.", privkey_hex=priv)

    # Quoter quotes all three at v1
    quoter = "blame-quoter.xnd"
    body = (
        f"A: {{{{xnd://{src_a}@v1#{r_a1['sha256'][:12]}:0-14}}}}\n"
        f"B: {{{{xnd://{src_b}@v1#{r_b1['sha256'][:12]}:0-19}}}}\n"
        f"C: {{{{xnd://{src_c}@v1#{r_c1['sha256'][:12]}:0-16}}}}"
    )
    hub.publish_document(quoter, "Quoter", body, privkey_hex=priv)

    # Mutate A (edit) and B (retract)
    hub.publish_document(src_a, "Source A v2", "Modified claim about centralized systems.", privkey_hex=priv)
    hub.publish_document(src_b, "Source B v2", " ", privkey_hex=priv)

    blame = time_travel.build_blame_payload(hub, quoter)
    quotes = [s for s in blame["segments"] if s["type"] == "transclusion"]
    assert len(quotes) == 3

    by_dom = {q["target_domain"]: q for q in quotes}
    assert by_dom[src_a]["source_status"] == "edited"
    assert by_dom[src_a]["latest_version"] == 2
    assert by_dom[src_a]["author_pubkey"] == pub

    assert by_dom[src_b]["source_status"] == "retracted"
    assert by_dom[src_b]["latest_version"] == 2

    assert by_dom[src_c]["source_status"] == "unchanged"
    assert by_dom[src_c]["latest_version"] == 1


def test_timetravel_graph_scrubs_past_state() -> None:
    pub, priv = hub.generate_keypair()
    t1 = 1700100000.0
    t2 = 1700200000.0

    dom1 = "tt-origin.xnd"
    dom2 = "tt-future.xnd"
    c1 = "Origin at t1."
    s1 = hub.rust_sha256(c1)
    hub.store.append_version(
        {
            "domain": dom1,
            "version_num": 1,
            "sha256": s1,
            "prev_sha256": "",
            "title": "Origin",
            "kind": "document",
            "pubkey_hex": pub,
            "signature_hex": hub.sign_payload(priv, dom1, 1, s1, ""),
            "created_at": t1,
        },
        c1,
        pinned=True,
    )

    c2 = f"Future quote: {{{{xnd://{dom1}@v1#{s1[:12]}:0-13}}}}"
    s2 = hub.rust_sha256(c2)
    hub.store.append_version(
        {
            "domain": dom2,
            "version_num": 1,
            "sha256": s2,
            "prev_sha256": "",
            "title": "Future",
            "kind": "document",
            "pubkey_hex": pub,
            "signature_hex": hub.sign_payload(priv, dom2, 1, s2, ""),
            "created_at": t2,
        },
        c2,
        pinned=True,
    )

    past = time_travel.build_timetravel_graph(hub, ts=t1 + 10.0)
    past_ids = {n["id"] for n in past["nodes"]}
    assert dom1 in past_ids
    assert dom2 not in past_ids
    assert not any(e["source"] == dom2 for e in past["edges"])

    present = time_travel.build_timetravel_graph(hub, ts=t2 + 10.0)
    present_ids = {n["id"] for n in present["nodes"]}
    assert dom1 in present_ids and dom2 in present_ids
    assert any(e["source"] == dom2 and e["target"] == dom1 for e in present["edges"])


def test_timetravel_and_blame_routes_registered() -> None:
    paths = set(hub.app.openapi()["paths"].keys())
    assert "/api/blame/{domain}" in paths
    assert "/api/graph/timetravel" in paths
