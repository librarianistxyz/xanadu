"""Tests for SQLite+FTS5 index, bounded metadata eviction, on-demand peer resolution, and paginated manifest."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

HUB_DIR = Path(__file__).resolve().parent.parent
if str(HUB_DIR) not in sys.path:
    sys.path.insert(0, str(HUB_DIR))

os.environ.setdefault("XND_DATA_DIR", tempfile.mkdtemp(prefix="xnd_scale_pytest_"))
os.environ.setdefault("XND_RATE_LIMIT", "0")

import hub  # noqa: E402
import peer_store  # noqa: E402
from peer_store import PeerStore  # noqa: E402


def test_sqlite_fts5_indexing_and_search(tmp_path: Path) -> None:
    st = PeerStore(tmp_path, hub.rust_sha256)
    try:
        pub, priv = hub.generate_keypair()
        content = "Decentralized hypertext with deterministic FTS5 indexing."
        sha = hub.rust_sha256(content)
        sig = hub.sign_payload(priv, "fts-demo.xnd", 1, sha, "")
        st.append_version(
            {
                "domain": "fts-demo.xnd",
                "version_num": 1,
                "sha256": sha,
                "prev_sha256": "",
                "title": "FTS Demo",
                "kind": "document",
                "pubkey_hex": pub,
                "signature_hex": sig,
                "created_at": time.time(),
            },
            content,
            pinned=True,
        )
        fts_hits = st.index_db.search_fts("deterministic indexing")
        assert any(h["domain"] == "fts-demo.xnd" for h in fts_hits)
        ram_hits = st.search_ram("deterministic indexing")
        assert any(h["domain"] == "fts-demo.xnd" for h in ram_hits)
    finally:
        st.index_db.close()


def test_unpinned_metadata_and_blob_eviction(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(peer_store, "MAX_CACHED_DOMAINS", 4)
    st = PeerStore(tmp_path, hub.rust_sha256)
    try:
        # 1 pinned/owned domain that must NEVER be evicted
        pub_own, priv_own = hub.generate_keypair()
        st.get_or_create_domain_keys("owned-keep.xnd", pub_own, priv_own)
        c_own = "Owned site content"
        s_own = hub.rust_sha256(c_own)
        st.append_version(
            {
                "domain": "owned-keep.xnd",
                "version_num": 1,
                "sha256": s_own,
                "prev_sha256": "",
                "title": "Owned",
                "kind": "document",
                "pubkey_hex": pub_own,
                "signature_hex": hub.sign_payload(priv_own, "owned-keep.xnd", 1, s_own, ""),
                "created_at": 100.0,
            },
            c_own,
            pinned=True,
        )

        # 7 unpinned domains -> oldest should be evicted to stay <= MAX_CACHED_DOMAINS (4)
        for i in range(7):
            dom = f"cached-{i}.xnd"
            pub, priv = hub.generate_keypair()
            txt = f"Cached ephemeral page {i}"
            sha = hub.rust_sha256(txt)
            st.append_version(
                {
                    "domain": dom,
                    "version_num": 1,
                    "sha256": sha,
                    "prev_sha256": "",
                    "title": f"Cached {i}",
                    "kind": "document",
                    "pubkey_hex": pub,
                    "signature_hex": hub.sign_payload(priv, dom, 1, sha, ""),
                    "created_at": 200.0 + i,
                },
                txt,
                pinned=False,
            )
            time.sleep(0.005)

        assert "owned-keep.xnd" in st.domains
        assert st.index_db.count_unpinned_domains() <= 4
        assert "cached-0.xnd" not in st.domains
        assert "cached-6.xnd" in st.domains
    finally:
        st.index_db.close()


def test_on_demand_peer_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    dom = "on-demand-peer-test.xnd"
    pub, priv = hub.generate_keypair()
    content = "Served on-demand from a LAN/DHT peer."
    sha = hub.rust_sha256(content)
    sig = hub.sign_payload(priv, dom, 1, sha, "")
    fake_bundle = {
        "domains": [{"name": dom, "pubkey_hex": pub, "created_at": time.time()}],
        "blobs": [{"sha256": sha, "content": content, "created_at": time.time()}],
        "versions": [
            {
                "domain": dom,
                "version_num": 1,
                "sha256": sha,
                "prev_sha256": "",
                "title": "On-Demand Peer Site",
                "kind": "document",
                "pubkey_hex": pub,
                "signature_hex": sig,
                "created_at": time.time(),
            }
        ],
        "links": [],
    }

    monkeypatch.setitem(hub._LAN_PEERS, "http://10.0.0.42:8765", {"url": "http://10.0.0.42:8765", "label": "Peer"})
    monkeypatch.setattr(hub, "_peer_get", lambda peer_url, path, timeout=2.5: json.dumps(fake_bundle))

    client = TestClient(hub.app, client=("127.0.0.1", 50000))
    resp = client.get(f"/api/resolve/{dom}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == dom
    assert data["verified"] is True
    assert data["raw_content"] == content


def test_paginated_sync_manifest() -> None:
    client = TestClient(hub.app, client=("127.0.0.1", 50000))
    r1 = client.get("/api/sync/manifest?since=0&limit=1")
    assert r1.status_code == 200
    p1 = r1.json()
    assert p1["ok"] is True
    assert len(p1["domains"]) <= 1
    if p1["has_more"]:
        r2 = client.get(f"/api/sync/manifest?since={p1['next_cursor']}&limit=1")
        assert r2.status_code == 200
        p2 = r2.json()
        assert set(p1["domains"].keys()).isdisjoint(set(p2["domains"].keys()))
