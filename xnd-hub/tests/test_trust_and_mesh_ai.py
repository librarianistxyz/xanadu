"""Tests for Web-of-Trust PageRank and E2EE Distributed Mesh Inference."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

HUB_DIR = Path(__file__).resolve().parent.parent
if str(HUB_DIR) not in sys.path:
    sys.path.insert(0, str(HUB_DIR))

os.environ.setdefault("XND_DATA_DIR", tempfile.mkdtemp(prefix="xnd_trustmesh_pytest_"))
os.environ.setdefault("XND_RATE_LIMIT", "0")

import e2ee_spaces  # noqa: E402
import hub  # noqa: E402
from services import mesh_inference, trust_rank  # noqa: E402


def test_trust_rank_boosts_endorsed_targets_and_excludes_blocked() -> None:
    pub, priv = hub.generate_keypair()

    # Create a target domain cited by multiple seed domains, plus an unlinked domain and a blocked domain
    target = "wot-target.xnd"
    seed1 = "wot-seed1.xnd"
    seed2 = "wot-seed2.xnd"
    lonely = "wot-lonely.xnd"
    spam = "wot-spam.xnd"

    r_t = hub.publish_document(target, "Target", "Trusted primary reference material.", privkey_hex=priv)
    ptr = f"{{{{xnd://{target}@v1#{r_t['sha256'][:12]}:0-15}}}}"
    hub.publish_document(seed1, "Seed 1", f"Endorsed: {ptr}", privkey_hex=priv)
    hub.publish_document(seed2, "Seed 2", f"Also endorsed: {ptr}", privkey_hex=priv)
    hub.publish_document(lonely, "Lonely", "Nobody cites this page.", privkey_hex=priv)
    hub.publish_document(spam, "Spam", "Blocked spam page.", privkey_hex=priv)

    hub.store.blocked_domains.add(spam)
    ranks = trust_rank.compute_trust_ranks(hub.store, seed_domains=[seed1, seed2])

    assert spam not in ranks
    assert ranks[target] > ranks[lonely]


def test_mesh_inference_e2ee_roundtrip() -> None:
    pub, priv = hub.generate_keypair()
    hub.publish_document(
        "mesh-knowledge.xnd",
        "Mesh Knowledge",
        "Xanadu uses Ed25519 signatures and exact character-span transclusions for verifiable citations.",
        privkey_hex=priv,
    )

    phone_pub, phone_priv = hub.generate_keypair()
    desktop_pub, desktop_priv = hub.generate_keypair()

    req_envelope = e2ee_spaces.encrypt_for_peers(
        json.dumps({"query": "Ed25519 signatures transclusions", "max_spans": 3}),
        phone_priv,
        [desktop_pub],
    )
    res = mesh_inference.process_encrypted_inference(
        desktop_priv,
        desktop_pub,
        phone_pub,
        req_envelope,
        hub.store,
        hub.verify_signature,
        hub.rust_sha256,
        pattern_mem=hub.pattern_mem,
    )
    assert res["ok"] is True
    assert res["citations_count"] >= 1
    assert e2ee_spaces.is_encrypted_blob(res["envelope"])

    # Phone decrypts the desktop's response
    ok, plain, _ = e2ee_spaces.decrypt_with_privkeys(res["envelope"], [phone_priv])
    assert ok is True
    decoded = json.loads(plain)
    assert decoded["citations_count"] >= 1
    assert any("Ed25519" in c["excerpt"] for c in decoded["citations"])


def test_trust_and_mesh_ai_routes_registered() -> None:
    paths = set(hub.app.openapi()["paths"].keys())
    assert "/api/trust/rank" in paths
    assert "/api/mesh/ai/capability" in paths
    assert "/api/mesh/ai/infer" in paths
