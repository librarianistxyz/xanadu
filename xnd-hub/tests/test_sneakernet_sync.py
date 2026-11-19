"""Tests for air-gapped Sneakernet (.xndbundle) and Animated QR (`XNDQ1`) delta sync."""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

HUB_DIR = Path(__file__).resolve().parent.parent
if str(HUB_DIR) not in sys.path:
    sys.path.insert(0, str(HUB_DIR))

os.environ.setdefault("XND_DATA_DIR", tempfile.mkdtemp(prefix="xnd_sneaker_pytest_"))
os.environ.setdefault("XND_RATE_LIMIT", "0")

import crdt_sync  # noqa: E402
import e2ee_spaces  # noqa: E402
import hub  # noqa: E402
from services import sneakernet_sync  # noqa: E402


def _make_signed_version(domain: str, ver_num: int, content: str, priv: str, pub: str, ts: float, prev_sha: str = "") -> dict:
    sha = hub.rust_sha256(content)
    sig = hub.sign_payload(priv, domain, ver_num, sha, prev_sha)
    return {
        "domain": domain,
        "version_num": ver_num,
        "sha256": sha,
        "prev_sha256": prev_sha,
        "title": f"{domain} v{ver_num}",
        "kind": "document",
        "pubkey_hex": pub,
        "signature_hex": sig,
        "created_at": ts,
    }


def test_delta_bundle_pack_unpack_and_tamper_detection(tmp_path: Path) -> None:
    pub, priv = hub.generate_keypair()
    t1, t2 = 1700000100.0, 1700000200.0
    v1 = _make_signed_version("alpha.xnd", 1, "old doc", priv, pub, t1)
    v2 = _make_signed_version("beta.xnd", 1, "new doc", priv, pub, t2)
    full = {
        "domains": [
            {"name": "alpha.xnd", "pubkey_hex": pub, "created_at": t1},
            {"name": "beta.xnd", "pubkey_hex": pub, "created_at": t2},
        ],
        "blobs": [
            {"sha256": v1["sha256"], "content": "old doc", "created_at": t1},
            {"sha256": v2["sha256"], "content": "new doc", "created_at": t2},
        ],
        "versions": [v1, v2],
        "links": [],
        "assets": [],
        "forum_posts": [],
        "crdt_events": [],
        "wiki_shards": [],
    }
    delta = sneakernet_sync.build_delta_bundle(full, since_ts=1700000150.0)
    assert [v["domain"] for v in delta["versions"]] == ["beta.xnd"]
    assert [b["content"] for b in delta["blobs"]] == ["new doc"]

    env = sneakernet_sync.pack_sneakernet_envelope(delta, since_ts=1700000150.0)
    dest = sneakernet_sync.export_bundle_to_file(str(tmp_path), env, filename="delta_test")
    assert dest.name == "delta_test.xndbundle"
    assert dest.is_file()

    unpacked = sneakernet_sync.import_bundle_from_file(str(dest))
    assert unpacked["versions"][0]["domain"] == "beta.xnd"

    env["bundle_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        sneakernet_sync.unpack_sneakernet_envelope(env)


def test_sneakernet_e2ee_and_crdt_import_roundtrip(tmp_path: Path) -> None:
    alice_pub, alice_priv = hub.generate_keypair()
    bob_pub, bob_priv = hub.generate_keypair()

    dom = "secret-sneaker.xnd"
    ciphertext = e2ee_spaces.encrypt_for_peers("Meet at dock 7 at noon.", alice_priv, [bob_pub])
    now = time.time()
    ver = _make_signed_version(dom, 1, ciphertext, alice_priv, alice_pub, now)
    evt = crdt_sync.create_signed_event(dom, "append", "posts", "", {"msg": "offline hello"}, alice_priv, ts=now)

    bundle = {
        "domains": [{"name": dom, "pubkey_hex": alice_pub, "created_at": now}],
        "blobs": [{"sha256": ver["sha256"], "content": ciphertext, "created_at": now}],
        "versions": [ver],
        "links": [],
        "assets": [],
        "forum_posts": [],
        "crdt_events": [evt],
        "wiki_shards": [],
    }
    env = sneakernet_sync.pack_sneakernet_envelope(bundle)
    saved = sneakernet_sync.export_bundle_to_file(str(tmp_path), env)
    unpacked = sneakernet_sync.import_bundle_from_file(str(saved))

    stats = hub.import_sync_bundle(unpacked)
    assert stats["imported_versions"] == 1
    assert stats["rejected"] == 0

    stored_row = hub.store.get_version(dom, None)
    assert stored_row is not None
    stored_ct = hub.store.get_blob(stored_row["sha256"]) or ""
    ok, plaintext, _ = e2ee_spaces.decrypt_with_privkeys(stored_ct, [bob_priv])
    assert ok is True
    assert plaintext == "Meet at dock 7 at noon."
    assert hub.crdt_log.materialize_collection(dom, "posts") == [{"msg": "offline hello"}]


def test_animated_qr_encode_out_of_order_reassembly_and_crc() -> None:
    pub, priv = hub.generate_keypair()
    dom = "qr-mesh-test.xnd"
    body = "Xanadu air-gapped QR payload. " * 60
    now = time.time()
    ver = _make_signed_version(dom, 1, body, priv, pub, now)
    bundle = {
        "domains": [{"name": dom, "pubkey_hex": pub, "created_at": now}],
        "blobs": [{"sha256": ver["sha256"], "content": body, "created_at": now}],
        "versions": [ver],
        "links": [],
        "assets": [],
        "forum_posts": [],
        "crdt_events": [],
        "wiki_shards": [],
    }

    encoded = sneakernet_sync.encode_animated_qr_frames(bundle, chunk_bytes=160, include_svg=True)
    frames = encoded["frames"]
    assert encoded["total_frames"] >= 2
    assert len(encoded["svgs"]) == len(frames)
    assert "<svg" in encoded["svgs"][0]

    # Corrupt CRC on first frame
    parts = frames[0].split("|", 5)
    bad_frame = "|".join([parts[0], parts[1], parts[2], parts[3], "deadbeef", parts[5]])
    rx = sneakernet_sync.QrReassemblySession()
    with pytest.raises(ValueError, match="CRC32 mismatch"):
        rx.add_frame(bad_frame)

    # Feed frames in reverse order + duplicate frame
    last_res = None
    for f in reversed(frames):
        last_res = rx.add_frame(f)
    assert last_res is not None
    assert last_res["complete"] is True
    assert last_res["bundle_sha256"] == encoded["bundle_sha256"]
    assert last_res["bundle"]["versions"][0]["domain"] == dom


def test_sneakernet_routes_registered() -> None:
    paths = set(hub.app.openapi()["paths"].keys())
    expected = {
        "/api/sneakernet/usb/mounts",
        "/api/sneakernet/export/file",
        "/api/sneakernet/import/file",
        "/api/sneakernet/qr/encode",
        "/api/sneakernet/qr/receive",
    }
    assert not (expected - paths)
