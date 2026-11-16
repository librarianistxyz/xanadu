#!/usr/bin/env python3
"""Cross-implementation conformance verifier for Xanadu (.xnd) Wire Spec v1."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SPEC_DIR = Path(__file__).resolve().parent
ROOT_DIR = SPEC_DIR.parent
HUB_DIR = ROOT_DIR / "xnd-hub"
RUST_CORE = ROOT_DIR / "xnd-core" / "target" / "release" / "xnd-core"
ANDROID_SRC = ROOT_DIR / "xnd-android" / "src" / "com" / "xanadu" / "browser"


def main() -> None:
    os.environ["XND_DATA_DIR"] = tempfile.mkdtemp(prefix="xnd_conf_")
    sys.path.insert(0, str(HUB_DIR))

    import e2ee_spaces
    import hub
    import transclusion_engine

    tv = json.loads((SPEC_DIR / "test_vectors.json").read_text(encoding="utf-8"))
    dom = tv["domain"]

    # 1. Python hub conformance
    assert hub.rust_sha256(tv["v1"]["content"]) == tv["v1"]["sha256"]
    assert hub.rust_sha256(tv["v2"]["content"]) == tv["v2"]["sha256"]
    assert hub.verify_signature(
        tv["author_pubkey_hex"], dom, 1, tv["v1"]["sha256"], tv["v1"]["signature_hex"], ""
    )
    assert hub.verify_signature(
        tv["author_pubkey_hex"], dom, 2, tv["v2"]["sha256"], tv["v2"]["signature_hex"], tv["v2"]["prev_sha256"]
    )
    assert hub._canonical_domain_for(dom, tv["author_pubkey_hex"]) == tv["canonical_domain"]
    assert hub._format_fingerprint(tv["author_pubkey_hex"]) == tv["key_fingerprint"]

    # 2. Transclusion parsing conformance
    tr = tv["v2"]["transclusion"]
    refs = transclusion_engine.extract_transclusion_links(
        dom,
        2,
        tv["v2"]["content"],
        lambda d, v: {"version_num": 1, "sha256": tv["v1"]["sha256"]} if d == dom and v == 1 else None,
    )
    assert len(refs) == 1
    assert refs[0]["target_domain"] == tr["target_domain"]
    assert refs[0]["target_version"] == tr["target_version"]
    assert refs[0]["target_start"] == tr["start"]
    assert refs[0]["target_end"] == tr["end"]
    assert tv["v1"]["content"][tr["start"] : tr["end"]] == tr["expected_slice"]

    # 3. E2EE conformance (author + peer decrypt)
    env_str = tv["e2ee"]["envelope"]
    for priv in (tv["author_privkey_hex"], tv["peer_privkey_hex"]):
        ok, plain, recips = e2ee_spaces.decrypt_with_privkeys(env_str, [priv])
        assert ok and plain == tv["e2ee"]["plaintext"], (ok, plain)
        assert tv["author_pubkey_hex"] in recips and tv["peer_pubkey_hex"] in recips

    # 4. Rust xnd-core conformance (hash + span + verify)
    if RUST_CORE.exists():
        p_hash = subprocess.run([str(RUST_CORE), "hash"], input=tv["v1"]["content"].encode("utf-8"), capture_output=True, check=True)
        assert json.loads(p_hash.stdout)["sha256"] == tv["v1"]["sha256"]

        p_span = subprocess.run(
            [str(RUST_CORE), "span", str(tr["start"]), str(tr["end"])],
            input=tv["v1"]["content"].encode("utf-8"),
            capture_output=True,
            check=True,
        )
        span_out = json.loads(p_span.stdout)
        assert span_out["text"] == tr["expected_slice"]

        subprocess.run(
            [str(RUST_CORE), "verify", tv["v1"]["sha256"]],
            input=tv["v1"]["content"].encode("utf-8"),
            capture_output=True,
            check=True,
        )

    # 5. Android Java wire-format parity check
    java_node = (ANDROID_SRC / "LocalNodeServer.java").read_text(encoding="utf-8")
    java_e2ee = (ANDROID_SRC / "E2eeSpaces.java").read_text(encoding="utf-8")
    assert '|v" + ver + "|" + sha' in java_node
    assert 'XND-E2EE-v1:' in java_e2ee

    print("CONFORMANCE_PASSED")


if __name__ == "__main__":
    main()
