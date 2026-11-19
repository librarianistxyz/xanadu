"""Tests for Hardware-Gated Domain Signing (Phone Biometric Key Vault)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi import HTTPException

HUB_DIR = Path(__file__).resolve().parent.parent
if str(HUB_DIR) not in sys.path:
    sys.path.insert(0, str(HUB_DIR))

os.environ.setdefault("XND_DATA_DIR", tempfile.mkdtemp(prefix="xnd_hwvault_pytest_"))
os.environ.setdefault("XND_RATE_LIMIT", "0")

import hub  # noqa: E402
from services import hardware_vault  # noqa: E402


def test_hardware_vault_strips_local_key_and_gates_publish_and_rotate() -> None:
    # 1. Start with a normal local domain key on disk
    dom = "hw-gated-vault.xnd"
    local_pub, local_priv = hub.generate_keypair()
    hub.store.import_domain_key(dom, local_pub, local_priv)
    assert hub.store.domains[dom]["privkey_hex"] == local_priv

    # 2. Enroll phone's hardware Ed25519 public key + biometric HMAC secret, stripping local key
    phone_pub, phone_priv = hub.generate_keypair()
    bio_secret_hex = secrets.token_hex(32)
    state_dir = hub.DATA_DIR / "state"

    hardware_vault.enroll_hardware_signer(
        state_dir, dom, phone_pub, device_id="galaxy-s9-keystore", mode="android_keystore", bio_secret_hex=bio_secret_hex
    )
    hub.store.import_domain_key(dom, phone_pub, "")
    stripped = hardware_vault.strip_local_private_key(hub.store, dom)
    assert stripped is True or hub.store.domains[dom]["privkey_hex"] == ""
    key_file = hub.store.keys_dir / f"{dom}.json"
    if key_file.exists():
        assert json.loads(key_file.read_text(encoding="utf-8")).get("privkey_hex") == ""

    # 3. Publishing without hardware signature MUST fail with 403
    with pytest.raises(HTTPException) as exc:
        hub.publish_document(dom, "Unauthorized", "Should fail without phone tap")
    assert exc.value.status_code == 403
    assert "hardware-gated" in str(exc.value.detail).lower()

    # 4. Phone signs v1 payload offline with its Android Keystore key
    content = "Signed by physical phone biometric key!"
    sha = hub.rust_sha256(content)
    hw_sig = hub.sign_payload(phone_priv, dom, 1, sha, "")

    res = hub.publish_document(dom, "HW Signed v1", content, hardware_signature_hex=hw_sig)
    assert res["version"] == 1
    assert res["pubkey"] == phone_pub
    assert res["signature"] == hw_sig

    # 5. Challenge-response biometric rotation (replay-protected)
    new_phone_pub, _ = hub.generate_keypair()
    rot_payload = f"xnd-rotate-v1|{dom}|{new_phone_pub}"
    ch = hardware_vault.create_signing_challenge(state_dir, dom, "rotate", rot_payload)

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sig_hex = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(phone_priv)).sign(rot_payload.encode("utf-8")).hex()
    bad_hmac = "00" * 32

    # Wrong biometric HMAC fails
    with pytest.raises(HTTPException) as exc_bio:
        hardware_vault.verify_and_consume_challenge(state_dir, ch["challenge_id"], sig_hex, bad_hmac)
    assert exc_bio.value.status_code == 403

    # Fresh challenge with valid Ed25519 sig + biometric HMAC succeeds
    ch2 = hardware_vault.create_signing_challenge(state_dir, dom, "rotate", rot_payload)
    good_hmac = hmac.new(bytes.fromhex(bio_secret_hex), ch2["nonce"].encode("utf-8"), hashlib.sha256).hexdigest()
    verified = hardware_vault.verify_and_consume_challenge(state_dir, ch2["challenge_id"], sig_hex, good_hmac)
    assert verified["domain"] == dom

    # Replay of same challenge_id is rejected
    with pytest.raises(HTTPException) as exc_replay:
        hardware_vault.verify_and_consume_challenge(state_dir, ch2["challenge_id"], sig_hex, good_hmac)
    assert exc_replay.value.status_code == 401


def test_hardware_vault_routes_registered() -> None:
    paths = set(hub.app.openapi()["paths"].keys())
    expected = {
        "/api/hardware-vault/status",
        "/api/hardware-vault/enroll",
        "/api/hardware-vault/challenge",
        "/api/hardware-vault/rotate",
    }
    assert not (expected - paths)
