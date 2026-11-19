"""Hardware-Gated Domain Signing (Phone Biometric Key Vault / FIDO2 Bridge) for Xanadu."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import HTTPException

_LOCK = threading.RLock()
_PENDING_CHALLENGES: dict[str, dict[str, Any]] = {}


def _vault_path(state_dir: Path) -> Path:
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / "hardware_vault.json"


def _load_vault(state_dir: Path) -> dict[str, Any]:
    p = _vault_path(state_dir)
    if not p.exists():
        return {"domains": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("domains"), dict):
            return data
    except Exception:
        pass
    return {"domains": {}}


def _save_vault(state_dir: Path, data: dict[str, Any]) -> None:
    p = _vault_path(state_dir)
    tmp = state_dir / ".hardware_vault.json.tmp"
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(p)


def get_enrolled_signer(state_dir: Path, domain: str) -> dict[str, Any] | None:
    dom = (domain or "").strip().lower()
    with _LOCK:
        return _load_vault(state_dir)["domains"].get(dom)


def is_hardware_gated(state_dir: Path, domain: str) -> bool:
    return get_enrolled_signer(state_dir, domain) is not None


def list_hardware_domains(state_dir: Path) -> dict[str, dict[str, Any]]:
    with _LOCK:
        raw = _load_vault(state_dir)["domains"]
        out: dict[str, dict[str, Any]] = {}
        for dom, rec in raw.items():
            out[dom] = {
                "domain": dom,
                "device_id": rec.get("device_id", ""),
                "mode": rec.get("mode", "android_keystore"),
                "pubkey_hex": rec.get("pubkey_hex", ""),
                "require_bio_hmac": bool(rec.get("bio_secret_hash")),
                "enrolled_at": rec.get("enrolled_at", 0.0),
            }
        return out


def enroll_hardware_signer(
    state_dir: Path,
    domain: str,
    pubkey_hex: str,
    device_id: str = "android-biometric-vault",
    mode: str = "android_keystore",
    bio_secret_hex: str = "",
) -> dict[str, Any]:
    dom = (domain or "").strip().lower()
    pub = (pubkey_hex or "").strip().lower()
    if len(pub) != 64:
        raise HTTPException(status_code=400, detail="Invalid Ed25519 pubkey_hex (expected 64 hex chars)")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid Ed25519 public key: {exc}") from exc

    bio_hash = ""
    if bio_secret_hex.strip():
        bio_hash = hashlib.sha256(bytes.fromhex(bio_secret_hex.strip())).hexdigest()

    rec = {
        "domain": dom,
        "pubkey_hex": pub,
        "device_id": (device_id or "android-biometric-vault").strip()[:64],
        "mode": (mode or "android_keystore").strip()[:32],
        "bio_secret_hash": bio_hash,
        "bio_secret_hex": bio_secret_hex.strip().lower() if bio_secret_hex.strip() else "",
        "enrolled_at": round(time.time(), 3),
    }
    with _LOCK:
        data = _load_vault(state_dir)
        data["domains"][dom] = rec
        _save_vault(state_dir, data)
    return {
        "domain": dom,
        "pubkey_hex": pub,
        "device_id": rec["device_id"],
        "mode": rec["mode"],
        "require_bio_hmac": bool(bio_hash),
    }


def strip_local_private_key(store: Any, domain: str) -> bool:
    """Remove local privkey_hex from memory and node_data/keys/<domain>.json."""
    dom = (domain or "").strip().lower()
    changed = False
    with store.lock:
        rec = store.domains.get(dom)
        if rec and rec.get("privkey_hex"):
            rec["privkey_hex"] = ""
            changed = True
        key_file = store.keys_dir / f"{dom}.json"
        if key_file.exists():
            try:
                kd = json.loads(key_file.read_text(encoding="utf-8"))
                if kd.get("privkey_hex"):
                    kd["privkey_hex"] = ""
                    key_file.write_text(json.dumps(kd, indent=2), encoding="utf-8")
                    changed = True
            except Exception:
                pass
    return changed


def create_signing_challenge(
    state_dir: Path,
    domain: str,
    action: str,
    signing_payload: str,
    ttl_sec: int = 120,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    dom = (domain or "").strip().lower()
    enrolled = get_enrolled_signer(state_dir, dom)
    if enrolled is None:
        raise HTTPException(status_code=404, detail=f"Domain '{dom}' is not enrolled in Hardware Vault")

    challenge_id = secrets.token_hex(16)
    nonce = secrets.token_hex(24)
    exp = time.time() + max(15, int(ttl_sec))
    rec = {
        "challenge_id": challenge_id,
        "domain": dom,
        "action": (action or "publish").strip(),
        "nonce": nonce,
        "signing_payload": signing_payload,
        "expires_at": exp,
        "extra": dict(extra or {}),
    }
    with _LOCK:
        now = time.time()
        if len(_PENDING_CHALLENGES) > 512:
            for k in [cid for cid, v in _PENDING_CHALLENGES.items() if v["expires_at"] < now]:
                _PENDING_CHALLENGES.pop(k, None)
        _PENDING_CHALLENGES[challenge_id] = rec
    return {
        "challenge_id": challenge_id,
        "domain": dom,
        "action": rec["action"],
        "nonce": nonce,
        "signing_payload": signing_payload,
        "expected_pubkey_hex": enrolled["pubkey_hex"],
        "require_bio_hmac": bool(enrolled.get("bio_secret_hex")),
        "expires_in": ttl_sec,
    }


def verify_and_consume_challenge(
    state_dir: Path,
    challenge_id: str,
    signature_hex: str,
    bio_hmac_hex: str = "",
) -> dict[str, Any]:
    with _LOCK:
        rec = _PENDING_CHALLENGES.pop((challenge_id or "").strip(), None)
    if rec is None or time.time() > rec["expires_at"]:
        raise HTTPException(status_code=401, detail="Hardware signing challenge expired or invalid")

    enrolled = get_enrolled_signer(state_dir, rec["domain"])
    if enrolled is None:
        raise HTTPException(status_code=404, detail="Hardware signer no longer enrolled")

    if enrolled.get("bio_secret_hex"):
        expected_hmac = hmac.new(
            bytes.fromhex(enrolled["bio_secret_hex"]),
            rec["nonce"].encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest((bio_hmac_hex or "").strip().lower(), expected_hmac):
            raise HTTPException(status_code=403, detail="Biometric device HMAC verification failed")

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(enrolled["pubkey_hex"]))
        pub.verify(bytes.fromhex((signature_hex or "").strip()), rec["signing_payload"].encode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Hardware Ed25519 signature invalid: {exc}") from exc

    return rec


def verify_hardware_publish_signature(
    state_dir: Path,
    domain: str,
    version_num: int,
    sha256_hex: str,
    prev_sha256: str,
    signature_hex: str,
) -> str:
    """Verify a pre-signed publish payload against the domain's enrolled hardware pubkey."""
    enrolled = get_enrolled_signer(state_dir, domain)
    if enrolled is None:
        raise HTTPException(status_code=403, detail="Domain is not enrolled in Hardware Vault")
    sig = (signature_hex or "").strip().lower()
    if not sig:
        raise HTTPException(
            status_code=403,
            detail="Domain is hardware-gated: physical device/biometric signature required",
        )
    msg = f"{domain}|v{version_num}|{sha256_hex}|{prev_sha256}" if prev_sha256 else f"{domain}|v{version_num}|{sha256_hex}"
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(enrolled["pubkey_hex"]))
        pub.verify(bytes.fromhex(sig), msg.encode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Hardware publish signature invalid: {exc}") from exc
    return enrolled["pubkey_hex"]
