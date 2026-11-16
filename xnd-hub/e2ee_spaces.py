"""Independent End-to-End Encrypted Private .xnd Spaces (Ed25519 -> X25519 + AES-256-GCM).

Relays, LAN peers, and unauthorized nodes only ever see `XND-E2EE-v1:...` ciphertext.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

E2EE_PREFIX = "XND-E2EE-v1:"
_CURVE25519_P = (1 << 255) - 19
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def is_encrypted_blob(content: str | None) -> bool:
    return isinstance(content, str) and content.startswith(E2EE_PREFIX)


def _ed_priv_to_x25519(seed: bytes) -> X25519PrivateKey:
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return X25519PrivateKey.from_private_bytes(bytes(h))


def _ed_pub_to_x25519(ed_pub_bytes: bytes) -> X25519PublicKey:
    y = int.from_bytes(ed_pub_bytes, "little") & ((1 << 255) - 1)
    u = ((1 + y) * pow((1 - y) % _CURVE25519_P, _CURVE25519_P - 2, _CURVE25519_P)) % _CURVE25519_P
    return X25519PublicKey.from_public_bytes(u.to_bytes(32, "little"))


def parse_allowed_pubkeys(raw: list[str] | str | None) -> list[str]:
    items = raw if isinstance(raw, list) else re.split(r"[\s,;]+", raw or "")
    out: list[str] = []
    for item in items:
        h = item.strip().lower()
        if _HEX64_RE.match(h) and h not in out:
            out.append(h)
    return out


def encrypt_for_peers(plaintext: str, author_priv_hex: str, allowed_pubkeys: list[str] | str | None = None) -> str:
    seed = bytes.fromhex(author_priv_hex.strip())
    ed_sk = Ed25519PrivateKey.from_private_bytes(seed)
    author_pub_hex = ed_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()

    recips = parse_allowed_pubkeys(allowed_pubkeys)
    if author_pub_hex not in recips:
        recips.insert(0, author_pub_hex)

    doc_key = os.urandom(32)
    doc_nonce = os.urandom(12)
    ct = AESGCM(doc_key).encrypt(doc_nonce, plaintext.encode("utf-8"), None)

    wrapped: dict[str, dict[str, str]] = {}
    for pub_hex in recips:
        eph_sk = X25519PrivateKey.generate()
        eph_pub_hex = eph_sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        recip_x_pub = _ed_pub_to_x25519(bytes.fromhex(pub_hex))
        wrap_key = hashlib.sha256(eph_sk.exchange(recip_x_pub)).digest()
        w_nonce = os.urandom(12)
        wk = AESGCM(wrap_key).encrypt(w_nonce, doc_key, None)
        wrapped[pub_hex] = {
            "eph": eph_pub_hex,
            "nonce": base64.b64encode(w_nonce).decode("ascii"),
            "wk": base64.b64encode(wk).decode("ascii"),
        }

    env = {
        "v": 1,
        "nonce": base64.b64encode(doc_nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
        "recipients": wrapped,
    }
    return E2EE_PREFIX + json.dumps(env, separators=(",", ":"))


def inspect_recipients(envelope_str: str) -> list[str]:
    if not is_encrypted_blob(envelope_str):
        return []
    try:
        env = json.loads(envelope_str[len(E2EE_PREFIX) :])
        return list((env.get("recipients") or {}).keys())
    except Exception:
        return []


def decrypt_with_privkeys(envelope_str: str, candidate_privkeys: list[str]) -> tuple[bool, str, list[str]]:
    if not is_encrypted_blob(envelope_str):
        return True, envelope_str, []
    try:
        env = json.loads(envelope_str[len(E2EE_PREFIX) :])
        recipients: dict[str, Any] = env.get("recipients") or {}
        recip_list = list(recipients.keys())
        doc_nonce = base64.b64decode(env["nonce"])
        ct = base64.b64decode(env["ct"])
    except Exception:
        return False, "", []

    for priv_hex in candidate_privkeys:
        ph = (priv_hex or "").strip()
        if not _HEX64_RE.match(ph):
            continue
        try:
            seed = bytes.fromhex(ph)
            ed_sk = Ed25519PrivateKey.from_private_bytes(seed)
            pub_hex = ed_sk.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ).hex()
            entry = recipients.get(pub_hex)
            if not entry:
                continue
            x_sk = _ed_priv_to_x25519(seed)
            eph_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(entry["eph"]))
            wrap_key = hashlib.sha256(x_sk.exchange(eph_pub)).digest()
            doc_key = AESGCM(wrap_key).decrypt(
                base64.b64decode(entry["nonce"]),
                base64.b64decode(entry["wk"]),
                None,
            )
            plain = AESGCM(doc_key).decrypt(doc_nonce, ct, None).decode("utf-8")
            return True, plain, recip_list
        except Exception:
            continue

    return False, "", recip_list
