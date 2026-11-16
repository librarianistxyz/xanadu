#!/usr/bin/env python3
"""
Public Gateway & Node Abuse Protection for Xanadu (.xnd):
- Sliding-window per-IP and per-pubkey rate limiting
- Max blob / asset size enforcement
- Ed25519-signed shareable blocklists (Web-of-Trust moderation)
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MAX_BLOB_BYTES = int(os.environ.get("XND_MAX_BLOB_BYTES", str(512 * 1024)))        # 512 KB for docs
MAX_CAPSULE_BYTES = int(os.environ.get("XND_MAX_CAPSULE_BYTES", str(16 * 1024 * 1024)))  # 16 MB for multi-file sites
MAX_ASSET_BYTES = int(os.environ.get("XND_MAX_ASSET_BYTES", str(4 * 1024 * 1024)))  # 4 MB
MAX_BUNDLE_VERSIONS = int(os.environ.get("XND_MAX_BUNDLE_VERSIONS", "250"))


def check_blob_size(content: str, max_bytes: int = MAX_BLOB_BYTES) -> tuple[bool, int]:
    size = len((content or "").encode("utf-8"))
    return size <= max_bytes, size


class SlidingWindowLimiter:
    """Thread-safe sliding-window rate limiter keyed by IP or pubkey."""

    def __init__(self, max_requests: int, window_sec: float = 60.0) -> None:
        self.max_requests = max(1, int(max_requests))
        self.window_sec = max(1.0, float(window_sec))
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = {}
        self._ops = 0

    def allow(self, key: str) -> tuple[bool, int]:
        k = (key or "unknown").strip().lower()
        now = time.monotonic()
        cutoff = now - self.window_sec
        with self._lock:
            q = self._hits.get(k)
            if q is None:
                q = deque()
                self._hits[k] = q
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self.max_requests:
                retry_after = max(1, int(self.window_sec - (now - q[0])))
                return False, retry_after
            q.append(now)
            self._ops += 1
            if self._ops % 500 == 0:
                stale = [hk for hk, hq in self._hits.items() if not hq or hq[-1] < cutoff]
                for hk in stale:
                    self._hits.pop(hk, None)
            return True, 0


def _blocklist_signing_payload(
    issuer_pub: str,
    ts: float,
    domains: list[str],
    pubkeys: list[str],
) -> bytes:
    obj = {
        "v": 1,
        "issuer_pub": issuer_pub.strip().lower(),
        "ts": round(float(ts), 3),
        "blocked_domains": sorted(set(d.strip().lower() for d in domains if d.strip())),
        "blocked_pubkeys": sorted(set(p.strip().lower() for p in pubkeys if p.strip())),
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_blocklist(
    privkey_hex: str,
    blocked_domains: list[str],
    blocked_pubkeys: list[str],
    ts: float | None = None,
) -> dict[str, Any]:
    t = round(float(ts if ts is not None else time.time()), 3)
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(privkey_hex.strip()))
    pub_hex = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    doms = sorted(set(d.strip().lower() for d in blocked_domains if d.strip()))
    pubs = sorted(set(p.strip().lower() for p in blocked_pubkeys if p.strip()))
    payload = _blocklist_signing_payload(pub_hex, t, doms, pubs)
    sig_hex = sk.sign(payload).hex()
    return {
        "v": 1,
        "issuer_pub": pub_hex,
        "ts": t,
        "blocked_domains": doms,
        "blocked_pubkeys": pubs,
        "sig": sig_hex,
    }


def verify_signed_blocklist(bundle: dict[str, Any]) -> bool:
    try:
        pub_hex = str(bundle["issuer_pub"]).strip().lower()
        sig_hex = str(bundle["sig"]).strip().lower()
        ts = float(bundle["ts"])
        doms = list(bundle.get("blocked_domains") or [])
        pubs = list(bundle.get("blocked_pubkeys") or [])
        payload = _blocklist_signing_payload(pub_hex, ts, doms, pubs)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex), payload)
        return True
    except Exception:
        return False


class BlocklistManager:
    """Manages local + imported Web-of-Trust blocklists."""

    def __init__(self, state_dir: Path | None = None) -> None:
        self._path = (state_dir / "shared_blocklist.json") if state_dir else None
        self._lock = threading.Lock()
        self.blocked_domains: set[str] = set()
        self.blocked_pubkeys: set[str] = set()
        self.trusted_issuers: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not self._path or not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self.blocked_domains = set(data.get("blocked_domains") or [])
            self.blocked_pubkeys = set(data.get("blocked_pubkeys") or [])
            self.trusted_issuers = set(data.get("trusted_issuers") or [])
        except Exception:
            pass

    def _save(self) -> None:
        if not self._path:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(
                    {
                        "blocked_domains": sorted(self.blocked_domains),
                        "blocked_pubkeys": sorted(self.blocked_pubkeys),
                        "trusted_issuers": sorted(self.trusted_issuers),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            tmp.replace(self._path)
        except Exception:
            pass

    def is_blocked(self, domain: str = "", pubkey_hex: str = "") -> bool:
        d = domain.strip().lower()
        p = pubkey_hex.strip().lower()
        with self._lock:
            return (bool(d) and d in self.blocked_domains) or (bool(p) and p in self.blocked_pubkeys)

    def import_signed(self, bundle: dict[str, Any], require_trusted_issuer: bool = False) -> dict[str, Any]:
        if not verify_signed_blocklist(bundle):
            return {"ok": False, "error": "Invalid blocklist Ed25519 signature"}
        issuer = str(bundle["issuer_pub"]).strip().lower()
        with self._lock:
            if require_trusted_issuer and self.trusted_issuers and issuer not in self.trusted_issuers:
                return {"ok": False, "error": "Untrusted blocklist issuer"}
            added_d = 0
            added_p = 0
            for d in bundle.get("blocked_domains") or []:
                cd = str(d).strip().lower()
                if cd and cd not in self.blocked_domains:
                    self.blocked_domains.add(cd)
                    added_d += 1
            for p in bundle.get("blocked_pubkeys") or []:
                cp = str(p).strip().lower()
                if cp and cp not in self.blocked_pubkeys:
                    self.blocked_pubkeys.add(cp)
                    added_p += 1
            self._save()
        return {"ok": True, "issuer_pub": issuer, "added_domains": added_d, "added_pubkeys": added_p}
