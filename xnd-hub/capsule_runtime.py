#!/usr/bin/env python3
"""
Serverless Runtime Helpers for Xanadu (.xnd) App Capsules:
- Isolated per-capsule SQLite database with SQLite authorizer guard
- Ed25519 challenge-response Auth & HMAC-signed session tokens
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_SESSION_SECRET = secrets.token_bytes(32)
_NONCE_LOCK = threading.Lock()
_AUTH_NONCES: dict[str, tuple[str, float]] = {}  # nonce -> (domain, expires_at)
_DB_LOCK = threading.Lock()


def _safe_db_path(state_dir: Path, domain: str) -> Path:
    clean = "".join(c if c.isalnum() or c in ".-_" else "_" for c in domain.strip().lower())
    db_dir = state_dir / "capsule_dbs"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / f"{clean}.sqlite3"


def _sqlite_authorizer(action: int, arg1: str | None, arg2: str | None, db_name: str | None, trigger: str | None) -> int:
    # Block ATTACH/DETACH, PRAGMA, and virtual/module loading so capsules cannot escape their DB file.
    if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_PRAGMA):
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and arg2 and arg2.lower() == "load_extension":
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def db_query(state_dir: Path, domain: str, sql: str, params: list[Any] | dict[str, Any] | None = None) -> dict[str, Any]:
    q = (sql or "").strip()
    if not q:
        raise ValueError("SQL query cannot be empty")
    if len(q) > 16384:
        raise ValueError("SQL query exceeds 16 KB limit")
    if re.search(r";\s*\S", q):
        raise ValueError("Multiple SQL statements per call are not allowed")

    db_path = _safe_db_path(state_dir, domain)
    with _DB_LOCK:
        conn = sqlite3.connect(str(db_path), timeout=2.0)
        try:
            conn.row_factory = sqlite3.Row
            conn.set_authorizer(_sqlite_authorizer)
            cur = conn.cursor()
            if isinstance(params, (list, tuple, dict)):
                cur.execute(q, params)
            else:
                cur.execute(q)
            if cur.description is not None:
                cols = [d[0] for d in cur.description]
                rows = [dict(r) for r in cur.fetchmany(500)]
                conn.commit()
                return {"ok": True, "columns": cols, "rows": rows, "rowcount": len(rows), "lastrowid": cur.lastrowid}
            conn.commit()
            return {"ok": True, "columns": [], "rows": [], "rowcount": cur.rowcount, "lastrowid": cur.lastrowid}
        finally:
            conn.close()


def create_auth_challenge(domain: str, ttl_sec: int = 120) -> dict[str, Any]:
    dom = domain.strip().lower()
    nonce = secrets.token_hex(24)
    exp = time.time() + ttl_sec
    with _NONCE_LOCK:
        now = time.time()
        if len(_AUTH_NONCES) > 1000:
            stale = [k for k, (_, e) in _AUTH_NONCES.items() if e < now]
            for k in stale:
                _AUTH_NONCES.pop(k, None)
        _AUTH_NONCES[nonce] = (dom, exp)
    return {"ok": True, "domain": dom, "nonce": nonce, "expires_in": ttl_sec}


def verify_auth_challenge(
    domain: str,
    nonce: str,
    pubkey_hex: str,
    signature_hex: str,
    ttl_sec: int = 86400,
) -> dict[str, Any]:
    dom = domain.strip().lower()
    with _NONCE_LOCK:
        rec = _AUTH_NONCES.pop(nonce.strip(), None)
    if not rec:
        return {"ok": False, "error": "Invalid or already-used auth nonce"}
    expected_dom, exp = rec
    if expected_dom != dom or time.time() > exp:
        return {"ok": False, "error": "Auth nonce expired or domain mismatch"}

    pub = pubkey_hex.strip().lower()
    sig = signature_hex.strip().lower()
    # Matches xnd-sdk.js sign.message() which signs sha256(message).hexdigest()
    msg_str = f"xnd-auth-v1|{dom}|{nonce.strip()}"
    digest = hashlib.sha256(msg_str.encode("utf-8")).hexdigest()
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
            bytes.fromhex(sig), digest.encode("utf-8")
        )
    except Exception:
        return {"ok": False, "error": "Ed25519 signature verification failed"}

    claims = {
        "sub": pub,
        "dom": dom,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl_sec,
    }
    b64 = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii").rstrip("=")
    mac = hmac.new(_SESSION_SECRET, b64.encode("ascii"), hashlib.sha256).hexdigest()
    token = f"{b64}.{mac}"
    fp = f"{pub[:4]}-{pub[4:8]}" if len(pub) >= 8 else pub
    return {"ok": True, "domain": dom, "pubkey_hex": pub, "fingerprint": fp, "token": token, "expires_at": claims["exp"]}


def verify_session_token(domain: str, token: str) -> dict[str, Any]:
    try:
        dom = domain.strip().lower()
        b64, mac = token.strip().split(".", 1)
        expected = hmac.new(_SESSION_SECRET, b64.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            return {"ok": False, "valid": False, "error": "Invalid session signature"}
        pad = "=" * (-len(b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(b64 + pad).decode("utf-8"))
        if claims.get("dom") != dom or int(claims.get("exp", 0)) < int(time.time()):
            return {"ok": False, "valid": False, "error": "Session expired or wrong domain"}
        pub = str(claims.get("sub") or "")
        fp = f"{pub[:4]}-{pub[4:8]}" if len(pub) >= 8 else pub
        return {"ok": True, "valid": True, "domain": dom, "pubkey_hex": pub, "fingerprint": fp, "exp": claims["exp"]}
    except Exception:
        return {"ok": False, "valid": False, "error": "Malformed session token"}


_SECRETS_LOCK = threading.Lock()


def _secrets_path(state_dir: Path, domain: str) -> Path:
    clean = "".join(c if c.isalnum() or c in ".-_" else "_" for c in domain.strip().lower())
    s_dir = state_dir / "capsule_secrets"
    s_dir.mkdir(parents=True, exist_ok=True)
    return s_dir / f"{clean}.json"


def load_capsule_secrets(state_dir: Path, domain: str) -> dict[str, str]:
    p = _secrets_path(state_dir, domain)
    with _SECRETS_LOCK:
        if not p.exists():
            return {}
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
        except Exception:
            return {}


def set_capsule_secret(state_dir: Path, domain: str, key: str, value: str) -> list[str]:
    k = key.strip()
    if not k or not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$", k):
        raise ValueError("Secret key must be a valid env identifier (e.g. SUPABASE_SERVICE_KEY)")
    p = _secrets_path(state_dir, domain)
    with _SECRETS_LOCK:
        cur = {}
        if p.exists():
            try:
                cur = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                cur = {}
        cur[k] = str(value)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(cur, indent=2), encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(p)
        return sorted(cur.keys())


def delete_capsule_secret(state_dir: Path, domain: str, key: str) -> list[str]:
    p = _secrets_path(state_dir, domain)
    with _SECRETS_LOCK:
        if not p.exists():
            return []
        try:
            cur = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            cur = {}
        cur.pop(key.strip(), None)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(cur, indent=2), encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(p)
        return sorted(cur.keys())
