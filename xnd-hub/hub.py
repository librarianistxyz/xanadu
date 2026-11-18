#!/usr/bin/env python3
"""
xnd-hub: Zero-DB Xanadu (.xnd) Peer Node.
Uses PeerStore (In-Memory RAM Index + Append-Only Cryptographic Logs +
Zlib-Compressed Pinned/Pruned Flat Blobs) — never exhausts disk storage.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import shutil
import socket
import sys
import threading
import subprocess
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import scrapers

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import abuse_guard
import ai_citations
import capsule_runtime
import crdt_sync
import deep_search
import e2ee_spaces
import transclusion_engine
from peer_store import MAX_CACHE_BYTES, PeerStore
from github_hosting import GitHubHosting
from nat_tunnel import NatTunnel
from ir_engine import PatternMemory, answer_from_xnd_corpus
from p2p_discovery import (
    announce_doc_nostr,
    announce_peer_nostr,
    discover_docs_nostr,
    discover_peers_nostr,
    lookup_doc_nostr,
    start_lan_discovery,
    subscribe_docs_nostr,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("XND_DATA_DIR", str(Path(__file__).resolve().parent / "node_data")))
gh_hosting = GitHubHosting(DATA_DIR)
pattern_mem = PatternMemory(DATA_DIR / "state")
UI_DIR = Path(os.environ.get("XND_UI_DIR", str(ROOT_DIR / "xnd-ui")))
RUST_CORE_BIN = ROOT_DIR / "xnd-core" / "target" / "release" / "xnd-core"

TRANSCLUSION_RE = re.compile(
    r"\{\{\s*xnd://((?:[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,62}\.)+xnd)(?:@v(\d+))?(?:#([0-9a-fA-F]{6,64}))?(?::(\d+)-(\d+))?\s*\}\}"
)
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,62}\.)+xnd$")


def normalize_xnd_domain(raw: str, append_tld: bool = True) -> str:
    dom = (raw or "").strip().lower()
    dom = re.sub(r"^(?:xnd|https?)://", "", dom)
    dom = dom.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip()
    if append_tld and dom and not dom.endswith(".xnd"):
        dom = f"{dom}.xnd"
    return dom
SHORT_DOMAIN_TOKEN = os.environ.get("XND_SHORT_TOKEN", "xanadu-genesis")
GOSSIP_INTERVAL = int(os.environ.get("XND_GOSSIP_INTERVAL", "15"))

SAFE_BUILTINS = {
    "len": len, "str": str, "int": int, "float": float, "bool": bool,
    "list": list, "dict": dict, "tuple": tuple, "set": set,
    "min": min, "max": max, "sum": sum, "sorted": sorted,
    "enumerate": enumerate, "zip": zip, "range": range, "abs": abs, "round": round,
}

gossip_stats: dict[str, Any] = {
    "enabled": True,
    "interval_sec": GOSSIP_INTERVAL,
    "last_run": 0.0,
    "total_imported": 0,
    "last_quorum_push": None,
    "mesh_reseeded": 0,
}

_NODE_ID_CACHE: str = ""
nat_tunnel: NatTunnel | None = None


def _get_node_id() -> str:
    global _NODE_ID_CACHE
    if _NODE_ID_CACHE:
        return _NODE_ID_CACHE
    nid_file = DATA_DIR / "node_id.txt"
    try:
        if nid_file.exists():
            val = nid_file.read_text(encoding="utf-8").strip()
            if val:
                _NODE_ID_CACHE = val
                return val
        nid_file.parent.mkdir(parents=True, exist_ok=True)
        val = secrets.token_hex(8)
        nid_file.write_text(val, encoding="utf-8")
        _NODE_ID_CACHE = val
        return val
    except Exception:
        _NODE_ID_CACHE = secrets.token_hex(8)
        return _NODE_ID_CACHE


def _rendezvous_rank(node_id: str, domain: str) -> str:
    return hashlib.sha256(f"{node_id}:{domain}".encode("utf-8")).hexdigest()


def rust_sha256(text: str) -> str:
    if RUST_CORE_BIN.exists():
        try:
            proc = subprocess.run(
                [str(RUST_CORE_BIN), "hash"],
                input=text.encode("utf-8"),
                capture_output=True,
                timeout=3,
                check=True,
            )
            data = json.loads(proc.stdout.decode("utf-8"))
            return str(data["sha256"])
        except Exception:
            pass
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


store = PeerStore(DATA_DIR, rust_sha256)

_CANONICAL_DOMAIN_RE = re.compile(r"^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.([0-9a-f]{8,16})\.xnd$")


def _parse_canonical_domain(domain: str) -> tuple[str, str] | None:
    m = _CANONICAL_DOMAIN_RE.match((domain or "").strip().lower())
    if not m:
        return None
    return f"{m.group(1)}.xnd", m.group(2)


def _canonical_domain_for(domain: str, pub_hex: str) -> str:
    clean = (domain or "").strip().lower()
    parsed = _parse_canonical_domain(clean)
    base = parsed[0] if parsed else clean
    stem = base[:-4] if base.endswith(".xnd") else base
    tag = (pub_hex or "00000000")[:8].lower()
    return f"{stem}.{tag}.xnd"


def _format_fingerprint(pub_hex: str) -> str:
    h = (pub_hex or "").strip().lower()
    if len(h) < 8:
        return h or "unknown"
    return f"{h[:4]}-{h[4:8]}"


class TrustStore:
    """First-seen key pinning, local petnames, and conflict tracking for .xnd domains."""

    def __init__(self, state_dir: Path) -> None:
        self._path = state_dir / "trust_pins.json"
        self._lock = threading.Lock()
        self.pins: dict[str, dict[str, Any]] = {}
        self.petnames: dict[str, str] = {}
        self.conflicts: dict[str, dict[str, str]] = {}  # base_domain -> {alias_domain: pubkey_hex}
        self._load()

    def _load(self) -> None:
        try:
            if self._path.exists():
                data = json.loads(self._path.read_text(encoding="utf-8"))
                self.pins = dict(data.get("pins") or {})
                self.petnames = dict(data.get("petnames") or {})
                self.conflicts = dict(data.get("conflicts") or {})
        except Exception:
            pass

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps({"pins": self.pins, "petnames": self.petnames, "conflicts": self.conflicts}, indent=2),
                encoding="utf-8",
            )
            tmp.replace(self._path)
        except Exception:
            pass

    def get_pinned_pubkey(self, domain: str) -> str:
        with self._lock:
            rec = self.pins.get(domain.strip().lower())
            return str(rec.get("pubkey_hex", "")) if isinstance(rec, dict) else ""

    def get_pin_source(self, domain: str) -> str:
        with self._lock:
            rec = self.pins.get(domain.strip().lower())
            return str(rec.get("source", "")) if isinstance(rec, dict) else ""

    def ensure_first_seen(self, domain: str, pubkey_hex: str, source: str = "first_seen") -> str:
        dom = domain.strip().lower()
        pub = (pubkey_hex or "").strip().lower()
        if not dom or not pub:
            return pub
        with self._lock:
            existing = self.pins.get(dom)
            if not existing or not existing.get("pubkey_hex"):
                self.pins[dom] = {"pubkey_hex": pub, "pinned_at": time.time(), "source": source}
                self._save()
                return pub
            return str(existing["pubkey_hex"])

    def set_pin(self, domain: str, pubkey_hex: str, source: str = "manual") -> None:
        dom = domain.strip().lower()
        pub = (pubkey_hex or "").strip().lower()
        if not dom or not pub:
            return
        with self._lock:
            self.pins[dom] = {"pubkey_hex": pub, "pinned_at": time.time(), "source": source}
            self._save()

    def record_conflict(self, base_domain: str, alias_domain: str, pubkey_hex: str) -> None:
        base = base_domain.strip().lower()
        alias = alias_domain.strip().lower()
        pub = (pubkey_hex or "").strip().lower()
        if not base or not alias or not pub:
            return
        with self._lock:
            bucket = self.conflicts.setdefault(base, {})
            if bucket.get(alias) != pub:
                bucket[alias] = pub
                self._save()

    def get_conflicts(self, base_domain: str) -> list[dict[str, str]]:
        base = base_domain.strip().lower()
        with self._lock:
            bucket = self.conflicts.get(base, {})
            return [
                {"domain": alias, "pubkey_hex": pub, "fingerprint": _format_fingerprint(pub)}
                for alias, pub in sorted(bucket.items())
            ]

    def set_petname(self, key: str, petname: str) -> None:
        k = key.strip().lower()
        p = petname.strip()
        if not k:
            return
        with self._lock:
            if p:
                self.petnames[k] = p[:64]
            else:
                self.petnames.pop(k, None)
            self._save()

    def get_petname(self, domain: str, pubkey_hex: str = "") -> str:
        with self._lock:
            return (
                self.petnames.get(domain.strip().lower(), "")
                or self.petnames.get((pubkey_hex or "").strip().lower(), "")
            )


trust_store = TrustStore(DATA_DIR / "state")
crdt_log = crdt_sync.CapsuleCrdtLog(DATA_DIR / "state")
ip_limiter = abuse_guard.SlidingWindowLimiter(int(os.environ.get("XND_RATE_IP_PER_MIN", "240")), 60.0)
pubkey_limiter = abuse_guard.SlidingWindowLimiter(int(os.environ.get("XND_RATE_PUBKEY_PER_MIN", "40")), 60.0)
blocklist_mgr = abuse_guard.BlocklistManager(DATA_DIR / "state")

app = FastAPI(title="Xanadu Peer Node (.xnd)", version="0.4.0-zerodb")
if UI_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")

_CAP_TOKEN_SECRET = secrets.token_bytes(32)
_SENSITIVE_NODE_PREFIXES = (
    "/api/keys",
    "/api/auth",
    "/api/publish",
    "/api/domain",
    "/api/github",
    "/api/e2ee",
    "/api/trust",
    "/api/moderation",
    "/api/secrets",
    "/api/ai/publish_note",
    "/api/ai/tools",
)
_CAPSULE_CORS_PREFIXES = (
    "/xnd-app/",
    "/static/xnd-sdk.js",
    "/api/app/",
    "/api/sdk/",
    "/api/crdt/",
    "/api/search",
    "/api/peers",
    "/api/lan/peers",
    "/api/lan/sync",
)


def _mint_capsule_token(domain: str, ttl_sec: int = 86400) -> str:
    dom = domain.strip().lower()
    exp = int(time.time()) + ttl_sec
    sig = hmac.new(_CAP_TOKEN_SECRET, f"{dom}|{exp}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{exp}.{sig}"


def _verify_capsule_token(domain: str, token: str) -> bool:
    try:
        exp_s, sig = token.strip().split(".", 1)
        exp = int(exp_s)
        if exp < int(time.time()):
            return False
        dom = domain.strip().lower()
        expected = hmac.new(_CAP_TOKEN_SECRET, f"{dom}|{exp}".encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


def _require_capsule_token(request: Request, domain: str) -> None:
    tok = (request.headers.get("x-xnd-cap-token") or "").strip()
    if tok:
        if not _verify_capsule_token(domain, tok):
            raise HTTPException(status_code=403, detail="Invalid or expired capsule capability token for this domain")
        return
    origin = (request.headers.get("origin") or "").strip().lower()
    referer = (request.headers.get("referer") or "").strip().lower()
    if origin == "null" or "/xnd-app/" in referer:
        raise HTTPException(status_code=403, detail="Missing capsule capability token (X-Xnd-Cap-Token)")


@app.middleware("http")
async def _capsule_isolation_middleware(request: Request, call_next: Any) -> Response:
    path = request.url.path
    origin = (request.headers.get("origin") or "").strip()
    referer = (request.headers.get("referer") or "").strip().lower()

    if not path.startswith("/static/") and os.environ.get("XND_RATE_LIMIT", "1") != "0":
        xff = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        client_ip = xff or (request.client.host if request.client else "127.0.0.1")
        if client_ip not in ("127.0.0.1", "::1", "testclient") or os.environ.get("XND_RATE_LOCALHOST", "0") == "1":
            ok_rate, retry_after = ip_limiter.allow(client_ip)
            if not ok_rate:
                return Response(
                    content=json.dumps({"detail": "Rate limit exceeded"}),
                    status_code=429,
                    media_type="application/json",
                    headers={"Retry-After": str(retry_after)},
                )

    if path.startswith(_SENSITIVE_NODE_PREFIXES) and (origin.lower() == "null" or "/xnd-app/" in referer):
        return Response(
            content=json.dumps({"detail": "Blocked: sandboxed capsule origin cannot access node key/auth endpoints"}),
            status_code=403,
            media_type="application/json",
        )

    is_capsule_cors = path.startswith(_CAPSULE_CORS_PREFIXES)
    if request.method == "OPTIONS" and is_capsule_cors:
        allow_origin = "null" if origin.lower() == "null" else "*"
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": allow_origin,
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, X-Xnd-Cap-Token",
                "Access-Control-Max-Age": "600",
                "Vary": "Origin",
            },
        )

    if request.method in ("GET", "HEAD") and not path.startswith(("/api/", "/static/", "/xnd-app/", "/xnd-asset/")):
        m_ref = re.search(r"/xnd-app/([^/?#]+)", referer)
        if m_ref:
            ref_dom = urllib.parse.unquote(m_ref.group(1)).strip().lower()
            try:
                cap_resp = _serve_capsule_file(ref_dom, path.lstrip("/") or "index.html", None)
                cap_resp.headers["Access-Control-Allow-Origin"] = "null" if origin.lower() == "null" else "*"
                cap_resp.headers["Vary"] = "Origin"
                return cap_resp
            except HTTPException:
                pass

    response = await call_next(request)
    if is_capsule_cors:
        response.headers["Access-Control-Allow-Origin"] = "null" if origin.lower() == "null" else "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Xnd-Cap-Token"
        response.headers["Vary"] = "Origin"
    return response


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._skip = 0
        self._in_title = False
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if t in ("script", "style", "noscript", "svg", "nav", "footer"):
            self._skip += 1
        elif t == "title":
            self._in_title = True
        elif t == "h1":
            self.text_parts.append("\n# ")
        elif t in ("h2", "h3", "h4"):
            self.text_parts.append("\n## ")
        elif t == "blockquote":
            self.text_parts.append("\n> ")
        elif t == "li":
            self.text_parts.append("\n• ")
        elif t in ("p", "br", "div", "tr", "section", "article"):
            self.text_parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in ("script", "style", "noscript", "svg", "nav", "footer") and self._skip > 0:
            self._skip -= 1
        elif t == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._skip > 0:
            return
        if self._in_title:
            self.title_parts.append(data)
        self.text_parts.append(data)


def generate_keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return (
        pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
        priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex(),
    )


def pubkey_from_priv_hex(priv_hex: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign_payload(priv_hex: str, domain: str, version_num: int, sha256: str, prev_sha256: str = "") -> str:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    msg = f"{domain}|v{version_num}|{sha256}|{prev_sha256}" if prev_sha256 else f"{domain}|v{version_num}|{sha256}"
    return priv.sign(msg.encode("utf-8")).hex()


def _is_capsule_blob(raw: str | None) -> bool:
    if not raw or not isinstance(raw, str):
        return False
    s = raw.lstrip()
    if not s.startswith("{"):
        return False
    try:
        obj = json.loads(s)
        return isinstance(obj, dict) and isinstance(obj.get("files"), dict)
    except Exception:
        return False


def verify_signature(pub_hex: str, domain: str, version_num: int, sha256: str, sig_hex: str, prev_sha256: str = "") -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        msg = f"{domain}|v{version_num}|{sha256}|{prev_sha256}" if prev_sha256 else f"{domain}|v{version_num}|{sha256}"
        pub.verify(bytes.fromhex(sig_hex), msg.encode("utf-8"))
        return True
    except Exception:
        return False


_WAN_CACHE: dict[str, Any] = {"ok": False, "ts": 0.0}
_SHARE_GATEWAY: bool = True
_MESH_GATEWAY_PEER: dict[str, Any] | None = None


def _check_has_wan(force: bool = False) -> bool:
    now = time.time()
    if not force and now - float(_WAN_CACHE.get("ts", 0.0)) < 15.0:
        return bool(_WAN_CACHE.get("ok", False))
    ok = False
    for probe_url in ("https://clients3.google.com/generate_204", "https://cp.cloudflare.com/generate_204"):
        try:
            with httpx.Client(timeout=1.8, follow_redirects=False) as hc:
                r = hc.get(probe_url)
                if r.status_code == 204:
                    ok = True
                    break
        except Exception:
            continue
    _WAN_CACHE["ok"] = ok
    _WAN_CACHE["ts"] = now
    return ok


def _invalidate_lan_gateway(url: str = "") -> None:
    global _MESH_GATEWAY_PEER
    if _MESH_GATEWAY_PEER and (not url or _MESH_GATEWAY_PEER.get("url") == url):
        _MESH_GATEWAY_PEER = None


def _find_lan_gateway() -> dict[str, Any] | None:
    global _MESH_GATEWAY_PEER
    if _check_has_wan():
        _MESH_GATEWAY_PEER = None
        return None
    now = time.time()
    if (
        _MESH_GATEWAY_PEER
        and str(_MESH_GATEWAY_PEER.get("url", "")).startswith(("http://", "https://"))
        and now - float(_MESH_GATEWAY_PEER.get("updated_at", 0.0)) < 90.0
    ):
        return _MESH_GATEWAY_PEER
    _MESH_GATEWAY_PEER = None
    with _LAN_LOCK:
        lan_urls = [u for u in _LAN_PEERS.keys()]
    candidates = lan_urls + [p.get("url", "") for p in list(store.peers.values()) if p.get("url")]
    self_set = _self_urls()
    http_candidates = [
        base
        for base in dict.fromkeys(u.rstrip("/") for u in candidates if u)
        if base not in self_set and base.startswith(("http://", "https://"))
    ][:12]
    if not http_candidates:
        return None

    def _probe(base: str) -> dict[str, Any] | None:
        try:
            data = json.loads(_peer_get(base, "/api/sync/manifest", timeout=1.5))
            if data.get("has_wan") and data.get("share_gateway", True):
                return {
                    "url": base,
                    "label": str(data.get("label") or "LAN Peer"),
                    "updated_at": time.time(),
                }
        except Exception:
            pass
        return None

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=min(6, len(http_candidates))) as pool:
        for found in pool.map(_probe, http_candidates):
            if found is not None:
                _MESH_GATEWAY_PEER = found
                return _MESH_GATEWAY_PEER
    return None


def _is_safe_public_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        host = parsed.hostname.lower()
        if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or host.endswith(".local"):
            return False
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        except ValueError:
            pass
        return True
    except Exception:
        return False


def _dht_distance(node_id: str, key: str) -> int:
    a = hashlib.sha256((node_id or "").encode("utf-8")).digest()
    b = hashlib.sha256((key or "").strip().lower().encode("utf-8")).digest()
    return int.from_bytes(bytes(x ^ y for x, y in zip(a, b)), "big")


def _seeds_path() -> Path:
    return DATA_DIR / "state" / "seeds.json"


def _load_seeds() -> list[dict[str, Any]]:
    try:
        p = _seeds_path()
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return [x for x in data if isinstance(x, dict) and str(x.get("url", "")).startswith(("http://", "https://"))]
    except Exception:
        pass
    return []


def _save_seeds(seeds: list[dict[str, Any]]) -> None:
    try:
        p = _seeds_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(seeds[:32], indent=2), encoding="utf-8")
        tmp.replace(p)
    except Exception:
        pass


def _remember_seed(url: str, label: str = "Community Seed") -> None:
    clean = (url or "").strip().rstrip("/")
    if not clean.startswith(("http://", "https://")) or clean in _self_urls():
        return
    seeds = _load_seeds()
    for s in seeds:
        if s.get("url") == clean:
            s["last_seen"] = time.time()
            if label:
                s["label"] = label
            _save_seeds(seeds)
            return
    seeds.append({"url": clean, "label": label or "Community Seed", "last_seen": time.time()})
    _save_seeds(seeds)


_NEG_RESOLVE_CACHE: dict[str, float] = {}


def _try_resolve_from_nostr(domain: str) -> bool:
    """Query Nostr relays, DHT peers, seed nodes, and LAN gateway on-demand for a specific .xnd domain."""
    clean = domain.strip().lower()
    if not clean or clean in store.blocked_domains:
        return False
    now_ts = time.time()
    if now_ts - float(_NEG_RESOLVE_CACHE.get(clean, 0.0)) < 30.0:
        return False
    parsed = _parse_canonical_domain(clean)
    lookup_targets = [clean] + ([parsed[0]] if parsed and parsed[0] not in store.blocked_domains else [])

    def _has_resolved() -> bool:
        if clean in store.domains and bool(store.versions.get(clean)):
            return True
        if parsed:
            base_dom, pub_prefix = parsed
            base_pub = (store.domains.get(base_dom, {}).get("pubkey_hex") or "").lower()
            if base_pub.startswith(pub_prefix) and bool(store.versions.get(base_dom)):
                return True
        return False

    if _check_has_wan():
        for target in lookup_targets:
            try:
                bundle = lookup_doc_nostr(target)
                if bundle.get("versions"):
                    import_sync_bundle(bundle, ignore_follow_filter=True)
                    if _has_resolved():
                        return True
            except Exception:
                pass
    gw = _find_lan_gateway()
    if gw:
        for target in lookup_targets:
            try:
                q_dom = urllib.parse.quote(target)
                with httpx.Client(timeout=2.5) as hc:
                    r = hc.get(f"{gw['url']}/api/gateway/lookup?domain={q_dom}")
                    if r.status_code == 200:
                        import_sync_bundle(r.json(), ignore_follow_filter=True)
                        if _has_resolved():
                            return True
            except Exception:
                pass
    peer_urls = (
        [u for u in list(_LAN_PEERS.keys())]
        + [s.get("url", "") for s in _load_seeds()]
        + [p.get("url", "") for p in list(store.peers.values()) if p.get("url")]
    )
    self_set = _self_urls()
    frontier = [u.rstrip("/") for u in dict.fromkeys(peer_urls) if u and u.rstrip("/") not in self_set][:6]
    if frontier:
        from concurrent.futures import ThreadPoolExecutor

        def _dht_probe(base: str) -> list[str]:
            extra: list[str] = []
            for target in lookup_targets:
                try:
                    q_dom = urllib.parse.quote(target)
                    with httpx.Client(timeout=1.2) as hc:
                        r = hc.get(f"{base}/api/dht/find?domain={q_dom}")
                        if r.status_code == 200:
                            dj = r.json()
                            if dj.get("found") and isinstance(dj.get("bundle"), dict):
                                import_sync_bundle(dj["bundle"], ignore_follow_filter=True)
                            for cp in dj.get("closest_peers") or []:
                                cu = str(cp.get("url", "")).rstrip("/")
                                if cu and cu not in self_set:
                                    extra.append(cu)
                except Exception:
                    pass
            return extra

        with ThreadPoolExecutor(max_workers=min(6, len(frontier))) as pool:
            next_hop: list[str] = []
            for extra in pool.map(_dht_probe, frontier):
                next_hop.extend(extra)
            if _has_resolved():
                return True
            hop2 = [u for u in dict.fromkeys(next_hop) if u not in frontier][:4]
            if hop2:
                list(pool.map(_dht_probe, hop2))
                if _has_resolved():
                    return True
    _NEG_RESOLVE_CACHE[clean] = time.time()
    return False


def _ensure_domain_keys(
    domain: str,
    claim_token: str = "",
    bypass_short_rule: bool = False,
    privkey_hex: str = "",
) -> tuple[str, str]:
    dom = store.domains.get(domain)
    if dom is None and not bypass_short_rule:
        if _try_resolve_from_nostr(domain):
            dom = store.domains.get(domain)
    provided_priv = privkey_hex.strip()
    if dom is not None:
        if not bypass_short_rule:
            if not provided_priv:
                raise HTTPException(
                    status_code=403,
                    detail=f"'{domain}' already exists. Enter its Ed25519 Private Key to edit or claim ownership.",
                )
            try:
                derived_pub = pubkey_from_priv_hex(provided_priv)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid Ed25519 Private Key hex.")
            if derived_pub != dom.get("pubkey_hex", ""):
                raise HTTPException(
                    status_code=403,
                    detail="Invalid Private Key: cryptographic public key does not match this domain's owner.",
                )
            if not dom.get("privkey_hex"):
                store.import_domain_key(domain, derived_pub, provided_priv)
            return derived_pub, provided_priv
        if not dom.get("privkey_hex"):
            raise HTTPException(status_code=403, detail=f"{domain} is owned by a remote peer key.")
        return dom["pubkey_hex"], dom["privkey_hex"]

    label = domain[:-4]
    if not bypass_short_rule and len(label) <= 4 and claim_token != SHORT_DOMAIN_TOKEN:
        raise HTTPException(
            status_code=403,
            detail=f"'{domain}' is a reserved ultra-short (1-4 char) .xnd name. Use 5+ chars or supply claim_token.",
        )
    if provided_priv:
        try:
            pub_hex = pubkey_from_priv_hex(provided_priv)
            priv_hex = provided_priv
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid Ed25519 Private Key hex.")
    else:
        pub_hex, priv_hex = generate_keypair()
    dom = store.get_or_create_domain_keys(domain, pub_hex, priv_hex)
    return dom["pubkey_hex"], dom["privkey_hex"]


def publish_document(
    domain: str,
    title: str,
    content: str,
    claim_token: str = "",
    bypass_short_rule: bool = False,
    pinned: bool = True,
    privkey_hex: str = "",
) -> dict[str, Any]:
    domain = normalize_xnd_domain(domain, append_tld=True)
    if not DOMAIN_RE.match(domain) or len(domain) > 253:
        raise HTTPException(status_code=400, detail="Invalid .xnd domain. Only letters, numbers, '-' and '.' between labels are allowed (e.g. domain-name.xnd or sub.domain.xnd).")
    ok_sz, sz_bytes = abuse_guard.check_blob_size(content)
    if not ok_sz:
        raise HTTPException(status_code=413, detail=f"Document exceeds max blob size ({sz_bytes} > {abuse_guard.MAX_BLOB_BYTES} bytes)")

    now = time.time()
    pub_hex, priv_hex = _ensure_domain_keys(domain, claim_token, bypass_short_rule, privkey_hex)
    if not bypass_short_rule:
        ok_pk, retry_pk = pubkey_limiter.allow(pub_hex)
        if not ok_pk:
            raise HTTPException(status_code=429, detail=f"Pubkey publish rate limit exceeded; retry in {retry_pk}s")
    vers = store.versions.get(domain, [])
    next_ver = (vers[-1]["version_num"] + 1) if vers else 1
    prev_sha256 = str(vers[-1]["sha256"]) if vers else ""

    sha256 = rust_sha256(content)
    sig_hex = sign_payload(priv_hex, domain, next_ver, sha256, prev_sha256)
    header = {
        "domain": domain,
        "version_num": next_ver,
        "sha256": sha256,
        "prev_sha256": prev_sha256,
        "title": title.strip() or domain,
        "kind": "document",
        "pubkey_hex": pub_hex,
        "signature_hex": sig_hex,
        "created_at": now,
    }
    store.append_version(header, content, pinned=pinned)

    for lk in transclusion_engine.extract_transclusion_links(domain, next_ver, content, store.get_version):
        lk["source_hash"] = sha256
        lk["created_at"] = now
        store.append_link(lk)

    if pinned:
        threading.Thread(target=push_domain_to_quorum, args=(domain, 3), daemon=True).start()
    _notify_domain_updated(domain, next_ver)

    return {"domain": domain, "version": next_ver, "sha256": sha256, "pubkey": pub_hex, "signature": sig_hex, "kind": "document"}


_ORIGIN_RE = re.compile(r"^(https|wss)://[a-z0-9.-]+(?::\d{1,5})?$|^http://(?:127\.0\.0\.1|localhost)(?::\d{1,5})?$", re.IGNORECASE)


def _sanitize_connect_origins(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw[:16]:
        u = str(item or "").strip().rstrip("/")
        if u and _ORIGIN_RE.match(u) and u not in out:
            out.append(u)
    return out


def publish_capsule(
    domain: str,
    title: str,
    files: dict[str, str],
    backend_py: str,
    initial_state: dict[str, Any] | None = None,
    claim_token: str = "",
    bypass_short_rule: bool = False,
    privkey_hex: str = "",
    connect_origins: list[str] | None = None,
) -> dict[str, Any]:
    domain = normalize_xnd_domain(domain, append_tld=True)
    if not DOMAIN_RE.match(domain) or len(domain) > 253:
        raise HTTPException(status_code=400, detail="Invalid .xnd domain. Only letters, numbers, '-' and '.' between labels are allowed.")
    if "index.html" not in files:
        raise HTTPException(status_code=400, detail="Capsule must include index.html")

    now = time.time()
    pub_hex, priv_hex = _ensure_domain_keys(domain, claim_token, bypass_short_rule, privkey_hex)
    vers = store.versions.get(domain, [])
    next_ver = (vers[-1]["version_num"] + 1) if vers else 1
    prev_sha256 = str(vers[-1]["sha256"]) if vers else ""

    raw_origins = list(connect_origins or [])
    if not raw_origins:
        for cfg_name in ("xanadu.json", "xnd.json"):
            if isinstance(files.get(cfg_name), str):
                try:
                    raw_origins = json.loads(files[cfg_name]).get("connect_origins") or []
                    if raw_origins:
                        break
                except Exception:
                    pass
    clean_origins = _sanitize_connect_origins(raw_origins)
    payload_obj: dict[str, Any] = {"files": files, "backend_py": backend_py}
    if clean_origins:
        payload_obj["connect_origins"] = clean_origins
    bundle_payload = json.dumps(payload_obj, sort_keys=True)
    ok_sz, sz_bytes = abuse_guard.check_blob_size(bundle_payload, abuse_guard.MAX_CAPSULE_BYTES)
    if not ok_sz:
        raise HTTPException(status_code=413, detail=f"Capsule bundle exceeds max blob size ({sz_bytes} > {abuse_guard.MAX_CAPSULE_BYTES} bytes)")
    sha256 = rust_sha256(bundle_payload)
    sig_hex = sign_payload(priv_hex, domain, next_ver, sha256, prev_sha256)
    header = {
        "domain": domain,
        "version_num": next_ver,
        "sha256": sha256,
        "prev_sha256": prev_sha256,
        "title": title.strip() or domain,
        "kind": "capsule",
        "pubkey_hex": pub_hex,
        "signature_hex": sig_hex,
        "created_at": now,
    }
    store.append_version(header, bundle_payload, pinned=True)
    if initial_state is not None:
        store.save_capsule_state(domain, initial_state)

    threading.Thread(target=push_domain_to_quorum, args=(domain, 3), daemon=True).start()
    _notify_domain_updated(domain, next_ver)

    return {"domain": domain, "version": next_ver, "sha256": sha256, "pubkey": pub_hex, "signature": sig_hex, "kind": "capsule"}


_CAPSULE_FORBIDDEN_NAMES = frozenset({
    "eval", "exec", "compile", "open", "getattr", "setattr", "delattr",
    "globals", "locals", "vars", "dir", "input", "breakpoint", "__import__",
    "type", "object", "super", "classmethod", "staticmethod", "property",
    "memoryview", "bytearray",
})
_CAPSULE_FORBIDDEN_AST = (
    ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
    ast.AsyncFunctionDef, ast.AsyncFor, ast.AsyncWith, ast.Await,
    ast.Yield, ast.YieldFrom, ast.TryStar if hasattr(ast, "TryStar") else ast.Try,
)


def _validate_capsule_ast(backend_py: str) -> ast.Module:
    if len(backend_py) > 65536:
        raise HTTPException(status_code=400, detail="Capsule backend exceeds 64 KB limit")
    try:
        tree = ast.parse(backend_py, filename="<xnd-capsule>", mode="exec")
    except SyntaxError as exc:
        raise HTTPException(status_code=400, detail=f"Capsule backend syntax error: {exc.msg}")

    nodes = list(ast.walk(tree))
    if len(nodes) > 2500:
        raise HTTPException(status_code=400, detail="Capsule backend AST complexity limit exceeded")

    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
                             ast.AsyncFunctionDef, ast.AsyncFor, ast.AsyncWith, ast.Await,
                             ast.Yield, ast.YieldFrom)):
            raise HTTPException(status_code=403, detail=f"Disallowed syntax in capsule backend: {type(node).__name__}")
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            raise HTTPException(status_code=403, detail="Private/dunder attribute access is forbidden in capsule backend")
        if isinstance(node, ast.Name):
            if node.id.startswith("_") or node.id in _CAPSULE_FORBIDDEN_NAMES:
                raise HTTPException(status_code=403, detail=f"Disallowed identifier in capsule backend: {node.id}")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
            if isinstance(node.right, ast.Constant) and isinstance(node.right.value, (int, float)) and abs(node.right.value) > 1000:
                raise HTTPException(status_code=403, detail="Exponent too large in capsule backend")
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and node.value.bit_length() > 1024:
            raise HTTPException(status_code=403, detail="Integer literal too large in capsule backend")
    return tree


_CAPSULE_SUBPROC_RUNNER = r"""
import inspect, json, socket, sys
try:
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
except Exception:
    pass

SAFE_BUILTINS = {
    "len": len, "str": str, "int": int, "float": float, "bool": bool,
    "list": list, "dict": dict, "tuple": tuple, "set": set,
    "min": min, "max": max, "sum": sum, "sorted": sorted,
    "enumerate": enumerate, "zip": zip, "range": range, "abs": abs, "round": round,
    "True": True, "False": False, "None": None,
}
req = json.loads(sys.stdin.read())
rpc_fd = req.get("rpc_fd")
rpc_sock = socket.fromfd(int(rpc_fd), socket.AF_UNIX, socket.SOCK_STREAM) if rpc_fd is not None else None
rpc_file = rpc_sock.makefile("rwb", buffering=0) if rpc_sock is not None else None

def _rpc_call(op, args):
    if rpc_file is None:
        return {"ok": False, "error": "Runtime RPC bridge unavailable"}
    rpc_file.write((json.dumps({"op": op, **args}) + "\n").encode("utf-8"))
    line = rpc_file.readline()
    if not line:
        return {"ok": False, "error": "RPC bridge closed"}
    return json.loads(line.decode("utf-8"))

class _CapsuleDB:
    def query(self, sql, params=None):
        res = _rpc_call("db_query", {"sql": str(sql), "params": params})
        if not res.get("ok"):
            raise RuntimeError(res.get("error", "SQL error"))
        return res
    def exec(self, sql, params=None):
        return self.query(sql, params)

class _CapsuleAuth:
    def verify(self, token):
        return _rpc_call("auth_verify", {"token": str(token or "")})

env = {"__builtins__": SAFE_BUILTINS, "json": json, "db": _CapsuleDB(), "auth": _CapsuleAuth(), "secrets": dict(req.get("secrets") or {})}
exec(compile(req["code"], "<xnd-capsule>", "exec"), env, env)
handler = env.get("handle")
if not callable(handler):
    raise RuntimeError("Capsule backend missing handle(...)")
sig_params = len(inspect.signature(handler).parameters)
if sig_params >= 5:
    res = handler(req.get("method", "POST"), req.get("path", "/"), dict(req.get("headers") or {}), req["payload"], dict(req["state"]))
else:
    res = handler(req["action"], req["payload"], dict(req["state"]))
if isinstance(res, tuple) and len(res) == 2:
    out = {"resp": dict(res[0]), "state": dict(res[1])}
else:
    out = {"resp": dict(res), "state": req["state"]}
sys.stdout.write(json.dumps(out))
"""


def _find_python_sandbox_bin() -> str | None:
    if not getattr(sys, "frozen", False) and sys.executable:
        return sys.executable
    return shutil.which("python3")


def run_capsule_backend(
    backend_py: str,
    action: str,
    payload: dict[str, Any],
    state: dict[str, Any],
    domain: str = "",
    method: str = "POST",
    req_path: str = "/",
    req_headers: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not backend_py.strip():
        return {"ok": True, "state": state}, state
    tree = _validate_capsule_ast(backend_py)
    state_dir = DATA_DIR / "state"

    py_bin = _find_python_sandbox_bin()
    if py_bin:
        parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        def _serve_rpc() -> None:
            try:
                f = parent_sock.makefile("rwb", buffering=0)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    msg = json.loads(line.decode("utf-8"))
                    op = msg.get("op")
                    try:
                        if op == "db_query" and domain:
                            out_r = capsule_runtime.db_query(state_dir, domain, str(msg.get("sql") or ""), msg.get("params"))
                        elif op == "auth_verify" and domain:
                            out_r = capsule_runtime.verify_session_token(domain, str(msg.get("token") or ""))
                        else:
                            out_r = {"ok": False, "error": f"Unknown op: {op}"}
                    except Exception as exc:
                        out_r = {"ok": False, "error": str(exc)}
                    f.write((json.dumps(out_r) + "\n").encode("utf-8"))
            except Exception:
                pass
            finally:
                try:
                    parent_sock.close()
                except Exception:
                    pass

        rpc_thr = threading.Thread(target=_serve_rpc, daemon=True)
        rpc_thr.start()
        cap_secrets = capsule_runtime.load_capsule_secrets(state_dir, domain) if domain else {}
        req_json = json.dumps({
            "code": backend_py,
            "action": action,
            "payload": payload,
            "state": state,
            "method": method,
            "path": req_path,
            "headers": req_headers or {},
            "secrets": cap_secrets,
            "rpc_fd": child_sock.fileno(),
        })
        try:
            proc = subprocess.run(
                [py_bin, "-I", "-S", "-c", _CAPSULE_SUBPROC_RUNNER],
                input=req_json,
                capture_output=True,
                text=True,
                timeout=2.5,
                env={},
                close_fds=True,
                pass_fds=(child_sock.fileno(),),
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="Capsule backend execution timed out")
        finally:
            try:
                child_sock.close()
            except Exception:
                pass
            try:
                parent_sock.close()
            except Exception:
                pass
        if proc.returncode < 0:
            raise HTTPException(status_code=504, detail="Capsule backend killed by CPU/memory limit")
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "Capsule execution failed").strip().splitlines()[-1][:240]
            raise HTTPException(status_code=500, detail=f"Capsule backend error: {err}")
        try:
            out = json.loads(proc.stdout)
            return dict(out["resp"]), dict(out["state"])
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Invalid capsule backend output: {exc}")

    class _DirectDB:
        def query(self, sql: str, params: Any = None) -> dict[str, Any]:
            return capsule_runtime.db_query(state_dir, domain, sql, params)
        def exec(self, sql: str, params: Any = None) -> dict[str, Any]:
            return self.query(sql, params)

    class _DirectAuth:
        def verify(self, token: str) -> dict[str, Any]:
            return capsule_runtime.verify_session_token(domain, token)

    cap_secrets = capsule_runtime.load_capsule_secrets(state_dir, domain) if domain else {}
    env: dict[str, Any] = {"__builtins__": SAFE_BUILTINS, "json": json, "db": _DirectDB(), "auth": _DirectAuth(), "secrets": cap_secrets}
    exec(compile(tree, "<xnd-capsule>", "exec"), env, env)
    handler = env.get("handle")
    if not callable(handler):
        raise HTTPException(status_code=500, detail="Capsule backend missing handle(...)")
    import inspect as _inspect
    if len(_inspect.signature(handler).parameters) >= 5:
        result = handler(method, req_path, req_headers or {}, payload, dict(state))
    else:
        result = handler(action, payload, dict(state))
    if isinstance(result, tuple) and len(result) == 2:
        return dict(result[0]), dict(result[1])
    return dict(result), state


def _ensure_builtin_docs() -> None:
    doc_title = "documentation.xnd — Xanadu Browser Official Documentation"
    doc_body = (
        "Xanadu Browser (.xnd) — Official Documentation & Architecture\n\n"
        "Founder & Inspiration:\n"
        "Founded in June 2026 in Kenya by Justin Ndambiri, Xanadu Browser is directly inspired by Ted Nelson's original Project Xanadu — the first hypertext project conceived in 1960.\n"
        "Where the modern World Wide Web settled for fragile one-way links, centralized servers, and rented domain names, Xanadu Browser brings Ted Nelson's 1960 vision to life: a two-way, attribution-preserving, cryptographic web that belongs to its users.\n\n"
        "What Xanadu Browser Does:\n"
        "Xanadu Browser is a sovereign, zero-database peer-to-peer browser and local node that runs natively on Android phones and Linux desktops. Every device acts as its own independent node, storing, verifying, indexing, and syncing .xnd documents and full web applications without any central server.\n\n"
        "Core Functions:\n"
        "1. Sovereign .xnd Domains (Ed25519 + Hash-Chained History):\n"
        "   • Domains are owned directly by Ed25519 cryptographic keypairs — zero ICANN registrars, zero yearly fees, and zero central takedowns.\n"
        "   • Every update is SHA-256 content-addressed and linked with prev_sha256 (Bitcoin-style tamper-evident version chains).\n"
        "   • Multi-device QR/passphrase key sync lets you publish to the same .xnd domain from both your phone and laptop.\n\n"
        "2. Two-Way Transclusion & Origin Bridges:\n"
        "   • Instead of dead copy-paste quotes, Xanadu links exact character spans ({{xnd://domain@v1:start-end}}) permanently back to their origin.\n"
        "   • Readers can open the cited source side-by-side and verify context in one click.\n\n"
        "3. Cryptographic App Capsules & GitHub Hosting:\n"
        "   • Host full multi-file HTML/CSS/JS websites and sandboxed backends directly on .xnd domains, or auto-deploy from GitHub.\n"
        "   • Sites replicate across peers and public Nostr relays (kind:30078) so anyone can open them worldwide.\n\n"
        "4. Instant Local RAM Search & Deterministic Featured Snippets:\n"
        "   • Sub-millisecond local RAM indexing paired with a Google-style deterministic IR & Featured Snippet engine (zero paid AI, zero central search server).\n"
        "   • Combines local .xnd knowledge with live web, Wikipedia, and real-time news.\n\n"
        "5. LAN Mesh, Wi-Fi Direct & Offline Internet Sharing:\n"
        "   • Devices on the same Wi-Fi or Wi-Fi Direct automatically discover each other and sync .xnd sites.\n"
        "   • If a device goes offline, it automatically shares live news, search, and web access through nearby online Xanadu peers — while strictly using its own internet whenever online.\n\n"
        "Why Choose Xanadu Over Centralized Modern WWW:\n"
        "• No Link Rot or Silent Rewrites: Content hashes and version chains preserve truth and history.\n"
        "• True Ownership: Your domain and keys live on your device, not a corporation's database.\n"
        "• Zero Central Gatekeepers: No single server to censor, track, paywall, or shut down your voice.\n"
        "• Works Offline & Peer-to-Peer: Browse pinned .xnd sites locally or share connectivity with nearby peers."
    )
    existing_meta = store.domains.get("documentation.xnd")
    if existing_meta and not existing_meta.get("privkey_hex"):
        return
    existing_doc = store.get_version("documentation.xnd")
    existing_doc_txt = store.get_blob(existing_doc["sha256"]) if existing_doc else ""
    if existing_doc_txt != doc_body:
        publish_document(
            "documentation.xnd",
            doc_title,
            doc_body,
            bypass_short_rule=True,
        )


def seed_universe() -> None:
    if store.domains:
        _ensure_builtin_docs()
        return

    publish_document(
        "manifesto.xnd",
        "The Two-Way Web Manifesto",
        (
            "The web was built on one-way links that break and vanish.\n\n"
            "Every quote on the network should remain permanently tethered to its origin span, "
            "so readers can inspect context side-by-side and verify truth without dead URLs.\n\n"
            "In Xanadu, nothing is silently erased: every document is addressed by its cryptographic hash, "
            "and every citation creates a visible two-way bridge."
        ),
        bypass_short_rule=True,
    )
    publish_document(
        "manifesto.xnd",
        "The Two-Way Web Manifesto (Expanded)",
        (
            "The modern web was built on one-way links that rot, paywall, and silently rewrite history.\n\n"
            "Every quote on the network should remain permanently tethered to its origin span, "
            "so readers can inspect context side-by-side and verify truth without dead URLs.\n\n"
            "In Xanadu (.xnd), nothing is silently erased: every document is addressed by its cryptographic hash, "
            "no ICANN domain is required, and every citation creates a visible two-way bridge across the network."
        ),
        bypass_short_rule=True,
    )
    publish_document(
        "x.xnd",
        "x.xnd — Sovereign Short Node",
        (
            "x.xnd — Ultra-short sovereign identity node.\n\n"
            "Core Principle: Ownership belongs to the Ed25519 public key, not a yearly registrar bill.\n\n"
            "Notice how manifesto.xnd already connects to this space:\n"
            "{{xnd://manifesto.xnd@v1:59-208}}"
        ),
        bypass_short_rule=True,
    )
    publish_document(
        "heart.xnd",
        "heart.xnd — Living Node",
        (
            "Welcome to heart.xnd — A living node inside the Xanadu universe.\n\n"
            "Why this matters:\n"
            "{{xnd://manifesto.xnd@v2:95-244}}\n\n"
            "And on domain ownership:\n"
            "{{xnd://x.xnd@v1:46-135}}\n\n"
            "Click any glowing quote block above to open its original source side-by-side "
            "and see the live bridge line connecting exact character spans."
        ),
        bypass_short_rule=True,
    )
    publish_document(
        "home.xnd",
        "Xanadu",
        (
            "Welcome to Xanadu Browser (.xnd Universe).\n\n"
            "You are running a Zero-DB Cryptographic Peer Node: pinned sites stay permanent while crawled cache auto-prunes.\n"
            "Explore documents (heart.xnd, x.xnd, manifesto.xnd), open forum.xnd, or search any topic/domain.\n\n"
            "Featured Live Transclusion from heart.xnd:\n"
            "{{xnd://heart.xnd@v1:0-64}}\n\n"
            "Select any text on any .xnd page to quote & bridge it into your own .xnd site."
        ),
        bypass_short_rule=True,
    )

    forum_html = """<!DOCTYPE html>
<html><head><meta charset="utf-8" /><style>
  body { font-family: Inter, sans-serif; background: #fff; color: #202124; margin: 0; padding: 24px; }
  .box { max-width: 680px; margin: 0 auto; }
  h1 { margin: 0 0 6px; font-size: 24px; }
  .sub { font-family: monospace; font-size: 12px; color: #1a73e8; margin-bottom: 18px; }
  form { display: flex; gap: 8px; margin-bottom: 20px; }
  input { flex: 1; padding: 9px 14px; border: none; border-radius: 999px; background: #f1f3f4; font-family: monospace; }
  button { background: #1a73e8; color: #fff; border: none; border-radius: 999px; padding: 9px 18px; font-weight: 600; cursor: pointer; }
  .post { background: #f8f9fa; border-radius: 12px; padding: 12px 16px; margin-bottom: 10px; }
  .post-meta { font-family: monospace; font-size: 11px; color: #5f6368; margin-bottom: 4px; }
</style></head><body><div class="box">
  <h1>forum.xnd — Live Dynamic Capsule</h1>
  <div class="sub">ZERO-DB CRYPTOGRAPHIC CAPSULE + SANDBOXED BACKEND</div>
  <form id="f"><input id="author" placeholder="Handle" style="max-width:160px;" required /><input id="msg" placeholder="Post to forum.xnd..." required /><button type="submit">Post</button></form>
  <div id="feed">Loading...</div></div>
<script>
async function load() {
  const r = await fetch('/api/app/forum.xnd/list', { method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}' });
  const d = await r.json();
  document.getElementById('feed').innerHTML = d.posts.map(p => `<div class="post"><div class="post-meta">${p.author} · span#post-${p.id}</div><div>${p.text}</div></div>`).join('');
}
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  await fetch('/api/app/forum.xnd/post', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ author: document.getElementById('author').value, text: document.getElementById('msg').value }) });
  document.getElementById('msg').value = ''; load();
});
load();
</script></body></html>"""

    forum_backend = """def handle(action, payload, state):
    posts = list(state.get("posts", []))
    if action == "post":
        author = str(payload.get("author", "anon"))[:32]
        text = str(payload.get("text", "")).strip()[:280]
        if text:
            posts.insert(0, {"id": len(posts) + 1, "author": author, "text": text})
            state["posts"] = posts
        return {"ok": True, "posts": posts}, state
    return {"ok": True, "posts": posts}, state
"""
    publish_capsule(
        "forum.xnd",
        "forum.xnd — Sovereign App Capsule",
        {"index.html": forum_html},
        forum_backend,
        {"posts": [{"id": 1, "author": "@xanadu", "text": "Zero-DB cryptographic app capsule online."}]},
        bypass_short_rule=True,
    )

    f_title, f_body = _founder_summary_doc()
    existing_founder = store.get_version("founder.xnd")
    existing_text = store.get_blob(existing_founder["sha256"]) if existing_founder else ""
    if existing_text != f_body:
        publish_document(
            "founder.xnd",
            f_title,
            f_body,
            bypass_short_rule=True,
        )

    doc_title = "documentation.xnd — Xanadu Browser Official Documentation"
    doc_body = (
        "Xanadu Browser (.xnd) — Official Documentation & Architecture\n\n"
        "Founder & Inspiration:\n"
        "Founded in June 2026 in Kenya by Justin Ndambiri, Xanadu Browser is directly inspired by Ted Nelson's original Project Xanadu — the first hypertext project conceived in 1960.\n"
        "Where the modern World Wide Web settled for fragile one-way links, centralized servers, and rented domain names, Xanadu Browser brings Ted Nelson's 1960 vision to life: a two-way, attribution-preserving, cryptographic web that belongs to its users.\n\n"
        "What Xanadu Browser Does:\n"
        "Xanadu Browser is a sovereign, zero-database peer-to-peer browser and local node that runs natively on Android phones and Linux desktops. Every device acts as its own independent node, storing, verifying, indexing, and syncing .xnd documents and full web applications without any central server.\n\n"
        "Core Functions:\n"
        "1. Sovereign .xnd Domains (Ed25519 + Hash-Chained History):\n"
        "   • Domains are owned directly by Ed25519 cryptographic keypairs — zero ICANN registrars, zero yearly fees, and zero central takedowns.\n"
        "   • Every update is SHA-256 content-addressed and linked with prev_sha256 (Bitcoin-style tamper-evident version chains).\n"
        "   • Multi-device QR/passphrase key sync lets you publish to the same .xnd domain from both your phone and laptop.\n\n"
        "2. Two-Way Transclusion & Origin Bridges:\n"
        "   • Instead of dead copy-paste quotes, Xanadu links exact character spans ({{xnd://domain@v1:start-end}}) permanently back to their origin.\n"
        "   • Readers can open the cited source side-by-side and verify context in one click.\n\n"
        "3. Cryptographic App Capsules & GitHub Hosting:\n"
        "   • Host full multi-file HTML/CSS/JS websites and sandboxed backends directly on .xnd domains, or auto-deploy from GitHub.\n"
        "   • Sites replicate across peers and public Nostr relays (kind:30078) so anyone can open them worldwide.\n\n"
        "4. Instant Local RAM Search & Deterministic Featured Snippets:\n"
        "   • Sub-millisecond local RAM indexing paired with a Google-style deterministic IR & Featured Snippet engine (zero paid AI, zero central search server).\n"
        "   • Combines local .xnd knowledge with live web, Wikipedia, and real-time news.\n\n"
        "5. LAN Mesh, Wi-Fi Direct & Offline Internet Sharing:\n"
        "   • Devices on the same Wi-Fi or Wi-Fi Direct automatically discover each other and sync .xnd sites.\n"
        "   • If a device goes offline, it automatically shares live news, search, and web access through nearby online Xanadu peers — while strictly using its own internet whenever online.\n\n"
        "Why Choose Xanadu Over Centralized Modern WWW:\n"
        "• No Link Rot or Silent Rewrites: Content hashes and version chains preserve truth and history.\n"
        "• True Ownership: Your domain and keys live on your device, not a corporation's database.\n"
        "• Zero Central Gatekeepers: No single server to censor, track, paywall, or shut down your voice.\n"
        "• Works Offline & Peer-to-Peer: Browse pinned .xnd sites locally or share connectivity with nearby peers."
    )
    existing_meta = store.domains.get("documentation.xnd")
    if existing_meta and not existing_meta.get("privkey_hex"):
        return
    existing_doc = store.get_version("documentation.xnd")
    existing_doc_txt = store.get_blob(existing_doc["sha256"]) if existing_doc else ""
    if existing_doc_txt != doc_body:
        publish_document(
            "documentation.xnd",
            doc_title,
            doc_body,
            bypass_short_rule=True,
        )
    if "wikipedia.xnd" not in store.domains:
        publish_document(
            "wikipedia.xnd",
            "wikipedia.xnd — Live Auto-Indexed Encyclopedia",
            "wikipedia.xnd — Live Sovereign Encyclopedia Index\n\nInitializing 10 continuous background scrapers (World News, Tech, Science, Sports, CEOs, Musicians, Footballers, Countries & Random Wikipedia)...",
            bypass_short_rule=True,
        )
    scrapers.start_background_scrapers(store, publish_document)


def _justin_age() -> int:
    from datetime import date
    today = date.today()
    return today.year - 2000 - (1 if (today.month, today.day) < (9, 7) else 0)


def _founder_summary_doc() -> tuple[str, str]:
    age = _justin_age()
    title = "Justin Ndambiri — Founder & Owner of Xanadu (.xnd)"
    body = (
        "Xanadu (.xnd) — Official Founder & Origin Summary\n\n"
        f"Founder & Owner: Justin Ndambiri\n"
        f"Location: Kenya\n"
        f"Founded: June 2026\n"
        f"Age: {age}\n\n"
        "Executive Overview:\n"
        "Xanadu was created and founded in June 2026 by Justin Ndambiri in Kenya as a sovereign, "
        "peer-to-peer web architecture and browser. Designed around a zero-DB cryptographic node model, "
        "Xanadu replaces centralized domain registrars with Ed25519 keypair ownership, millisecond local "
        "RAM indexing, and live character-level transclusion across .xnd documents and app capsules.\n\n"
        "Core Pillars:\n"
        "• Sovereign Identity: Domains (.xnd) are owned directly by Ed25519 cryptographic keys.\n"
        "• Two-Way Web: Live web discovery paired with an instant local .xnd knowledge index.\n"
        "• Built in Kenya: Engineered from the ground up starting June 2026 by Justin Ndambiri."
    )
    return title, body


def _is_xanadu_founder_query(query: str) -> bool:
    ql = query.strip().lower()
    if not ql:
        return False
    if "justin ndambiri" in ql or "ndambiri" in ql:
        return True
    intent_words = ("own", "owner", "founder", "found", "creat", "made", "built", "develop", "architect", "who", "when", "where", "age", "what is", "about", "browser", "app")
    if "xanadu" in ql and any(iw in ql for iw in intent_words):
        return True
    self_refs = ("this browser", "this app", "this platform", "this web", "this search engine", "this site", ".xnd")
    if any(sr in ql for sr in self_refs) and any(iw in ql for iw in intent_words):
        return True
    return False


def _founder_knowledge_card(query: str = "") -> dict[str, Any]:
    import random

    age = _justin_age()
    ql = (query or "").strip().lower()

    is_when = any(k in ql for k in ("when", "created", "founded", "date", "year", "started", "born"))
    is_owner = any(k in ql for k in ("owner", "own", "owns", "founder", "who made", "who created", "who built", "who developed", "who is behind", "behind"))
    is_justin = "justin" in ql or "ndambiri" in ql
    is_how_xnd = any(k in ql for k in ("what is .xnd", "what is xanadu", "how does xanadu", "how does this browser"))

    if is_when and ("xanadu" in ql or "this browser" in ql or "this app" in ql):
        titles = [
            "Xanadu Was Created in June 2026",
            "Xanadu (.xnd) — Founded June 2026 in Kenya",
            "Origin of Xanadu Browser: Created June 2026",
        ]
        summaries = [
            (
                f"Xanadu was created in June 2026 in Kenya by founder Justin Ndambiri (age {age}). "
                "It was built as a sovereign, zero-DB peer-to-peer web and browser powered by Ed25519 cryptographic ownership."
            ),
            (
                f"Founded in June 2026, Xanadu (.xnd) was created by Justin Ndambiri in Kenya (currently age {age}). "
                "The platform replaces centralized domain registrars with cryptographic .xnd domains and millisecond local indexing."
            ),
            (
                f"This browser (Xanadu .xnd) was founded in June 2026 by Kenya-based engineer Justin Ndambiri (age {age}) "
                "to establish a two-way, peer-owned web with live transclusion."
            ),
        ]
        subtitle = "Founded June 2026 · Kenya · Founder: Justin Ndambiri"
    elif is_owner:
        titles = [
            "Justin Ndambiri — Owner & Founder of Xanadu Browser",
            "Justin Ndambiri Owns Xanadu (.xnd)",
            "Browser Owner & Founder: Justin Ndambiri (Kenya)",
        ]
        summaries = [
            (
                f"Justin Ndambiri owns and founded this browser (Xanadu .xnd). Based in Kenya and currently age {age}, "
                "he created Xanadu in June 2026 as a decentralized, cryptographically verified web."
            ),
            (
                f"This browser — Xanadu (.xnd) — is owned and engineered by Justin Ndambiri (age {age}), based in Kenya. "
                "Founded in June 2026, Xanadu gives domain holders direct Ed25519 cryptographic ownership instead of registrar leases."
            ),
            (
                f"The owner and founder of Xanadu Browser is Justin Ndambiri (age {age}, Kenya), who launched it in June 2026 "
                "to power a fast, peer-to-peer two-way web."
            ),
        ]
        subtitle = f"Justin Ndambiri · Age {age} · Kenya · Founded June 2026"
    elif is_justin:
        titles = [
            "Justin Ndambiri — Founder of Xanadu (.xnd)",
            "Justin Ndambiri (Kenya) · Creator of Xanadu Browser",
        ]
        summaries = [
            (
                f"Justin Ndambiri (age {age}) is a Kenya-based software architect and the founder of Xanadu (.xnd), "
                "the sovereign peer-to-peer web browser and network he created in June 2026."
            ),
            (
                f"Based in Kenya, Justin Ndambiri (age {age}) founded Xanadu in June 2026—engineering a zero-DB cryptographic "
                "browser ecosystem where domains, apps, and live transclusions belong directly to keyholders."
            ),
        ]
        subtitle = f"Founder of Xanadu · Kenya · Age {age}"
    elif is_how_xnd:
        titles = [
            "Xanadu (.xnd) — Two-Way Sovereign Browser",
            "Inside Xanadu Browser — Ed25519 Web & Live Index",
        ]
        summaries = [
            (
                f"Xanadu (.xnd) is a two-way sovereign web browser created in June 2026 by Justin Ndambiri (age {age}) in Kenya. "
                "It pairs an instant local RAM index of .xnd domains and app capsules with live WWW search and character-level transclusion."
            ),
            (
                f"Built in Kenya in June 2026 by Justin Ndambiri (age {age}), Xanadu runs as a zero-DB peer node where .xnd domains "
                "are owned by Ed25519 keys and indexed in milliseconds."
            ),
        ]
        subtitle = f"Xanadu (.xnd) · Founded June 2026 · Justin Ndambiri"
    else:
        titles = [
            "Xanadu (.xnd) — Sovereign Peer-to-Peer Web",
            "About Xanadu — Founded June 2026 by Justin Ndambiri",
        ]
        summaries = [
            (
                f"Xanadu (.xnd) is a sovereign, zero-DB peer-to-peer web and browser created in June 2026 by Justin Ndambiri "
                f"(age {age}) in Kenya. It combines live WWW discovery with an instant local .xnd index and Ed25519 domain ownership."
            ),
            (
                f"Created in June 2026 in Kenya by Justin Ndambiri (age {age}), Xanadu (.xnd) is a two-way web browser "
                "featuring millisecond local RAM indexing, live character transclusion, and cryptographic app capsules."
            ),
        ]
        subtitle = f"Founded June 2026 · Justin Ndambiri · Kenya"

    return {
        "domain": "founder.xnd",
        "title": random.choice(titles),
        "subtitle": subtitle,
        "summary": random.choice(summaries),
    }


def build_segments(content: str) -> list[dict[str, Any]]:
    return transclusion_engine.build_segments(content, store.get_version, store.get_blob)


class PublishRequest(BaseModel):
    domain: str
    title: str
    content: str
    claim_token: str = ""
    privkey_hex: str = ""
    private_space: bool = False
    allowed_pubkeys: list[str] | str = ""


class E2eeUnlockRequest(BaseModel):
    domain: str
    privkey_hex: str


class PublishCapsuleRequest(BaseModel):
    domain: str
    title: str
    html: str = ""
    files: dict[str, str] | None = None
    backend_py: str = ""
    claim_token: str = ""
    privkey_hex: str = ""
    connect_origins: list[str] | None = None


class KeyImportRequest(BaseModel):
    domain: str
    privkey_hex: str


class ArchiveUrlRequest(BaseModel):
    url: str
    domain: str = ""


class PeerRequest(BaseModel):
    url: str
    label: str = "Peer Node"


class AssetUploadRequest(BaseModel):
    filename: str
    mime_type: str = "application/octet-stream"
    data_b64: str


def seed_bootstrap_peers() -> None:
    raw = os.environ.get("XND_BOOTSTRAP_PEERS", "").strip()
    if not raw:
        return
    for entry in raw.split(","):
        url = entry.strip().rstrip("/")
        if url and url not in store.peers:
            store.save_peer(url, "Bootstrap Peer", 0.0)


def _require_localhost(request: Request) -> None:
    host = request.client.host if request.client else ""
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=403, detail="Private keys and node admin actions are restricted to localhost.")


def _self_urls() -> set[str]:
    port = os.environ.get("XND_PORT", "8765")
    urls = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
    pub = os.environ.get("XND_PUBLIC_URL", "").strip().rstrip("/")
    if pub:
        urls.add(pub)
    return urls


def _pull_from_peer_sync(peer_url: str, label: str = "Peer Node") -> dict[str, int]:
    peer_url = peer_url.rstrip("/")
    with urllib.request.urlopen(f"{peer_url}/api/sync/export", timeout=5) as resp:
        bundle = json.loads(resp.read().decode("utf-8"))
    stats = import_sync_bundle(bundle)
    store.save_peer(peer_url, label, time.time(), subscribed=True)

    # Bitcoin-style Peer Exchange (PEX): learn other live peers from this peer
    self_set = _self_urls()
    try:
        with urllib.request.urlopen(f"{peer_url}/api/peers", timeout=3) as presp:
            pdata = json.loads(presp.read().decode("utf-8"))
        for p in pdata.get("peers", []):
            u = str(p.get("url", "")).strip().rstrip("/")
            if u.startswith(("http://", "https://")) and u not in self_set and u not in store.peers and len(store.peers) < 50:
                store.save_peer(u, p.get("label", "PEX Peer"), 0.0)
    except Exception:
        pass

    # Announce ourselves if we have a public URL (e.g. tunnel / LAN / public IP)
    pub_url = os.environ.get("XND_PUBLIC_URL", "").strip().rstrip("/")
    if pub_url:
        try:
            req = urllib.request.Request(
                f"{peer_url}/api/peers/announce",
                data=json.dumps({"url": pub_url, "label": "Xanadu Peer"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3).close()
        except Exception:
            pass
    return stats


def _peer_get(peer_url: str, path: str, timeout: float = 3.0) -> str:
    if peer_url.startswith("stun://") and nat_tunnel is not None:
        return nat_tunnel.rpc(peer_url, "GET", path, "", timeout=timeout)
    with urllib.request.urlopen(f"{peer_url}{path}", timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def _peer_post_json(peer_url: str, path: str, payload_str: str, timeout: float = 3.0) -> bool:
    if peer_url.startswith("stun://") and nat_tunnel is not None:
        raw = nat_tunnel.rpc(peer_url, "POST", path, payload_str, timeout=timeout)
        return bool(raw)
    req = urllib.request.Request(
        f"{peer_url}{path}",
        data=payload_str.encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return 200 <= resp.status < 300


def _collect_active_peer_urls() -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    def _add(u: str) -> None:
        clean = (u or "").strip().rstrip("/")
        if not (clean.startswith("http://") or clean.startswith("https://") or clean.startswith("stun://")):
            return
        low = clean.lower()
        if "127.0.0.1" in low or "localhost" in low:
            return
        if clean not in seen:
            seen.add(clean)
            urls.append(clean)

    for p in list(store.peers.values()):
        _add(str(p.get("url", "")))
    with _LAN_LOCK:
        for lp in list(_LAN_PEERS.values()):
            _add(str(lp.get("url", "")))
    try:
        for np_obj in discover_peers_nostr():
            _add(str(np_obj.get("url", "")))
    except Exception:
        pass
    if nat_tunnel is not None:
        try:
            for sp in nat_tunnel.discover_stun_peers_nostr():
                _add(str(sp.get("stun_url", "")))
        except Exception:
            pass
    return urls


def push_domain_to_quorum(domain: str, quorum: int = 3) -> int:
    """Immediately push a signed domain bundle to up to K online peers before this node sleeps."""
    bundle = export_domain_bundle(domain)
    if not bundle.get("versions"):
        return 0
    candidates = _collect_active_peer_urls()[: max(quorum * 2, 6)]
    if not candidates:
        return 0
    payload_str = json.dumps(bundle)
    acked = 0
    lock = threading.Lock()

    def _push_one(p_url: str) -> None:
        nonlocal acked
        try:
            if _peer_post_json(p_url, "/api/sync/import", payload_str, timeout=3.0):
                with lock:
                    acked += 1
        except Exception:
            pass

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=min(6, len(candidates))) as pool:
        list(pool.map(_push_one, candidates))
    gossip_stats["last_quorum_push"] = {"domain": domain, "acked": acked, "ts": time.time()}
    return acked


def _run_mesh_anti_entropy() -> dict[str, int]:
    """Exchange lightweight manifests, enforce Rendezvous protected shas, and re-seed under-replicated sites."""
    self_id = _get_node_id()
    peers = _collect_active_peer_urls()[:8]
    peer_manifests: list[tuple[str, str, dict[str, Any]]] = []
    if peers:
        from concurrent.futures import ThreadPoolExecutor

        def _fetch_m(p_url: str) -> tuple[str, str, dict[str, Any]] | None:
            global _MESH_GATEWAY_PEER
            try:
                data = json.loads(_peer_get(p_url, "/api/sync/manifest", timeout=2.5))
                if isinstance(data, dict) and isinstance(data.get("domains"), dict):
                    if p_url.startswith(("http://", "https://")) and not _check_has_wan() and data.get("has_wan") and data.get("share_gateway", True):
                        _MESH_GATEWAY_PEER = {
                            "url": p_url,
                            "label": str(data.get("label") or "LAN Peer"),
                            "updated_at": time.time(),
                        }
                    return (p_url, str(data.get("node_id") or p_url), data["domains"])
            except Exception:
                return None
            return None

        with ThreadPoolExecutor(max_workers=min(6, len(peers))) as pool:
            for item in pool.map(_fetch_m, peers):
                if item is not None:
                    peer_manifests.append(item)

    all_node_ids = [self_id] + [nid for _, nid, _ in peer_manifests]
    all_domains: set[str] = set(store.domains.keys())
    for _, _, p_doms in peer_manifests:
        all_domains.update(p_doms.keys())

    # Update Rendezvous-protected blob hashes so cache pruning keeps sites we deterministically seed
    protected_shas: set[str] = set()
    for dom in all_domains:
        ranked = sorted(all_node_ids, key=lambda nid: _rendezvous_rank(nid, dom), reverse=True)
        if self_id in ranked[:3]:
            vers = store.versions.get(dom, [])
            if vers:
                protected_shas.add(str(vers[-1].get("sha256", "")))
    store.mesh_protected_shas = protected_shas

    pulled = 0
    reseeded = 0
    under_quota = store.get_cache_bytes() < int(MAX_CACHE_BYTES * 0.9)

    # Pull missing or newer versions from peer manifests
    for p_url, _, p_doms in peer_manifests:
        for dom, info in p_doms.items():
            if dom in store.blocked_domains:
                continue
            p_ver = int(info.get("latest_version", 0) or 0)
            local_vers = store.versions.get(dom, [])
            local_ver = int(local_vers[-1].get("version_num", 0)) if local_vers else 0
            if p_ver > local_ver:
                ranked = sorted(all_node_ids, key=lambda nid: _rendezvous_rank(nid, dom), reverse=True)
                if self_id in ranked[:3] or under_quota:
                    try:
                        q_dom = urllib.parse.quote(dom)
                        bundle = json.loads(_peer_get(p_url, f"/api/sync/export?domain={q_dom}", timeout=4.0))
                        st = import_sync_bundle(bundle, ignore_follow_filter=True)
                        pulled += st.get("imported_versions", 0)
                    except Exception:
                        pass

    # Re-seed any local domain that has fewer than K=3 online replicas
    if peer_manifests:
        for dom, vers in list(store.versions.items()):
            if not vers or dom in store.blocked_domains:
                continue
            local_ver = int(vers[-1].get("version_num", 0))
            replicas = 1  # self
            missing_peers: list[str] = []
            for p_url, _, p_doms in peer_manifests:
                p_ver = int((p_doms.get(dom) or {}).get("latest_version", 0) or 0)
                if p_ver >= local_ver:
                    replicas += 1
                else:
                    missing_peers.append(p_url)
            if replicas < 3 and missing_peers:
                bundle = export_domain_bundle(dom)
                if bundle.get("versions"):
                    payload_str = json.dumps(bundle)
                    for target_url in missing_peers[: (3 - replicas)]:
                        try:
                            if _peer_post_json(target_url, "/api/sync/import", payload_str, timeout=3.0):
                                reseeded += 1
                        except Exception:
                            pass

    if pulled:
        gossip_stats["total_imported"] += pulled
    if reseeded:
        gossip_stats["mesh_reseeded"] = int(gossip_stats.get("mesh_reseeded", 0)) + reseeded
    return {"pulled": pulled, "reseeded": reseeded}


_NOSTR_CONFIRMED_VERSIONS: dict[str, int] = {}


def _sync_unconfirmed_local_domains_to_nostr() -> int:
    """Self-healing: re-announce any locally-owned domain versions not yet confirmed on Nostr relays."""
    pushed = 0
    for dom, dmeta in list(store.domains.items()):
        if not dmeta.get("privkey_hex") or dom in store.blocked_domains:
            continue
        vers = store.versions.get(dom, [])
        if not vers:
            continue
        latest = vers[-1]
        vnum = int(latest.get("version_num", 1))
        if _NOSTR_CONFIRMED_VERSIONS.get(dom, 0) >= vnum:
            continue
        sha = str(latest.get("sha256", ""))
        blob_txt = store.get_blob(sha) or ""
        pub_hex = str(dmeta.get("pubkey_hex") or latest.get("pubkey_hex") or "")
        sig_hex = str(latest.get("signature_hex", ""))
        if not sha or not blob_txt or not pub_hex or not sig_hex:
            continue
        try:
            accepted = announce_doc_nostr(
                dom,
                vnum,
                str(latest.get("title") or dom),
                sha,
                pub_hex,
                sig_hex,
                blob_txt,
                latest.get("kind") == "capsule",
                prev_sha256=str(latest.get("prev_sha256", "")),
            )
            if accepted > 0:
                _NOSTR_CONFIRMED_VERSIONS[dom] = vnum
                pushed += 1
        except Exception:
            pass
    return pushed


async def _auto_gossip_loop() -> None:
    await asyncio.sleep(0.5)
    while True:
        try:
            await asyncio.to_thread(_sync_unconfirmed_local_domains_to_nostr)
        except Exception:
            pass
        try:
            bundle = await asyncio.to_thread(discover_docs_nostr, None, 250)
            stats = import_sync_bundle(bundle, ignore_follow_filter=True)
            gossip_stats["total_imported"] += stats.get("imported_versions", 0)
        except Exception:
            pass
        for p in list(store.peers.values()):
            if not p.get("subscribed"):
                continue
            try:
                stats = await asyncio.to_thread(_pull_from_peer_sync, p["url"], p["label"])
                gossip_stats["total_imported"] += stats.get("imported_versions", 0)
            except Exception:
                pass
        try:
            await asyncio.to_thread(_run_mesh_anti_entropy)
        except Exception:
            pass
        gossip_stats["last_run"] = time.time()
        try:
            await asyncio.to_thread(store.crawl_all_domains)
        except Exception:
            pass
        await asyncio.sleep(GOSSIP_INTERVAL)


_LAN_PEERS: dict[str, dict[str, Any]] = {}
_LAN_LOCK = threading.Lock()


def _sync_one_lan_peer(peer_url: str, label: str = "LAN Peer") -> dict[str, int]:
    stats = _pull_from_peer_sync(peer_url, label)
    try:
        payload = json.dumps(sync_export()).encode("utf-8")
        req = urllib.request.Request(
            f"{peer_url}/api/sync/import",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    except Exception:
        pass
    with _LAN_LOCK:
        if peer_url in _LAN_PEERS:
            _LAN_PEERS[peer_url]["last_synced"] = time.time()
    return stats


def _on_lan_peer_found(peer_url: str, label: str) -> None:
    peer_url = peer_url.rstrip("/")
    if peer_url in _self_urls():
        return
    now = time.time()
    should_sync = False
    with _LAN_LOCK:
        prev = _LAN_PEERS.get(peer_url)
        last_synced = float(prev.get("last_synced", 0.0)) if prev else 0.0
        _LAN_PEERS[peer_url] = {
            "url": peer_url,
            "label": label or "LAN Peer",
            "last_seen": now,
            "last_synced": last_synced,
        }
        if now - last_synced > 30.0:
            _LAN_PEERS[peer_url]["last_synced"] = now
            should_sync = True
    if peer_url not in store.peers and len(store.peers) < 50:
        store.save_peer(peer_url, label or "LAN Peer", 0.0, subscribed=True)
    if should_sync:
        threading.Thread(target=_sync_one_lan_peer, args=(peer_url, label or "LAN Peer"), daemon=True).start()


@app.get("/api/lan/peers")
def lan_peers() -> dict[str, Any]:
    now = time.time()
    with _LAN_LOCK:
        active = [
            dict(v)
            for v in _LAN_PEERS.values()
            if (now - float(v.get("last_seen", 0.0))) < 90.0
        ]
    return {"peers": active, "port": int(os.environ.get("XND_PORT", "8765"))}


@app.post("/api/lan/sync")
def lan_sync_now() -> dict[str, Any]:
    now = time.time()
    with _LAN_LOCK:
        active = [
            (v["url"], v.get("label", "LAN Peer"))
            for v in _LAN_PEERS.values()
            if (now - float(v.get("last_seen", 0.0))) < 90.0
        ]
    totals = {"synced_peers": 0, "imported_versions": 0, "imported_forum_posts": 0, "imported_wiki_shards": 0, "rejected": 0}
    for pu, lbl in active:
        try:
            st = _sync_one_lan_peer(pu, lbl)
            totals["synced_peers"] += 1
            totals["imported_versions"] += st.get("imported_versions", 0)
            totals["imported_forum_posts"] += st.get("imported_forum_posts", 0)
            totals["imported_wiki_shards"] += st.get("imported_wiki_shards", 0)
            totals["rejected"] += st.get("rejected", 0)
        except Exception:
            pass
    return {"ok": True, **totals}


def _nat_rpc_dispatch(method: str, path: str, body: str) -> str:
    clean_path, _, query = path.partition("?")
    if method == "GET" and clean_path == "/api/sync/manifest":
        return json.dumps(sync_manifest())
    if method == "GET" and clean_path == "/api/sync/export":
        dom = ""
        if query:
            qs = urllib.parse.parse_qs(query)
            dom = (qs.get("domain") or [""])[0]
        return json.dumps(sync_export(dom))
    if method == "POST" and clean_path == "/api/sync/import":
        bundle = json.loads(body) if body else {}
        return json.dumps({"ok": True, **import_sync_bundle(bundle)})
    return json.dumps({"ok": False, "detail": f"Unsupported NAT RPC: {method} {clean_path}"})


@app.get("/api/nat/status")
def nat_status() -> dict[str, Any]:
    if nat_tunnel is None:
        return {"ok": False, "stun_ok": False, "node_id": _get_node_id(), "detail": "NAT tunnel not started"}
    return nat_tunnel.status()


_LIVE_LOCK = threading.Lock()
_LIVE_SUBSCRIBERS: set[asyncio.Queue[dict[str, Any]]] = set()
_MAIN_LOOP: asyncio.AbstractEventLoop | None = None


def _notify_domain_updated(domain: str, version_num: int) -> None:
    """Push a real-time domain update event to all connected SSE UI clients."""
    payload = {"domain": domain, "version": int(version_num), "ts": time.time()}
    with _LIVE_LOCK:
        subs = list(_LIVE_SUBSCRIBERS)
        loop = _MAIN_LOOP
    if not subs or loop is None or loop.is_closed():
        return
    for q in subs:
        try:
            loop.call_soon_threadsafe(q.put_nowait, payload)
        except Exception:
            pass


def _on_realtime_nostr_bundle(bundle: dict[str, Any]) -> None:
    try:
        import_sync_bundle(bundle, ignore_follow_filter=True)
    except Exception:
        pass


@app.get("/api/events/stream")
async def api_events_stream(request: Request) -> StreamingResponse:
    _require_localhost(request)
    q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=64)
    with _LIVE_LOCK:
        _LIVE_SUBSCRIBERS.add(q)

    async def _gen():
        try:
            yield ": connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=25.0)
                    yield f"event: domain_update\ndata: {json.dumps(ev)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            with _LIVE_LOCK:
                _LIVE_SUBSCRIBERS.discard(q)

    return StreamingResponse(_gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.on_event("startup")
async def startup() -> None:
    global nat_tunnel, _MAIN_LOOP
    _MAIN_LOOP = asyncio.get_running_loop()
    seed_universe()
    _purge_collision_aliases()
    _ensure_builtin_docs()
    seed_bootstrap_peers()
    if nat_tunnel is None:
        nat_tunnel = NatTunnel(_get_node_id(), _nat_rpc_dispatch, int(os.environ.get("XND_NAT_PORT", "8767")))
        nat_tunnel.start()
    asyncio.create_task(asyncio.to_thread(store.crawl_all_domains))
    start_lan_discovery(int(os.environ.get("XND_PORT", "8765")), _on_lan_peer_found, "Xanadu Desktop")
    subscribe_docs_nostr(_on_realtime_nostr_bundle)
    asyncio.create_task(_auto_gossip_loop())
    asyncio.create_task(_github_autosync_loop())


async def _github_autosync_loop() -> None:
    while True:
        await asyncio.sleep(60)
        try:
            if not gh_hosting.get_status().get("connected"):
                continue
            links = gh_hosting.load_links()
            for dom, info in list(links.items()):
                repo = info.get("repo", "")
                branch = info.get("branch", "")
                subdir = info.get("subdir", "")
                last_sha = info.get("last_sha", "")
                if not repo or not dom:
                    continue
                latest_sha = await asyncio.to_thread(gh_hosting.get_latest_commit_sha, repo, branch)
                if not latest_sha or latest_sha == last_sha:
                    continue
                priv = store.domains.get(dom, {}).get("privkey_hex", "")
                if not priv:
                    continue
                files, backend_py, used_branch = await asyncio.to_thread(gh_hosting.fetch_repo_bundle, repo, branch, subdir)
                res = publish_capsule(dom, dom, files, backend_py, None, "", privkey_hex=priv)
                gh_hosting.save_link(dom, repo, used_branch, subdir, latest_sha)
                pub_hex = store.domains.get(dom, {}).get("pubkey_hex", "")
                blob_txt = store.get_blob(res.get("sha256", "")) or ""
                if pub_hex and res.get("signature") and blob_txt:
                    threading.Thread(
                        target=announce_doc_nostr,
                        args=(dom, int(res["version"]), dom, res["sha256"], pub_hex, res["signature"], blob_txt, True),
                        daemon=True,
                    ).start()
        except Exception:
            pass


@app.get("/", response_class=HTMLResponse)
def index() -> FileResponse:
    index_file = UI_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="UI not found")
    return FileResponse(str(index_file))


@app.get("/api/storage/stats")
def storage_stats() -> dict[str, Any]:
    return store.storage_stats()


@app.get("/api/blob/{sha256}")
def get_raw_blob(sha256: str) -> Response:
    content = store.get_blob(sha256.strip().lower())
    if content is None:
        raise HTTPException(status_code=404, detail="Blob not found or pruned")
    return Response(content=content, media_type="text/plain; charset=utf-8")


@app.get("/api/domains")
def list_domains() -> dict[str, Any]:
    out = []
    for name, dom in store.domains.items():
        vers = store.versions.get(name, [])
        if not vers:
            if not dom.get("privkey_hex"):
                continue
            out.append(
                {
                    "name": name,
                    "pubkey_hex": dom.get("pubkey_hex", ""),
                    "owned_locally": True,
                    "latest_version": 0,
                    "title": name,
                    "kind": "capsule",
                    "backlinks_count": len(store.links_by_target.get(name, [])),
                }
            )
            continue
        latest = vers[-1]
        k = latest.get("kind") or ("capsule" if latest.get("is_app") else "document")
        out.append(
            {
                "name": name,
                "pubkey_hex": dom.get("pubkey_hex", ""),
                "owned_locally": bool(dom.get("privkey_hex")),
                "latest_version": latest.get("version_num", 1),
                "title": latest.get("title", name),
                "kind": k,
                "backlinks_count": len(store.links_by_target.get(name, [])),
            }
        )
    out.sort(key=lambda x: (-x["backlinks_count"], x["name"]))
    return {"domains": out}


@app.get("/api/graph")
def universe_graph() -> dict[str, Any]:
    nodes = []
    for name in store.domains:
        latest = store.get_version(name)
        if not latest:
            continue
        k = latest.get("kind") or ("capsule" if latest.get("is_app") else "document")
        nodes.append(
            {
                "id": name,
                "title": latest.get("title", name),
                "kind": k,
                "backlinks": len(store.links_by_target.get(name, [])),
            }
        )
    seen = set()
    edges = []
    for lk in store.all_links:
        k = (lk["source_domain"], lk["target_domain"], lk["link_type"])
        if k not in seen:
            seen.add(k)
            edges.append({"source": lk["source_domain"], "target": lk["target_domain"], "link_type": lk["link_type"]})
    return {"nodes": nodes, "edges": edges}


@app.get("/api/resolve/{domain}")
def resolve_domain(domain: str, version: int | None = Query(default=None)) -> dict[str, Any]:
    domain = domain.strip().lower()
    if not DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail="Only .xnd domains are supported in Xanadu.")
    parsed_canon = _parse_canonical_domain(domain)
    storage_domain = domain
    row = store.get_version(domain, version)
    if (row is None or not row.get("pubkey_hex")) and parsed_canon:
        base_dom, pub_prefix = parsed_canon
        base_pub = (store.domains.get(base_dom, {}).get("pubkey_hex") or "").lower()
        if base_pub.startswith(pub_prefix):
            base_row = store.get_version(base_dom, version)
            if base_row is not None:
                storage_domain = base_dom
                row = base_row
    if (row is None or not row.get("pubkey_hex")) and _try_resolve_from_nostr(domain):
        row = store.get_version(domain, version)
        if row is None and parsed_canon:
            base_dom, pub_prefix = parsed_canon
            base_pub = (store.domains.get(base_dom, {}).get("pubkey_hex") or "").lower()
            if base_pub.startswith(pub_prefix):
                base_row = store.get_version(base_dom, version)
                if base_row is not None:
                    storage_domain = base_dom
                    row = base_row
    if row is None:
        raise HTTPException(status_code=404, detail=f"{domain} not found in .xnd registry")

    content = store.get_blob(row.get("sha256", ""))
    if content is None:
        raise HTTPException(status_code=404, detail="Blob pruned locally and unavailable from peers")

    dom = store.domains.get(storage_domain, {})
    pub_hex = row.get("pubkey_hex") or dom.get("pubkey_hex", "")
    sig_hex = row.get("signature_hex", "")
    sha = row.get("sha256", "")
    ver_num = int(row.get("version_num", 1))
    prev_sha = str(row.get("prev_sha256", ""))
    sig_ok = verify_signature(pub_hex, storage_domain, ver_num, sha, sig_hex, prev_sha)
    if not sig_ok and parsed_canon:
        sig_ok = verify_signature(pub_hex, parsed_canon[0], ver_num, sha, sig_hex, prev_sha)
    kind = row.get("kind") or ("capsule" if row.get("is_app") else "document")
    if kind != "capsule" and _is_capsule_blob(content):
        kind = "capsule"

    is_encrypted = kind == "document" and e2ee_spaces.is_encrypted_blob(content)
    is_decrypted = not is_encrypted
    allowed_pubkeys: list[str] = []
    display_content = content
    if is_encrypted:
        candidates: list[str] = []
        if dom.get("privkey_hex"):
            candidates.append(dom["privkey_hex"])
        for d_info in store.domains.values():
            if d_info.get("privkey_hex"):
                candidates.append(d_info["privkey_hex"])
        for acc in _vault_accounts.values():
            if acc.get("privkey_hex"):
                candidates.append(acc["privkey_hex"])
        ok_dec, plain_txt, allowed_pubkeys = e2ee_spaces.decrypt_with_privkeys(content, candidates)
        is_decrypted = ok_dec
        display_content = plain_txt if ok_dec else "🔒 End-to-End Encrypted Private .xnd Space.\n\nOnly invited Ed25519 keyholders can decrypt this document. Relays and unauthorized peers only see ciphertext."

    segments = [] if kind == "capsule" else build_segments(display_content)
    versions_list = [
        {
            "version_num": int(v.get("version_num", 1)),
            "sha256": v.get("sha256", ""),
            "title": v.get("title", domain),
            "kind": v.get("kind") or ("capsule" if v.get("is_app") else "document"),
            "created_at": v.get("created_at", 0.0),
        }
        for v in store.versions.get(domain, [])
    ]

    m_src = re.match(r"^Archived from:\s*(https?://\S+)", content[:300], re.IGNORECASE)
    capsule_files: list[str] = []
    has_backend = False
    connect_origins: list[str] = []
    if kind == "capsule":
        try:
            _b = json.loads(content)
            capsule_files = sorted(list(_b.get("files", {}).keys()))
            has_backend = bool(str(_b.get("backend_py", "")).strip())
            connect_origins = _sanitize_connect_origins(_b.get("connect_origins"))
        except Exception:
            pass
    base_for_trust = parsed_canon[0] if parsed_canon else domain
    if pub_hex and not parsed_canon:
        trust_store.ensure_first_seen(domain, pub_hex, "self" if dom.get("privkey_hex") else "first_seen")
    pinned_pub = trust_store.get_pinned_pubkey(base_for_trust)
    if parsed_canon:
        trust_status = "canonical"
    elif dom.get("privkey_hex"):
        trust_status = "self_owned"
    elif pinned_pub and pub_hex and pinned_pub != pub_hex.lower():
        trust_status = "conflict"
    elif pinned_pub and pub_hex and pinned_pub == pub_hex.lower():
        trust_status = "pinned"
    else:
        trust_status = "first_seen"

    return {
        "domain": domain,
        "title": row.get("title", domain),
        "kind": kind,
        "version": ver_num,
        "sha256": sha,
        "pubkey": pub_hex,
        "key_fingerprint": _format_fingerprint(pub_hex),
        "canonical_domain": _canonical_domain_for(base_for_trust, pub_hex) if pub_hex else domain,
        "pinned_pubkey": pinned_pub,
        "trust_status": trust_status,
        "petname": trust_store.get_petname(domain, pub_hex),
        "conflicts": trust_store.get_conflicts(base_for_trust),
        "signature": sig_hex,
        "verified": sig_ok,
        "owned_locally": bool(dom.get("privkey_hex")),
        "source_url": m_src.group(1) if m_src else "",
        "raw_content": display_content if kind == "document" else "",
        "encrypted": is_encrypted,
        "decrypted": is_decrypted,
        "allowed_pubkeys": allowed_pubkeys,
        "files": capsule_files,
        "has_backend": has_backend,
        "connect_origins": connect_origins,
        "segments": segments,
        "versions": versions_list,
        "backlinks": store.links_by_target.get(storage_domain, []),
        "rust_core_active": RUST_CORE_BIN.exists(),
    }


@app.get("/api/trust/pins")
def get_trust_pins() -> dict[str, Any]:
    return {
        "ok": True,
        "pins": trust_store.pins,
        "petnames": trust_store.petnames,
        "conflicts": trust_store.conflicts,
    }


@app.post("/api/trust/pin")
async def pin_domain_key(request: Request) -> dict[str, Any]:
    body = await request.json()
    dom = str(body.get("domain") or "").strip().lower()
    pub = str(body.get("pubkey_hex") or "").strip().lower()
    pet = str(body.get("petname") or "").strip()
    if not DOMAIN_RE.match(dom) or not re.match(r"^[0-9a-f]{64}$", pub):
        raise HTTPException(status_code=400, detail="Valid .xnd domain and 64-char hex pubkey_hex are required")
    trust_store.set_pin(dom, pub, source="manual")
    if pet:
        trust_store.set_petname(dom, pet)
    return {
        "ok": True,
        "domain": dom,
        "pubkey_hex": pub,
        "key_fingerprint": _format_fingerprint(pub),
        "canonical_domain": _canonical_domain_for(dom, pub),
    }


@app.post("/api/trust/petname")
async def set_domain_petname(request: Request) -> dict[str, Any]:
    body = await request.json()
    key = str(body.get("key") or body.get("domain") or "").strip().lower()
    pet = str(body.get("petname") or "").strip()
    if not key:
        raise HTTPException(status_code=400, detail="key or domain is required")
    trust_store.set_petname(key, pet)
    return {"ok": True, "key": key, "petname": pet}


@app.get("/api/moderation/blocklist/export")
def export_signed_blocklist() -> dict[str, Any]:
    _, agent_priv = _get_or_create_ai_agent_key()
    all_doms = list(set(store.blocked_domains) | blocklist_mgr.blocked_domains)
    all_pubs = list(set(store.blocked_pubkeys) | blocklist_mgr.blocked_pubkeys)
    return abuse_guard.sign_blocklist(agent_priv, all_doms, all_pubs)


@app.post("/api/moderation/blocklist/import")
async def import_signed_blocklist(request: Request) -> dict[str, Any]:
    body = await request.json()
    req_trusted = bool(body.get("require_trusted_issuer", False))
    res = blocklist_mgr.import_signed(body, require_trusted_issuer=req_trusted)
    if not res.get("ok"):
        raise HTTPException(status_code=403, detail=res.get("error", "Invalid blocklist"))
    for d in blocklist_mgr.blocked_domains:
        store.blocked_domains.add(d)
    for p in blocklist_mgr.blocked_pubkeys:
        store.blocked_pubkeys.add(p)
    return res


def _get_public_gateway_url() -> str:
    cfg_path = DATA_DIR / "state" / "public_gateway.json"
    try:
        if cfg_path.exists():
            u = str(json.loads(cfg_path.read_text(encoding="utf-8")).get("url") or "").strip().rstrip("/")
            if u:
                return u
    except Exception:
        pass
    default_gw = f"http://127.0.0.1:{os.environ.get('XND_PORT', '8765')}"
    return os.environ.get("XND_PUBLIC_GATEWAY_URL", default_gw).strip().rstrip("/")


@app.get("/site/{domain}")
@app.get("/site/{domain}/{asset_path:path}")
def serve_public_site_share(domain: str, request: Request, asset_path: str = "index.html") -> Response:
    doc = resolve_domain(domain, version=None)
    clean_dom = doc["domain"]
    if doc.get("kind") == "capsule":
        rel = (asset_path or "index.html").lstrip("/") or "index.html"
        return RedirectResponse(url=f"/xnd-app/{urllib.parse.quote(clean_dom)}/{rel}", status_code=307)
    segs = doc.get("segments") or []
    parts: list[str] = []
    for seg in segs:
        if seg.get("type") == "text":
            parts.append(html.escape(seg.get("text", "")))
        elif seg.get("type") == "transclusion":
            q_txt = html.escape(seg.get("quoted_text", ""))
            t_dom = html.escape(seg.get("target_domain", ""))
            parts.append(f'<blockquote style="margin:10px 0;padding:10px 14px;border-left:3px solid #2563eb;background:#f8fafc;border-radius:6px;"><div style="font-size:11px;color:#64748b;margin-bottom:4px;">xnd://{t_dom}</div>{q_txt}</blockquote>')
        elif seg.get("type") == "broken_transclusion":
            parts.append(f'<code>{html.escape(seg.get("raw", ""))}</code>')
    body_html = "".join(parts) if parts else html.escape(doc.get("raw_content", ""))
    title = html.escape(str(doc.get("title") or clean_dom))
    page = (
        f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{title} — xnd://{html.escape(clean_dom)}</title>"
        "<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:760px;margin:48px auto;padding:0 20px;line-height:1.7;color:#0f172a;background:#fff;}"
        ".meta{font-family:ui-monospace,monospace;font-size:12px;color:#64748b;margin-bottom:8px;}"
        "h1{margin:0 0 18px;font-size:28px;}article{white-space:pre-wrap;font-size:16px;}</style></head>"
        f"<body><div class='meta'>xnd://{html.escape(clean_dom)} · v{int(doc.get('version', 1))}</div>"
        f"<h1>{title}</h1><article>{body_html}</article></body></html>"
    )
    return HTMLResponse(content=page)


@app.get("/api/config/public-gateway")
def get_public_gateway_config() -> dict[str, Any]:
    return {"ok": True, "url": _get_public_gateway_url()}


@app.post("/api/config/public-gateway")
async def set_public_gateway_config(request: Request) -> dict[str, Any]:
    body = await request.json()
    url = str(body.get("url") or "").strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Public gateway URL must start with http:// or https://")
    cfg_path = DATA_DIR / "state" / "public_gateway.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps({"url": url}, indent=2), encoding="utf-8")
    return {"ok": True, "url": url}


@app.post("/api/ai/cite")
async def ai_cite(request: Request) -> dict[str, Any]:
    body = await request.json()
    query = str(body.get("query") or "").strip()
    if not query:
        raise HTTPException(status_code=400, detail="query is required")
    dom_filter = str(body.get("domain") or "").strip().lower()
    use_llm = bool(body.get("use_llm", True))
    model = str(body.get("model") or "").strip()
    max_spans = max(1, min(10, int(body.get("max_spans") or 5)))

    citations = await asyncio.to_thread(
        ai_citations.retrieve_verified_spans,
        query,
        store,
        verify_signature,
        rust_sha256,
        pattern_mem,
        dom_filter,
        max_spans,
    )
    return await asyncio.to_thread(
        ai_citations.synthesize_cited_answer,
        query,
        citations,
        use_llm,
        model,
    )


@app.post("/api/ai/publish_note")
async def ai_publish_note(request: Request) -> dict[str, Any]:
    body = await request.json()
    query = str(body.get("query") or "").strip()
    target_domain = normalize_xnd_domain(str(body.get("target_domain") or ""))
    if not query or not DOMAIN_RE.match(target_domain):
        raise HTTPException(status_code=400, detail="query and valid target_domain (.xnd) are required")
    use_llm = bool(body.get("use_llm", True))
    model = str(body.get("model") or "").strip()
    title = str(body.get("title") or f"AI Research Note: {query[:64]}").strip()

    citations = await asyncio.to_thread(
        ai_citations.retrieve_verified_spans,
        query,
        store,
        verify_signature,
        rust_sha256,
        pattern_mem,
        "",
        5,
    )
    synth = await asyncio.to_thread(
        ai_citations.synthesize_cited_answer,
        query,
        citations,
        use_llm,
        model,
    )
    pub_res = publish_document(target_domain, title, synth["answer_markdown"], pinned=True)
    return {**synth, "published": pub_res}


def _get_or_create_ai_agent_key() -> tuple[str, str]:
    key_path = DATA_DIR / "state" / "ai_agent_key.json"
    try:
        if key_path.exists():
            data = json.loads(key_path.read_text(encoding="utf-8"))
            pub = str(data.get("pubkey_hex") or "")
            priv = str(data.get("privkey_hex") or "")
            if len(pub) == 64 and len(priv) == 64:
                return pub, priv
    except Exception:
        pass
    pub, priv = generate_keypair()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(json.dumps({"pubkey_hex": pub, "privkey_hex": priv}, indent=2), encoding="utf-8")
    return pub, priv


_MCP_TOOLS = [
    {
        "name": "xnd_search",
        "description": "Instant local + mesh search across .xnd documents with verified citation spans.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "limit": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
    },
    {
        "name": "xnd_resolve",
        "description": "Resolve and verify a .xnd domain document, returning content, signature status, trust status, and backlinks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "version": {"type": "integer"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "xnd_slice_span",
        "description": "Slice an exact verified character span [start, end) from a .xnd document and return its transclusion pointer.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "start": {"type": "integer", "minimum": 0},
                "end": {"type": "integer", "minimum": 0},
                "version": {"type": "integer"},
            },
            "required": ["domain", "start", "end"],
        },
    },
    {
        "name": "xnd_publish",
        "description": "Publish a .xnd note or report signed by the node's dedicated AI agent Ed25519 key.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "content": {"type": "string"},
                "title": {"type": "string"},
            },
            "required": ["domain", "content"],
        },
    },
    {
        "name": "xnd_trust_status",
        "description": "Check first-seen key pinning, petname, key fingerprint, and conflicts for a .xnd domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
            },
            "required": ["domain"],
        },
    },
]


def _dispatch_mcp_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "xnd_search":
        q = str(args.get("query") or "").strip()
        if not q:
            raise HTTPException(status_code=400, detail="query is required")
        limit = max(1, min(30, int(args.get("limit") or 10)))
        hits = store.search_ram(q)[:limit]
        spans = ai_citations.retrieve_verified_spans(q, store, verify_signature, rust_sha256, pattern_mem, "", min(5, limit))
        return {"query": q, "results": hits, "verified_spans": spans}

    if name == "xnd_resolve":
        dom = normalize_xnd_domain(str(args.get("domain") or ""))
        ver = int(args["version"]) if args.get("version") is not None else None
        return resolve_domain(dom, ver)

    if name == "xnd_slice_span":
        dom = normalize_xnd_domain(str(args.get("domain") or ""))
        ver = int(args["version"]) if args.get("version") is not None else None
        doc = resolve_domain(dom, ver)
        if doc.get("kind") != "document":
            raise HTTPException(status_code=400, detail="xnd_slice_span only supports document .xnd domains")
        raw = doc.get("raw_content", "")
        s = max(0, int(args.get("start") or 0))
        e = min(len(raw), int(args.get("end") or 0))
        if e < s:
            raise HTTPException(status_code=400, detail="end must be >= start")
        ptr = transclusion_engine.format_span_pointer(dom, int(doc["version"]), str(doc.get("sha256") or ""), s, e)
        return {
            "domain": dom,
            "version": doc["version"],
            "sha256": doc["sha256"],
            "verified": doc["verified"],
            "start": s,
            "end": e,
            "pointer": ptr,
            "text": raw[s:e],
        }

    if name == "xnd_publish":
        dom = normalize_xnd_domain(str(args.get("domain") or ""))
        content = str(args.get("content") or "")
        title = str(args.get("title") or dom).strip()
        if not DOMAIN_RE.match(dom) or not content.strip():
            raise HTTPException(status_code=400, detail="Valid .xnd domain and non-empty content are required")
        agent_pub, agent_priv = _get_or_create_ai_agent_key()
        res = publish_document(dom, title, content, pinned=True, privkey_hex=agent_priv)
        if not trust_store.get_petname(dom, agent_pub):
            trust_store.set_petname(dom, "AI Agent")
        return {**res, "agent_pubkey_hex": agent_pub, "agent_fingerprint": _format_fingerprint(agent_pub)}

    if name == "xnd_trust_status":
        dom = normalize_xnd_domain(str(args.get("domain") or ""))
        if not DOMAIN_RE.match(dom):
            raise HTTPException(status_code=400, detail="Valid .xnd domain is required")
        parsed = _parse_canonical_domain(dom)
        base = parsed[0] if parsed else dom
        local_pub = (store.domains.get(dom, {}).get("pubkey_hex") or "").lower()
        pinned_pub = trust_store.get_pinned_pubkey(base)
        return {
            "domain": dom,
            "base_domain": base,
            "pinned_pubkey": pinned_pub,
            "local_pubkey": local_pub,
            "key_fingerprint": _format_fingerprint(pinned_pub or local_pub),
            "petname": trust_store.get_petname(dom, pinned_pub or local_pub),
            "conflicts": trust_store.get_conflicts(base),
            "blocked": dom in store.blocked_domains or (bool(local_pub) and local_pub in store.blocked_pubkeys),
        }

    raise HTTPException(status_code=404, detail=f"Unknown tool: {name}")


@app.get("/api/ai/tools")
def list_ai_tools() -> dict[str, Any]:
    agent_pub, _ = _get_or_create_ai_agent_key()
    return {
        "ok": True,
        "protocol": "mcp-jsonrpc-2.0",
        "agent_pubkey_hex": agent_pub,
        "agent_fingerprint": _format_fingerprint(agent_pub),
        "tools": _MCP_TOOLS,
    }


@app.post("/api/ai/tools")
async def call_ai_tools(request: Request) -> dict[str, Any]:
    body = await request.json()
    rpc_id = body.get("id")
    method = str(body.get("method") or "").strip()
    params = body.get("params") if isinstance(body.get("params"), dict) else {}

    # Convenience direct call: {"tool": "xnd_search", "arguments": {...}}
    if not method and body.get("tool"):
        method = "tools/call"
        params = {"name": body.get("tool"), "arguments": body.get("arguments") or {}}

    try:
        if method == "initialize":
            result: Any = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "xanadu-xnd-hub", "version": "1.0.0"},
            }
        elif method == "tools/list":
            result = {"tools": _MCP_TOOLS}
        elif method == "tools/call":
            t_name = str(params.get("name") or "").strip()
            t_args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            out = await asyncio.to_thread(_dispatch_mcp_tool, t_name, t_args)
            result = {
                "content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}],
                "structuredContent": out,
                "isError": False,
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        return {"jsonrpc": "2.0", "id": rpc_id, "result": result}
    except HTTPException as exc:
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {"code": -32000, "message": str(exc.detail)},
        }


def _serve_capsule_file(domain: str, file_path: str, version: int | None) -> Response:
    domain = domain.strip().lower()
    row = store.get_version(domain, version)
    if row is None:
        raise HTTPException(status_code=404, detail="Site/Capsule not found")
    raw = store.get_blob(row["sha256"])
    if raw is None:
        raise HTTPException(status_code=404, detail="Site/Capsule blob missing")
    if row.get("kind") != "capsule" and not _is_capsule_blob(raw):
        raise HTTPException(status_code=404, detail="Site/Capsule not found")
    bundle = json.loads(raw)
    files: dict[str, str] = bundle.get("files", {})
    rel = re.sub(r"/+", "/", (file_path or "index.html").lstrip("/"))
    while rel.startswith("./"):
        rel = rel[2:]
    if not rel:
        rel = "index.html"
    if rel not in files:
        if f"{rel.rstrip('/')}/index.html" in files:
            rel = f"{rel.rstrip('/')}/index.html"
        elif f"{rel.rstrip('/')}.html" in files:
            rel = f"{rel.rstrip('/')}.html"
        else:
            lower_map = {k.lower(): k for k in files}
            if rel.lower() in lower_map:
                rel = lower_map[rel.lower()]
            elif f"{rel.rstrip('/').lower()}/index.html" in lower_map:
                rel = lower_map[f"{rel.rstrip('/').lower()}/index.html"]
            elif f"{rel.rstrip('/').lower()}.html" in lower_map:
                rel = lower_map[f"{rel.rstrip('/').lower()}.html"]
            elif "." not in rel.rsplit("/", 1)[-1] and "index.html" in files:
                rel = "index.html"
    if rel not in files:
        raise HTTPException(status_code=404, detail=f"File '{rel}' not found in {domain}")

    val = files[rel]
    if isinstance(val, str) and val.startswith("data:") and ";base64," in val[:128]:
        hdr, b64 = val.split(";base64,", 1)
        mime = hdr[5:] or "application/octet-stream"
        return Response(content=base64.b64decode(b64), media_type=mime)

    mime, _ = mimetypes.guess_type(rel)
    if not mime:
        mime = "text/html" if rel.endswith((".html", ".htm")) else "text/plain"
    app_prefix = f"/xnd-app/{urllib.parse.quote(domain)}/"
    if mime == "text/html" and isinstance(val, str):
        val = re.sub(
            r'(?i)\b(href|src|action|poster|data-src)\s*=\s*(["\'])\/(?!\/|xnd-app\/|static\/|api\/)([^"\']*)\2',
            lambda m: f'{m.group(1)}={m.group(2)}{app_prefix}{m.group(3)}{m.group(2)}',
            val,
        )
        val = re.sub(
            r'(?i)\bsrcset\s*=\s*(["\'])([^"\']+)\1',
            lambda m: f'srcset={m.group(1)}' + re.sub(r'(^|,\s*)\/(?!\/|xnd-app\/|static\/|api\/)', rf'\1{app_prefix}', m.group(2)) + m.group(1),
            val,
        )
        cap_token = _mint_capsule_token(domain)
        shim = (
            f"<script>(function(){{var p={json.dumps(app_prefix)},tok={json.dumps(cap_token)};"
            "function rw(u){if(typeof u!=='string'||!u.startsWith('/')||u.startsWith('//')||u.startsWith('/xnd-app/')||u.startsWith('/static/'))return u;if(u.startsWith('/api/')){if(u.startsWith('/api/sdk/')||u.startsWith('/api/app/')||u.startsWith('/api/search')||u.startsWith('/api/peers')||u.startsWith('/api/lan/'))return u;return p+u.slice(1);}return p+u.slice(1);}"
            "function needsTok(u){return typeof u==='string'&&(u.indexOf('/api/app/')!==-1||u.indexOf('/api/sdk/')!==-1||u.indexOf('/api/')!==-1&&u.indexOf('/xnd-app/')!==-1);}"
            "var _f=window.fetch;if(_f){window.fetch=function(i,o){var u=(typeof i==='string')?rw(i):i;var us=(typeof u==='string')?u:(u&&u.url?u.url:'');if(needsTok(us)){o=Object.assign({},o||{});var h=new Headers(o.headers||(typeof i!=='string'&&i&&i.headers)||{});if(!h.has('X-Xnd-Cap-Token'))h.set('X-Xnd-Cap-Token',tok);o.headers=h;}return _f.call(this,u,o);};}"
            "var _o=XMLHttpRequest.prototype.open,_s=XMLHttpRequest.prototype.send;"
            "XMLHttpRequest.prototype.open=function(m,u){var ru=rw(u);this._xndUrl=ru;arguments[1]=ru;return _o.apply(this,arguments);};"
            "XMLHttpRequest.prototype.send=function(){try{if(needsTok(this._xndUrl))this.setRequestHeader('X-Xnd-Cap-Token',tok);}catch(e){}return _s.apply(this,arguments);};"
            "document.addEventListener('click',function(e){var a=e.target&&e.target.closest?e.target.closest('a[href]'):null;if(!a)return;var h=a.getAttribute('href');if(h&&h.startsWith('/')&&!h.startsWith('//')&&!h.startsWith('/xnd-app/')&&!h.startsWith('/api/')&&!h.startsWith('/static/')){a.setAttribute('href',rw(h));}},true);"
            "})();</script>"
        )
        sdk_tag = f'<script src="/static/xnd-sdk.js" data-domain="{html.escape(domain)}" data-cap-token="{html.escape(cap_token)}"></script>'
        base_tag = f'<base href="{app_prefix}">' if "<base " not in val.lower() else ""
        inject = f"{base_tag}{shim}{sdk_tag}"
        if re.search(r"(?i)<head\b[^>]*>", val):
            val = re.sub(r"(?i)(<head\b[^>]*>)", lambda m: m.group(1) + inject, val, count=1)
        else:
            val = inject + val
    if mime == "text/css" and isinstance(val, str):
        val = re.sub(
            r'url\(\s*(["\']?)\/(?!\/|xnd-app\/|static\/|api\/)([^"\')]+)\1\s*\)',
            lambda m: f"url({m.group(1)}{app_prefix}{m.group(2)}{m.group(1)})",
            val,
        )
        val = re.sub(
            r'@import\s+(["\'])\/(?!\/|xnd-app\/|static\/|api\/)([^"\']+)\1',
            lambda m: f'@import {m.group(1)}{app_prefix}{m.group(2)}{m.group(1)}',
            val,
        )
    resp_headers = {
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    if mime == "text/html":
        extra_connect = ""
        raw_origins = _sanitize_connect_origins(bundle.get("connect_origins"))
        if raw_origins:
            dom_pub = str(row.get("pubkey_hex") or store.domains.get(domain, {}).get("pubkey_hex") or "")
            sig_valid = verify_signature(
                dom_pub,
                domain,
                int(row.get("version_num", 1)),
                str(row.get("sha256", "")),
                str(row.get("signature_hex", "")),
                str(row.get("prev_sha256", "")),
            )
            if sig_valid:
                extra_connect = " " + " ".join(raw_origins)
        resp_headers["Content-Security-Policy"] = (
            "sandbox allow-scripts allow-forms allow-modals; "
            "default-src 'self' data: blob:; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob: https:; "
            "font-src 'self' data:; "
            f"connect-src 'self' data: blob:{extra_connect}; "
            "frame-ancestors 'self'; "
            "base-uri 'self';"
        )
    else:
        resp_headers["Content-Security-Policy"] = "sandbox; default-src 'self' data: blob:; style-src 'self' 'unsafe-inline';"
    return Response(content=val, media_type=mime, headers=resp_headers)


@app.get("/api/repo/{domain}/file")
def get_repo_file(domain: str, path: str = Query(default="index.html"), version: int | None = Query(default=None)) -> dict[str, Any]:
    domain = domain.strip().lower()
    row = store.get_version(domain, version)
    if row is None:
        raise HTTPException(status_code=404, detail="Domain not found")
    raw = store.get_blob(row["sha256"])
    if raw is None:
        raise HTTPException(status_code=404, detail="Blob missing")
    kind = row.get("kind") or "document"
    if kind != "capsule":
        return {"domain": domain, "path": "content.txt", "content": raw, "is_binary": False}
    bundle = json.loads(raw)
    if path == "backend.py":
        return {"domain": domain, "path": "backend.py", "content": bundle.get("backend_py", ""), "is_binary": False}
    files = bundle.get("files", {})
    if path not in files:
        raise HTTPException(status_code=404, detail=f"File '{path}' not found")
    val = files[path]
    is_bin = isinstance(val, str) and val.startswith("data:") and ";base64," in val[:128]
    return {"domain": domain, "path": path, "content": val if not is_bin else "(binary asset)", "is_binary": is_bin}


@app.get("/xnd-app/{domain}")
def serve_capsule_index(domain: str, version: int | None = Query(default=None)) -> Response:
    return _serve_capsule_file(domain, "index.html", version)


@app.api_route("/xnd-app/{domain}/api/{api_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def rest_capsule_api(domain: str, api_path: str, request: Request) -> Response:
    dom = domain.strip().lower()
    _require_capsule_token(request, dom)
    raw_body = await request.body()
    payload: Any = {}
    if raw_body:
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception:
            payload = {"raw": raw_body.decode("utf-8", errors="replace")}
    row = store.get_version(dom, None)
    if row is None or row["kind"] != "capsule":
        raise HTTPException(status_code=404, detail="Capsule not found")
    raw = store.get_blob(row["sha256"])
    if raw is None:
        raise HTTPException(status_code=404, detail="Capsule blob missing")
    bundle = json.loads(raw)
    state = store.get_capsule_state(dom)
    clean_api = "/api/" + api_path.lstrip("/")
    resp, new_state = run_capsule_backend(
        bundle.get("backend_py", ""),
        api_path.lstrip("/"),
        payload if isinstance(payload, dict) else {"data": payload},
        state,
        domain=dom,
        method=request.method,
        req_path=clean_api,
        req_headers={k.lower(): v for k, v in request.headers.items()},
    )
    store.save_capsule_state(dom, new_state)
    if isinstance(resp, dict) and "status" in resp and "body" in resp:
        return Response(content=json.dumps(resp["body"]), status_code=int(resp["status"]), media_type="application/json")
    return Response(content=json.dumps(resp), status_code=200, media_type="application/json")


@app.get("/xnd-app/{domain}/{file_path:path}")
def serve_capsule_subpath(domain: str, file_path: str, version: int | None = Query(default=None)) -> Response:
    return _serve_capsule_file(domain, file_path, version)


@app.post("/api/app/{domain}/{action}")
async def call_capsule_backend(domain: str, action: str, request: Request) -> dict[str, Any]:
    domain = domain.strip().lower()
    _require_capsule_token(request, domain)
    body = await request.body()
    payload = json.loads(body.decode("utf-8")) if body else {}
    row = store.get_version(domain, None)
    if row is None or row["kind"] != "capsule":
        raise HTTPException(status_code=404, detail="Capsule not found")
    raw = store.get_blob(row["sha256"])
    if raw is None:
        raise HTTPException(status_code=404, detail="Capsule blob missing")
    bundle = json.loads(raw)
    state = store.get_capsule_state(domain)
    crdt_posts = crdt_log.materialize_collection(domain, "posts")
    if crdt_posts:
        existing_posts = list(state.get("posts") or [])
        seen_ids = {json.dumps(p, sort_keys=True, separators=(",", ":")) for p in existing_posts}
        for cp in crdt_posts:
            fp = json.dumps(cp, sort_keys=True, separators=(",", ":"))
            if fp not in seen_ids:
                seen_ids.add(fp)
                existing_posts.append(cp)
        state["posts"] = existing_posts
    prev_posts_len = len(state.get("posts") or []) if isinstance(state.get("posts"), list) else 0
    resp, new_state = run_capsule_backend(bundle.get("backend_py", ""), action, payload, state, domain=domain)
    if isinstance(new_state.get("posts"), list) and len(new_state["posts"]) > prev_posts_len:
        _, priv_hex = _get_or_create_sdk_signing_key(domain)
        for item in new_state["posts"][prev_posts_len:]:
            crdt_log.append_signed_event(
                crdt_sync.create_signed_event(domain, "append", "posts", "", item, priv_hex)
            )
    store.save_capsule_state(domain, new_state)
    return resp


@app.get("/api/sdk/store")
def sdk_store_get(request: Request, domain: str = Query(default=""), key: str = Query(default="")) -> dict[str, Any]:
    dom = domain.strip().lower()
    if not DOMAIN_RE.match(dom):
        raise HTTPException(status_code=400, detail="Invalid .xnd domain")
    _require_capsule_token(request, dom)
    st = store.get_capsule_state(dom)
    kv = dict(st.get("sdk_kv")) if isinstance(st.get("sdk_kv"), dict) else {}
    kv.update(crdt_log.materialize_kv(dom))
    if key:
        return {"ok": True, "domain": dom, "key": key, "value": kv.get(key)}
    return {"ok": True, "domain": dom, "state": kv}


@app.post("/api/sdk/store")
async def sdk_store_set(request: Request) -> dict[str, Any]:
    body = await request.json()
    dom = str(body.get("domain") or "").strip().lower()
    key = str(body.get("key") or "").strip()
    if not DOMAIN_RE.match(dom) or not key:
        raise HTTPException(status_code=400, detail="domain and key are required")
    _require_capsule_token(request, dom)
    st = store.get_capsule_state(dom)
    kv = dict(st.get("sdk_kv")) if isinstance(st.get("sdk_kv"), dict) else {}
    _, priv_hex = _get_or_create_sdk_signing_key(dom)
    if body.get("delete"):
        kv.pop(key, None)
        crdt_log.append_signed_event(crdt_sync.create_signed_event(dom, "kv_del", "sdk_kv", key, None, priv_hex))
    else:
        val = body.get("value")
        kv[key] = val
        crdt_log.append_signed_event(crdt_sync.create_signed_event(dom, "kv_set", "sdk_kv", key, val, priv_hex))
    st["sdk_kv"] = kv
    store.save_capsule_state(dom, st)
    return {"ok": True, "domain": dom, "key": key}


@app.get("/api/crdt/events")
def get_crdt_events(domain: str = Query(default=""), since: float = Query(default=0.0)) -> dict[str, Any]:
    evts = crdt_log.export_events(domain, since)
    return {"ok": True, "count": len(evts), "events": evts}


@app.post("/api/crdt/merge")
async def merge_crdt_events(request: Request) -> dict[str, Any]:
    body = await request.json()
    events = body.get("events") if isinstance(body.get("events"), list) else []
    res = crdt_log.merge_events(events)
    return {"ok": True, **res}


@app.post("/api/sdk/db")
async def sdk_db_query(request: Request) -> dict[str, Any]:
    body = await request.json()
    dom = str(body.get("domain") or "").strip().lower()
    sql = str(body.get("sql") or "")
    params = body.get("params")
    if not DOMAIN_RE.match(dom):
        raise HTTPException(status_code=400, detail="Invalid .xnd domain")
    _require_capsule_token(request, dom)
    try:
        return capsule_runtime.db_query(DATA_DIR / "state", dom, sql, params)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"SQLite error: {exc}")


@app.post("/api/sdk/auth/challenge")
async def sdk_auth_challenge(request: Request) -> dict[str, Any]:
    body = await request.json()
    dom = str(body.get("domain") or "").strip().lower()
    if not DOMAIN_RE.match(dom):
        raise HTTPException(status_code=400, detail="Invalid .xnd domain")
    _require_capsule_token(request, dom)
    return capsule_runtime.create_auth_challenge(dom)


@app.post("/api/sdk/auth/verify")
async def sdk_auth_verify(request: Request) -> dict[str, Any]:
    body = await request.json()
    dom = str(body.get("domain") or "").strip().lower()
    if not DOMAIN_RE.match(dom):
        raise HTTPException(status_code=400, detail="Invalid .xnd domain")
    _require_capsule_token(request, dom)
    res = capsule_runtime.verify_auth_challenge(
        dom,
        str(body.get("nonce") or ""),
        str(body.get("pubkey_hex") or ""),
        str(body.get("signature_hex") or ""),
    )
    if not res.get("ok"):
        raise HTTPException(status_code=403, detail=res.get("error", "Auth failed"))
    return res


@app.post("/api/sdk/auth/session")
async def sdk_auth_session(request: Request) -> dict[str, Any]:
    body = await request.json()
    dom = str(body.get("domain") or "").strip().lower()
    if not DOMAIN_RE.match(dom):
        raise HTTPException(status_code=400, detail="Invalid .xnd domain")
    _require_capsule_token(request, dom)
    return capsule_runtime.verify_session_token(dom, str(body.get("token") or ""))


@app.get("/api/secrets/{domain}")
def list_capsule_secrets_api(domain: str, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    dom = normalize_xnd_domain(domain, append_tld=True)
    if not DOMAIN_RE.match(dom):
        raise HTTPException(status_code=400, detail="Invalid .xnd domain")
    keys = sorted(capsule_runtime.load_capsule_secrets(DATA_DIR / "state", dom).keys())
    return {"ok": True, "domain": dom, "keys": keys}


@app.post("/api/secrets/{domain}")
async def set_capsule_secret_api(domain: str, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    dom = normalize_xnd_domain(domain, append_tld=True)
    if not DOMAIN_RE.match(dom):
        raise HTTPException(status_code=400, detail="Invalid .xnd domain")
    body = await request.json()
    key = str(body.get("key") or "").strip()
    if body.get("delete"):
        keys = capsule_runtime.delete_capsule_secret(DATA_DIR / "state", dom, key)
        return {"ok": True, "domain": dom, "keys": keys}
    val = str(body.get("value") or "")
    try:
        keys = capsule_runtime.set_capsule_secret(DATA_DIR / "state", dom, key, val)
        return {"ok": True, "domain": dom, "keys": keys}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _get_or_create_sdk_signing_key(dom: str) -> tuple[str, str]:
    d_info = store.domains.get(dom, {})
    priv = d_info.get("privkey_hex", "")
    pub = d_info.get("pubkey_hex", "")
    if priv:
        if not pub:
            pub = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv)).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ).hex()
        return pub, priv
    # Local node signing key for peer-owned capsules (never leaks owner key)
    st = store.get_capsule_state(dom)
    node_priv = str(st.get("_sdk_node_priv") or "")
    node_pub = str(st.get("_sdk_node_pub") or "")
    if not node_priv:
        node_pub, node_priv = generate_keypair()
        st["_sdk_node_pub"] = node_pub
        st["_sdk_node_priv"] = node_priv
        store.save_capsule_state(dom, st)
    return node_pub, node_priv


@app.get("/api/sdk/identity")
def sdk_identity(request: Request, domain: str = Query(default="")) -> dict[str, Any]:
    dom = domain.strip().lower()
    if not DOMAIN_RE.match(dom):
        raise HTTPException(status_code=400, detail="Invalid .xnd domain")
    _require_capsule_token(request, dom)
    pub, _ = _get_or_create_sdk_signing_key(dom)
    return {"ok": True, "domain": dom, "pubkey_hex": pub}


@app.post("/api/sdk/sign")
async def sdk_sign(request: Request) -> dict[str, Any]:
    body = await request.json()
    dom = str(body.get("domain") or "").strip().lower()
    msg = str(body.get("message") or "")
    if not DOMAIN_RE.match(dom):
        raise HTTPException(status_code=400, detail="Invalid .xnd domain")
    _require_capsule_token(request, dom)
    pub, priv = _get_or_create_sdk_signing_key(dom)
    digest = hashlib.sha256(msg.encode("utf-8")).hexdigest()
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv))
    sig_hex = sk.sign(digest.encode("utf-8")).hex()
    return {"ok": True, "domain": dom, "pubkey_hex": pub, "sha256": digest, "signature_hex": sig_hex}


@app.post("/api/sdk/verify")
async def sdk_verify(request: Request) -> dict[str, Any]:
    body = await request.json()
    msg = str(body.get("message") or "")
    pub = str(body.get("pubkey_hex") or "").strip()
    sig = str(body.get("signature_hex") or "").strip()
    digest = hashlib.sha256(msg.encode("utf-8")).hexdigest()
    valid = False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(sig), digest.encode("utf-8"))
        valid = True
    except Exception:
        valid = False
    return {"ok": True, "valid": valid, "sha256": digest}


def _extract_search_core(query: str) -> str:
    q = query.strip()
    lowered = re.sub(
        r"^(what\s+is\s+(?:the\s+)?|what's\s+(?:the\s+)?|whats\s+|what\s+are\s+|who\s+(?:is|was|are|owns|created|made|founded|built|invented)\s+(?:the\s+)?|who's\s+|when\s+(?:was|did|is)\s+(?:the\s+)?|where\s+(?:is|was|are)\s+(?:the\s+)?|why\s+(?:is|does|do|did)\s+|how\s+(?:does|do|to|can\s+i|do\s+i)\s+|difference\s+between\s+|steps\s+to\s+|guide\s+to\s+|define\s+|explain\s+|meaning\s+of\s+|tell\s+me\s+about\s+)",
        "",
        q,
        flags=re.IGNORECASE,
    ).strip(" ?.!\"'")
    return lowered or q


def _safe_math_eval(expr: str) -> float | None:
    import ast
    import math
    import operator

    cleaned = expr.strip().replace("^", "**").replace("×", "*").replace("÷", "/")
    if not cleaned or len(cleaned) > 80 or not re.match(r"^[0-9a-zA-Z_+\-*/%.()\s]+$", cleaned):
        return None
    ops = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
        ast.USub: operator.neg,
        ast.UAdd: operator.pos,
    }
    funcs = {"sqrt": math.sqrt, "abs": abs, "round": round}
    consts = {"pi": math.pi, "e": math.e}

    def _ev(node: ast.AST) -> float:
        if isinstance(node, ast.Expression):
            return _ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return float(node.value)
        if isinstance(node, ast.Name) and node.id.lower() in consts:
            return consts[node.id.lower()]
        if isinstance(node, ast.BinOp) and type(node.op) in ops:
            if isinstance(node.op, ast.Pow):
                b = _ev(node.right)
                if abs(b) > 1000:
                    raise ValueError("exponent too large")
            return float(ops[type(node.op)](_ev(node.left), _ev(node.right)))
        if isinstance(node, ast.UnaryOp) and type(node.op) in ops:
            return float(ops[type(node.op)](_ev(node.operand)))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id.lower() in funcs and len(node.args) == 1:
            return float(funcs[node.func.id.lower()](_ev(node.args[0])))
        raise ValueError("unsupported")

    try:
        tree = ast.parse(cleaned, mode="eval")
        val = _ev(tree)
        if math.isfinite(val):
            return val
    except Exception:
        return None
    return None


def _solve_instant_calc(query: str) -> dict[str, Any] | None:
    q = query.strip()
    ql = q.lower()

    # 1. Percentage: "15% of 4200"
    m_pct = re.match(r"^(\d+(?:\.\d+)?)\s*%\s+of\s+(\d+(?:\.\d+)?)\s*\??$", ql)
    if m_pct:
        pct, base = float(m_pct.group(1)), float(m_pct.group(2))
        ans = (pct / 100.0) * base
        fmt = f"{ans:g}"
        return {
            "domain": "home.xnd",
            "title": f"{m_pct.group(1)}% of {m_pct.group(2)} = {fmt}",
            "subtitle": "Instant Calculator · Deterministic",
            "summary": f"{m_pct.group(1)}% of {m_pct.group(2)} equals {fmt}.",
        }

    # 2. Unit conversion: "100 km to miles", "72 f to c"
    m_unit = re.match(r"^(?:convert\s+)?(-?\d+(?:\.\d+)?)\s*([a-z]+)\s+(?:to|in)\s+([a-z]+)\s*\??$", ql)
    if m_unit:
        val = float(m_unit.group(1))
        u1, u2 = m_unit.group(2), m_unit.group(3)
        aliases = {"mile": "mi", "miles": "mi", "kilometer": "km", "kilometers": "km", "meter": "m", "meters": "m", "foot": "ft", "feet": "ft", "lbs": "lb", "pound": "lb", "pounds": "lb", "kilogram": "kg", "kilograms": "kg", "celsius": "c", "fahrenheit": "f"}
        u1, u2 = aliases.get(u1, u1), aliases.get(u2, u2)
        conv: float | None = None
        if (u1, u2) == ("km", "mi"):
            conv = val * 0.621371
        elif (u1, u2) == ("mi", "km"):
            conv = val * 1.60934
        elif (u1, u2) == ("m", "ft"):
            conv = val * 3.28084
        elif (u1, u2) == ("ft", "m"):
            conv = val * 0.3048
        elif (u1, u2) == ("kg", "lb"):
            conv = val * 2.20462
        elif (u1, u2) == ("lb", "kg"):
            conv = val * 0.453592
        elif (u1, u2) == ("c", "f"):
            conv = (val * 9.0 / 5.0) + 32.0
        elif (u1, u2) == ("f", "c"):
            conv = (val - 32.0) * 5.0 / 9.0
        elif u1 in ("mb", "gb", "tb", "kb") and u2 in ("mb", "gb", "tb", "kb"):
            scale = {"kb": 1, "mb": 1024, "gb": 1024 ** 2, "tb": 1024 ** 3}
            conv = val * scale[u1] / scale[u2]
        if conv is not None:
            out_s = f"{conv:.4f}".rstrip("0").rstrip(".")
            return {
                "domain": "home.xnd",
                "title": f"{val:g} {u1} = {out_s} {u2}",
                "subtitle": "Instant Unit Converter · Deterministic",
                "summary": f"{val:g} {u1} converts to {out_s} {u2}.",
            }

    # 3. Timezone lookup: "time in nairobi"
    m_tz = re.match(r"^(?:what\s+is\s+the\s+)?time\s+in\s+([a-z\s]+?)\s*\??$", ql)
    if m_tz:
        city = m_tz.group(1).strip()
        tz_map = {
            "nairobi": "Africa/Nairobi", "kenya": "Africa/Nairobi", "london": "Europe/London",
            "new york": "America/New_York", "tokyo": "Asia/Tokyo", "paris": "Europe/Paris",
            "dubai": "Asia/Dubai", "lagos": "Africa/Lagos", "cairo": "Africa/Cairo",
            "san francisco": "America/Los_Angeles", "utc": "UTC", "gmt": "UTC",
        }
        tz_name = tz_map.get(city)
        if tz_name:
            try:
                from datetime import datetime
                from zoneinfo import ZoneInfo
                now_tz = datetime.now(ZoneInfo(tz_name))
                return {
                    "domain": "home.xnd",
                    "title": f"Local Time in {city.title()}: {now_tz.strftime('%I:%M %p')}",
                    "subtitle": f"{tz_name} · {now_tz.strftime('%A, %B %d, %Y')}",
                    "summary": f"The current time in {city.title()} ({tz_name}) is {now_tz.strftime('%H:%M (%I:%M %p)')}.",
                }
            except Exception:
                pass

    # 4. Arithmetic expression
    if any(op in q for op in ("+", "-", "*", "/", "^", "%", "sqrt(")):
        expr = re.sub(r"^(?:calculate|compute|eval|what\s+is)\s+", "", q, flags=re.IGNORECASE).rstrip("? ")
        if not re.fullmatch(r"\d+(?:\.\d+)?", expr):
            res = _safe_math_eval(expr)
            if res is not None:
                fmt = str(int(res)) if res.is_integer() else f"{res:.6f}".rstrip("0").rstrip(".")
                return {
                    "domain": "home.xnd",
                    "title": f"{expr} = {fmt}",
                    "subtitle": "Instant Calculator · Deterministic",
                    "summary": f"{expr} evaluates to {fmt}.",
                }
    return None


def _classify_query_intent(query: str) -> tuple[str, str, str, dict[str, Any] | None]:
    q = query.strip()
    ql = q.lower()

    calc = _solve_instant_calc(q)
    if calc is not None:
        return "CALCULATE", "internal", q, calc

    if _is_xanadu_founder_query(q):
        is_pure_self = any(sr in ql for sr in ("this browser", "this app", "this platform", "this web", "this search engine"))
        scope = "internal" if is_pure_self else "hybrid"
        return "SELF", scope, _extract_search_core(q), _founder_knowledge_card(q)

    if ql.endswith(".xnd"):
        return "SELF", "internal", ql, None

    if re.search(r"\b(vs\.?|versus)\b", ql) or ql.startswith("difference between "):
        return "COMPARE", "external", _extract_search_core(q), None
    if re.match(r"^(who\s|who's\s|whose\s)", ql):
        return "WHO", "external", _extract_search_core(q), None
    if re.match(r"^(when\s|what\s+year\s|what\s+date\s)", ql):
        return "WHEN", "external", _extract_search_core(q), None
    if re.match(r"^(where\s|which\s+country\s|which\s+city\s)", ql):
        return "WHERE", "external", _extract_search_core(q), None
    if re.match(r"^(how\s+to\s|how\s+do\s+i\s|how\s+can\s+i\s|steps\s+to\s|guide\s+to\s)", ql):
        return "HOW_TO", "external", _extract_search_core(q), None
    return "WHAT_IS", "external", _extract_search_core(q), None


def _search_internet_web(query: str) -> list[dict[str, Any]]:
    """Fast live internet web search via Bing RSS, DuckDuckGo HTML, and Wikipedia full-text in parallel."""
    q = (query or "").strip()
    if not q:
        return []

    def _bing_rss() -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        try:
            u = "https://www.bing.com/search?format=rss&q=" + urllib.parse.quote(q)
            req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36"})
            with urllib.request.urlopen(req, timeout=5.5) as resp:
                root = ET.fromstring(resp.read(240_000))
            for item in root.findall(".//item")[:10]:
                t = html.unescape(re.sub(r"<[^>]+>", " ", (item.findtext("title") or "").strip()))
                t = re.sub(r"\s+", " ", t).strip()
                link = (item.findtext("link") or "").strip()
                desc = html.unescape(re.sub(r"<[^>]+>", " ", (item.findtext("description") or "").strip()))
                desc = re.sub(r"\s+", " ", desc).strip()
                if t and link.startswith("http"):
                    host = urllib.parse.urlparse(link).netloc.removeprefix("www.")
                    rows.append({
                        "title": t,
                        "category": f"Internet Web · {host}" if host else "Internet Web",
                        "summary": desc or f"Live web result from {host or link}",
                        "url": link,
                    })
        except Exception:
            pass
        return rows

    def _ddg_html() -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        try:
            payload = urllib.parse.urlencode({"q": q}).encode("utf-8")
            req = urllib.request.Request(
                "https://html.duckduckgo.com/html/",
                data=payload,
                headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Referer": "https://html.duckduckgo.com/",
                },
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status != 200:
                    return []
                body = resp.read(160_000).decode("utf-8", errors="ignore")
            links = re.findall(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', body, re.S)
            snips = re.findall(r'class="result__snippet"[^>]*>(.*?)</(?:a|div|span)>', body, re.S)
            for idx, (raw_u, raw_t) in enumerate(links[:10]):
                u = html.unescape(raw_u).strip()
                if "uddg=" in u:
                    parsed = urllib.parse.parse_qs(urllib.parse.urlparse(u).query)
                    if parsed.get("uddg"):
                        u = parsed["uddg"][0]
                if u.startswith("//"):
                    u = "https:" + u
                if not u.startswith("http"):
                    continue
                t = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", raw_t))).strip()
                s = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", snips[idx]))).strip() if idx < len(snips) else ""
                if t:
                    host = urllib.parse.urlparse(u).netloc.removeprefix("www.")
                    rows.append({
                        "title": t,
                        "category": f"Internet Web · {host}" if host else "Internet Web",
                        "summary": s or f"Live web result from {host or u}",
                        "url": u,
                    })
        except Exception:
            pass
        return rows

    def _wiki_search() -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        try:
            u = "https://en.wikipedia.org/w/api.php?action=query&list=search&srlimit=4&format=json&srsearch=" + urllib.parse.quote(q)
            req = urllib.request.Request(u, headers={"User-Agent": "XanaduSmartSearch/0.4"})
            with urllib.request.urlopen(req, timeout=5.5) as resp:
                hits = json.loads(resp.read().decode("utf-8")).get("query", {}).get("search", [])
            for h in hits:
                title = (h.get("title") or "").strip()
                snip = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", h.get("snippet") or ""))).strip()
                if title:
                    wurl = "https://en.wikipedia.org/wiki/" + urllib.parse.quote(title.replace(" ", "_"))
                    rows.append({
                        "title": title,
                        "category": "Live Web · Wikipedia",
                        "summary": snip or f"Wikipedia article on {title}",
                        "url": wurl,
                    })
        except Exception:
            pass
        return rows

    def _google_news_rss() -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        try:
            u = "https://news.google.com/rss/search?hl=en-US&gl=US&ceid=US:en&q=" + urllib.parse.quote(q)
            req = urllib.request.Request(u, headers={"User-Agent": "XanaduSmartSearch/0.4"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                root = ET.fromstring(resp.read(200_000))
            for item in root.findall(".//item")[:5]:
                t = re.sub(r"\s+", " ", html.unescape((item.findtext("title") or "").strip())).strip()
                link = (item.findtext("link") or "").strip()
                src_el = item.find("source")
                src_name = src_el.text.strip() if src_el is not None and src_el.text else "Google News"
                if t and link.startswith("http"):
                    rows.append({
                        "title": t,
                        "category": f"Google News · {src_name}",
                        "summary": f"Live news coverage from {src_name}",
                        "url": link,
                    })
        except Exception:
            pass
        return rows

    def _stackoverflow() -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        try:
            u = "https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=relevance&pagesize=4&site=stackoverflow&q=" + urllib.parse.quote(q)
            req = urllib.request.Request(u, headers={"User-Agent": "XanaduSmartSearch/0.4", "Accept-Encoding": "identity"})
            with urllib.request.urlopen(req, timeout=5.5) as resp:
                items = json.loads(resp.read().decode("utf-8")).get("items", [])
            for it in items:
                title = html.unescape(it.get("title") or "").strip()
                link = (it.get("link") or "").strip()
                tags = ", ".join((it.get("tags") or [])[:3])
                if title and link.startswith("http"):
                    rows.append({
                        "title": title,
                        "category": "StackOverflow · Q&A",
                        "summary": f"Score {it.get('score', 0)} · {it.get('answer_count', 0)} answers" + (f" · [{tags}]" if tags else ""),
                        "url": link,
                    })
        except Exception:
            pass
        return rows

    def _github_repos() -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        try:
            u = "https://api.github.com/search/repositories?per_page=4&q=" + urllib.parse.quote(q)
            req = urllib.request.Request(u, headers={"User-Agent": "XanaduSmartSearch/0.4", "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=5.5) as resp:
                items = json.loads(resp.read().decode("utf-8")).get("items", [])
            for it in items:
                name = (it.get("full_name") or "").strip()
                link = (it.get("html_url") or "").strip()
                desc = (it.get("description") or "").strip()
                stars = it.get("stargazers_count", 0)
                if name and link.startswith("http"):
                    rows.append({
                        "title": name,
                        "category": "GitHub · Repository",
                        "summary": f"{stars} stars" + (f" — {desc}" if desc else ""),
                        "url": link,
                    })
        except Exception:
            pass
        return rows

    def _openalex() -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        try:
            u = "https://api.openalex.org/works?per-page=3&search=" + urllib.parse.quote(q)
            req = urllib.request.Request(u, headers={"User-Agent": "XanaduSmartSearch/0.4"})
            with urllib.request.urlopen(req, timeout=5.5) as resp:
                items = json.loads(resp.read().decode("utf-8")).get("results", [])
            for it in items:
                title = (it.get("title") or "").strip()
                link = (it.get("id") or "").strip()
                year = it.get("publication_year") or ""
                cites = it.get("cited_by_count", 0)
                if title and link.startswith("http"):
                    rows.append({
                        "title": title,
                        "category": "OpenAlex · Research",
                        "summary": f"Published {year} · {cites} citations" if year else f"{cites} citations",
                        "url": link,
                    })
        except Exception:
            pass
        return rows

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=7) as pool:
        futures = [
            pool.submit(_bing_rss),
            pool.submit(_google_news_rss),
            pool.submit(_wiki_search),
            pool.submit(_ddg_html),
            pool.submit(_stackoverflow),
            pool.submit(_github_repos),
            pool.submit(_openalex),
        ]
        batches = [f.result() for f in futures]

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for batch in batches:
        for item in batch:
            u = item.get("url", "")
            if u and u not in seen:
                seen.add(u)
                out.append(item)
    return out[:18]


def _smart_disambiguate(core_term: str, full_query: str = "") -> list[dict[str, Any]]:
    from concurrent.futures import ThreadPoolExecutor

    senses: list[dict[str, Any]] = []
    ct = core_term.strip()
    fq = (full_query or ct).strip()
    if re.match(r"^(https?://)?[a-z0-9.-]+\.[a-z]{2,}(/.*)?$", ct, re.IGNORECASE) and not ct.lower().endswith(".xnd"):
        live_url = ct if ct.lower().startswith(("http://", "https://")) else f"https://{ct}"
        senses.append(
            {
                "title": f"Open {ct} — Live Website on WWW",
                "category": "Live WWW Website",
                "summary": f"Navigate directly to {live_url} as it is on the World Wide Web.",
                "url": live_url,
            }
        )
    if ct.lower() == "x":
        senses.extend(
            [
                {"title": "X (formerly Twitter) — Live Website (x.com)", "category": "Live WWW Platform · x.com", "summary": "Global real-time microblogging & social media platform.", "url": "https://x.com"},
                {"title": "X — 24th Letter of the Latin Alphabet", "category": "Alphabet & Linguistics", "summary": "The twenty-fourth letter of the modern English and Latin alphabet.", "url": "https://en.wikipedia.org/wiki/X"},
                {"title": "x — Unknown Variable in Algebra & Math", "category": "Mathematics", "summary": "Standard symbol representing an unknown quantity in equations.", "url": "https://en.wikipedia.org/wiki/Variable_(mathematics)"},
            ]
        )

    def _wiki_open() -> list[dict[str, Any]]:
        res: list[dict[str, Any]] = []
        try:
            api_url = "https://en.wikipedia.org/w/api.php?action=opensearch&limit=4&namespace=0&format=json&search=" + urllib.parse.quote(ct)
            req = urllib.request.Request(api_url, headers={"User-Agent": "XanaduSmartSearch/0.4"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            for t, d, u in zip(data[1] if len(data) > 1 else [], data[2] if len(data) > 2 else [], data[3] if len(data) > 3 else []):
                res.append({"title": t, "category": "Knowledge Graph · Wikipedia", "summary": d or f"Encyclopedia entry for {t}.", "url": u})
        except Exception:
            pass
        return res

    def _ddg_ia() -> list[dict[str, Any]]:
        res: list[dict[str, Any]] = []
        try:
            ddg_url = "https://api.duckduckgo.com/?format=json&no_html=1&skip_disambig=1&q=" + urllib.parse.quote(ct)
            dreq = urllib.request.Request(ddg_url, headers={"User-Agent": "XanaduSmartSearch/1.0"})
            with urllib.request.urlopen(dreq, timeout=1.8) as dresp:
                ddg = json.loads(dresp.read().decode("utf-8"))
            abs_txt = (ddg.get("AbstractText") or "").strip()
            abs_url = (ddg.get("AbstractURL") or "").strip()
            abs_head = (ddg.get("Heading") or ct).strip()
            if abs_txt and abs_url:
                res.append({"title": abs_head, "category": f"Live Web · {ddg.get('AbstractSource') or 'Instant'}", "summary": abs_txt, "url": abs_url})
        except Exception:
            pass
        return res

    def _gnews() -> list[dict[str, Any]]:
        res: list[dict[str, Any]] = []
        try:
            news_url = "https://news.google.com/rss/search?hl=en-US&gl=US&ceid=US:en&q=" + urllib.parse.quote(ct)
            nreq = urllib.request.Request(news_url, headers={"User-Agent": "XanaduSmartSearch/0.4"})
            with urllib.request.urlopen(nreq, timeout=2.0) as nresp:
                root = ET.fromstring(nresp.read(256_000))
            for item in root.findall(".//item")[:3]:
                t = html.unescape((item.findtext("title") or "").strip())
                u = (item.findtext("link") or "").strip()
                pub = (item.findtext("pubDate") or "").strip()
                if t and u:
                    res.append({"title": t, "category": "Live News / Web", "summary": f"Published {pub}" if pub else "Live search result", "url": u})
        except Exception:
            pass
        return res

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_web = pool.submit(_search_internet_web, fq)
        f_wiki = pool.submit(_wiki_open)
        f_ddg = pool.submit(_ddg_ia)
        f_news = pool.submit(_gnews)
        batches = [f_web.result(), f_ddg.result(), f_wiki.result(), f_news.result()]

    seen = {s["url"] for s in senses}
    for batch in batches:
        for item in batch:
            if item["url"] not in seen:
                seen.add(item["url"])
                senses.append(item)
    return senses[:24]


_NEWS_FEEDS = {
    "top": [
        ("Breaking · 1h", "https://news.google.com/rss/search?q=when:1h&hl=en-US&gl=US&ceid=US:en"),
        ("Al Jazeera", "https://www.aljazeera.com/xml/rss/all.xml"),
        ("BBC News", "https://feeds.bbci.co.uk/news/rss.xml"),
        ("NPR News", "https://feeds.npr.org/1001/rss.xml"),
    ],
    "trending": [
        ("Trending · 1h", "https://news.google.com/rss/search?q=when:1h&hl=en-US&gl=US&ceid=US:en"),
        ("BBC News", "https://feeds.bbci.co.uk/news/rss.xml"),
        ("ESPN", "https://www.espn.com/espn/rss/news"),
        ("TechCrunch", "https://techcrunch.com/feed/"),
        ("Ars Technica", "https://feeds.arstechnica.com/arstechnica/index"),
    ],
    "world": [
        ("World · 1h", "https://news.google.com/rss/search?q=world+when:1h&hl=en-US&gl=US&ceid=US:en"),
        ("Al Jazeera", "https://www.aljazeera.com/xml/rss/all.xml"),
        ("BBC World", "https://feeds.bbci.co.uk/news/world/rss.xml"),
        ("NPR World", "https://feeds.npr.org/1004/rss.xml"),
    ],
    "tech": [
        ("Tech · 1h", "https://news.google.com/rss/search?q=technology+when:1h&hl=en-US&gl=US&ceid=US:en"),
        ("TechCrunch", "https://techcrunch.com/feed/"),
        ("Ars Technica", "https://feeds.arstechnica.com/arstechnica/index"),
        ("BBC Tech", "https://feeds.bbci.co.uk/news/technology/rss.xml"),
    ],
    "sports": [
        ("Sports · 1h", "https://news.google.com/rss/search?q=sports+when:1h&hl=en-US&gl=US&ceid=US:en"),
        ("ESPN", "https://www.espn.com/espn/rss/news"),
        ("BBC Sport", "https://feeds.bbci.co.uk/sport/rss.xml"),
    ],
    "business": [
        ("Business · 1h", "https://news.google.com/rss/search?q=business+when:1h&hl=en-US&gl=US&ceid=US:en"),
        ("BBC Business", "https://feeds.bbci.co.uk/news/business/rss.xml"),
        ("NPR Business", "https://feeds.npr.org/1006/rss.xml"),
    ],
    "science": [
        ("Science · 1h", "https://news.google.com/rss/search?q=science+when:1h&hl=en-US&gl=US&ceid=US:en"),
        ("ScienceDaily", "https://www.sciencedaily.com/rss/all.xml"),
        ("BBC Science", "https://feeds.bbci.co.uk/news/science_and_environment/rss.xml"),
        ("NPR Science", "https://feeds.npr.org/1007/rss.xml"),
    ],
}
_NEWS_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}


def _format_age(pub_str: str, now: float) -> tuple[float, str]:
    if not pub_str:
        return 0.0, ""
    try:
        ts = parsedate_to_datetime(pub_str).timestamp()
        diff = max(0, int(now - ts))
        if diff < 60:
            return ts, "Just now"
        if diff < 3600:
            return ts, f"{diff // 60}m ago"
        if diff < 86400:
            return ts, f"{diff // 3600}h ago"
        return ts, f"{diff // 86400}d ago"
    except Exception:
        return 0.0, pub_str


def _upgrade_image_4k(url: str) -> str:
    if not url:
        return ""
    # Upgrade BBC ichef low-res 240px thumbnails to crisp 2048px (2K/4K class)
    url = re.sub(r"(https?://ichef\.bbci\.co\.uk/ace/standard/)\d+(/.*)", r"\g<1>2048\g<2>", url)
    url = re.sub(r"(https?://ichef\.bbci\.co\.uk/news/)\d+(/.*)", r"\g<1>2048\g<2>", url)
    return url


def _extract_rss_image(item: ET.Element, raw_desc: str) -> str:
    best_url = ""
    best_w = -1
    for el in item.iter():
        tag = el.tag.lower()
        if tag.endswith("thumbnail") or tag.endswith("content") or tag.endswith("enclosure"):
            u = (el.attrib.get("url") or "").strip()
            if u.startswith("http"):
                try:
                    w = int(el.attrib.get("width") or 0)
                except ValueError:
                    w = 0
                if w >= best_w:
                    best_w = w
                    best_url = u
    if best_url:
        return _upgrade_image_4k(best_url)
    m = re.search(r'<img[^>]+src=["\'](https?://[^"\']+)["\']', raw_desc, re.IGNORECASE)
    if m:
        return _upgrade_image_4k(m.group(1))
    return ""


@app.get("/api/news")
def get_live_news(category: str = Query(default="top")) -> dict[str, Any]:
    cat = category.strip().lower()
    if cat not in _NEWS_FEEDS:
        cat = "top"
    now = time.time()
    cached = _NEWS_CACHE.get(cat)
    if cached and (now - cached[0]) < 60:
        return {"category": cat, "stories": cached[1]}

    import random
    from concurrent.futures import ThreadPoolExecutor

    def _fetch_feed(feed_pair: tuple[str, str]) -> list[dict[str, Any]]:
        default_src, feed_url = feed_pair
        batch: list[dict[str, Any]] = []
        try:
            req = urllib.request.Request(feed_url, headers={"User-Agent": "XanaduNews/1.0"})
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                root = ET.fromstring(resp.read(450_000))
            for item in root.findall(".//item")[:8]:
                raw_title = html.unescape((item.findtext("title") or "").strip())
                url = (item.findtext("link") or "").strip()
                pub = (item.findtext("pubDate") or "").strip()
                src_el = item.find("source")
                src_name = html.unescape((src_el.text or "").strip()) if src_el is not None and src_el.text else default_src
                if not src_name and " - " in raw_title:
                    raw_title, src_name = raw_title.rsplit(" - ", 1)
                pub_ts, age_label = _format_age(pub, now)
                raw_desc = item.findtext("description") or ""
                img_url = _extract_rss_image(item, raw_desc)
                if not img_url and url:
                    host = urllib.parse.urlparse(url).netloc
                    if host:
                        img_url = f"https://www.google.com/s2/favicons?domain={urllib.parse.quote(host)}&sz=256"
                desc_clean = re.sub(r"<[^>]+>", " ", html.unescape(raw_desc))
                desc_clean = re.sub(r"\s+", " ", desc_clean).strip()
                if raw_title and url:
                    batch.append(
                        {
                            "title": raw_title,
                            "url": url,
                            "source": src_name or default_src,
                            "published": age_label or pub,
                            "pub_ts": pub_ts,
                            "is_fresh": bool(pub_ts and (now - pub_ts) <= 3900),
                            "summary": desc_clean[:200],
                            "image": img_url,
                        }
                    )
        except Exception:
            pass
        return batch

    with ThreadPoolExecutor(max_workers=len(_NEWS_FEEDS[cat])) as pool:
        feed_batches = list(pool.map(_fetch_feed, _NEWS_FEEDS[cat]))

    # Round-robin interleave across organizations + shuffle within each round
    stories: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    max_len = max((len(b) for b in feed_batches), default=0)
    for i in range(max_len):
        round_items: list[dict[str, Any]] = []
        for b in feed_batches:
            if i < len(b):
                st = b[i]
                if st["url"] not in seen_urls:
                    seen_urls.add(st["url"])
                    round_items.append(st)
        random.shuffle(round_items)
        stories.extend(round_items)

    if stories:
        _NEWS_CACHE[cat] = (now, stories)
    elif cached:
        stories = cached[1]
    elif not _check_has_wan():
        gw = _find_lan_gateway()
        if gw:
            try:
                with httpx.Client(timeout=5.0) as hc:
                    gr = hc.get(f"{gw['url']}/api/news", params={"category": cat})
                    if gr.status_code == 200:
                        g_stories = gr.json().get("stories") or []
                        if g_stories:
                            _NEWS_CACHE[cat] = (now, g_stories)
                            return {"category": cat, "stories": g_stories[:30]}
            except Exception:
                pass
    return {"category": cat, "stories": stories[:30]}


@app.get("/api/crawler/status")
def crawler_status() -> dict[str, Any]:
    sf = Path(__file__).resolve().parent / "crawler_status.json"
    out = store.storage_stats()
    if sf.exists():
        try:
            out.update(json.loads(sf.read_text(encoding="utf-8")))
        except Exception:
            pass
    return out


def _search_images(core_term: str) -> list[dict[str, str]]:
    imgs: list[dict[str, str]] = []
    seen: set[str] = set()
    # 1. Wikipedia high-res pageimages (up to 2160px / 4K)
    try:
        w_url = (
            "https://en.wikipedia.org/w/api.php?action=query&generator=search&gsrlimit=6"
            "&prop=pageimages|info&inprop=url&piprop=thumbnail|original&pithumbsize=2160&format=json&gsrsearch="
            + urllib.parse.quote(core_term)
        )
        req = urllib.request.Request(w_url, headers={"User-Agent": "XanaduSmartSearch/0.4"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for page in (data.get("query", {}).get("pages") or {}).values():
            orig = (page.get("original") or {}).get("source", "")
            thumb = (page.get("thumbnail") or {}).get("source", "")
            img = orig or thumb
            if img and img not in seen and not img.lower().endswith(".svg"):
                seen.add(img)
                imgs.append(
                    {
                        "title": page.get("title", core_term),
                        "image": img,
                        "url": page.get("fullurl", img),
                        "source": "Wikipedia",
                    }
                )
    except Exception:
        pass

    # 2. Wikimedia Commons 4K/2K image search
    try:
        c_url = (
            "https://commons.wikimedia.org/w/api.php?action=query&generator=search&gsrnamespace=6&gsrlimit=8"
            "&prop=imageinfo&iiprop=url|size&iiurlwidth=2160&format=json&gsrsearch="
            + urllib.parse.quote(core_term)
        )
        req = urllib.request.Request(c_url, headers={"User-Agent": "XanaduSmartSearch/0.4"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for page in (data.get("query", {}).get("pages") or {}).values():
            info = (page.get("imageinfo") or [{}])[0]
            img = info.get("thumburl") or info.get("url") or ""
            if img and img not in seen and not img.lower().endswith((".svg", ".ogg", ".webm", ".pdf")):
                seen.add(img)
                imgs.append(
                    {
                        "title": page.get("title", "").replace("File:", ""),
                        "image": img,
                        "url": info.get("descriptionurl") or img,
                        "source": "Wikimedia Commons",
                    }
                )
    except Exception:
        pass
    return imgs[:12]


def _search_forums(core_term: str) -> list[dict[str, Any]]:
    forums: list[dict[str, Any]] = []
    # 1. Hacker News Algolia Discussions (capped at 3 so internet results stay primary)
    try:
        hn_url = "https://hn.algolia.com/api/v1/search?hitsPerPage=3&tags=story&query=" + urllib.parse.quote(core_term)
        req = urllib.request.Request(hn_url, headers={"User-Agent": "XanaduSmartSearch/0.4"})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for hit in data.get("hits", []):
            title = hit.get("title") or ""
            oid = hit.get("objectID") or ""
            if title and oid:
                forums.append(
                    {
                        "title": title,
                        "url": f"https://news.ycombinator.com/item?id={oid}",
                        "forum": "Hacker News",
                        "comments": int(hit.get("num_comments") or 0),
                        "points": int(hit.get("points") or 0),
                    }
                )
    except Exception:
        pass

    # 2. Reddit Forum Threads
    try:
        r_url = "https://www.reddit.com/search.json?limit=3&sort=relevance&q=" + urllib.parse.quote(core_term)
        req = urllib.request.Request(r_url, headers={"User-Agent": "XanaduBrowser/1.0 (by /u/xanadu)"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for child in data.get("data", {}).get("children", []):
            d = child.get("data") or {}
            title = d.get("title") or ""
            perma = d.get("permalink") or ""
            if title and perma:
                forums.append(
                    {
                        "title": title,
                        "url": "https://www.reddit.com" + perma,
                        "forum": d.get("subreddit_name_prefixed") or "Reddit",
                        "comments": int(d.get("num_comments") or 0),
                        "points": int(d.get("score") or 0),
                    }
                )
    except Exception:
        pass
    return forums[:10]


def _apply_seeded_images(query: str, images: list[dict[str, Any]], knowledge_card: dict[str, Any] | None) -> list[dict[str, Any]]:
    ql_img = query.lower()
    is_founder_q = _is_xanadu_founder_query(query)
    out = list(images or [])
    if is_founder_q:
        founder_dir = UI_DIR / "founder"
        founder_files = (
            sorted(
                p.name for p in founder_dir.iterdir()
                if p.is_file() and p.suffix.lower() in (".jpg", ".jpeg", ".png", ".webp")
            )
            if founder_dir.exists()
            else ["image2.png"]
        )
        founder_imgs = [
            {"title": f"Justin Ndambiri — Founder & Owner of Xanadu (.xnd) #{i + 1}", "image": f"/static/founder/{fname}", "source": "founder.xnd"}
            for i, fname in enumerate(founder_files)
        ]
        f_urls = {im["image"] for im in founder_imgs}
        out = founder_imgs + [im for im in out if im.get("image") not in f_urls]
        if knowledge_card and not knowledge_card.get("image") and founder_imgs:
            knowledge_card["image"] = founder_imgs[0]["image"]
    if "xanadu" in ql_img or "xnd" in ql_img:
        xnd_logo_img = {"title": "Xanadu (.xnd) Official Logo", "image": "/static/logo.png", "source": "xanadu.xnd"}
        xnd_math_img = {"title": "Xanadu (.xnd) Mathematical Logo", "image": "/static/mathematical.png", "source": "xanadu.xnd"}
        xnd_imgs = [xnd_logo_img, xnd_math_img]
        xnd_urls = {"/static/logo.png", "/static/mathematical.png"}
        out = (xnd_imgs if not is_founder_q else []) + [im for im in out if im.get("image") not in xnd_urls] + (xnd_imgs if is_founder_q else [])
        if knowledge_card and not knowledge_card.get("image"):
            knowledge_card["image"] = "/static/logo.png"
    return out


@app.get("/api/search")
def search_universe(q: str = Query(default=""), fast: bool = Query(default=False)) -> dict[str, Any]:
    query = q.strip()
    if not query:
        return list_domains()
    intent, scope, core, knowledge_card = _classify_query_intent(query)
    t0 = time.perf_counter()
    results = store.search_ram(core)
    if not results and core != query:
        results = store.search_ram(query)
    if results:
        results.sort(
            key=lambda r: (pattern_mem.get_domain_boost(query, str(r.get("domain", ""))), float(r.get("score", 0.0))),
            reverse=True,
        )
    ql_check = query.lower()
    is_explicit_xnd = (
        ".xnd" in ql_check
        or "xnd://" in ql_check
        or "xanadu" in ql_check
        or any(k in ql_check for k in ("manifesto", "documentation", "founder.xnd", "forum.xnd", "heart.xnd"))
        or ql_check in store.domains
    )
    if scope != "internal" and not is_explicit_xnd:
        builtin_boilerplate = {"home.xnd", "manifesto.xnd", "heart.xnd", "x.xnd", "documentation.xnd", "founder.xnd", "forum.xnd", "wikipedia.xnd"}
        results = [r for r in results if (r.get("domain") or "").lower() not in builtin_boilerplate]
    if knowledge_card is None and (scope == "internal" or is_explicit_xnd):
        knowledge_card = answer_from_xnd_corpus(query, store, results, pattern_mem)
    if intent == "SELF" and knowledge_card and not any((r.get("domain") or "").lower() == "founder.xnd" for r in results):
        results.insert(
            0,
            {
                "domain": "founder.xnd",
                "title": knowledge_card["title"],
                "kind": "document",
                "version": 1,
                "backlinks_count": 0,
                "snippet": knowledge_card["summary"],
                "source_url": "",
            },
        )
    index_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    wiki_hit = None
    if scope != "internal":
        wiki_hit = scrapers.search_wiki_ram(core)
        cached = store.get_crawl_cache(core) or (store.get_crawl_cache(query) if core != query else None)
        if cached:
            kc_out = knowledge_card or cached.get("knowledge_card")
            if not kc_out and wiki_hit:
                kc_out = {
                    "title": wiki_hit["title"],
                    "subtitle": "wikipedia.xnd · Auto-Indexed Live",
                    "summary": wiki_hit["summary"],
                    "url": wiki_hit["url"],
                    "facts": [],
                }
            return {
                "query": query,
                "core_term": core,
                "intent": intent,
                "scope": scope,
                "results": results,
                "index_ms": round((time.perf_counter() - t0) * 1000.0, 2),
                "fast": False,
                "knowledge_card": kc_out,
                "details_card": cached.get("details_card"),
                "alternatives": cached.get("alternatives", []),
                "deep_passages": cached.get("deep_passages", []),
                "disambiguation": cached.get("disambiguation", []),
                "images": _apply_seeded_images(query, cached.get("images", []), kc_out),
                "forums": cached.get("forums", []),
            }

    if fast or scope == "internal":
        kc_fast = knowledge_card
        if not kc_fast and wiki_hit:
            kc_fast = {
                "title": wiki_hit["title"],
                "subtitle": "wikipedia.xnd · Auto-Indexed Live",
                "summary": wiki_hit["summary"],
                "url": wiki_hit["url"],
                "facts": [],
            }
        fast_imgs = _apply_seeded_images(query, [], kc_fast)
        return {
            "query": query,
            "core_term": core,
            "intent": intent,
            "scope": scope,
            "results": results,
            "index_ms": index_ms,
            "fast": bool(fast and scope != "internal"),
            "knowledge_card": kc_fast,
            "disambiguation": [],
            "images": fast_imgs,
            "forums": [],
        }

    from concurrent.futures import ThreadPoolExecutor

    def _nostr_search_sync() -> None:
        q_low = query.lower()
        if DOMAIN_RE.match(q_low):
            _try_resolve_from_nostr(q_low)
        elif not results:
            try:
                import_sync_bundle(discover_docs_nostr(limit=30))
                store.crawl_all_domains()
            except Exception:
                pass

    def _extract_html_title_and_text(raw_html: str) -> tuple[str, str]:
        p = _TextExtractor()
        p.feed(raw_html)
        p.close()
        return " ".join(p.title_parts).strip(), "".join(p.text_parts).strip()

    peer_urls = [u for u in list(_LAN_PEERS.keys())] + [
        p.get("url", "") for p in list(store.peers.values()) if p.get("url")
    ]

    want_forums = any(k in query.lower() for k in ("forum", "discussion", "reddit", "hacker news", "hn ", "forum.xnd"))
    with ThreadPoolExecutor(max_workers=7) as pool:
        f_nostr = pool.submit(_nostr_search_sync) if (not results or DOMAIN_RE.match(query.lower())) else None
        f_dis = pool.submit(_smart_disambiguate, core, query)
        f_img = pool.submit(_search_images, core)
        f_frm = pool.submit(_search_forums, core) if want_forums else None
        f_wiki_rest = pool.submit(deep_search.fetch_wikipedia_rest_and_wikidata, core) if scope != "internal" else None
        f_alts = pool.submit(deep_search.fetch_alternatives, core) if scope != "internal" else None
        f_fed = pool.submit(deep_search.query_federated_peers, core, peer_urls) if peer_urls else None
        if f_nostr is not None:
            f_nostr.result()
            t1 = time.perf_counter()
            results = store.search_ram(core)
            if not results and core != query:
                results = store.search_ram(query)
            index_ms = round((time.perf_counter() - t1) * 1000.0, 2)
        if f_fed is not None:
            fed_hits = f_fed.result()
            seen_doms = {(r.get("domain") or "").lower() for r in results}
            for fh in fed_hits:
                d = (fh.get("domain") or "").lower()
                if d and d not in seen_doms:
                    seen_doms.add(d)
                    results.append(fh)
        disambig = f_dis.result()
        deep_passages = (
            deep_search.deep_fetch_live_pages(
                [d.get("url", "") for d in disambig[:3]],
                query,
                _extract_html_title_and_text,
                max_pages=3,
            )
            if scope != "internal" and disambig
            else []
        )
        details_card = f_wiki_rest.result() if f_wiki_rest is not None else None
        alternatives = f_alts.result() if f_alts is not None else []
        if details_card and deep_passages:
            details_card["deep_passages"] = deep_passages
        elif deep_passages and not details_card:
            details_card = {
                "title": deep_passages[0]["title"],
                "subtitle": "Live Web · Deep-Extracted Passages",
                "summary": deep_passages[0]["excerpt"],
                "url": deep_passages[0]["url"],
                "thumbnail": "",
                "facts": [],
                "deep_passages": deep_passages,
            }
        if knowledge_card is None and details_card:
            knowledge_card = {
                "title": details_card["title"],
                "subtitle": details_card["subtitle"],
                "summary": details_card["summary"],
                "url": details_card.get("url", ""),
                "facts": details_card.get("facts", []),
            }
        images = _apply_seeded_images(query, f_img.result(), knowledge_card)
        forums = f_frm.result() if f_frm is not None else []

    ql_check = query.lower()
    is_explicit_xnd = (
        ".xnd" in ql_check
        or "xnd://" in ql_check
        or "xanadu" in ql_check
        or any(k in ql_check for k in ("manifesto", "documentation", "founder.xnd", "forum.xnd", "heart.xnd"))
        or ql_check in store.domains
    )
    if scope != "internal" and not is_explicit_xnd:
        builtin_boilerplate = {"home.xnd", "manifesto.xnd", "heart.xnd", "x.xnd", "documentation.xnd", "founder.xnd", "forum.xnd", "wikipedia.xnd"}
        results = [r for r in results if (r.get("domain") or "").lower() not in builtin_boilerplate]

    indexed_terms: set[str] = {core.lower()}
    for r in results[:10]:
        dom = (r.get("domain") or "").lower()
        if dom:
            indexed_terms.add(dom)
            indexed_terms.add(dom.removesuffix(".xnd"))
        for w in re.findall(r"[a-z0-9]{3,}", (r.get("title") or "").lower()):
            indexed_terms.add(w)

    def _indexed_boost(item: dict[str, Any]) -> int:
        text = f"{item.get('title', '')} {item.get('summary', '')}".lower()
        return sum(1 for t in indexed_terms if len(t) >= 3 and t in text)

    forums = sorted(forums, key=_indexed_boost, reverse=True) if want_forums else []
    disambig = sorted(disambig, key=_indexed_boost, reverse=True)

    if knowledge_card is None and scope != "internal":
        knowledge_card = _extractive_qa_answer(query, core, intent, disambig, forums)
    if knowledge_card is None and wiki_hit:
        knowledge_card = {
            "title": wiki_hit["title"],
            "subtitle": "wikipedia.xnd · Auto-Indexed Live",
            "summary": wiki_hit["summary"],
            "url": wiki_hit["url"],
            "facts": [],
        }

    if scope != "internal" and not _check_has_wan() and (not disambig or knowledge_card is None):
        gw = _find_lan_gateway()
        if gw:
            try:
                with httpx.Client(timeout=5.0) as hc:
                    gr = hc.get(
                        f"{gw['url']}/api/gateway/search",
                        params={"q": query, "scope": scope},
                    )
                    if gr.status_code == 200:
                        gd = gr.json()
                        if knowledge_card is None and gd.get("knowledge_card"):
                            knowledge_card = gd["knowledge_card"]
                        if not disambig and gd.get("disambiguation"):
                            disambig = gd["disambiguation"]
                        if not images and gd.get("images"):
                            images = gd["images"]
                        if gd.get("forums"):
                            forums = forums + [f for f in gd["forums"] if f not in forums]
            except Exception:
                pass

    if scope != "internal":
        store.put_crawl_cache(
            core,
            {
                "knowledge_card": knowledge_card,
                "details_card": details_card,
                "alternatives": alternatives,
                "deep_passages": deep_passages,
                "disambiguation": disambig,
                "images": images,
                "forums": forums,
            },
        )

    return {
        "query": query,
        "core_term": core,
        "intent": intent,
        "scope": scope,
        "results": results,
        "index_ms": index_ms,
        "knowledge_card": knowledge_card,
        "details_card": details_card,
        "alternatives": alternatives,
        "deep_passages": deep_passages,
        "disambiguation": disambig,
        "images": images,
        "forums": forums,
    }


@app.post("/api/search/federated")
async def federated_search(request: Request) -> dict[str, Any]:
    body = await request.json()
    q = str(body.get("query") or "").strip()
    limit = max(1, min(20, int(body.get("limit") or 8)))
    if not q:
        return {"ok": True, "node_id": _get_node_id(), "results": []}
    hits = store.search_ram(q)[:limit]
    return {"ok": True, "node_id": _get_node_id(), "results": hits}


class SearchFeedbackRequest(BaseModel):
    query: str
    domain: str
    helpful: bool = True


@app.post("/api/search/feedback")
def search_feedback(req: SearchFeedbackRequest) -> dict[str, Any]:
    delta = 1.0 if req.helpful else -0.8
    return pattern_mem.record_feedback(req.query, req.domain, delta=delta)


_FACT_ATTR_MAP = {
    "population": ("P1082", "Population"),
    "capital": ("P36", "Capital"),
    "president": ("P35", "Head of State"),
    "head of state": ("P35", "Head of State"),
    "ceo": ("P169", "CEO"),
    "chief executive": ("P169", "CEO"),
    "founder": ("P112", "Founder"),
    "founded": ("P571", "Founded"),
    "currency": ("P38", "Currency"),
    "area": ("P2046", "Area"),
    "boiling point": ("P2102", "Boiling Point"),
    "melting point": ("P2101", "Melting Point"),
    "country": ("P17", "Country"),
}

_WIKIDATA_PROPS = [
    ("P1082", "Population"),
    ("P36", "Capital"),
    ("P169", "CEO"),
    ("P35", "Head of State"),
    ("P112", "Founder"),
    ("P38", "Currency"),
    ("P2102", "Boiling Point"),
    ("P2101", "Melting Point"),
    ("P2046", "Area"),
    ("P571", "Founded"),
]


def _parse_fact_attr(query: str) -> tuple[str | None, str | None]:
    ql = re.sub(r"^(?:what\s+is\s+(?:the\s+)?|what's\s+(?:the\s+)?|who\s+is\s+(?:the\s+)?)", "", query.strip(), flags=re.IGNORECASE).strip(" ?.!\"'")
    m = re.match(r"^(population|capital|president|head of state|ceo|chief executive|founder|currency|area|boiling point|melting point|country)\s+of\s+(.+)$", ql, re.IGNORECASE)
    if m:
        attr_key = m.group(1).lower()
        entity = m.group(2).strip(" ?.!\"'")
        return attr_key, entity
    return None, None


def _fetch_wikidata_facts(qid: str, target_pid: str | None = None) -> list[dict[str, str]]:
    if not qid or not re.match(r"^Q\d+$", qid):
        return []
    try:
        url = f"https://www.wikidata.org/w/api.php?action=wbgetentities&ids={qid}&props=claims&format=json"
        req = urllib.request.Request(url, headers={"User-Agent": "XanaduStructuredFacts/1.0"})
        with urllib.request.urlopen(req, timeout=1.6) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        claims = ((data.get("entities") or {}).get(qid) or {}).get("claims") or {}
    except Exception:
        return []

    raw_items: list[tuple[str, str, str]] = []  # (pid, label, raw_val_or_qid)
    qids_to_resolve: list[str] = []
    props_ordered = _WIKIDATA_PROPS[:]
    if target_pid:
        props_ordered.sort(key=lambda p: 0 if p[0] == target_pid else 1)

    for pid, label in props_ordered:
        arr = claims.get(pid)
        if not arr:
            continue
        # Prefer preferred rank if present
        best_claim = next((c for c in arr if c.get("rank") == "preferred"), arr[0])
        dv = ((best_claim.get("mainsnak") or {}).get("datavalue") or {})
        vtype = dv.get("type")
        val = dv.get("value")
        if vtype == "wikibase-entityid" and isinstance(val, dict) and val.get("id"):
            ref_id = val["id"]
            raw_items.append((pid, label, f"QREF:{ref_id}"))
            qids_to_resolve.append(ref_id)
        elif vtype == "quantity" and isinstance(val, dict) and val.get("amount"):
            amt_s = str(val["amount"]).lstrip("+")
            try:
                num = float(amt_s)
                fmt = f"{int(num):,}" if num.is_integer() and abs(num) >= 1000 else f"{num:g}"
            except Exception:
                fmt = amt_s
            unit = str(val.get("unit") or "")
            if unit.endswith("/Q11579"):
                fmt += " K"
            elif unit.endswith("/Q25267"):
                fmt += " °C"
            elif unit.endswith("/Q712226"):
                fmt += " km²"
            raw_items.append((pid, label, fmt))
        elif vtype == "time" and isinstance(val, dict) and val.get("time"):
            t_str = str(val["time"]).lstrip("+").split("T")[0]
            year_m = re.match(r"^(\d{4})", t_str)
            raw_items.append((pid, label, year_m.group(1) if year_m else t_str))
        if len(raw_items) >= 5:
            break

    labels_map: dict[str, str] = {}
    if qids_to_resolve:
        try:
            ids_param = "|".join(dict.fromkeys(qids_to_resolve[:8]))
            lurl = f"https://www.wikidata.org/w/api.php?action=wbgetentities&ids={ids_param}&props=labels&languages=en&format=json"
            lreq = urllib.request.Request(lurl, headers={"User-Agent": "XanaduStructuredFacts/1.0"})
            with urllib.request.urlopen(lreq, timeout=1.4) as lresp:
                ldata = json.loads(lresp.read().decode("utf-8"))
            for rq, ent in (ldata.get("entities") or {}).items():
                lbl = ((ent.get("labels") or {}).get("en") or {}).get("value")
                if lbl:
                    labels_map[rq] = lbl
        except Exception:
            pass

    facts: list[dict[str, str]] = []
    for pid, label, val in raw_items:
        if val.startswith("QREF:"):
            resolved = labels_map.get(val[5:])
            if resolved:
                facts.append({"label": label, "value": resolved, "_pid": pid})
        else:
            facts.append({"label": label, "value": val, "_pid": pid})
    return facts[:4]


def _extractive_qa_answer(
    query: str,
    core: str,
    intent: str,
    disambig: list[dict[str, Any]],
    forums: list[dict[str, Any]],
) -> dict[str, Any] | None:
    import random
    from concurrent.futures import ThreadPoolExecutor

    stop = {
        "the", "is", "are", "was", "were", "a", "an", "of", "in", "on", "to", "for",
        "and", "or", "what", "who", "when", "where", "why", "how", "did", "do", "does",
        "this", "that", "with", "from", "by", "as", "at", "about",
    }
    q_tokens = [w for w in re.findall(r"[a-z0-9]+", f"{query} {core}".lower()) if len(w) >= 2 and w not in stop]
    if not q_tokens:
        return None

    attr_key, attr_entity = _parse_fact_attr(query)
    target_pid, target_attr_label = _FACT_ATTR_MAP.get(attr_key or "", (None, None))

    wiki_title = attr_entity or next((d.get("title") for d in disambig if "wikipedia.org" in (d.get("url") or "")), None) or core
    live_urls: list[tuple[str, str]] = []
    passages: list[tuple[str, str, str, bool]] = []  # (source_label, url, text, is_wiki)
    for item in disambig:
        u = item.get("url") or ""
        snip = (item.get("summary") or "").strip()
        lbl = item.get("title") or u
        if snip and u.startswith("http") and "news.google.com" not in u and len(snip) >= 40:
            passages.append((lbl, u, snip, "wikipedia.org" in u))
        if (
            u.startswith("http")
            and "wikipedia.org" not in u
            and "news.google.com" not in u
            and "news.ycombinator.com" not in u
            and "reddit.com" not in u
            and len(live_urls) < 2
        ):
            live_urls.append((lbl, u))

    wiki_qid_holder: list[str] = []

    def _fetch_wiki() -> tuple[str, str, str, bool] | None:
        try:
            slug = urllib.parse.quote(wiki_title.replace(" ", "_"))
            u = f"https://en.wikipedia.org/api/rest_v1/page/summary/{slug}"
            req = urllib.request.Request(u, headers={"User-Agent": "XanaduExtractiveQA/1.0"})
            with urllib.request.urlopen(req, timeout=1.8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            ext = (data.get("extract") or "").strip()
            qid = (data.get("wikibase_item") or "").strip()
            if qid:
                wiki_qid_holder.append(qid)
            page_url = ((data.get("content_urls") or {}).get("desktop") or {}).get("page") or f"https://en.wikipedia.org/wiki/{slug}"
            if ext:
                return (data.get("title") or wiki_title, page_url, ext, True)
        except Exception:
            pass
        return None

    def _fetch_live(label: str, url: str) -> tuple[str, str, str, bool] | None:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 XanaduExtractiveQA/1.0"})
            with urllib.request.urlopen(req, timeout=1.6) as resp:
                ctype = (resp.headers.get("Content-Type") or "").lower()
                if "html" not in ctype and "text" not in ctype:
                    return None
                raw_html = resp.read(110_000).decode("utf-8", errors="ignore")
            cleaned = re.sub(r"(?is)<(script|style|nav|header|footer|aside|noscript)[^>]*>.*?</\1>", " ", raw_html)
            cleaned = re.sub(r"(?s)<[^>]+>", " ", cleaned)
            cleaned = html.unescape(re.sub(r"\s+", " ", cleaned)).strip()
            if len(cleaned) >= 60:
                return (label, url, cleaned[:6000], False)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=3) as pool:
        f_w = pool.submit(_fetch_wiki)
        f_ls = [pool.submit(_fetch_live, lbl, u) for lbl, u in live_urls]
        res_w = f_w.result()
        if res_w:
            passages.append(res_w)
        for f_l in f_ls:
            res_l = f_l.result()
            if res_l:
                passages.append(res_l)

    if not passages:
        return None

    scored_sents: list[tuple[float, str, str, str]] = []
    seen_sents: set[str] = set()
    for src_label, src_url, text, is_wiki in passages:
        sents = re.split(r"(?<=[.!?])\s+", text)
        for idx, s in enumerate(sents[:24]):
            s = s.strip()
            if len(s) < 35 or len(s) > 320:
                continue
            sl = s.lower()
            if sl in seen_sents:
                continue
            seen_sents.add(sl)

            # BM25-style keyword overlap
            overlap = sum(1.5 if len(t) >= 5 else 1.0 for t in q_tokens if t in sl)
            if overlap == 0 and not is_wiki:
                continue
            score = overlap + (1.5 if is_wiki and idx < 2 else 0.0)

            # Question-type boosts
            if intent == "WHEN":
                if re.search(r"\b(1\d{3}|20\d{2})\b", s):
                    score += 3.5
                if any(w in sl for w in ("founded", "created", "born", "established", "launched", "started", "released", "january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december")):
                    score += 2.5
            elif intent == "WHO":
                if re.search(r"\b[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}\b", s):
                    score += 2.5
                if any(w in sl for w in ("founder", "ceo", "owner", "invented", "created by", "president", "author", "director", "leader")):
                    score += 3.0
            elif intent == "WHERE":
                if any(w in sl for w in ("located in", "based in", "capital", "country", "city", "situated", "headquartered", "region")):
                    score += 3.5
            elif intent == "HOW_TO":
                if any(w in sl for w in ("first", "step", "install", "run", "use", "create", "configure", "build")):
                    score += 2.5
            elif intent == "WHAT_IS":
                if any(w in sl for w in (" is a ", " is an ", " refers to ", " defined as ", " is the ")):
                    score += 2.0

            scored_sents.append((score, s, src_label, src_url))

    if not scored_sents:
        return None
    scored_sents.sort(key=lambda x: x[0], reverse=True)
    best_score, best_sent, best_src, best_url = scored_sents[0]
    second = next((x[1] for x in scored_sents[1:4] if x[3] == best_url and x[1] != best_sent and x[0] >= best_score * 0.6), "")

    lead_ins = [
        f"According to {best_src}:",
        f"From {best_src}:",
        f"Summarized from {best_src}:",
        f"{best_src} notes:",
    ]
    summary_text = f"{random.choice(lead_ins)} {best_sent}" + (f" {second}" if second else "")
    host = urllib.parse.urlparse(best_url).netloc or best_src

    facts = _fetch_wikidata_facts(wiki_qid_holder[0], target_pid) if wiki_qid_holder else []
    title_out = best_src
    if target_pid and facts:
        matched_fact = next((f for f in facts if f.get("_pid") == target_pid), None)
        if matched_fact:
            title_out = f"{best_src} — {matched_fact['label']}: {matched_fact['value']}"
            summary_text = f"{matched_fact['label']} of {best_src}: {matched_fact['value']}. {best_sent}"
    clean_facts = [{"label": f["label"], "value": f["value"]} for f in facts]

    return {
        "title": title_out,
        "subtitle": f"Structured Fact & QA ({intent}) · {host}",
        "summary": summary_text,
        "url": best_url,
        "facts": clean_facts,
    }


@app.post("/api/publish")
def api_publish(req: PublishRequest) -> dict[str, Any]:
    effective_priv = req.privkey_hex.strip()
    dom_q = req.domain.strip().lower()
    if not dom_q.endswith(".xnd"):
        dom_q = f"{dom_q}.xnd"
    if not effective_priv and _vault_unlocked and dom_q in store.domains:
        effective_priv = store.domains[dom_q].get("privkey_hex", "")
    if not effective_priv and dom_q in store.domains:
        effective_priv = store.domains[dom_q].get("privkey_hex", "")

    content_to_publish = req.content
    if req.private_space:
        if not effective_priv:
            _, effective_priv = generate_keypair()
        try:
            content_to_publish = e2ee_spaces.encrypt_for_peers(req.content, effective_priv, req.allowed_pubkeys)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"E2EE encryption failed: {e}")

    res = {"ok": True, **publish_document(req.domain, req.title, content_to_publish, req.claim_token, pinned=True, privkey_hex=effective_priv)}
    dom = res.get("domain", "")
    if int(res.get("version_num", res.get("version", 0))) == 1:
        priv_hex = store.domains.get(dom, {}).get("privkey_hex", "")
        if priv_hex:
            res["privkey_hex"] = priv_hex
            res["is_new_domain"] = True
            if _vault_unlocked:
                _save_vault()
    try:
        pub_hex = store.domains.get(dom, {}).get("pubkey_hex", "")
        if dom and pub_hex and res.get("signature_hex"):
            threading.Thread(
                target=announce_doc_nostr,
                args=(dom, int(res["version_num"]), req.title or dom, res["sha256"], pub_hex, res["signature_hex"], content_to_publish, False),
                daemon=True,
            ).start()
    except Exception:
        pass
    return res


@app.post("/api/e2ee/unlock")
def api_e2ee_unlock(req: E2eeUnlockRequest) -> dict[str, Any]:
    dom = req.domain.strip().lower()
    row = store.get_version(dom, None)
    if not row:
        raise HTTPException(status_code=404, detail="Domain not found")
    blob = store.get_blob(row.get("sha256", "")) or ""
    ok_dec, plain, recips = e2ee_spaces.decrypt_with_privkeys(blob, [req.privkey_hex.strip()])
    if not ok_dec:
        raise HTTPException(status_code=403, detail="Key is not in the invited E2EE recipient list for this space.")
    return {
        "ok": True,
        "domain": dom,
        "raw_content": plain,
        "segments": build_segments(plain),
        "allowed_pubkeys": recips,
    }


@app.post("/api/publish_capsule")
def api_publish_capsule(req: PublishCapsuleRequest, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    bundle_files: dict[str, str] = {}
    if req.files:
        for raw_path, val in req.files.items():
            clean_p = str(raw_path).replace("\\", "/").lstrip("./").lstrip("/")
            if not clean_p or ".." in clean_p.split("/"):
                continue
            bundle_files[clean_p] = val
    if req.html.strip() or "index.html" not in bundle_files:
        if req.html.strip():
            bundle_files["index.html"] = req.html
    effective_priv = req.privkey_hex.strip()
    dom_q = req.domain.strip().lower()
    if not effective_priv and _vault_unlocked and dom_q in store.domains:
        effective_priv = store.domains[dom_q].get("privkey_hex", "")
    res = {"ok": True, **publish_capsule(req.domain, req.title, bundle_files, req.backend_py, None, req.claim_token, privkey_hex=effective_priv, connect_origins=req.connect_origins)}
    dom = res.get("domain", "")
    if int(res.get("version_num", res.get("version", 0))) == 1:
        priv_hex = store.domains.get(dom, {}).get("privkey_hex", "")
        if priv_hex:
            res["privkey_hex"] = priv_hex
            res["is_new_domain"] = True
            if _vault_unlocked:
                _save_vault()
    try:
        pub_hex = store.domains.get(dom, {}).get("pubkey_hex", "")
        blob_txt = store.get_blob(res.get("sha256", "")) or ""
        if dom and pub_hex and res.get("signature") and blob_txt:
            threading.Thread(
                target=announce_doc_nostr,
                args=(dom, int(res["version"]), req.title or dom, res["sha256"], pub_hex, res["signature"], blob_txt, True),
                daemon=True,
            ).start()
    except Exception:
        pass
    return res


# ---------------------------------------------------------------------------
# Private Account Vault & Dashboard Lock (scrypt + AES-256-GCM)
# ---------------------------------------------------------------------------

_vault_unlocked: bool = False
_vault_key: bytes | None = None
_vault_username: str = ""


def _account_path() -> Path:
    return store.data_dir / "account.json"


def _derive_account_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=64)
    return dk[:32], dk[32:]


_vault_account_privkey: str = ""
_vault_username_hash: str = ""


def _save_vault() -> None:
    p = _account_path()
    if not p.exists() or _vault_key is None:
        return
    acct = json.loads(p.read_text(encoding="utf-8"))
    keyring = {
        name: {"pubkey_hex": d.get("pubkey_hex", ""), "privkey_hex": d.get("privkey_hex", "")}
        for name, d in store.domains.items()
        if d.get("privkey_hex")
    }
    vault_obj = {
        "keyring": keyring,
        "account_privkey_hex": _vault_account_privkey,
    }
    nonce = os.urandom(12)
    ct = AESGCM(_vault_key).encrypt(nonce, json.dumps(vault_obj).encode("utf-8"), None)
    acct["vault_nonce_hex"] = nonce.hex()
    acct["vault_ct_hex"] = ct.hex()
    p.write_text(json.dumps(acct, indent=2), encoding="utf-8")


class AuthSetupRequest(BaseModel):
    username: str
    password: str


class AuthLoginRequest(BaseModel):
    username_hash: str = ""
    password: str
    account_privkey_hex: str = ""


@app.get("/api/auth/status")
def auth_status(request: Request) -> dict[str, Any]:
    _require_localhost(request)
    p = _account_path()
    if not p.exists():
        return {"configured": False, "unlocked": False, "username": "", "username_hash": ""}
    try:
        acct = json.loads(p.read_text(encoding="utf-8"))
        uname = acct.get("username", "")
        uhash = acct.get("username_hash", "")
    except Exception:
        uname = ""
        uhash = ""
    return {"configured": True, "unlocked": _vault_unlocked, "username": uname, "username_hash": uhash}


@app.post("/api/auth/setup")
def auth_setup(req: AuthSetupRequest, request: Request) -> dict[str, Any]:
    global _vault_unlocked, _vault_key, _vault_username, _vault_account_privkey, _vault_username_hash
    _require_localhost(request)
    p = _account_path()
    if p.exists():
        raise HTTPException(status_code=409, detail="Private account already configured. Use Sign In.")
    uname = req.username.strip()
    pw = req.password
    if len(uname) < 2 or len(pw) < 4:
        raise HTTPException(status_code=400, detail="Username (2+ chars) and password (4+ chars) required.")

    sk = Ed25519PrivateKey.generate()
    acct_priv_hex = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    acct_pub_hex = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    username_hash = "xnd-" + hashlib.sha256(f"{uname}|{acct_pub_hex}".encode("utf-8")).hexdigest()[:10]
    acct_sig_hex = sk.sign(f"xnd-account|{username_hash}|{acct_pub_hex}".encode("utf-8")).hex()

    salt = os.urandom(16)
    auth_hash, v_key = _derive_account_keys(pw, salt)
    acct = {
        "username": uname,
        "username_hash": username_hash,
        "account_pubkey_hex": acct_pub_hex,
        "account_sig_hex": acct_sig_hex,
        "salt_hex": salt.hex(),
        "auth_hash_hex": auth_hash.hex(),
    }
    p.write_text(json.dumps(acct, indent=2), encoding="utf-8")
    _vault_key = v_key
    _vault_username = uname
    _vault_username_hash = username_hash
    _vault_account_privkey = acct_priv_hex
    _vault_unlocked = True
    _save_vault()
    return {
        "ok": True,
        "configured": True,
        "unlocked": True,
        "username": uname,
        "username_hash": username_hash,
        "account_pubkey_hex": acct_pub_hex,
        "account_privkey_hex": acct_priv_hex,
        "account_sig_hex": acct_sig_hex,
    }


@app.post("/api/auth/login")
def auth_login(req: AuthLoginRequest, request: Request) -> dict[str, Any]:
    global _vault_unlocked, _vault_key, _vault_username, _vault_account_privkey, _vault_username_hash
    _require_localhost(request)
    p = _account_path()
    if not p.exists():
        raise HTTPException(status_code=404, detail="No private account configured yet.")
    acct = json.loads(p.read_text(encoding="utf-8"))

    expected_uhash = acct.get("username_hash", "")
    provided_uhash = req.username_hash.strip().lower()
    if expected_uhash and not hmac.compare_digest(provided_uhash, expected_uhash):
        raise HTTPException(status_code=401, detail="Hashed username does not match this vault.")

    salt = bytes.fromhex(acct["salt_hex"])
    expected_hash = bytes.fromhex(acct["auth_hash_hex"])
    auth_hash, v_key = _derive_account_keys(req.password, salt)
    if not hmac.compare_digest(auth_hash, expected_hash):
        raise HTTPException(status_code=401, detail="Incorrect password.")

    acct_pub_hex = acct.get("account_pubkey_hex", "")
    acct_sig_hex = acct.get("account_sig_hex", "")
    if acct_pub_hex and acct_sig_hex:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(acct_pub_hex)).verify(
                bytes.fromhex(acct_sig_hex),
                f"xnd-account|{expected_uhash}|{acct_pub_hex}".encode("utf-8"),
            )
        except Exception:
            raise HTTPException(status_code=403, detail="Account Ed25519 cryptographic signature verification failed.")

    if req.account_privkey_hex.strip():
        try:
            derived_pub = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(req.account_privkey_hex.strip())).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ).hex()
            if derived_pub != acct_pub_hex:
                raise HTTPException(status_code=401, detail="Login hex key does not match account Ed25519 public key.")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid login hex key format.")

    if acct.get("vault_nonce_hex") and acct.get("vault_ct_hex"):
        nonce = bytes.fromhex(acct["vault_nonce_hex"])
        ct = bytes.fromhex(acct["vault_ct_hex"])
        plain = AESGCM(v_key).decrypt(nonce, ct, None)
        vault_obj = json.loads(plain.decode("utf-8"))
        keyring = vault_obj.get("keyring", vault_obj) if isinstance(vault_obj, dict) else {}
        if isinstance(vault_obj, dict) and vault_obj.get("account_privkey_hex"):
            _vault_account_privkey = vault_obj["account_privkey_hex"]
        for dom_name, kd in keyring.items():
            if isinstance(kd, dict) and dom_name in store.domains and kd.get("privkey_hex"):
                store.domains[dom_name]["privkey_hex"] = kd["privkey_hex"]

    _vault_key = v_key
    _vault_username = acct.get("username", "")
    _vault_username_hash = expected_uhash
    _vault_unlocked = True
    return {
        "ok": True,
        "configured": True,
        "unlocked": True,
        "username": _vault_username,
        "username_hash": _vault_username_hash,
        "account_pubkey_hex": acct_pub_hex,
    }


@app.get("/api/auth/download-account")
def download_account_key(request: Request) -> Response:
    _require_localhost(request)
    p = _account_path()
    if not p.exists() or not _vault_unlocked or not _vault_account_privkey:
        raise HTTPException(status_code=403, detail="Unlock your private account vault first.")
    acct = json.loads(p.read_text(encoding="utf-8"))
    payload = {
        "username_hash": acct.get("username_hash", _vault_username_hash),
        "account_pubkey_hex": acct.get("account_pubkey_hex", ""),
        "account_privkey_hex": _vault_account_privkey,
        "account_sig_hex": acct.get("account_sig_hex", ""),
    }
    fname = f"{payload['username_hash']}.xnd-account.json"
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.post("/api/auth/logout")
def auth_logout(request: Request) -> dict[str, Any]:
    global _vault_unlocked, _vault_key, _vault_account_privkey
    _require_localhost(request)
    _vault_key = None
    _vault_account_privkey = ""
    _vault_unlocked = False
    return {"ok": True, "unlocked": False}


@app.get("/api/domain/check")
def check_domain_availability(name: str = Query(default="")) -> dict[str, Any]:
    dom = normalize_xnd_domain(name, append_tld=True)
    if not dom or len(dom) > 253 or not DOMAIN_RE.match(dom):
        return {"domain": dom, "available": False, "reason": "Invalid .xnd domain. Only letters, numbers, '-' and '.' between labels are allowed (e.g. domain-name.xnd or sub.domain.xnd)."}
    label = dom[:-4]
    if len(label) <= 4:
        return {"domain": dom, "available": False, "reason": "Reserved 1–4 character .xnd domain"}
    if dom in store.domains or _try_resolve_from_nostr(dom):
        return {"domain": dom, "available": False, "reason": "Already registered on the .xnd network"}
    return {"domain": dom, "available": True, "reason": "Available for registration"}


class DomainRegisterRequest(BaseModel):
    domain: str


@app.post("/api/domain/register")
def register_domain(req: DomainRegisterRequest, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    dom = normalize_xnd_domain(req.domain, append_tld=True)
    if not dom or len(dom) > 253 or not DOMAIN_RE.match(dom):
        raise HTTPException(status_code=400, detail="Invalid .xnd domain. Only letters, numbers, '-' and '.' between labels are allowed (e.g. domain-name.xnd or sub.domain.xnd).")
    label = dom[:-4]
    if len(label) <= 4:
        raise HTTPException(status_code=400, detail="Reserved 1–4 character .xnd domain")
    if dom in store.domains or _try_resolve_from_nostr(dom):
        raise HTTPException(status_code=409, detail="Name taken — claim another")

    starter_html = (
        f"<!doctype html><html><head><meta charset='utf-8'><title>{dom}</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:64px auto;padding:0 20px;line-height:1.6;color:#0f172a;}"
        "code{background:#f1f5f9;padding:2px 6px;border-radius:6px;}</style></head>"
        f"<body><h1>{dom}</h1><p>Welcome to <code>{dom}</code> on the XND New Internet.</p>"
        "<p>This domain is sovereignly registered with an Ed25519 keypair. Push your website files from the Xanadu Dashboard.</p>"
        "</body></html>"
    )
    res = publish_capsule(dom, dom, {"index.html": starter_html}, "", None, "", privkey_hex="")
    priv_hex = store.domains.get(dom, {}).get("privkey_hex", "")
    pub_hex = store.domains.get(dom, {}).get("pubkey_hex", "")
    if _vault_unlocked:
        _save_vault()
    try:
        blob_txt = store.get_blob(res.get("sha256", "")) or ""
        vnum = int(res["version"])
        if dom and pub_hex and res.get("signature") and blob_txt:
            threading.Thread(
                target=announce_doc_nostr,
                args=(dom, vnum, dom, res["sha256"], pub_hex, res["signature"], blob_txt, True),
                daemon=True,
            ).start()
    except Exception:
        pass
    return {
        "ok": True,
        "domain": dom,
        "pubkey_hex": pub_hex,
        "privkey_hex": priv_hex,
        "version": int(res.get("version_num", res.get("version", 1))),
        "is_new_domain": True,
    }


@app.get("/api/keys/export/{domain}")
def export_domain_key(domain: str, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    if _account_path().exists() and not _vault_unlocked:
        raise HTTPException(status_code=403, detail="Account vault is locked. Unlock your Dashboard first.")
    dom = store.domains.get(domain.strip().lower())
    if dom is None:
        raise HTTPException(status_code=404, detail="Domain not found")
    if not dom.get("privkey_hex"):
        raise HTTPException(status_code=403, detail="This node does not hold the private key for this domain")
    return {"domain": dom["name"], "pubkey_hex": dom["pubkey_hex"], "privkey_hex": dom["privkey_hex"]}


@app.get("/api/keys/download/{domain}")
def download_domain_key(domain: str, request: Request) -> Response:
    data = export_domain_key(domain, request)
    fname = f"{data['domain']}.key.json"
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.post("/api/keys/import")
def import_domain_key(req: KeyImportRequest, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    domain = normalize_xnd_domain(req.domain, append_tld=True)
    if not DOMAIN_RE.match(domain) or len(domain) > 253:
        raise HTTPException(status_code=400, detail="Invalid .xnd domain. Only letters, numbers, '-' and '.' between labels are allowed.")
    try:
        derived_pub = pubkey_from_priv_hex(req.privkey_hex.strip())
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Ed25519 private key hex")

    if domain not in store.domains:
        _try_resolve_from_nostr(domain)
    existing = store.domains.get(domain)
    if existing is not None and existing["pubkey_hex"] != derived_pub:
        raise HTTPException(status_code=403, detail="Private key does not match the registered public key")
    store.import_domain_key(domain, derived_pub, req.privkey_hex.strip())
    if _vault_unlocked:
        _save_vault()
    return {"ok": True, "domain": domain, "pubkey_hex": derived_pub}


@app.post("/api/keys/rotate/{domain}")
async def rotate_domain_key(domain: str, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    if _account_path().exists() and not _vault_unlocked:
        raise HTTPException(status_code=403, detail="Account vault is locked. Unlock your Dashboard first.")
    dom = normalize_xnd_domain(domain, append_tld=True)
    if not DOMAIN_RE.match(dom) or len(dom) > 253:
        raise HTTPException(status_code=400, detail="Invalid .xnd domain.")
    existing = store.domains.get(dom)
    if existing is None:
        raise HTTPException(status_code=404, detail="Domain not found")
    if not existing.get("privkey_hex"):
        raise HTTPException(status_code=403, detail="This node does not hold the private key for this domain")
    try:
        body = await request.json()
    except Exception:
        body = {}
    custom_priv = str((body or {}).get("new_privkey_hex") or "").strip()
    if custom_priv:
        try:
            new_pub = pubkey_from_priv_hex(custom_priv)
            new_priv = custom_priv
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid Ed25519 private key hex")
    else:
        new_pub, new_priv = generate_keypair()
    store.import_domain_key(dom, new_pub, new_priv)
    trust_store.set_pin(dom, new_pub, source="self")
    if _vault_unlocked:
        _save_vault()
    return {"ok": True, "domain": dom, "pubkey_hex": new_pub, "privkey_hex": new_priv}


class GitHubConnectRequest(BaseModel):
    token: str


class GitHubDevicePollRequest(BaseModel):
    device_code: str


class GitHubDeployRequest(BaseModel):
    repo: str
    branch: str = ""
    subdir: str = ""
    domain: str
    title: str = ""
    privkey_hex: str = ""


class GitHubDetachRequest(BaseModel):
    domain: str
    privkey_hex: str


class GitHubActionRequest(BaseModel):
    repo: str
    branch: str = ""


class GitHubPushRequest(BaseModel):
    repo: str
    branch: str = ""
    subdir: str = ""
    domain: str
    message: str = "Update site from Xanadu"


@app.get("/api/github/status")
def api_github_status(request: Request) -> dict[str, Any]:
    _require_localhost(request)
    return gh_hosting.get_status()


@app.post("/api/github/connect")
def api_github_connect(req: GitHubConnectRequest, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    try:
        return {"ok": True, **gh_hosting.connect(req.token)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/github/disconnect")
def api_github_disconnect(request: Request) -> dict[str, Any]:
    _require_localhost(request)
    return gh_hosting.disconnect()


@app.post("/api/github/device/start")
def api_github_device_start(request: Request) -> dict[str, Any]:
    _require_localhost(request)
    try:
        return gh_hosting.start_device_flow()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/github/device/poll")
def api_github_device_poll(req: GitHubDevicePollRequest, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    try:
        return gh_hosting.poll_device_flow(req.device_code)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/github/repos")
def api_github_repos(request: Request) -> dict[str, Any]:
    _require_localhost(request)
    try:
        return {"repos": gh_hosting.list_repos()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/github/deploy")
def api_github_deploy(req: GitHubDeployRequest, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    dom = normalize_xnd_domain(req.domain, append_tld=True)
    if not dom or len(dom) > 253 or not DOMAIN_RE.match(dom):
        raise HTTPException(status_code=400, detail="Invalid .xnd domain.")
    links = gh_hosting.load_links()
    existing_link = links.get(dom)
    clean_repo_lower = (req.repo or "").strip().lower()
    if existing_link and existing_link.get("repo", "").lower() != clean_repo_lower:
        raise HTTPException(
            status_code=409,
            detail=f"Domain '{dom}' is permanently locked to '{existing_link['repo']}'. Detach it first using the Domain Private Key.",
        )
    for other_dom, link_info in links.items():
        if other_dom != dom and (link_info.get("repo", "").strip().lower() == clean_repo_lower):
            raise HTTPException(
                status_code=409,
                detail=f"Repository '{req.repo}' is already locked to '{other_dom}'. Detach '{other_dom}' first using its Domain Private Key.",
            )
    try:
        files, backend_py, used_branch = gh_hosting.fetch_repo_bundle(req.repo, req.branch, req.subdir)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    effective_priv = req.privkey_hex.strip()
    if not effective_priv and dom in store.domains:
        effective_priv = store.domains[dom].get("privkey_hex", "")
    res = publish_capsule(dom, req.title.strip() or dom, files, backend_py, None, "", privkey_hex=effective_priv)
    if _vault_unlocked:
        _save_vault()
    try:
        pub_hex = store.domains.get(dom, {}).get("pubkey_hex", "")
        blob_txt = store.get_blob(res.get("sha256", "")) or ""
        if dom and pub_hex and res.get("signature") and blob_txt:
            threading.Thread(
                target=announce_doc_nostr,
                args=(dom, int(res["version"]), req.title.strip() or dom, res["sha256"], pub_hex, res["signature"], blob_txt, True),
                daemon=True,
            ).start()
    except Exception:
        pass
    out_res: dict[str, Any] = {
        "ok": True,
        **res,
        "repo": req.repo,
        "branch": used_branch,
        "files_count": len(files),
        "auto_sync": True,
    }
    sha = ""
    try:
        sha = gh_hosting.get_latest_commit_sha(req.repo, used_branch)
    except Exception:
        pass
    try:
        gh_hosting.save_link(dom, req.repo, used_branch, req.subdir, sha)
    except Exception:
        pass
    if int(res.get("version", 0)) == 1 and store.domains.get(dom, {}).get("privkey_hex"):
        out_res["privkey_hex"] = store.domains[dom]["privkey_hex"]
        out_res["is_new_domain"] = True
    return out_res


@app.get("/api/github/links")
def api_github_links(request: Request) -> dict[str, Any]:
    _require_localhost(request)
    return {"links": gh_hosting.load_links()}


@app.post("/api/github/detach")
def api_github_detach(req: GitHubDetachRequest, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    dom = normalize_xnd_domain(req.domain, append_tld=True)
    if not dom or not DOMAIN_RE.match(dom):
        raise HTTPException(status_code=400, detail="Invalid .xnd domain.")
    priv = (req.privkey_hex or "").strip()
    if len(priv) < 64:
        raise HTTPException(status_code=400, detail="Valid Domain Private Key is required to detach.")
    try:
        derived_pub = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv[:64])).public_key().public_bytes_raw().hex()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Ed25519 private key.")
    expected_pub = store.domains.get(dom, {}).get("pubkey_hex", "")
    if not expected_pub:
        row = store.get_version(dom, None)
        expected_pub = row.get("pubkey_hex", "") if row else ""
    if not expected_pub or derived_pub != expected_pub:
        raise HTTPException(status_code=403, detail="Private key does not match this domain.")
    gh_hosting.remove_link(dom)
    return {"ok": True, "domain": dom, "detached": True}


@app.post("/api/github/setup-action")
def api_github_setup_action(req: GitHubActionRequest, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    try:
        return gh_hosting.install_build_workflow(req.repo, req.branch)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/github/push")
def api_github_push(req: GitHubPushRequest, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    dom = normalize_xnd_domain(req.domain, append_tld=True)
    row = store.get_version(dom, None)
    if not row:
        raise HTTPException(status_code=404, detail="Domain not found locally")
    blob = store.get_blob(row.get("sha256", "")) or ""
    files: dict[str, str] = {}
    backend_py = ""
    if (row.get("kind") or "") == "capsule":
        try:
            parsed = json.loads(blob)
            files = dict(parsed.get("files") or {})
            backend_py = str(parsed.get("backend_py") or "")
        except Exception:
            files = {"index.html": blob}
    else:
        files = {"content.txt": blob}
    try:
        return gh_hosting.push_files_to_repo(req.repo, req.branch, req.subdir, files, backend_py, req.message)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


_WWW_BRIDGE_JS = """<script>
(function(){
  document.addEventListener("click", function(e) {
    var a = e.target && e.target.closest ? e.target.closest("a[href]") : null;
    if (!a) return;
    var href = a.getAttribute("href") || "";
    if (!href || href.startsWith("#") || href.startsWith("javascript:") || href.startsWith("mailto:")) return;
    e.preventDefault();
    try {
      var resolved = new URL(href, document.baseURI).href;
      window.parent.postMessage({ type: "xnd-www-navigate", url: resolved }, "*");
    } catch (_) {}
  }, true);
  document.addEventListener("submit", function(e) {
    var form = e.target;
    if (!form || form.tagName !== "FORM") return;
    if ((form.method || "get").toLowerCase() !== "get") return;
    e.preventDefault();
    try {
      var u = new URL(form.getAttribute("action") || document.baseURI, document.baseURI);
      var fd = new FormData(form);
      for (var pair of fd.entries()) { u.searchParams.set(pair[0], pair[1]); }
      window.parent.postMessage({ type: "xnd-www-navigate", url: u.href }, "*");
    } catch (_) {}
  }, true);
  document.addEventListener("mouseup", function() {
    var sel = (window.getSelection ? window.getSelection().toString() : "").trim();
    if (sel) {
      window.parent.postMessage({ type: "xnd-www-selection", text: sel, url: location.href, title: document.title }, "*");
    }
  });
})();
</script>"""


@app.get("/api/www")
def proxy_live_www(url: str = Query(...)) -> Response:
    target = url.strip()
    if not target:
        raise HTTPException(status_code=400, detail="URL is required")
    if not target.lower().startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid HTTP/HTTPS URL")

    req = urllib.request.Request(
        target,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            effective_url = resp.geturl() or target
            ctype = resp.headers.get("Content-Type", "text/html; charset=utf-8")
            raw_bytes = resp.read(2_000_000)
    except urllib.error.HTTPError as he:
        effective_url = he.geturl() or target
        ctype = he.headers.get("Content-Type", "text/html; charset=utf-8") if he.headers else "text/html"
        raw_bytes = he.read(512_000) if hasattr(he, "read") else b""
        if not raw_bytes or "html" not in ctype.lower():
            return HTMLResponse(
                content=f"<html><body style='font-family:system-ui;padding:32px;background:#0f172a;color:#e2e8f0;'>"
                f"<h2>Live Site Returned HTTP {he.code}</h2>"
                f"<p>Target: <code>{html.escape(target)}</code></p>"
                f"<p>Some sites (like X.com or Cloudflare-protected portals) block automated proxy requests from localhost.</p>"
                f"<p><a href='{html.escape(target)}' target='_blank' rel='noopener' style='color:#38bdf8;'>Open {html.escape(target)} directly in a new tab ↗</a></p>"
                f"</body></html>",
                status_code=200,
            )
    except Exception as exc:
        return HTMLResponse(
            content=f"<html><body style='font-family:system-ui;padding:32px;background:#0f172a;color:#e2e8f0;'>"
            f"<h2>Could Not Load {html.escape(target)}</h2>"
            f"<p>{html.escape(str(exc))}</p>"
            f"</body></html>",
            status_code=200,
        )

    if "html" not in ctype.lower():
        return Response(content=raw_bytes, media_type=ctype.split(";")[0].strip())

    text = raw_bytes.decode("utf-8", errors="replace")
    # Remove meta CSP / X-Frame-Options that would block rendering inside Xanadu's viewport
    text = re.sub(r'<meta[^>]+http-equiv=["\']?(Content-Security-Policy|X-Frame-Options)["\']?[^>]*>', "", text, flags=re.IGNORECASE)
    base_tag = f'<base href="{html.escape(effective_url, quote=True)}">'
    if re.search(r"<head[^>]*>", text, re.IGNORECASE):
        text = re.sub(r"(<head[^>]*>)", r"\1\n" + base_tag, text, count=1, flags=re.IGNORECASE)
    else:
        text = base_tag + "\n" + text

    if re.search(r"</body>", text, re.IGNORECASE):
        text = re.sub(r"(</body>)", _WWW_BRIDGE_JS + r"\n\1", text, count=1, flags=re.IGNORECASE)
    else:
        text = text + "\n" + _WWW_BRIDGE_JS

    return HTMLResponse(content=text)


@app.post("/api/archive_url")
def archive_web_url(req: ArchiveUrlRequest) -> dict[str, Any]:
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url
    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        with urllib.request.urlopen(request, timeout=10) as resp:
            raw_html = resp.read(512_000).decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch URL: {exc}")

    parser = _TextExtractor()
    parser.feed(raw_html)
    title = html.unescape("".join(parser.title_parts).strip()) or url
    body_text = html.unescape("".join(parser.text_parts))
    clean_lines = [line.strip() for line in body_text.splitlines() if line.strip()]
    snapshot = f"Archived from: {url}\n\n" + "\n".join(clean_lines)[:18000]

    target_domain = req.domain.strip().lower()
    if target_domain:
        if target_domain.endswith(".xnd"):
            target_domain = target_domain[:-4]
        clean_label = re.sub(r"[^a-z0-9\-]+", "-", target_domain).strip("-")[:63]
        target_domain = f"{clean_label}.xnd" if clean_label else ""
    if not target_domain:
        target_domain = f"web-{rust_sha256(url)[:8]}.xnd"

    # Store external web snapshots in the bounded pruned cache!
    return {"ok": True, **publish_document(target_domain, f"[Archive] {title[:80]}", snapshot, pinned=False)}


@app.post("/api/visit")
def visit_any_domain(req: ArchiveUrlRequest) -> dict[str, Any]:
    raw = req.url.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Domain or URL required")
    url = raw if (raw.startswith("http://") or raw.startswith("https://")) else f"https://{raw}"
    host = urllib.parse.urlparse(url).netloc.lower().split(":")[0]
    clean_label = re.sub(r"[^a-z0-9\-]+", "-", host).strip("-")[:63]
    xnd_domain = f"{clean_label}.xnd" if clean_label else f"web-{rust_sha256(url)[:8]}.xnd"

    existing = store.get_version(xnd_domain, None)
    if existing is not None and store.get_blob(existing["sha256"]) is not None:
        return {"ok": True, "domain": xnd_domain, "cached": True}

    res = archive_web_url(ArchiveUrlRequest(url=url, domain=xnd_domain))
    return {"ok": True, "domain": res["domain"], "cached": False}


@app.post("/api/assets")
def upload_asset(req: AssetUploadRequest) -> dict[str, Any]:
    try:
        raw = base64.b64decode(req.data_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 asset data")
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Asset exceeds 5 MB limit")
    sha256 = hashlib.sha256(raw).hexdigest()
    safe_name = os.path.basename(req.filename.strip()) or "asset.bin"
    store.put_asset(sha256, safe_name, req.mime_type.strip() or "application/octet-stream", raw)
    return {"ok": True, "sha256": sha256, "url": f"/xnd-asset/{sha256}", "bytes": len(raw)}


@app.get("/xnd-asset/{sha256}")
def serve_asset(sha256: str) -> Response:
    res = store.get_asset(sha256.strip().lower())
    if res is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return Response(content=res[1], media_type=res[0], headers={"Cache-Control": "public, max-age=31536000, immutable"})


def export_domain_bundle(domain: str) -> dict[str, Any]:
    clean = normalize_xnd_domain(domain, append_tld=True)
    dom_obj = store.domains.get(clean)
    vers = list(store.versions.get(clean, []))
    if not dom_obj or not vers:
        return {"domains": [], "blobs": [], "versions": [], "links": [], "assets": [], "forum_posts": [], "wiki_shards": []}
    blobs = []
    seen_blobs: set[str] = set()
    for v in vers:
        sha = v["sha256"]
        if sha not in seen_blobs:
            txt = store.get_blob(sha)
            if txt is not None:
                blobs.append({"sha256": sha, "content": txt, "created_at": v["created_at"]})
                seen_blobs.add(sha)
    return {
        "domains": [{"name": dom_obj["name"], "pubkey_hex": dom_obj["pubkey_hex"], "created_at": dom_obj["created_at"]}],
        "blobs": blobs,
        "versions": vers,
        "links": [lk for lk in store.all_links if lk.get("source_domain") == clean],
        "assets": [],
        "forum_posts": [],
        "wiki_shards": [],
    }


@app.get("/api/sync/manifest")
def sync_manifest() -> dict[str, Any]:
    dom_map: dict[str, dict[str, Any]] = {}
    for dom, dom_obj in list(store.domains.items()):
        vers = store.versions.get(dom, [])
        if not vers:
            continue
        latest = vers[-1]
        dom_map[dom] = {
            "latest_version": int(latest.get("version_num", 1)),
            "sha256": latest.get("sha256", ""),
            "pubkey_hex": dom_obj.get("pubkey_hex", ""),
        }
    return {
        "ok": True,
        "node_id": _get_node_id(),
        "label": os.environ.get("XND_NODE_LABEL", "Xanadu Desktop"),
        "has_wan": _check_has_wan(),
        "share_gateway": _SHARE_GATEWAY,
        "seed_node": bool(_SHARE_GATEWAY and _check_has_wan()),
        "dht_k": 3,
        "domains": dom_map,
        "mesh_bytes": store.get_cache_bytes(),
        "mesh_quota_bytes": MAX_CACHE_BYTES,
    }


@app.get("/api/gateway/status")
def api_gateway_status() -> dict[str, Any]:
    has_wan = _check_has_wan()
    gw = None if has_wan else _find_lan_gateway()
    return {
        "ok": True,
        "has_wan": has_wan,
        "share_gateway": _SHARE_GATEWAY,
        "active_gateway": gw,
    }


class GatewayToggleRequest(BaseModel):
    share_gateway: bool


@app.post("/api/gateway/toggle")
def api_gateway_toggle(req: GatewayToggleRequest, request: Request) -> dict[str, Any]:
    global _SHARE_GATEWAY
    _require_localhost(request)
    _SHARE_GATEWAY = bool(req.share_gateway)
    return {"ok": True, "share_gateway": _SHARE_GATEWAY}


@app.get("/api/gateway/lookup")
def api_gateway_lookup(domain: str = Query(default="")) -> dict[str, Any]:
    if not _SHARE_GATEWAY:
        raise HTTPException(status_code=403, detail="Mesh gateway sharing disabled")
    clean = normalize_xnd_domain(domain, append_tld=True)
    if not clean:
        raise HTTPException(status_code=400, detail="Missing domain")
    if clean not in store.domains or not store.versions.get(clean):
        _try_resolve_from_nostr(clean)
    bundle = export_domain_bundle(clean)
    if not bundle.get("versions"):
        raise HTTPException(status_code=404, detail="Domain not found")
    return bundle


@app.get("/api/gateway/search")
def api_gateway_search(q: str = Query(default=""), scope: str = Query(default="all")) -> dict[str, Any]:
    if not _SHARE_GATEWAY:
        raise HTTPException(status_code=403, detail="Mesh gateway sharing disabled")
    return search(q=q, fast=0, scope=scope)


@app.post("/api/gateway/nostr_publish")
def api_gateway_nostr_publish(payload: dict[str, Any]) -> dict[str, Any]:
    if not _SHARE_GATEWAY:
        raise HTTPException(status_code=403, detail="Mesh gateway sharing disabled")
    ev = payload.get("event")
    if not isinstance(ev, dict) or not ev.get("id") or not ev.get("sig") or not ev.get("pubkey"):
        raise HTTPException(status_code=400, detail="Invalid Nostr event")
    import p2p_discovery
    msg = json.dumps(["EVENT", ev], separators=(",", ":"))
    accepted = 0
    for r_url in p2p_discovery.DEFAULT_RELAYS:
        try:
            ws = p2p_discovery._ws_connect(r_url, timeout=3.0)
            p2p_discovery._ws_send_text(ws, msg)
            ack = p2p_discovery._ws_recv_text(ws)
            ws.close()
            if ack and '"OK"' in ack and "true" in ack:
                accepted += 1
        except Exception:
            pass
    return {"ok": accepted > 0, "accepted": accepted}


def _proxy_fetch_url(target_url: str, browse_prefix: str, method: str = "GET", body: bytes = b"") -> Response:
    if not _is_safe_public_url(target_url):
        raise HTTPException(status_code=400, detail="Invalid or restricted URL")
    try:
        with httpx.Client(timeout=12.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"}) as hc:
            if method.upper() == "POST":
                r = hc.post(target_url, content=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
            else:
                r = hc.get(target_url)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Upstream fetch failed: {e}")
    ctype = (r.headers.get("content-type") or "application/octet-stream").split(";")[0].strip().lower()
    raw = r.content[: 4 * 1024 * 1024]
    final_url = str(r.url)
    if ctype == "text/html":
        txt = raw.decode("utf-8", errors="replace")
        def _rw_attr(m: re.Match[str]) -> str:
            attr, q, u = m.group(1), m.group(2), m.group(3)
            if not u or u.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
                return m.group(0)
            abs_u = urllib.parse.urljoin(final_url, u)
            if abs_u.startswith(("http://", "https://")):
                return f"{attr}={q}{browse_prefix}{urllib.parse.quote(abs_u, safe='')}{q}"
            return m.group(0)
        txt = re.sub(r'(?i)\b(href|src|action|poster|data-src)\s*=\s*(["\'])([^"\']*)\2', _rw_attr, txt)
        txt = re.sub(r'(?i)\s+integrity\s*=\s*(["\'])[^"\']*\1', "", txt)
        txt = re.sub(r'(?i)<meta[^>]+http-equiv\s*=\s*(["\'])Content-Security-Policy\1[^>]*>', "", txt)
        base_tag = f'<base href="{html.escape(final_url)}">' if "<base " not in txt.lower() else ""
        web_shim = (
            f"<script>(function(){{var bp={json.dumps(browse_prefix)},bu={json.dumps(final_url)};"
            "function rw(u){try{if(!u||typeof u!=='string')return u;if(u.startsWith(bp)||u.startsWith('data:')||u.startsWith('javascript:')||u.startsWith('#'))return u;var a=new URL(u,bu).href;if(a.startsWith('http://')||a.startsWith('https://'))return bp+encodeURIComponent(a);}catch(e){}return u;}"
            "var _f=window.fetch;if(_f){window.fetch=function(i,o){if(typeof i==='string')i=rw(i);return _f.call(this,i,o);};}"
            "var _o=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=rw(u);return _o.apply(this,arguments);};"
            "})();</script>"
        )
        inject_head = base_tag + web_shim
        if re.search(r"(?i)<head\b[^>]*>", txt):
            txt = re.sub(r"(?i)(<head\b[^>]*>)", lambda m: m.group(1) + inject_head, txt, count=1)
        else:
            txt = inject_head + txt
        return Response(content=txt, media_type="text/html")
    if ctype == "text/css":
        css = raw.decode("utf-8", errors="replace")
        def _rw_css(m: re.Match[str]) -> str:
            q, u = m.group(1), m.group(2).strip()
            if not u or u.startswith(("data:", "#")):
                return m.group(0)
            abs_u = urllib.parse.urljoin(final_url, u)
            if abs_u.startswith(("http://", "https://")):
                return f"url({q}{browse_prefix}{urllib.parse.quote(abs_u, safe='')}{q})"
            return m.group(0)
        css = re.sub(r'url\(\s*(["\']?)([^"\')]+)\1\s*\)', _rw_css, css)
        return Response(content=css, media_type="text/css")
    return Response(content=raw, media_type=ctype)


@app.api_route("/api/gateway/fetch", methods=["GET", "POST"])
async def api_gateway_fetch(request: Request, url: str = Query(default="")) -> Response:
    if not _SHARE_GATEWAY:
        raise HTTPException(status_code=403, detail="Mesh gateway sharing disabled")
    body = await request.body() if request.method == "POST" else b""
    return _proxy_fetch_url(url.strip(), "/api/web/browse?url=", request.method, body)


@app.api_route("/api/web/browse", methods=["GET", "POST"])
async def api_web_browse(request: Request, url: str = Query(default="")) -> Response:
    clean = url.strip()
    if not clean.startswith(("http://", "https://")):
        clean = "https://" + clean
    body = await request.body() if request.method == "POST" else b""
    if _check_has_wan():
        return _proxy_fetch_url(clean, "/api/web/browse?url=", request.method, body)
    gw = _find_lan_gateway()
    if not gw:
        raise HTTPException(status_code=503, detail="Offline and no LAN Mesh Gateway peer found")
    try:
        q_u = urllib.parse.quote(clean, safe="")
        with httpx.Client(timeout=14.0) as hc:
            if request.method == "POST":
                r = hc.post(f"{gw['url']}/api/gateway/fetch?url={q_u}", content=body)
            else:
                r = hc.get(f"{gw['url']}/api/gateway/fetch?url={q_u}")
        if r.status_code == 403:
            _invalidate_lan_gateway(gw["url"])
        ctype = r.headers.get("content-type", "text/html")
        return Response(content=r.content, status_code=r.status_code, media_type=ctype.split(";")[0].strip())
    except Exception as e:
        _invalidate_lan_gateway(gw["url"])
        raise HTTPException(status_code=502, detail=f"Mesh gateway error: {e}")


@app.get("/api/sync/export")
def sync_export(domain: str = "") -> dict[str, Any]:
    if domain.strip():
        return export_domain_bundle(domain)
    domains = [{"name": d["name"], "pubkey_hex": d["pubkey_hex"], "created_at": d["created_at"]} for d in store.domains.values()]
    versions = []
    blobs = []
    seen_blobs = set()
    for vers in store.versions.values():
        for v in vers:
            versions.append(v)
            sha = v["sha256"]
            if sha not in seen_blobs:
                txt = store.get_blob(sha)
                if txt is not None:
                    blobs.append({"sha256": sha, "content": txt, "created_at": v["created_at"]})
                    seen_blobs.add(sha)
    assets = []
    for am in store.list_assets_meta():
        got = store.get_asset(am["sha256"])
        if got:
            assets.append({"sha256": am["sha256"], "filename": am["filename"], "mime_type": am["mime_type"], "data_b64": base64.b64encode(got[1]).decode("ascii"), "created_at": am["created_at"]})
    forum_posts = list(store.get_capsule_state("forum.xnd").get("posts", []))[-150:]
    wiki_shards = scrapers.export_wiki_shards(120)
    return {
        "domains": domains,
        "blobs": blobs,
        "versions": versions,
        "links": store.all_links,
        "assets": assets,
        "forum_posts": forum_posts,
        "crdt_events": crdt_log.export_events(),
        "wiki_shards": wiki_shards,
        "qa_patterns": pattern_mem.export_patterns(),
    }


def _collision_alias(domain: str, pub_hex: str) -> str:
    return _canonical_domain_for(domain, pub_hex)


MIN_VALID_DOMAIN_TS = 1_577_836_800.0  # 2020-01-01T00:00:00Z


def _archive_displaced_local_domain(domain: str, dom_rec: dict[str, Any], versions: list[dict[str, Any]]) -> None:
    """Safely archive an offline-created local domain before yielding its public name."""
    try:
        pub = str(dom_rec.get("pubkey_hex") or "")[:8] or "local"
        arch_dir = DATA_DIR / "state" / "conflict_archive"
        arch_dir.mkdir(parents=True, exist_ok=True)
        arch_path = arch_dir / f"{domain}.{pub}.json"
        blobs = {}
        for ev in versions:
            sha = str(ev.get("sha256") or "")
            if sha and sha not in blobs:
                txt = store.get_blob(sha)
                if txt is not None:
                    blobs[sha] = txt
        payload = {
            "domain": domain,
            "archived_at": time.time(),
            "domain_record": dom_rec,
            "versions": versions,
            "blobs": blobs,
        }
        arch_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        pass


def _purge_collision_aliases() -> int:
    """Erase any legacy ~pubkey collision aliases from the local store and trust conflicts."""
    removed = 0
    for dom_name in [d for d in list(store.domains.keys()) if "~" in d]:
        if store.delete_domain(dom_name):
            removed += 1
    if trust_store.conflicts:
        with trust_store._lock:
            trust_store.conflicts.clear()
            trust_store._save()
    return removed


def import_sync_bundle(bundle: dict[str, Any], ignore_follow_filter: bool = False) -> dict[str, int]:
    _purge_collision_aliases()
    blobs_map = {b["sha256"]: b["content"] for b in bundle.get("blobs", [])}
    pubkeys_map = {d["name"]: d["pubkey_hex"] for d in bundle.get("domains", [])}
    domain_alias: dict[str, str] = {}
    imported_versions = 0
    rejected = 0

    for d in bundle.get("domains", []):
        raw_name = str(d.get("name") or "").strip().lower()
        if not raw_name or "~" in raw_name:
            rejected += 1
            continue
        in_pub = (d.get("pubkey_hex") or "").strip().lower()
        if raw_name in store.blocked_domains or (in_pub and in_pub in store.blocked_pubkeys) or blocklist_mgr.is_blocked(raw_name, in_pub):
            continue
        if not ignore_follow_filter and store.followed_pubkeys and in_pub and in_pub not in store.followed_pubkeys and raw_name not in store.domains:
            continue
        pinned_pub = trust_store.get_pinned_pubkey(raw_name)
        pin_source = trust_store.get_pin_source(raw_name)
        existing = store.domains.get(raw_name)
        expected_pub = pinned_pub or ((existing.get("pubkey_hex") or "").strip().lower() if existing else "")
        in_ts = float(d.get("nostr_ts") or d.get("created_at") or 0.0)
        ex_ts = float((existing or {}).get("nostr_ts") or (existing or {}).get("created_at") or 0.0)
        in_verified = bool(d.get("verified_ts") or d.get("nostr_ts"))
        ex_verified = bool((existing or {}).get("verified_ts") or (existing or {}).get("nostr_ts"))
        locally_owned = bool(existing and existing.get("privkey_hex"))

        if expected_pub and in_pub and expected_pub != in_pub:
            # Earliest verified registration wins:
            # - Reject spoofed pre-2020 timestamps.
            # - Displacing a verified or locally-owned domain requires a verified (e.g. Nostr) timestamp.
            can_displace = (
                pin_source != "manual"
                and in_ts >= MIN_VALID_DOMAIN_TS
                and ex_ts > 0
                and (in_ts + 60.0) < ex_ts
                and (in_verified or (not ex_verified and not locally_owned))
            )
            if can_displace:
                if locally_owned and existing is not None:
                    _archive_displaced_local_domain(raw_name, dict(existing), list(store.versions.get(raw_name, [])))
                store.delete_domain(raw_name)
                store.domains[raw_name] = {
                    "name": raw_name,
                    "pubkey_hex": in_pub,
                    "privkey_hex": "",
                    "created_at": in_ts,
                    "nostr_ts": float(d.get("nostr_ts") or 0.0),
                    "verified_ts": in_verified,
                }
                trust_store.set_pin(raw_name, in_pub, source="consensus_earliest")
                domain_alias[raw_name] = raw_name
            else:
                # Losing duplicate/alias: drop cleanly instead of creating ~pubkey aliases.
                domain_alias[raw_name] = ""
                rejected += 1
        elif existing is None:
            store.domains[raw_name] = {
                "name": raw_name,
                "pubkey_hex": in_pub,
                "privkey_hex": "",
                "created_at": in_ts if in_ts >= MIN_VALID_DOMAIN_TS else time.time(),
                "nostr_ts": float(d.get("nostr_ts") or 0.0),
                "verified_ts": in_verified,
            }
            if in_pub:
                trust_store.ensure_first_seen(raw_name, in_pub, "first_seen")
            domain_alias[raw_name] = raw_name
        elif not existing.get("pubkey_hex") and in_pub:
            existing["pubkey_hex"] = in_pub
            if in_verified:
                existing["verified_ts"] = True
                existing["nostr_ts"] = float(d.get("nostr_ts") or in_ts)
            trust_store.ensure_first_seen(raw_name, in_pub, "first_seen")
            domain_alias[raw_name] = raw_name
        else:
            if in_verified and existing is not None and not existing.get("verified_ts"):
                existing["verified_ts"] = True
                existing["nostr_ts"] = float(d.get("nostr_ts") or in_ts)
            if in_pub:
                trust_store.ensure_first_seen(raw_name, in_pub, "first_seen")
            domain_alias[raw_name] = raw_name

    for v in (bundle.get("versions") or [])[:abuse_guard.MAX_BUNDLE_VERSIONS]:
        orig_domain, sha = str(v.get("domain") or "").strip().lower(), v["sha256"]
        if not orig_domain or "~" in orig_domain:
            rejected += 1
            continue
        target_domain = domain_alias.get(orig_domain, orig_domain)
        if not target_domain or "~" in target_domain:
            rejected += 1
            continue
        content = blobs_map.get(sha)
        pub_hex = store.domains.get(target_domain, {}).get("pubkey_hex") or pubkeys_map.get(orig_domain, "") or v.get("pubkey_hex", "")
        if (
            orig_domain in store.blocked_domains
            or target_domain in store.blocked_domains
            or (pub_hex and pub_hex in store.blocked_pubkeys)
            or blocklist_mgr.is_blocked(orig_domain, pub_hex)
            or blocklist_mgr.is_blocked(target_domain, pub_hex)
        ):
            rejected += 1
            continue
        if not ignore_follow_filter and store.followed_pubkeys and pub_hex and pub_hex not in store.followed_pubkeys and target_domain not in store.domains:
            continue
        prev_sha = str(v.get("prev_sha256", ""))
        ver_num = int(v["version_num"])
        max_sz = abuse_guard.MAX_CAPSULE_BYTES if (v.get("kind") == "capsule" or _is_capsule_blob(content)) else abuse_guard.MAX_BLOB_BYTES
        ok_sz, _ = abuse_guard.check_blob_size(content or "", max_sz)
        if not content or not ok_sz or rust_sha256(content) != sha or not verify_signature(pub_hex, orig_domain, ver_num, sha, v["signature_hex"], prev_sha):
            rejected += 1
            continue
        if prev_sha and ver_num > 1:
            local_prev = store.get_version(target_domain, ver_num - 1)
            if local_prev is not None and str(local_prev.get("sha256", "")) != prev_sha:
                rejected += 1
                continue
        v_copy = dict(v)
        v_copy["domain"] = target_domain
        v_copy["pubkey_hex"] = v_copy.get("pubkey_hex") or pub_hex
        v_copy["kind"] = v_copy.get("kind") or ("capsule" if (v_copy.get("is_app") or _is_capsule_blob(content)) else "document")
        if v_copy["kind"] == "capsule":
            v_copy["is_app"] = True
        v_copy["title"] = v_copy.get("title") or target_domain
        if store.append_version(v_copy, content, pinned=False):
            imported_versions += 1
            _notify_domain_updated(target_domain, ver_num)

    for a in bundle.get("assets", []):
        try:
            raw = base64.b64decode(a["data_b64"], validate=True)
            if hashlib.sha256(raw).hexdigest() != a["sha256"]:
                rejected += 1
                continue
            store.put_asset(a["sha256"], a["filename"], a["mime_type"], raw)
        except Exception:
            rejected += 1

    for lk in bundle.get("links", []):
        store.append_link(lk)

    if isinstance(bundle.get("crdt_events"), list) and bundle["crdt_events"]:
        crdt_log.merge_events(bundle["crdt_events"])

    imported_forum_posts = 0
    in_posts = bundle.get("forum_posts", [])
    if isinstance(in_posts, list) and in_posts:
        f_state = store.get_capsule_state("forum.xnd")
        cur_posts = list(f_state.get("posts", []))
        seen_fp = {(str(p.get("author", "")), str(p.get("text", "")), str(p.get("created_at", ""))) for p in cur_posts if isinstance(p, dict)}
        for p in in_posts:
            if not isinstance(p, dict) or not str(p.get("text", "")).strip():
                continue
            key = (str(p.get("author", "")), str(p.get("text", "")), str(p.get("created_at", "")))
            if key not in seen_fp:
                seen_fp.add(key)
                cur_posts.append(p)
                imported_forum_posts += 1
        if imported_forum_posts:
            f_state["posts"] = cur_posts[-500:]
            store.save_capsule_state("forum.xnd", f_state)

    imported_wiki_shards = scrapers.import_wiki_shards(bundle.get("wiki_shards", []), store)

    if isinstance(bundle.get("qa_patterns"), dict):
        pattern_mem.import_patterns(bundle["qa_patterns"])
    return {
        "imported_versions": imported_versions,
        "imported_forum_posts": imported_forum_posts,
        "imported_wiki_shards": imported_wiki_shards,
        "rejected": rejected,
    }


@app.post("/api/sync/import")
async def sync_import(request: Request) -> dict[str, Any]:
    return {"ok": True, **import_sync_bundle(await request.json())}


class ModerationRequest(BaseModel):
    domain: str = ""
    pubkey_hex: str = ""


class PeerSubscribeRequest(BaseModel):
    url: str
    subscribed: bool = True


@app.get("/api/moderation")
def get_moderation() -> dict[str, Any]:
    return {
        "blocked_domains": sorted(store.blocked_domains),
        "blocked_pubkeys": sorted(store.blocked_pubkeys),
        "followed_pubkeys": sorted(store.followed_pubkeys),
    }


@app.post("/api/moderation/block")
def block_content(req: ModerationRequest) -> dict[str, Any]:
    dom = req.domain.strip().lower()
    pub = req.pubkey_hex.strip().lower()
    if dom:
        store.blocked_domains.add(dom)
        store.delete_domain(dom)
    if pub:
        store.blocked_pubkeys.add(pub)
        for d_name, d_obj in list(store.domains.items()):
            if d_obj.get("pubkey_hex", "").lower() == pub:
                store.delete_domain(d_name)
    store.save_moderation()
    return {"ok": True, **get_moderation()}


@app.post("/api/moderation/unblock")
def unblock_content(req: ModerationRequest) -> dict[str, Any]:
    dom = req.domain.strip().lower()
    pub = req.pubkey_hex.strip().lower()
    if dom:
        store.blocked_domains.discard(dom)
    if pub:
        store.blocked_pubkeys.discard(pub)
    store.save_moderation()
    return {"ok": True, **get_moderation()}


@app.post("/api/moderation/delete_domain")
def delete_local_domain(req: ModerationRequest) -> dict[str, Any]:
    dom = req.domain.strip().lower()
    deleted = store.delete_domain(dom) if dom else False
    return {"ok": True, "deleted": deleted, "domain": dom}


@app.post("/api/moderation/follow")
def follow_pubkey(req: ModerationRequest) -> dict[str, Any]:
    pub = req.pubkey_hex.strip().lower()
    if pub:
        if pub in store.followed_pubkeys:
            store.followed_pubkeys.discard(pub)
        else:
            store.followed_pubkeys.add(pub)
        store.save_moderation()
    return {"ok": True, **get_moderation()}


@app.post("/api/peers/subscribe")
def subscribe_peer(req: PeerSubscribeRequest) -> dict[str, Any]:
    u = req.url.strip().rstrip("/")
    if u in store.peers:
        p = store.peers[u]
        store.save_peer(u, p.get("label", "Peer"), p.get("last_sync", 0.0), subscribed=req.subscribed)
    return {"ok": True, "peers": list(store.peers.values())}


@app.get("/api/peers")
def get_peers() -> dict[str, Any]:
    return {"peers": list(store.peers.values()), "gossip": gossip_stats, "storage": store.storage_stats()}


@app.post("/api/peers/pull")
def pull_peer(req: PeerRequest) -> dict[str, Any]:
    peer_url = req.url.rstrip("/")
    try:
        stats = _pull_from_peer_sync(peer_url, req.label)
        return {"ok": True, "peer": peer_url, **stats}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to reach peer {peer_url}: {exc}")


class BookmarkRequest(BaseModel):
    url: str
    title: str = ""
    kind: str = "www"


class HistoryRequest(BaseModel):
    url: str
    title: str = ""
    kind: str = "www"


class ClipQuoteRequest(BaseModel):
    url: str
    title: str = ""
    quote: str
    domain: str = ""


@app.get("/api/bookmarks")
def api_get_bookmarks() -> dict[str, Any]:
    return {"bookmarks": store.get_bookmarks()}


@app.post("/api/bookmarks")
def api_add_bookmark(req: BookmarkRequest) -> dict[str, Any]:
    return {"ok": True, "bookmarks": store.add_bookmark(req.url, req.title, req.kind)}


@app.delete("/api/bookmarks")
def api_delete_bookmark(url: str = Query(...)) -> dict[str, Any]:
    return {"ok": True, "bookmarks": store.remove_bookmark(url)}


@app.get("/api/history")
def api_get_history(q: str = Query(default="")) -> dict[str, Any]:
    return {"history": store.search_history(q)}


@app.post("/api/history")
def api_add_history(req: HistoryRequest) -> dict[str, Any]:
    store.record_history(req.url, req.title, req.kind)
    return {"ok": True}


@app.post("/api/clip")
def api_clip_quote(req: ClipQuoteRequest) -> dict[str, Any]:
    quote = req.quote.strip()
    if not quote:
        raise HTTPException(status_code=400, detail="Selected quote text is required")
    src = req.url.strip() or "https://unknown"
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    target_domain = req.domain.strip().lower()
    if target_domain:
        if not target_domain.endswith(".xnd"):
            target_domain = re.sub(r"[^a-z0-9\-]+", "-", target_domain).strip("-")[:58] + ".xnd"
        if not DOMAIN_RE.match(target_domain):
            raise HTTPException(status_code=400, detail="Invalid .xnd domain")
    else:
        target_domain = f"clip-{rust_sha256(src + quote)[:8]}.xnd"

    existing = store.get_version(target_domain)
    existing_text = store.get_blob(existing["sha256"]) if existing else ""
    clip_block = f"Archived from: {src}\nClipped at: {ts}\n\n> {quote}\n"
    if existing_text:
        new_content = existing_text.rstrip() + "\n\n" + clip_block
    else:
        heading = req.title.strip() or src
        new_content = f"Archived from: {src}\n\n# {heading}\n\nClipped at: {ts}\n\n> {quote}\n"

    res = publish_document(target_domain, f"[Clip] {(req.title or src)[:70]}", new_content, bypass_short_rule=True, pinned=True)
    return {"ok": True, **res, "pointer": f"{{{{xnd://{target_domain}@v{res['version']}:0-{len(new_content)}}}}}"}


@app.get("/api/keys/bundle")
def api_export_key_bundle(request: Request) -> dict[str, Any]:
    _require_localhost(request)
    return {"identities": store.export_owned_identities()}


@app.post("/api/keys/bundle")
async def api_import_key_bundle(request: Request) -> dict[str, Any]:
    _require_localhost(request)
    data = await request.json()
    imported = 0
    for item in data.get("identities", []):
        dom = str(item.get("domain", "")).strip().lower()
        priv = str(item.get("privkey_hex", "")).strip()
        if not DOMAIN_RE.match(dom) or not priv:
            continue
        try:
            pub = pubkey_from_priv_hex(priv)
        except Exception:
            continue
        existing = store.domains.get(dom)
        if existing is not None and existing["pubkey_hex"] != pub:
            continue
        store.import_domain_key(dom, pub, priv)
        imported += 1
    return {"ok": True, "imported": imported}


class KeySyncExportRequest(BaseModel):
    passphrase: str
    domain: str = ""


class KeySyncImportRequest(BaseModel):
    token: str
    passphrase: str


def _derive_sync_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return kdf.derive(passphrase.encode("utf-8"))


@app.post("/api/keys/sync-export")
def api_keys_sync_export(req: KeySyncExportRequest, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    pw = (req.passphrase or "").strip()
    if len(pw) < 4:
        raise HTTPException(status_code=400, detail="Passphrase must be at least 4 characters.")
    identities = store.export_owned_identities()
    if req.domain.strip():
        clean = normalize_xnd_domain(req.domain, append_tld=True)
        identities = [x for x in identities if x.get("domain") == clean]
    if not identities:
        raise HTTPException(status_code=404, detail="No owned domain keys available to export.")
    payload = json.dumps({"identities": identities, "ts": int(time.time())}, separators=(",", ":")).encode("utf-8")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_sync_key(pw, salt)
    ct = AESGCM(key).encrypt(nonce, payload, None)
    token = "XNDKEY1:" + base64.b64encode(salt + nonce + ct).decode("ascii")
    return {"ok": True, "token": token, "count": len(identities)}


@app.post("/api/keys/sync-import")
def api_keys_sync_import(req: KeySyncImportRequest, request: Request) -> dict[str, Any]:
    _require_localhost(request)
    tok = (req.token or "").strip()
    pw = (req.passphrase or "").strip()
    if not tok.startswith("XNDKEY1:") or not pw:
        raise HTTPException(status_code=400, detail="Invalid XNDKEY1 token or passphrase.")
    try:
        raw = base64.b64decode(tok[len("XNDKEY1:") :])
        salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
        key = _derive_sync_key(pw, salt)
        plain = AESGCM(key).decrypt(nonce, ct, None)
        data = json.loads(plain.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to decrypt key sync token (wrong passphrase or corrupted token).")
    imported = 0
    for item in data.get("identities", []):
        dom = str(item.get("domain", "")).strip().lower()
        priv = str(item.get("privkey_hex", "")).strip()
        if not DOMAIN_RE.match(dom) or not priv:
            continue
        try:
            pub = pubkey_from_priv_hex(priv)
        except Exception:
            continue
        existing = store.domains.get(dom)
        if existing is not None and existing["pubkey_hex"] != pub:
            continue
        store.import_domain_key(dom, pub, priv)
        imported += 1
    return {"ok": True, "imported": imported}


class P2PJoinRequest(BaseModel):
    public_url: str = ""
    label: str = "Xanadu Peer"


@app.post("/api/peers/announce")
def announce_peer(req: PeerRequest) -> dict[str, Any]:
    peer_url = req.url.strip().rstrip("/")
    if not peer_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Peer URL must start with http:// or https://")
    if peer_url not in _self_urls() and len(store.peers) < 50:
        store.save_peer(peer_url, req.label or "PEX Peer", store.peers.get(peer_url, {}).get("last_sync", 0.0))
    return {"ok": True, "known_peers": list(store.peers.values())}


@app.get("/api/p2p/discover")
def p2p_discover() -> dict[str, Any]:
    discovered = discover_peers_nostr()
    self_set = _self_urls()
    added = 0
    for p in discovered:
        u = p["url"].rstrip("/")
        if u not in self_set and u not in store.peers and len(store.peers) < 50:
            store.save_peer(u, p.get("label", "Nostr Peer"), 0.0)
            added += 1
    doc_stats = {"imported_versions": 0, "rejected": 0}
    try:
        doc_stats = import_sync_bundle(discover_docs_nostr())
    except Exception:
        pass
    return {"ok": True, "discovered": discovered, "added": added, "total_peers": len(store.peers), "relay_docs": doc_stats}


@app.post("/api/p2p/join")
def p2p_join(req: P2PJoinRequest) -> dict[str, Any]:
    pub = req.public_url.strip().rstrip("/") or os.environ.get("XND_PUBLIC_URL", "").strip().rstrip("/")
    relays_accepted = 0
    if pub.startswith(("http://", "https://")):
        os.environ["XND_PUBLIC_URL"] = pub
        node_id = rust_sha256(pub)[:12]
        relays_accepted = announce_peer_nostr(pub, node_id, req.label)
    disc = p2p_discover()
    synced = 0
    for p in list(store.peers.values())[:5]:
        try:
            _pull_from_peer_sync(p["url"], p["label"])
            synced += 1
        except Exception:
            pass
    return {"ok": True, "announced_relays": relays_accepted, "discovered": len(disc["discovered"]), "synced_peers": synced}


@app.get("/api/dht/find")
def dht_find_domain(domain: str = Query(default="")) -> dict[str, Any]:
    clean = normalize_xnd_domain(domain, append_tld=True)
    if not clean:
        raise HTTPException(status_code=400, detail="Missing domain")
    if clean in store.domains and store.versions.get(clean):
        return {"ok": True, "found": True, "domain": clean, "bundle": export_domain_bundle(clean)}
    self_set = _self_urls()
    candidates: list[dict[str, Any]] = []
    seen_u: set[str] = set()
    for u, rec in list(_LAN_PEERS.items()):
        bu = u.rstrip("/")
        if bu and bu not in self_set and bu not in seen_u:
            seen_u.add(bu)
            candidates.append({"url": bu, "label": rec.get("label", "LAN Peer"), "dist": _dht_distance(bu, clean)})
    for s in _load_seeds():
        bu = str(s.get("url", "")).rstrip("/")
        if bu and bu not in self_set and bu not in seen_u:
            seen_u.add(bu)
            candidates.append({"url": bu, "label": s.get("label", "Seed Node"), "dist": _dht_distance(bu, clean)})
    for p in list(store.peers.values()):
        bu = str(p.get("url", "")).rstrip("/")
        if bu and bu not in self_set and bu not in seen_u:
            seen_u.add(bu)
            candidates.append({"url": bu, "label": p.get("label", "Peer"), "dist": _dht_distance(bu, clean)})
    candidates.sort(key=lambda x: x["dist"])
    closest = [{"url": c["url"], "label": c["label"]} for c in candidates[:6]]
    return {"ok": True, "found": False, "domain": clean, "closest_peers": closest}


@app.get("/api/consensus/{domain}")
def get_domain_consensus(domain: str) -> dict[str, Any]:
    clean = normalize_xnd_domain(domain, append_tld=True)
    dom_obj = store.domains.get(clean)
    pub = (dom_obj or {}).get("pubkey_hex", "") or trust_store.get_pinned_pubkey(clean)
    return {
        "ok": True,
        "domain": clean,
        "pubkey_hex": pub,
        "canonical_domain": _canonical_domain_for(clean, pub) if pub else clean,
        "pin_source": trust_store.get_pin_source(clean) or ("self" if (dom_obj or {}).get("privkey_hex") else "first_seen"),
        "created_at": float((dom_obj or {}).get("created_at") or 0.0),
        "policy": "earliest_claim_with_petname",
        "conflicts": trust_store.get_conflicts(clean),
    }


@app.get("/api/seeds")
def get_seeds() -> dict[str, Any]:
    return {
        "ok": True,
        "self_seed_active": bool(_SHARE_GATEWAY and _check_has_wan()),
        "seeds": _load_seeds(),
    }


@app.post("/api/seeds")
async def add_seed(request: Request) -> dict[str, Any]:
    _require_localhost(request)
    body = await request.json()
    url = str((body or {}).get("url") or "").strip().rstrip("/")
    label = str((body or {}).get("label") or "Community Seed").strip()[:48]
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Seed URL must start with http:// or https://")
    _remember_seed(url, label)
    return {"ok": True, "seeds": _load_seeds()}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("XND_PORT", "8765"))
    uvicorn.run(app, host="0.0.0.0", port=port)
