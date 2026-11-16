#!/usr/bin/env python3
"""
p2p_discovery.py: Zero-VPS, Zero-Domain Global Peer Discovery via Public Nostr Relays.
Uses pure Python stdlib (TLS WebSocket + BIP-340 Schnorr) — no external dependencies.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import socket
import ssl
import struct
import threading
import time
import urllib.parse
from typing import Any

DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
]
XANADU_TAG = "xanadu-p2p-v1"
XANADU_DOC_TAG = "xanadu-doc-v1"
XANADU_CHUNK_TAG = "xanadu-chunk-v1"
LAN_DISCOVERY_PORT = 8766

# secp256k1 parameters for BIP-340 Schnorr (Nostr NIP-01)
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _point_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        lam = (3 * x1 * x1 * pow(2 * y1, _P - 2, _P)) % _P
    else:
        lam = ((y2 - y1) * pow(x2 - x1, _P - 2, _P)) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _point_mul(k: int, p: tuple[int, int] = _G) -> tuple[int, int]:
    r: tuple[int, int] | None = None
    q: tuple[int, int] | None = p
    while k:
        if k & 1:
            r = _point_add(r, q)
        q = _point_add(q, q)
        k >>= 1
    assert r is not None
    return r


def _tagged_hash(tag: str, msg: bytes) -> bytes:
    th = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(th + th + msg).digest()


def _schnorr_sign(msg32: bytes, seckey_bytes: bytes) -> bytes:
    d0 = int.from_bytes(seckey_bytes, "big")
    pt = _point_mul(d0)
    d = d0 if (pt[1] % 2 == 0) else (_N - d0)
    px = pt[0].to_bytes(32, "big")
    t = bytes(a ^ b for a, b in zip(d.to_bytes(32, "big"), _tagged_hash("BIP0340/aux", secrets.token_bytes(32))))
    k0 = int.from_bytes(_tagged_hash("BIP0340/nonce", t + px + msg32), "big") % _N
    if k0 == 0:
        k0 = 1
    r_pt = _point_mul(k0)
    k = k0 if (r_pt[1] % 2 == 0) else (_N - k0)
    rx = r_pt[0].to_bytes(32, "big")
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", rx + px + msg32), "big") % _N
    s = (k + e * d) % _N
    return rx + s.to_bytes(32, "big")


def build_nostr_peer_event(public_url: str, node_id: str, label: str = "Xanadu Peer") -> dict[str, Any]:
    seckey = secrets.token_bytes(32)
    pub_x = _point_mul(int.from_bytes(seckey, "big"))[0].to_bytes(32, "big").hex()
    created_at = int(time.time())
    tags = [["t", XANADU_TAG]]
    content = json.dumps({"type": "xanadu-peer", "url": public_url.rstrip("/"), "node_id": node_id, "label": label})
    serialized = json.dumps([0, pub_x, created_at, 1, tags, content], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ev_id = hashlib.sha256(serialized).digest()
    sig = _schnorr_sign(ev_id, seckey).hex()
    return {
        "id": ev_id.hex(),
        "pubkey": pub_x,
        "created_at": created_at,
        "kind": 1,
        "tags": tags,
        "content": content,
        "sig": sig,
    }


def _ws_connect(wss_url: str, timeout: float = 4.0) -> ssl.SSLSocket | socket.socket:
    parsed = urllib.parse.urlparse(wss_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    raw = socket.create_connection((host, port), timeout=timeout)
    sock: ssl.SSLSocket | socket.socket = raw
    if parsed.scheme == "wss":
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(raw, server_hostname=host)
    sock.settimeout(timeout)

    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(req.encode("ascii"))
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    if b"101 " not in buf.split(b"\r\n", 1)[0]:
        sock.close()
        raise RuntimeError(f"WebSocket handshake failed for {wss_url}")
    return sock


def _ws_send_text(sock: ssl.SSLSocket | socket.socket, text: str) -> None:
    payload = text.encode("utf-8")
    mask = os.urandom(4)
    header = bytearray([0x81])
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", length))
    header.extend(mask)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + masked)


def _recv_exact(sock: ssl.SSLSocket | socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError("WebSocket closed")
        out.extend(chunk)
    return bytes(out)


def _ws_recv_text(sock: ssl.SSLSocket | socket.socket) -> str | None:
    b1, b2 = _recv_exact(sock, 2)
    opcode = b1 & 0x0F
    masked = bool(b2 & 0x80)
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(sock, 8))[0]
    mask = _recv_exact(sock, 4) if masked else b""
    payload = _recv_exact(sock, length) if length else b""
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    if opcode == 0x8:
        return None
    if opcode == 0x9:
        # Pong
        return ""
    return payload.decode("utf-8", errors="replace")


def discover_peers_nostr(relays: list[str] | None = None, limit: int = 20) -> list[dict[str, str]]:
    relays = relays or DEFAULT_RELAYS
    found: dict[str, dict[str, str]] = {}
    sub_id = f"xnd-{secrets.token_hex(4)}"
    for r_url in relays:
        try:
            sock = _ws_connect(r_url, timeout=3.5)
            try:
                _ws_send_text(sock, json.dumps(["REQ", sub_id, {"kinds": [1], "#t": [XANADU_TAG], "limit": limit}]))
                deadline = time.time() + 2.5
                while time.time() < deadline:
                    msg = _ws_recv_text(sock)
                    if msg is None:
                        break
                    if not msg:
                        continue
                    arr = json.loads(msg)
                    if isinstance(arr, list) and arr[0] == "EOSE":
                        break
                    if isinstance(arr, list) and len(arr) >= 3 and arr[0] == "EVENT":
                        try:
                            data = json.loads(arr[2].get("content", "{}"))
                            u = str(data.get("url", "")).strip().rstrip("/")
                            if data.get("type") == "xanadu-peer" and u.startswith(("http://", "https://")):
                                found[u] = {
                                    "url": u,
                                    "node_id": str(data.get("node_id", ""))[:24],
                                    "label": str(data.get("label", "Xanadu Peer"))[:48],
                                }
                        except Exception:
                            pass
            finally:
                sock.close()
        except Exception:
            continue
    return list(found.values())


def announce_peer_nostr(public_url: str, node_id: str, label: str = "Xanadu Peer", relays: list[str] | None = None) -> int:
    relays = relays or DEFAULT_RELAYS
    ev = build_nostr_peer_event(public_url, node_id, label)
    accepted = 0
    for r_url in relays:
        try:
            sock = _ws_connect(r_url, timeout=3.5)
            try:
                _ws_send_text(sock, json.dumps(["EVENT", ev]))
                msg = _ws_recv_text(sock)
                if msg:
                    arr = json.loads(msg)
                    if isinstance(arr, list) and arr[0] == "OK" and arr[2] is True:
                        accepted += 1
            finally:
                sock.close()
        except Exception:
            continue
    return accepted


def _nostr_event_id(pub_x: str, created_at: int, kind: int, tags: list[list[str]], content: str) -> str:
    serialized = json.dumps([0, pub_x, created_at, kind, tags, content], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _publish_nostr_event(
    priv: int,
    pub_x: str,
    tags: list[list[str]],
    payload: str,
    relays: list[str],
    kind: int = 1,
) -> int:
    created_at = int(time.time())
    ev_id = _nostr_event_id(pub_x, created_at, kind, tags, payload)
    seckey_bytes = priv.to_bytes(32, "big") if isinstance(priv, int) else priv
    sig = _schnorr_sign(bytes.fromhex(ev_id), seckey_bytes).hex()
    ev = {
        "id": ev_id,
        "pubkey": pub_x,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": payload,
        "sig": sig,
    }
    accepted = 0
    for r_url in relays:
        try:
            sock = _ws_connect(r_url, timeout=3.5)
            try:
                _ws_send_text(sock, json.dumps(["EVENT", ev]))
                msg = _ws_recv_text(sock)
                if msg:
                    arr = json.loads(msg)
                    if isinstance(arr, list) and arr[0] == "OK" and arr[2] is True:
                        accepted += 1
            finally:
                sock.close()
        except Exception:
            continue
    return accepted


def announce_doc_nostr(
    domain: str,
    version_num: int,
    title: str,
    sha256: str,
    pubkey_hex: str,
    signature_hex: str,
    content: str,
    is_app: bool = False,
    relays: list[str] | None = None,
    prev_sha256: str = "",
) -> int:
    """Publish a signed .xnd document capsule (or chunked manifest if >36 KB) to public Nostr relays."""
    relays = relays or DEFAULT_RELAYS
    priv = int.from_bytes(hashlib.sha256(f"xanadu-doc-nostr-{domain}".encode("utf-8")).digest(), "big") % (_N - 1) + 1
    pub_x = _point_mul(priv, _G)[0].to_bytes(32, "big").hex()
    created_at = int(time.time())
    raw_bytes = content.encode("utf-8")

    if len(raw_bytes) <= 36000:
        payload = json.dumps(
            {
                "type": "xanadu-doc",
                "domain": domain,
                "version_num": version_num,
                "title": title,
                "sha256": sha256,
                "prev_sha256": prev_sha256,
                "pubkey_hex": pubkey_hex,
                "signature_hex": signature_hex,
                "content": content,
                "is_app": is_app,
                "created_at": created_at,
            },
            separators=(",", ":"),
        )
        return _publish_nostr_event(
            priv,
            pub_x,
            [["t", XANADU_DOC_TAG], ["t", f"xnd-{domain}"], ["d", domain]],
            payload,
            relays,
            kind=30078,
        )

    chunk_size = 24000
    chunk_hashes: list[str] = []
    for i in range(0, len(raw_bytes), chunk_size):
        chunk = raw_bytes[i : i + chunk_size]
        c_sha = hashlib.sha256(chunk).hexdigest()
        chunk_hashes.append(c_sha)
        c_payload = json.dumps(
            {
                "type": "xanadu-chunk",
                "sha256": c_sha,
                "data_b64": base64.b64encode(chunk).decode("ascii"),
            },
            separators=(",", ":"),
        )
        _publish_nostr_event(priv, pub_x, [["t", XANADU_CHUNK_TAG], ["x", c_sha]], c_payload, relays)

    manifest = json.dumps(
        {
            "type": "xanadu-doc",
            "chunked": True,
            "chunks": chunk_hashes,
            "domain": domain,
            "version_num": version_num,
            "title": title,
            "sha256": sha256,
            "prev_sha256": prev_sha256,
            "pubkey_hex": pubkey_hex,
            "signature_hex": signature_hex,
            "is_app": is_app,
            "created_at": created_at,
        },
        separators=(",", ":"),
    )
    return _publish_nostr_event(
        priv,
        pub_x,
        [["t", XANADU_DOC_TAG], ["t", f"xnd-{domain}"], ["d", domain]],
        manifest,
        relays,
        kind=30078,
    )


def _query_relays_raw(
    req_filters: list[dict[str, Any]],
    relays: list[str] | None = None,
    timeout: float = 2.8,
) -> list[dict[str, Any]]:
    """Query multiple Nostr relays in parallel for raw EVENT objects."""
    from concurrent.futures import ThreadPoolExecutor

    relays = relays or DEFAULT_RELAYS
    events: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    lock = threading.Lock()

    def _query_one(r_url: str) -> None:
        sub_id = f"xq-{secrets.token_hex(4)}"
        try:
            sock = _ws_connect(r_url, timeout=timeout)
            try:
                _ws_send_text(sock, json.dumps(["REQ", sub_id, *req_filters]))
                deadline = time.time() + timeout
                while time.time() < deadline:
                    msg = _ws_recv_text(sock)
                    if msg is None:
                        break
                    if not msg:
                        continue
                    arr = json.loads(msg)
                    if isinstance(arr, list) and arr[0] == "EOSE":
                        break
                    if isinstance(arr, list) and len(arr) >= 3 and arr[0] == "EVENT" and isinstance(arr[2], dict):
                        ev = arr[2]
                        ev_id = str(ev.get("id", ""))
                        with lock:
                            if ev_id and ev_id in seen_ids:
                                continue
                            if ev_id:
                                seen_ids.add(ev_id)
                            events.append(ev)
            finally:
                sock.close()
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=max(1, len(relays))) as pool:
        list(pool.map(_query_one, relays))
    return events


def _events_to_sync_bundle(
    events: list[dict[str, Any]],
    relays: list[str] | None = None,
    fetch_missing_chunks: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    domains: dict[str, dict[str, Any]] = {}
    versions: dict[tuple[str, int], dict[str, Any]] = {}
    blobs: dict[str, dict[str, Any]] = {}
    chunks_map: dict[str, bytes] = {}
    manifests: list[dict[str, Any]] = []

    for ev in events:
        try:
            data = json.loads(ev.get("content", "{}"))
            ev_type = data.get("type")
            if ev_type == "xanadu-chunk":
                c_sha = str(data.get("sha256", "")).strip()
                raw_c = base64.b64decode(data.get("data_b64", ""), validate=True)
                if c_sha and hashlib.sha256(raw_c).hexdigest() == c_sha:
                    chunks_map[c_sha] = raw_c
            elif ev_type == "xanadu-doc":
                if data.get("chunked"):
                    manifests.append(data)
                    continue
                dom = str(data.get("domain", "")).strip().lower()
                sha = str(data.get("sha256", "")).strip()
                pub = str(data.get("pubkey_hex", "")).strip()
                sig = str(data.get("signature_hex", "")).strip()
                txt = str(data.get("content", ""))
                ver = int(data.get("version_num", 1))
                ts = float(data.get("created_at", time.time()))
                if not dom or not sha or not pub or not sig or not txt:
                    continue
                domains[dom] = {"name": dom, "pubkey_hex": pub, "created_at": ts}
                versions[(dom, ver)] = {
                    "domain": dom,
                    "version_num": ver,
                    "sha256": sha,
                    "prev_sha256": str(data.get("prev_sha256", "")).strip(),
                    "pubkey_hex": pub,
                    "signature_hex": sig,
                    "title": str(data.get("title", dom)),
                    "kind": "capsule" if data.get("is_app") else "document",
                    "created_at": ts,
                    "is_app": bool(data.get("is_app", False)),
                }
                blobs[sha] = {"sha256": sha, "content": txt, "created_at": ts}
        except Exception:
            pass

    if fetch_missing_chunks and manifests:
        missing = []
        for m in manifests:
            for c in m.get("chunks", []):
                if c not in chunks_map and c not in missing:
                    missing.append(c)
        if missing:
            c_events = _query_relays_raw(
                [{"kinds": [1], "#t": [XANADU_CHUNK_TAG], "#x": missing, "limit": len(missing) + 5}],
                relays=relays,
                timeout=3.0,
            )
            for ev in c_events:
                try:
                    data = json.loads(ev.get("content", "{}"))
                    if data.get("type") == "xanadu-chunk":
                        c_sha = str(data.get("sha256", "")).strip()
                        raw_c = base64.b64decode(data.get("data_b64", ""), validate=True)
                        if c_sha and hashlib.sha256(raw_c).hexdigest() == c_sha:
                            chunks_map[c_sha] = raw_c
                except Exception:
                    pass

    for data in manifests:
        try:
            dom = str(data.get("domain", "")).strip().lower()
            sha = str(data.get("sha256", "")).strip()
            pub = str(data.get("pubkey_hex", "")).strip()
            sig = str(data.get("signature_hex", "")).strip()
            ver = int(data.get("version_num", 1))
            ts = float(data.get("created_at", time.time()))
            c_list = data.get("chunks", [])
            if not dom or not sha or not pub or not sig or not c_list:
                continue
            if all(c in chunks_map for c in c_list):
                txt = b"".join(chunks_map[c] for c in c_list).decode("utf-8", errors="replace")
                domains[dom] = {"name": dom, "pubkey_hex": pub, "created_at": ts}
                versions[(dom, ver)] = {
                    "domain": dom,
                    "version_num": ver,
                    "sha256": sha,
                    "prev_sha256": str(data.get("prev_sha256", "")).strip(),
                    "pubkey_hex": pub,
                    "signature_hex": sig,
                    "title": str(data.get("title", dom)),
                    "kind": "capsule" if data.get("is_app") else "document",
                    "created_at": ts,
                    "is_app": bool(data.get("is_app", False)),
                }
                blobs[sha] = {"sha256": sha, "content": txt, "created_at": ts}
        except Exception:
            pass

    return {
        "domains": list(domains.values()),
        "versions": list(versions.values()),
        "blobs": list(blobs.values()),
        "assets": [],
        "links": [],
    }


def discover_docs_nostr(relays: list[str] | None = None, limit: int = 250) -> dict[str, list[dict[str, Any]]]:
    """Fetch signed .xnd document capsules (kind:30078) from public Nostr relays."""
    events = _query_relays_raw(
        [{"kinds": [30078], "#t": [XANADU_DOC_TAG], "limit": max(limit, 100)}],
        relays=relays,
        timeout=3.0,
    )
    return _events_to_sync_bundle(events, relays=relays, fetch_missing_chunks=False)


def lookup_doc_nostr(domain: str, relays: list[str] | None = None) -> dict[str, list[dict[str, Any]]]:
    """On-demand parallel lookup of a specific .xnd domain across public Nostr relays."""
    clean = domain.strip().lower()
    if not clean:
        return {"domains": [], "versions": [], "blobs": [], "assets": [], "links": []}
    priv = int.from_bytes(hashlib.sha256(f"xanadu-doc-nostr-{clean}".encode("utf-8")).digest(), "big") % (_N - 1) + 1
    pub_x = _point_mul(priv, _G)[0].to_bytes(32, "big").hex()
    events = _query_relays_raw(
        [
            {"kinds": [30078, 1], "authors": [pub_x], "limit": 10},
            {"kinds": [30078, 1], "#t": [f"xnd-{clean}"], "limit": 10},
            {"kinds": [30078, 1], "#t": [XANADU_DOC_TAG], "#d": [clean], "limit": 10},
        ],
        relays=relays,
        timeout=2.5,
    )
    return _events_to_sync_bundle(events, relays=relays, fetch_missing_chunks=True)


def start_lan_discovery(http_port: int, on_peer_found: Any, label: str = "Xanadu Desktop") -> None:
    """Broadcast & listen for LAN Xanadu nodes via UDP port 8766."""
    node_id = secrets.token_hex(8)
    beacon = json.dumps(
        {"type": "xanadu-lan-peer", "node_id": node_id, "port": http_port, "label": label},
        separators=(",", ":"),
    ).encode("utf-8")

    def _local_broadcast_targets() -> list[str]:
        targets = ["255.255.255.255"]
        seen_ips: set[str] = set()
        # Probe common private/hotspot gateways via UDP connect (no packets sent) to find active interface IPs
        for probe in ("192.168.43.1", "192.168.49.1", "192.168.1.1", "192.168.0.1", "10.0.0.1", "172.20.10.1", "8.8.8.8"):
            try:
                ps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ps.connect((probe, 80))
                ip = ps.getsockname()[0]
                ps.close()
                if ip and not ip.startswith("127."):
                    seen_ips.add(ip)
            except Exception:
                pass
        for ip in seen_ips:
            parts = ip.split(".")
            if len(parts) == 4:
                bcast = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
                if bcast not in targets:
                    targets.append(bcast)
        return targets

    def _broadcaster() -> None:
        while True:
            for dst in _local_broadcast_targets():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    s.sendto(beacon, (dst, LAN_DISCOVERY_PORT))
                    s.close()
                except Exception:
                    pass
            time.sleep(5)

    def _listener() -> None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except Exception:
                    pass
            s.bind(("", LAN_DISCOVERY_PORT))
        except Exception:
            return
        while True:
            try:
                data, addr = s.recvfrom(2048)
                msg = json.loads(data.decode("utf-8", errors="ignore"))
                if msg.get("type") != "xanadu-lan-peer" or msg.get("node_id") == node_id:
                    continue
                p_port = int(msg.get("port", 8765))
                p_label = str(msg.get("label", "LAN Peer"))[:48]
                on_peer_found(f"http://{addr[0]}:{p_port}", p_label)
            except Exception:
                pass

    threading.Thread(target=_broadcaster, daemon=True).start()
    threading.Thread(target=_listener, daemon=True).start()
