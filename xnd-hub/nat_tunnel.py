#!/usr/bin/env python3
"""
STUN UDP Hole-Punching & Nostr-Signaled P2P Tunnel for Xanadu (.xnd).
Zero-VPS WAN NAT traversal: discovers public (ip, port) via RFC 5389 STUN on a
persistent UDP socket, signals endpoints over Nostr relays (kind 21078), punches
NAT pinholes, and transports chunked JSON-RPC frames between peers.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import socket
import struct
import threading
import time
from typing import Any, Callable

from p2p_discovery import (
    DEFAULT_RELAYS,
    _N,
    _G,
    _point_mul,
    _publish_nostr_event,
    _query_relays_raw,
)

STUN_SERVERS: list[tuple[str, int]] = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]
STUN_MAGIC_COOKIE = 0x2112A442
XANADU_STUN_TAG = "xanadu-stun-v1"
STUN_NOSTR_KIND = 21078
CHUNK_RAW_SIZE = 750  # base64 -> ~1000 chars, safely under 1200-byte MTU


def _parse_stun_response(data: bytes, expected_tx: bytes) -> tuple[str, int] | None:
    if len(data) < 20:
        return None
    msg_type, msg_len, cookie = struct.unpack("!HHI", data[:8])
    if msg_type != 0x0101 or cookie != STUN_MAGIC_COOKIE:
        return None
    if data[8:20] != expected_tx:
        return None
    pos = 20
    end = min(len(data), 20 + msg_len)
    while pos + 4 <= end:
        attr_type, attr_len = struct.unpack("!HH", data[pos : pos + 4])
        val = data[pos + 4 : pos + 4 + attr_len]
        pos += 4 + ((attr_len + 3) & ~3)
        if attr_type == 0x0020 and len(val) >= 8 and val[1] == 0x01:
            xport = struct.unpack("!H", val[2:4])[0] ^ (STUN_MAGIC_COOKIE >> 16)
            xip_raw = struct.unpack("!I", val[4:8])[0] ^ STUN_MAGIC_COOKIE
            ip = socket.inet_ntoa(struct.pack("!I", xip_raw))
            return (ip, xport)
        if attr_type == 0x0001 and len(val) >= 8 and val[1] == 0x01:
            port = struct.unpack("!H", val[2:4])[0]
            ip = socket.inet_ntoa(val[4:8])
            return (ip, port)
    return None


class NatTunnel:
    def __init__(
        self,
        node_id: str,
        rpc_handler: Callable[[str, str, str], str],
        udp_port: int = 8767,
    ) -> None:
        self.node_id = node_id
        self.rpc_handler = rpc_handler
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(("0.0.0.0", udp_port))
        except OSError:
            self.sock.bind(("0.0.0.0", 0))
        self.local_port = int(self.sock.getsockname()[1])
        self.public_ip = ""
        self.public_port = 0
        self.stun_ok = False
        self.running = False

        self._lock = threading.Lock()
        self._stun_waiters: dict[bytes, tuple[threading.Event, list[tuple[str, int]]]] = {}
        self._incoming_reqs: dict[str, dict[str, Any]] = {}
        self._incoming_res: dict[str, dict[str, Any]] = {}
        self._res_events: dict[str, threading.Event] = {}
        self._res_payloads: dict[str, str] = {}
        self.punched_peers: dict[str, tuple[str, int, float]] = {}

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._recv_loop, daemon=True, name="xnd-nat-recv").start()
        threading.Thread(target=self._keepalive_loop, daemon=True, name="xnd-nat-stun").start()

    def stop(self) -> None:
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass

    def _recv_loop(self) -> None:
        self.sock.settimeout(1.0)
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) >= 20 and data[0:2] == b"\x01\x01" and struct.unpack("!I", data[4:8])[0] == STUN_MAGIC_COOKIE:
                tx = data[8:20]
                with self._lock:
                    waiter = self._stun_waiters.get(tx)
                if waiter is not None:
                    parsed = _parse_stun_response(data, tx)
                    if parsed:
                        waiter[1].append(parsed)
                        waiter[0].set()
                continue
            try:
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                continue
            if text.startswith("XND_PUNCH|"):
                peer_id = text.split("|", 1)[1].strip()
                with self._lock:
                    self.punched_peers[peer_id] = (addr[0], addr[1], time.time())
                try:
                    self.sock.sendto(f"XND_PUNCH_ACK|{self.node_id}".encode("utf-8"), addr)
                except OSError:
                    pass
            elif text.startswith("XND_PUNCH_ACK|"):
                peer_id = text.split("|", 1)[1].strip()
                with self._lock:
                    self.punched_peers[peer_id] = (addr[0], addr[1], time.time())
            elif text.startswith("XND_REQ|") or text.startswith("XND_RES|"):
                self._handle_chunk_frame(text, addr)

    def _handle_chunk_frame(self, text: str, addr: tuple[str, int]) -> None:
        parts = text.split("|", 3)
        if len(parts) != 4:
            return
        kind, msg_id, seq_info, b64_part = parts
        if "/" not in seq_info:
            return
        try:
            idx_s, tot_s = seq_info.split("/", 1)
            idx, total = int(idx_s), int(tot_s)
        except ValueError:
            return
        if total <= 0 or total > 512 or idx < 0 or idx >= total:
            return

        store_dict = self._incoming_reqs if kind == "XND_REQ" else self._incoming_res
        assembled: str | None = None
        with self._lock:
            entry = store_dict.setdefault(msg_id, {"total": total, "parts": {}, "ts": time.time()})
            entry["parts"][idx] = b64_part
            if len(entry["parts"]) == total:
                full_b64 = "".join(entry["parts"][i] for i in range(total))
                store_dict.pop(msg_id, None)
                try:
                    assembled = base64.b64decode(full_b64.encode("ascii")).decode("utf-8")
                except Exception:
                    assembled = None
        if assembled is None:
            return

        if kind == "XND_REQ":
            threading.Thread(
                target=self._dispatch_req,
                args=(msg_id, assembled, addr),
                daemon=True,
            ).start()
        else:
            with self._lock:
                self._res_payloads[msg_id] = assembled
                ev = self._res_events.get(msg_id)
                if ev is not None:
                    ev.set()

    def _dispatch_req(self, msg_id: str, assembled: str, addr: tuple[str, int]) -> None:
        try:
            req_obj = json.loads(assembled)
            method = str(req_obj.get("method", "GET"))
            path = str(req_obj.get("path", "/api/sync/manifest"))
            body = str(req_obj.get("body", ""))
            resp_body = self.rpc_handler(method, path, body)
        except Exception as exc:
            resp_body = json.dumps({"ok": False, "detail": str(exc)})
        self._send_chunked("XND_RES", msg_id, resp_body, addr)

    def _send_chunked(self, prefix: str, msg_id: str, text: str, addr: tuple[str, int]) -> None:
        raw = base64.b64encode(text.encode("utf-8")).decode("ascii")
        chunks = [raw[i : i + CHUNK_RAW_SIZE] for i in range(0, len(raw), CHUNK_RAW_SIZE)] or [""]
        total = len(chunks)
        for idx, ch in enumerate(chunks):
            frame = f"{prefix}|{msg_id}|{idx}/{total}|{ch}".encode("utf-8")
            try:
                self.sock.sendto(frame, addr)
            except OSError:
                break

    def discover_stun(self, timeout: float = 2.0) -> tuple[str, int] | None:
        for host, port in STUN_SERVERS:
            tx = os.urandom(12)
            req = struct.pack("!HHI", 0x0001, 0, STUN_MAGIC_COOKIE) + tx
            ev = threading.Event()
            res_list: list[tuple[str, int]] = []
            with self._lock:
                self._stun_waiters[tx] = (ev, res_list)
            try:
                self.sock.sendto(req, (host, port))
                if ev.wait(timeout) and res_list:
                    ip, p = res_list[0]
                    self.public_ip = ip
                    self.public_port = p
                    self.stun_ok = True
                    return (ip, p)
            except OSError:
                continue
            finally:
                with self._lock:
                    self._stun_waiters.pop(tx, None)
        return None

    def _keepalive_loop(self) -> None:
        time.sleep(1.0)
        last_announce = 0.0
        while self.running:
            res = self.discover_stun(timeout=2.0)
            now = time.time()
            if res and (now - last_announce) >= 120.0:
                last_announce = now
                try:
                    self.announce_stun_nostr()
                except Exception:
                    pass
            # Prune stale incomplete assemblies (>30s)
            with self._lock:
                for d in (self._incoming_reqs, self._incoming_res):
                    stale = [k for k, v in d.items() if now - v.get("ts", 0.0) > 30.0]
                    for k in stale:
                        d.pop(k, None)
            time.sleep(25.0)

    def announce_stun_nostr(self, relays: list[str] | None = None) -> int:
        if not self.public_ip or not self.public_port:
            return 0
        relays = relays or DEFAULT_RELAYS
        priv = int.from_bytes(hashlib.sha256(f"xanadu-stun-{self.node_id}".encode("utf-8")).digest(), "big") % (_N - 1) + 1
        pub_x = _point_mul(priv, _G)[0].to_bytes(32, "big").hex()
        payload = json.dumps(
            {
                "type": "xanadu-stun",
                "node_id": self.node_id,
                "public_ip": self.public_ip,
                "public_port": self.public_port,
                "local_port": self.local_port,
                "ts": int(time.time()),
            },
            separators=(",", ":"),
        )
        return _publish_nostr_event(
            priv,
            pub_x,
            [["t", XANADU_STUN_TAG], ["d", self.node_id]],
            payload,
            relays,
            kind=STUN_NOSTR_KIND,
        )

    def discover_stun_peers_nostr(self, relays: list[str] | None = None, limit: int = 20) -> list[dict[str, Any]]:
        events = _query_relays_raw(
            [{"kinds": [STUN_NOSTR_KIND, 1], "#t": [XANADU_STUN_TAG], "limit": limit}],
            relays=relays,
            timeout=2.2,
        )
        peers: dict[str, dict[str, Any]] = {}
        for ev in events:
            try:
                data = json.loads(ev.get("content", "{}"))
                if data.get("type") != "xanadu-stun":
                    continue
                nid = str(data.get("node_id", "")).strip()
                pip = str(data.get("public_ip", "")).strip()
                pport = int(data.get("public_port", 0) or 0)
                if not nid or nid == self.node_id or not pip or pport <= 0:
                    continue
                prev = peers.get(nid)
                if prev is None or int(data.get("ts", 0)) > int(prev.get("ts", 0)):
                    peers[nid] = {
                        "node_id": nid,
                        "public_ip": pip,
                        "public_port": pport,
                        "ts": int(data.get("ts", 0)),
                        "stun_url": f"stun://{nid}@{pip}:{pport}",
                    }
            except Exception:
                pass
        return list(peers.values())

    def punch(self, ip: str, port: int) -> None:
        pkt = f"XND_PUNCH|{self.node_id}".encode("utf-8")
        for _ in range(3):
            try:
                self.sock.sendto(pkt, (ip, port))
            except OSError:
                break
            time.sleep(0.05)

    def rpc(self, stun_url: str, method: str, path: str, body: str = "", timeout: float = 4.0) -> str:
        # Format: stun://<node_id>@<ip>:<port>
        raw = stun_url[len("stun://") :]
        hostport = raw.split("@", 1)[1] if "@" in raw else raw
        ip, port_s = hostport.rsplit(":", 1)
        addr = (ip.strip(), int(port_s.strip()))

        self.punch(addr[0], addr[1])
        msg_id = secrets.token_hex(6)
        ev = threading.Event()
        with self._lock:
            self._res_events[msg_id] = ev
        try:
            req_payload = json.dumps({"method": method, "path": path, "body": body}, separators=(",", ":"))
            self._send_chunked("XND_REQ", msg_id, req_payload, addr)
            if not ev.wait(timeout):
                raise TimeoutError(f"STUN UDP RPC timeout to {addr}")
            with self._lock:
                return self._res_payloads.pop(msg_id, "")
        finally:
            with self._lock:
                self._res_events.pop(msg_id, None)
                self._res_payloads.pop(msg_id, None)

    def status(self) -> dict[str, Any]:
        with self._lock:
            punched = {
                nid: {"ip": info[0], "port": info[1], "last_seen": info[2]}
                for nid, info in self.punched_peers.items()
            }
        return {
            "ok": True,
            "node_id": self.node_id,
            "local_port": self.local_port,
            "public_ip": self.public_ip,
            "public_port": self.public_port,
            "stun_ok": self.stun_ok,
            "punched_peers": punched,
        }
