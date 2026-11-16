#!/usr/bin/env python3
"""
Signed Append-Only Event Log & LWW-CRDT Sync for Xanadu (.xnd) Capsules.

Allows multi-user decentralized apps (forums, chats, collaborative KV stores)
to converge deterministically across peers without central coordination:
- `append` ops: deduplicated by event `id`, ordered by `(ts, id)`.
- `kv_set` / `kv_del` ops: Last-Write-Wins (LWW) per key, tie-broken by `(ts, id)`.
Every event is Ed25519-signed by its author and verified before merge.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _canonical_json(val: Any) -> str:
    return json.dumps(val, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _event_signing_string(
    domain: str,
    op: str,
    collection: str,
    key: str,
    value: Any,
    ts: float,
) -> str:
    return f"xnd-evt-v1|{domain}|{op}|{collection}|{key}|{_canonical_json(value)}|{ts:.6f}"


def _event_id(signing_str: str, author_pub: str) -> str:
    return hashlib.sha256(f"{signing_str}|{author_pub}".encode("utf-8")).hexdigest()


def create_signed_event(
    domain: str,
    op: str,
    collection: str,
    key: str,
    value: Any,
    privkey_hex: str,
    ts: float | None = None,
) -> dict[str, Any]:
    dom = domain.strip().lower()
    t = float(ts if ts is not None else time.time())
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(privkey_hex.strip()))
    pub_hex = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    s_str = _event_signing_string(dom, op, collection, key, value, t)
    evt_id = _event_id(s_str, pub_hex)
    sig_hex = sk.sign(s_str.encode("utf-8")).hex()
    return {
        "id": evt_id,
        "domain": dom,
        "op": op,
        "collection": collection,
        "key": key,
        "value": value,
        "ts": round(t, 6),
        "author_pub": pub_hex,
        "sig": sig_hex,
    }


def verify_signed_event(evt: dict[str, Any]) -> bool:
    try:
        dom = str(evt["domain"]).strip().lower()
        op = str(evt["op"])
        if op not in ("append", "kv_set", "kv_del"):
            return False
        col = str(evt.get("collection") or "")
        key = str(evt.get("key") or "")
        val = evt.get("value")
        ts = float(evt["ts"])
        pub_hex = str(evt["author_pub"]).strip().lower()
        sig_hex = str(evt["sig"]).strip().lower()
        s_str = _event_signing_string(dom, op, col, key, val, ts)
        if str(evt.get("id") or "").lower() != _event_id(s_str, pub_hex):
            return False
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(bytes.fromhex(sig_hex), s_str.encode("utf-8"))
        return True
    except Exception:
        return False


class CapsuleCrdtLog:
    """Thread-safe, disk-persisted signed CRDT event log per .xnd domain."""

    def __init__(self, state_dir: Path) -> None:
        self._dir = state_dir / "crdt_events"
        self._lock = threading.Lock()
        self._events_by_domain: dict[str, dict[str, dict[str, Any]]] = {}
        self._load_all()

    def _domain_file(self, domain: str) -> Path:
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in domain.strip().lower())
        return self._dir / f"{safe}.json"

    def _load_all(self) -> None:
        if not self._dir.exists():
            return
        for fp in self._dir.glob("*.json"):
            try:
                rows = json.loads(fp.read_text(encoding="utf-8"))
                if not isinstance(rows, list):
                    continue
                for evt in rows:
                    if isinstance(evt, dict) and verify_signed_event(evt):
                        dom = str(evt["domain"]).strip().lower()
                        self._events_by_domain.setdefault(dom, {})[evt["id"]] = evt
            except Exception:
                pass

    def _save_domain(self, domain: str) -> None:
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            fp = self._domain_file(domain)
            rows = sorted(
                self._events_by_domain.get(domain, {}).values(),
                key=lambda e: (float(e.get("ts", 0.0)), str(e.get("id", ""))),
            )
            tmp = fp.with_suffix(".tmp")
            tmp.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
            tmp.replace(fp)
        except Exception:
            pass

    def append_signed_event(self, evt: dict[str, Any]) -> bool:
        if not verify_signed_event(evt):
            return False
        dom = str(evt["domain"]).strip().lower()
        eid = str(evt["id"])
        with self._lock:
            bucket = self._events_by_domain.setdefault(dom, {})
            if eid in bucket:
                return False
            bucket[eid] = evt
            self._save_domain(dom)
            return True

    def merge_events(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        merged = 0
        rejected = 0
        touched_domains: set[str] = set()
        with self._lock:
            for evt in events or []:
                if not isinstance(evt, dict) or not verify_signed_event(evt):
                    rejected += 1
                    continue
                dom = str(evt["domain"]).strip().lower()
                eid = str(evt["id"])
                bucket = self._events_by_domain.setdefault(dom, {})
                if eid not in bucket:
                    bucket[eid] = evt
                    merged += 1
                    touched_domains.add(dom)
            for dom in touched_domains:
                self._save_domain(dom)
        return {"merged": merged, "rejected": rejected, "domains": sorted(touched_domains)}

    def export_events(self, domain: str = "", since_ts: float = 0.0) -> list[dict[str, Any]]:
        dom = domain.strip().lower()
        out: list[dict[str, Any]] = []
        with self._lock:
            targets = [dom] if dom else list(self._events_by_domain.keys())
            for d in targets:
                for evt in self._events_by_domain.get(d, {}).values():
                    if float(evt.get("ts", 0.0)) >= since_ts:
                        out.append(evt)
        out.sort(key=lambda e: (float(e.get("ts", 0.0)), str(e.get("id", ""))))
        return out

    def materialize_collection(self, domain: str, collection: str) -> list[Any]:
        dom = domain.strip().lower()
        with self._lock:
            evts = [
                e for e in self._events_by_domain.get(dom, {}).values()
                if e.get("op") == "append" and e.get("collection") == collection
            ]
        evts.sort(key=lambda e: (float(e.get("ts", 0.0)), str(e.get("id", ""))))
        return [e.get("value") for e in evts]

    def materialize_kv(self, domain: str) -> dict[str, Any]:
        dom = domain.strip().lower()
        with self._lock:
            evts = [
                e for e in self._events_by_domain.get(dom, {}).values()
                if e.get("op") in ("kv_set", "kv_del")
            ]
        evts.sort(key=lambda e: (float(e.get("ts", 0.0)), str(e.get("id", ""))))
        kv: dict[str, Any] = {}
        for e in evts:
            k = str(e.get("key") or "")
            if not k:
                continue
            if e.get("op") == "kv_del":
                kv.pop(k, None)
            else:
                kv[k] = e.get("value")
        return kv
