#!/usr/bin/env python3
"""
peer_store.py: Zero-DB In-Memory RAM Index + Append-Only Cryptographic Header Log
+ Zlib-Compressed Sharded Flat-File Store (Pinned vs. Bounded Pruned Cache).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
import time
import urllib.request
import zlib
from pathlib import Path
from typing import Any

from services.index_db import IndexDB

MAX_CACHE_MB = float(os.environ.get("XND_MAX_CACHE_MB", "512"))
MAX_CACHE_BYTES = int(MAX_CACHE_MB * 1024 * 1024)
MAX_CACHED_DOMAINS = max(10, int(os.environ.get("XND_MAX_CACHED_DOMAINS", "5000")))
TOKEN_RE = re.compile(r"[a-z0-9]{2,}")

_SYNONYM_GROUPS = [
    ("owner", "founder", "creator", "author", "architect", "maker"),
    ("made", "built", "created", "founded", "launched", "started"),
    ("site", "app", "website", "page", "capsule", "web"),
    ("browser", "node", "client"),
    ("kenya", "nairobi"),
    ("code", "repo", "repository", "source"),
    ("forum", "discussion", "thread", "post"),
]
_SYNONYM_MAP: dict[str, tuple[str, ...]] = {}
for _grp in _SYNONYM_GROUPS:
    for _w in _grp:
        _SYNONYM_MAP[_w] = tuple(x for x in _grp if x != _w)


def _stem_token(tok: str) -> str:
    if len(tok) <= 3:
        return tok
    if tok.endswith("ies") and len(tok) > 4:
        return tok[:-3] + "y"
    for suf in ("ation", "ment", "ness", "ing", "ers", "ed", "es", "er", "or", "ly"):
        if tok.endswith(suf) and len(tok) - len(suf) >= 3:
            return tok[: -len(suf)]
    if tok.endswith("s") and not tok.endswith("ss") and len(tok) > 3:
        return tok[:-1]
    return tok


class PeerStore:
    def __init__(self, data_dir: Path, hash_fn: Any) -> None:
        self.data_dir = data_dir
        self.hash_fn = hash_fn
        self.lock = threading.RLock()

        self.keys_dir = data_dir / "keys"
        self.pinned_dir = data_dir / "store" / "pinned"
        self.cache_dir = data_dir / "store" / "cache"
        self.assets_dir = data_dir / "store" / "assets"
        self.state_dir = data_dir / "state"
        self.headers_log = data_dir / "headers.jsonl"
        self.links_log = data_dir / "links.jsonl"
        self.peers_file = data_dir / "peers.json"
        self.moderation_file = data_dir / "moderation.json"
        self.bookmarks_file = data_dir / "bookmarks.json"
        self.history_log = data_dir / "history.jsonl"

        for d in (self.keys_dir, self.pinned_dir, self.cache_dir, self.assets_dir, self.state_dir):
            d.mkdir(parents=True, exist_ok=True)

        # In-Memory O(1) RAM Indexes
        self.domains: dict[str, dict[str, Any]] = {}
        self.versions: dict[str, list[dict[str, Any]]] = {}
        self.links_by_target: dict[str, list[dict[str, Any]]] = {}
        self.all_links: list[dict[str, Any]] = []
        self.seen_link_keys: set[tuple[Any, ...]] = set()
        self.tokens: dict[str, set[str]] = {}
        self.doc_tf: dict[str, dict[str, int]] = {}
        self.doc_len: dict[str, int] = {}
        self.doc_snippets: dict[str, str] = {}
        self.crawl_cache: dict[str, dict[str, Any]] = {}
        self.peers: dict[str, dict[str, Any]] = {}
        self.blocked_domains: set[str] = set()
        self.blocked_pubkeys: set[str] = set()
        self.followed_pubkeys: set[str] = set()
        self.bookmarks: list[dict[str, Any]] = []
        self.history: list[dict[str, Any]] = []
        self.index_db = IndexDB(data_dir / "index.sqlite3")

        self._load_from_disk()

    def _load_from_disk(self) -> None:
        with self.lock:
            for kf in self.keys_dir.glob("*.json"):
                try:
                    kd = json.loads(kf.read_text(encoding="utf-8"))
                    self.domains[kd["name"]] = kd
                except Exception:
                    pass

            if self.headers_log.exists():
                for line in self.headers_log.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        h = json.loads(line)
                        self._index_header_ram(h)
                    except Exception:
                        pass

            if self.links_log.exists():
                for line in self.links_log.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        lk = json.loads(line)
                        self._index_link_ram(lk)
                    except Exception:
                        pass

            if self.peers_file.exists():
                try:
                    self.peers = json.loads(self.peers_file.read_text(encoding="utf-8"))
                except Exception:
                    self.peers = {}

            if self.moderation_file.exists():
                try:
                    mod = json.loads(self.moderation_file.read_text(encoding="utf-8"))
                    self.blocked_domains = set(mod.get("blocked_domains", []))
                    self.blocked_pubkeys = set(mod.get("blocked_pubkeys", []))
                    self.followed_pubkeys = set(mod.get("followed_pubkeys", []))
                except Exception:
                    pass

            # One-time backfill into SQLite + FTS5 index if empty
            if self.domains and self.index_db.count_unpinned_domains() == 0:
                for dom_name, dom_obj in list(self.domains.items()):
                    vers = self.versions.get(dom_name, [])
                    is_pinned = bool(dom_obj.get("privkey_hex")) or any(v.get("pinned", True) for v in vers)
                    self.index_db.upsert_domain(
                        dom_name,
                        pubkey_hex=str(dom_obj.get("pubkey_hex") or ""),
                        privkey_hex=str(dom_obj.get("privkey_hex") or ""),
                        created_at=float(dom_obj.get("created_at") or time.time()),
                        updated_at=float(vers[-1].get("created_at") or time.time()) if vers else time.time(),
                        pinned=is_pinned,
                    )
                    for v in vers:
                        self.index_db.upsert_version(v)

    def _index_header_ram(self, h: dict[str, Any]) -> None:
        dom = h["domain"]
        pub = h.get("pubkey_hex") or self.domains.get(dom, {}).get("pubkey_hex", "")
        h["pubkey_hex"] = pub
        if "kind" not in h:
            h["kind"] = "capsule" if h.get("is_app") else "document"
        if dom not in self.domains:
            self.domains[dom] = {
                "name": dom,
                "pubkey_hex": pub,
                "privkey_hex": "",
                "created_at": h.get("created_at", time.time()),
            }
        vers = self.versions.setdefault(dom, [])
        if not any(v["version_num"] == h["version_num"] for v in vers):
            vers.append(h)
            vers.sort(key=lambda x: x["version_num"])

        # Index title + domain tokens in RAM
        self._index_text_tokens(dom, f"{dom} {h.get('title', '')} {h.get('preview', '')}")
        if h.get("preview"):
            self.doc_snippets[dom] = h["preview"]

    @staticmethod
    def extract_crawlable_text(content: str, kind: str = "document") -> tuple[str, str]:
        """Extract clean readable text and snippet from a document or multi-file site bundle."""
        text_parts: list[str] = []
        if kind == "capsule" or (content.lstrip().startswith("{") and '"files"' in content[:200]):
            try:
                bundle = json.loads(content)
                files = bundle.get("files") or {}
                for fname, fval in files.items():
                    if not isinstance(fval, str) or (fval.startswith("data:") and ";base64," in fval[:128]):
                        text_parts.append(fname)
                        continue
                    low_name = fname.lower()
                    if low_name.endswith((".html", ".htm")):
                        # Extract <title>, <meta description>, and visible body text
                        stripped = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", fval)
                        stripped = re.sub(r"(?s)<[^>]+>", " ", stripped)
                        text_parts.append(stripped)
                    elif low_name.endswith((".md", ".txt", ".json", ".js", ".css")):
                        text_parts.append(fval[:4000])
                b_py = bundle.get("backend_py") or ""
                if isinstance(b_py, str) and b_py.strip():
                    text_parts.append(b_py[:2000])
            except Exception:
                text_parts.append(content[:4000])
        else:
            cleaned = re.sub(r"\{\{xnd://[^}]+\}\}", " ", content)
            text_parts.append(cleaned)

        combined = re.sub(r"\s+", " ", " ".join(text_parts)).strip()
        snippet = combined[:240]
        return combined[:16000], snippet

    def crawl_all_domains(self) -> int:
        """Strictly crawl and index all registered .xnd domains into RAM for sub-ms search."""
        crawled = 0
        with self.lock:
            dom_names = list(self.domains.keys())
        for dom in dom_names:
            latest = self.get_version(dom)
            if not latest:
                continue
            blob = self.get_blob(latest.get("sha256", ""))
            if not blob:
                continue
            clean_text, snippet = self.extract_crawlable_text(blob, latest.get("kind", "document"))
            with self.lock:
                self._index_text_tokens(dom, f"{dom} {latest.get('title', '')} {clean_text}")
                if snippet:
                    self.doc_snippets[dom] = snippet
            crawled += 1
        return crawled

    def _index_text_tokens(self, domain: str, text: str) -> None:
        raw_toks = TOKEN_RE.findall(text.lower())
        tf: dict[str, int] = {}
        for tok in raw_toks:
            tf[tok] = tf.get(tok, 0) + 1
            self.tokens.setdefault(tok, set()).add(domain)
            st = _stem_token(tok)
            if st != tok:
                tf[st] = tf.get(st, 0) + 1
                self.tokens.setdefault(st, set()).add(domain)
        self.doc_tf[domain] = tf
        self.doc_len[domain] = max(1, len(raw_toks))

    def get_crawl_cache(self, key: str, ttl_sec: float = 600.0) -> dict[str, Any] | None:
        k = key.strip().lower()
        with self.lock:
            entry = self.crawl_cache.get(k)
            if not entry:
                return None
            if time.time() - entry.get("_ts", 0.0) > ttl_sec:
                self.crawl_cache.pop(k, None)
                return None
            return dict(entry["payload"])

    def put_crawl_cache(self, key: str, payload: dict[str, Any]) -> None:
        k = key.strip().lower()
        if not k:
            return
        with self.lock:
            if len(self.crawl_cache) >= 128:
                oldest = min(self.crawl_cache.items(), key=lambda x: x[1].get("_ts", 0.0))[0]
                self.crawl_cache.pop(oldest, None)
            self.crawl_cache[k] = {"_ts": time.time(), "payload": dict(payload)}

    def _index_link_ram(self, lk: dict[str, Any]) -> None:
        key = (lk["source_hash"], lk["source_start"], lk["target_hash"], lk["target_start"])
        if key in self.seen_link_keys:
            return
        self.seen_link_keys.add(key)
        self.all_links.append(lk)
        self.links_by_target.setdefault(lk["target_domain"], []).append(lk)

    def _blob_path(self, base: Path, sha256: str) -> Path:
        sub = base / sha256[:2]
        sub.mkdir(parents=True, exist_ok=True)
        return sub / f"{sha256}.xndz"

    def put_blob(self, sha256: str, content: str, pinned: bool = True) -> None:
        with self.lock:
            target_base = self.pinned_dir if pinned else self.cache_dir
            p = self._blob_path(target_base, sha256)
            if not p.exists():
                compressed = zlib.compress(content.encode("utf-8"), level=6)
                p.write_bytes(compressed)
            if not pinned:
                self._prune_cache_if_needed()

    def _prune_cache_if_needed(self) -> int:
        files: list[tuple[int, float, int, Path]] = []
        total = 0
        protected = getattr(self, "mesh_protected_shas", set())
        for p in self.cache_dir.rglob("*.xndz"):
            try:
                st = p.stat()
                total += st.st_size
                sha = p.stem
                # Evict non-Rendezvous blobs (0) before Rendezvous-protected mesh blobs (1)
                tier = 1 if sha in protected else 0
                files.append((tier, st.st_mtime, st.st_size, p))
            except OSError:
                pass
        if total <= MAX_CACHE_BYTES:
            return 0
        files.sort(key=lambda x: (x[0], x[1]))
        evicted = 0
        for _, _, sz, p in files:
            if total <= int(MAX_CACHE_BYTES * 0.85):
                break
            try:
                p.unlink()
                total -= sz
                evicted += 1
            except OSError:
                pass
        return evicted

    def get_cache_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.cache_dir.rglob("*.xndz") if p.is_file())

    def get_blob(self, sha256: str) -> str | None:
        with self.lock:
            for base in (self.pinned_dir, self.cache_dir):
                p = base / sha256[:2] / f"{sha256}.xndz"
                if p.exists():
                    try:
                        os.utime(p, None)
                    except OSError:
                        pass
                    return zlib.decompress(p.read_bytes()).decode("utf-8")

        # On-demand P2P fetch if pruned from local cache
        for peer_url in list(self.peers.keys()):
            try:
                req = urllib.request.Request(f"{peer_url.rstrip('/')}/api/blob/{sha256}")
                with urllib.request.urlopen(req, timeout=4) as resp:
                    text = resp.read().decode("utf-8")
                if self.hash_fn(text) == sha256:
                    self.put_blob(sha256, text, pinned=False)
                    return text
            except Exception:
                continue
        return None

    def get_or_create_domain_keys(
        self, domain: str, pub_hex: str, priv_hex: str
    ) -> dict[str, Any]:
        with self.lock:
            if domain not in self.domains:
                kd = {
                    "name": domain,
                    "pubkey_hex": pub_hex,
                    "privkey_hex": priv_hex,
                    "created_at": time.time(),
                }
                self.domains[domain] = kd
                (self.keys_dir / f"{domain}.json").write_text(json.dumps(kd), encoding="utf-8")
            return self.domains[domain]

    def import_domain_key(self, domain: str, pub_hex: str, priv_hex: str) -> None:
        with self.lock:
            kd = {
                "name": domain,
                "pubkey_hex": pub_hex,
                "privkey_hex": priv_hex,
                "created_at": self.domains.get(domain, {}).get("created_at", time.time()),
            }
            self.domains[domain] = kd
            (self.keys_dir / f"{domain}.json").write_text(json.dumps(kd), encoding="utf-8")

    def append_version(self, header: dict[str, Any], content: str, pinned: bool = True) -> bool:
        with self.lock:
            dom = header["domain"]
            existing = self.versions.get(dom, [])
            if any(v["version_num"] == header["version_num"] for v in existing):
                return False
            self.put_blob(header["sha256"], content, pinned=pinned)
            header["pinned"] = pinned
            clean_text, snippet = self.extract_crawlable_text(content, header.get("kind", "document"))
            header["preview"] = snippet
            with self.headers_log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(header) + "\n")
            self._index_header_ram(header)
            self._index_text_tokens(dom, f"{dom} {header.get('title', '')} {clean_text}")
            if snippet:
                self.doc_snippets[dom] = snippet
            self.index_db.upsert_domain(
                dom,
                pubkey_hex=str(header.get("pubkey_hex") or ""),
                privkey_hex=str(self.domains.get(dom, {}).get("privkey_hex") or ""),
                created_at=float(header.get("created_at") or time.time()),
                updated_at=float(header.get("created_at") or time.time()),
                last_accessed=time.time(),
                pinned=pinned,
            )
            self.index_db.upsert_version(header)
            self.index_db.index_fts(dom, str(header.get("title") or dom), clean_text)
            if not pinned:
                self._prune_metadata_if_needed()
            return True

    def _evict_unpinned_domain(self, dom: str) -> None:
        dom_obj = self.domains.get(dom, {})
        if dom_obj.get("privkey_hex"):
            return
        for v in self.versions.get(dom, []):
            sha = str(v.get("sha256") or "")
            if sha:
                p = self.cache_dir / sha[:2] / f"{sha}.xndz"
                if p.exists():
                    try:
                        p.unlink()
                    except OSError:
                        pass
        self.domains.pop(dom, None)
        self.versions.pop(dom, None)
        self.doc_tf.pop(dom, None)
        self.doc_len.pop(dom, None)
        self.doc_snippets.pop(dom, None)
        for doms in self.tokens.values():
            doms.discard(dom)
        self.index_db.evict_domain(dom)

    def _prune_metadata_if_needed(self) -> int:
        unpinned_count = self.index_db.count_unpinned_domains()
        if unpinned_count <= MAX_CACHED_DOMAINS:
            return 0
        excess = unpinned_count - int(MAX_CACHED_DOMAINS * 0.9)
        victims = self.index_db.get_evictable_domains(limit=max(1, excess))
        evicted = 0
        for dom in victims:
            if dom in self.domains and self.domains[dom].get("privkey_hex"):
                continue
            pub = str(self.domains.get(dom, {}).get("pubkey_hex") or "").lower()
            if pub and pub in self.followed_pubkeys:
                continue
            self._evict_unpinned_domain(dom)
            evicted += 1
        return evicted

    def append_link(self, link: dict[str, Any]) -> bool:
        with self.lock:
            key = (link["source_hash"], link["source_start"], link["target_hash"], link["target_start"])
            if key in self.seen_link_keys:
                return False
            with self.links_log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(link) + "\n")
            self._index_link_ram(link)
            self.index_db.add_link(
                str(link.get("source_domain") or ""),
                int(link.get("source_version") or 1),
                str(link.get("target_domain") or ""),
                int(link.get("target_version") or 1),
                int(link.get("target_start") or 0),
                int(link.get("target_end") or 0),
                str(link.get("target_hash") or ""),
                float(link.get("created_at") or time.time()),
            )
            return True

    def get_version(self, domain: str, version_num: int | None = None) -> dict[str, Any] | None:
        with self.lock:
            vers = self.versions.get(domain, [])
            if not vers:
                return None
            self.index_db.touch_domain(domain)
            if version_num is None:
                return vers[-1]
            for v in vers:
                if v["version_num"] == version_num:
                    return v
            return None

    def search_ram(self, query: str) -> list[dict[str, Any]]:
        with self.lock:
            q_low = query.lower()
            q_tokens = TOKEN_RE.findall(q_low)
            scores: dict[str, float] = {}
            n_docs = max(1, len(self.domains))
            avg_dl = (sum(self.doc_len.values()) / max(1, len(self.doc_len))) if self.doc_len else 40.0

            for dom in self.domains:
                if q_low in dom:
                    scores[dom] = scores.get(dom, 0.0) + 12.0

            def _bm25_add(term: str, weight: float) -> None:
                doms = self.tokens.get(term)
                if not doms:
                    return
                df = len(doms)
                idf = math.log(1.0 + (n_docs - df + 0.5) / (df + 0.5))
                for dom in doms:
                    tf = self.doc_tf.get(dom, {}).get(term, 1)
                    dl = self.doc_len.get(dom, int(avg_dl))
                    denom = tf + 1.2 * (0.25 + 0.75 * (dl / max(1.0, avg_dl)))
                    bm25 = idf * ((tf * 2.2) / max(0.1, denom))
                    scores[dom] = scores.get(dom, 0.0) + weight * (1.0 + bm25)

            for tok in q_tokens:
                _bm25_add(tok, 3.0)
                st = _stem_token(tok)
                if st != tok:
                    _bm25_add(st, 2.0)
                for syn in _SYNONYM_MAP.get(tok, ()):
                    _bm25_add(syn, 1.5)
                    syn_st = _stem_token(syn)
                    if syn_st != syn:
                        _bm25_add(syn_st, 1.1)
                # Prefix match on RAM tokens
                for k_tok, doms in self.tokens.items():
                    if k_tok.startswith(tok) and k_tok != tok:
                        for dom in doms:
                            scores[dom] = scores.get(dom, 0.0) + 0.8

            # Merge SQLite FTS5 BM25 results so disk-backed/stemmed queries always hit
            for fts_hit in self.index_db.search_fts(query, limit=30):
                f_dom = fts_hit["domain"]
                scores[f_dom] = scores.get(f_dom, 0.0) + float(fts_hit.get("score") or 1.0)

            results: list[dict[str, Any]] = []
            for dom, sc in scores.items():
                latest = self.get_version(dom)
                if not latest:
                    continue
                bl_count = len(self.links_by_target.get(dom, []))
                snip = self.doc_snippets.get(dom, "")
                m_src = re.match(r"^Archived from:\s*(https?://\S+)", snip, re.IGNORECASE)
                results.append(
                    {
                        "domain": dom,
                        "title": latest["title"],
                        "kind": latest.get("kind", "document"),
                        "version": latest.get("version_num", 1),
                        "sha256": latest["sha256"],
                        "backlinks_count": bl_count,
                        "snippet": snip,
                        "source_url": m_src.group(1) if m_src else "",
                        "_score": sc + bl_count * 2,
                    }
                )
            results.sort(key=lambda x: x["_score"], reverse=True)
            for r in results:
                r.pop("_score", None)
            return results[:30]

    def get_capsule_state(self, domain: str) -> dict[str, Any]:
        p = self.state_dir / f"{domain}.json"
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def save_capsule_state(self, domain: str, state: dict[str, Any]) -> None:
        (self.state_dir / f"{domain}.json").write_text(json.dumps(state), encoding="utf-8")

    # ---- Zero-DB Bookmarks, History & Identity Sync ----
    def _load_bookmarks_and_history(self) -> None:
        if self.bookmarks_file.exists():
            try:
                self.bookmarks = json.loads(self.bookmarks_file.read_text(encoding="utf-8"))
            except Exception:
                self.bookmarks = []
        if self.history_log.exists():
            lines = self.history_log.read_text(encoding="utf-8").splitlines()[-500:]
            for line in lines:
                if line.strip():
                    try:
                        self.history.append(json.loads(line))
                    except Exception:
                        pass

    def get_bookmarks(self) -> list[dict[str, Any]]:
        with self.lock:
            if not self.bookmarks and self.bookmarks_file.exists():
                self._load_bookmarks_and_history()
            return list(self.bookmarks)

    def add_bookmark(self, url: str, title: str, kind: str = "www") -> list[dict[str, Any]]:
        with self.lock:
            if not self.bookmarks and self.bookmarks_file.exists():
                self._load_bookmarks_and_history()
            clean = url.strip()
            self.bookmarks = [b for b in self.bookmarks if b.get("url") != clean]
            self.bookmarks.insert(0, {"url": clean, "title": (title or clean)[:120], "kind": kind, "created_at": time.time()})
            self.bookmarks_file.write_text(json.dumps(self.bookmarks, indent=2), encoding="utf-8")
            return list(self.bookmarks)

    def remove_bookmark(self, url: str) -> list[dict[str, Any]]:
        with self.lock:
            if not self.bookmarks and self.bookmarks_file.exists():
                self._load_bookmarks_and_history()
            clean = url.strip()
            self.bookmarks = [b for b in self.bookmarks if b.get("url") != clean]
            self.bookmarks_file.write_text(json.dumps(self.bookmarks, indent=2), encoding="utf-8")
            return list(self.bookmarks)

    def record_history(self, url: str, title: str, kind: str = "www") -> None:
        with self.lock:
            if not self.history and self.history_log.exists():
                self._load_bookmarks_and_history()
            entry = {"url": url.strip(), "title": (title or url)[:120], "kind": kind, "visited_at": time.time()}
            if self.history and self.history[-1].get("url") == entry["url"]:
                self.history[-1] = entry
            else:
                self.history.append(entry)
                if len(self.history) > 500:
                    self.history = self.history[-500:]
            with self.history_log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")

    def search_history(self, q: str = "") -> list[dict[str, Any]]:
        with self.lock:
            if not self.history and self.history_log.exists():
                self._load_bookmarks_and_history()
            ql = q.strip().lower()
            items = list(reversed(self.history))
            if ql:
                items = [h for h in items if ql in h.get("url", "").lower() or ql in h.get("title", "").lower()]
            return items[:100]

    def export_owned_identities(self) -> list[dict[str, str]]:
        with self.lock:
            return [
                {"domain": dom["name"], "pubkey_hex": dom["pubkey_hex"], "privkey_hex": dom["privkey_hex"]}
                for dom in self.domains.values()
                if dom.get("privkey_hex")
            ]

    def put_asset(self, sha256: str, filename: str, mime_type: str, raw: bytes) -> None:
        with self.lock:
            sub = self.assets_dir / sha256[:2]
            sub.mkdir(parents=True, exist_ok=True)
            meta_p = sub / f"{sha256}.meta.json"
            data_p = sub / f"{sha256}.xndz"
            if not data_p.exists():
                data_p.write_bytes(zlib.compress(raw, level=6))
                meta_p.write_text(
                    json.dumps({"sha256": sha256, "filename": filename, "mime_type": mime_type, "created_at": time.time()}),
                    encoding="utf-8",
                )

    def get_asset(self, sha256: str) -> tuple[str, bytes] | None:
        sub = self.assets_dir / sha256[:2]
        meta_p = sub / f"{sha256}.meta.json"
        data_p = sub / f"{sha256}.xndz"
        if not meta_p.exists() or not data_p.exists():
            return None
        meta = json.loads(meta_p.read_text(encoding="utf-8"))
        return meta["mime_type"], zlib.decompress(data_p.read_bytes())

    def list_assets_meta(self) -> list[dict[str, Any]]:
        out = []
        for mp in self.assets_dir.rglob("*.meta.json"):
            try:
                out.append(json.loads(mp.read_text(encoding="utf-8")))
            except Exception:
                pass
        return out

    def save_peer(self, url: str, label: str, last_sync: float, subscribed: bool | None = None) -> None:
        with self.lock:
            existing = self.peers.get(url, {})
            sub = existing.get("subscribed", False) if subscribed is None else bool(subscribed)
            self.peers[url] = {"url": url, "label": label, "last_sync": last_sync, "subscribed": sub}
            self.peers_file.write_text(json.dumps(self.peers, indent=2), encoding="utf-8")

    def save_moderation(self) -> None:
        with self.lock:
            self.moderation_file.write_text(
                json.dumps(
                    {
                        "blocked_domains": sorted(self.blocked_domains),
                        "blocked_pubkeys": sorted(self.blocked_pubkeys),
                        "followed_pubkeys": sorted(self.followed_pubkeys),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

    def delete_domain(self, domain: str) -> bool:
        dom = domain.strip().lower()
        with self.lock:
            existed = dom in self.domains or dom in self.versions
            self.domains.pop(dom, None)
            self.versions.pop(dom, None)
            self.doc_tf.pop(dom, None)
            self.doc_len.pop(dom, None)
            self.doc_snippets.pop(dom, None)
            for doms in self.tokens.values():
                doms.discard(dom)
            self.index_db.evict_domain(dom)
            kf = self.keys_dir / f"{dom}.json"
            if kf.exists():
                try:
                    kf.unlink()
                except Exception:
                    pass
            if self.headers_log.exists():
                kept = []
                for ln in self.headers_log.read_text(encoding="utf-8").splitlines():
                    if not ln.strip():
                        continue
                    try:
                        if json.loads(ln).get("domain") != dom:
                            kept.append(ln)
                    except Exception:
                        pass
                self.headers_log.write_text(("\n".join(kept) + "\n") if kept else "", encoding="utf-8")
            return existed

    def get_manifest_page(self, since: float = 0.0, limit: int = 500) -> tuple[dict[str, dict[str, Any]], float, bool]:
        return self.index_db.list_manifest_page(since=since, limit=limit)

    def storage_stats(self) -> dict[str, Any]:
        pinned_bytes = sum(p.stat().st_size for p in self.pinned_dir.rglob("*.xndz"))
        cache_bytes = self.get_cache_bytes()
        return {
            "mode": "sqlite-fts5-lru-merkle",
            "domains_in_ram": len(self.domains),
            "unpinned_cached_domains": self.index_db.count_unpinned_domains(),
            "max_cached_domains": MAX_CACHED_DOMAINS,
            "pinned_kb": round(pinned_bytes / 1024, 2),
            "cache_kb": round(cache_bytes / 1024, 2),
            "mesh_bytes": cache_bytes,
            "mesh_quota_bytes": MAX_CACHE_BYTES,
            "max_cache_mb": MAX_CACHE_MB,
        }
