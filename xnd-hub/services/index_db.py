"""SQLite + FTS5 persistent index for PeerStore (bounded RAM, O(1) lookups, BM25 search)."""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

_FTS_TOKEN_RE = re.compile(r"[a-z0-9]{2,}")


class IndexDB:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.lock = threading.RLock()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=5.0)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS domains (
                    name TEXT PRIMARY KEY,
                    pubkey_hex TEXT NOT NULL DEFAULT '',
                    privkey_hex TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL DEFAULT 0,
                    last_accessed REAL NOT NULL DEFAULT 0,
                    pinned INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_domains_updated ON domains(updated_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_domains_lru ON domains(pinned, last_accessed)")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS versions (
                    domain TEXT NOT NULL,
                    version_num INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    prev_sha256 TEXT NOT NULL DEFAULT '',
                    title TEXT NOT NULL DEFAULT '',
                    kind TEXT NOT NULL DEFAULT 'document',
                    pubkey_hex TEXT NOT NULL DEFAULT '',
                    signature_hex TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL DEFAULT 0,
                    PRIMARY KEY (domain, version_num)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS links (
                    source_domain TEXT NOT NULL,
                    source_version INTEGER NOT NULL,
                    target_domain TEXT NOT NULL,
                    target_version INTEGER NOT NULL DEFAULT 1,
                    start_idx INTEGER NOT NULL DEFAULT 0,
                    end_idx INTEGER NOT NULL DEFAULT 0,
                    quote_sha256 TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL DEFAULT 0,
                    UNIQUE (source_domain, source_version, target_domain, start_idx, end_idx)
                )
                """
            )
            cur.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS docs_fts USING fts5(
                    domain UNINDEXED,
                    title,
                    body,
                    tokenize='porter unicode61'
                )
                """
            )
            self.conn.commit()

    def close(self) -> None:
        with self.lock:
            try:
                self.conn.close()
            except Exception:
                pass

    def upsert_domain(
        self,
        name: str,
        pubkey_hex: str = "",
        privkey_hex: str = "",
        created_at: float = 0.0,
        updated_at: float = 0.0,
        last_accessed: float = 0.0,
        pinned: bool = False,
    ) -> None:
        now = time.time()
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO domains(name, pubkey_hex, privkey_hex, created_at, updated_at, last_accessed, pinned)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    pubkey_hex = CASE WHEN excluded.pubkey_hex != '' THEN excluded.pubkey_hex ELSE domains.pubkey_hex END,
                    privkey_hex = CASE WHEN excluded.privkey_hex != '' THEN excluded.privkey_hex ELSE domains.privkey_hex END,
                    updated_at = MAX(domains.updated_at, excluded.updated_at),
                    last_accessed = MAX(domains.last_accessed, excluded.last_accessed),
                    pinned = MAX(domains.pinned, excluded.pinned)
                """,
                (
                    name,
                    pubkey_hex,
                    privkey_hex,
                    created_at or now,
                    updated_at or now,
                    last_accessed or now,
                    1 if (pinned or privkey_hex) else 0,
                ),
            )
            self.conn.commit()

    def upsert_version(self, header: dict[str, Any]) -> None:
        dom = str(header["domain"]).strip().lower()
        ver = int(header["version_num"])
        with self.lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO versions(
                    domain, version_num, sha256, prev_sha256, title, kind, pubkey_hex, signature_hex, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dom,
                    ver,
                    str(header.get("sha256") or ""),
                    str(header.get("prev_sha256") or ""),
                    str(header.get("title") or dom),
                    str(header.get("kind") or "document"),
                    str(header.get("pubkey_hex") or ""),
                    str(header.get("signature_hex") or ""),
                    float(header.get("created_at") or time.time()),
                ),
            )
            self.conn.commit()

    def index_fts(self, domain: str, title: str, body: str) -> None:
        dom = domain.strip().lower()
        with self.lock:
            self.conn.execute("DELETE FROM docs_fts WHERE domain = ?", (dom,))
            self.conn.execute(
                "INSERT INTO docs_fts(domain, title, body) VALUES (?, ?, ?)",
                (dom, title or dom, (body or "")[:65536]),
            )
            self.conn.commit()

    def touch_domain(self, domain: str, ts: float | None = None) -> None:
        now = float(ts if ts is not None else time.time())
        with self.lock:
            self.conn.execute("UPDATE domains SET last_accessed = ? WHERE name = ?", (now, domain.strip().lower()))
            self.conn.commit()

    def add_link(
        self,
        source_domain: str,
        source_version: int,
        target_domain: str,
        target_version: int,
        start_idx: int,
        end_idx: int,
        quote_sha256: str,
        created_at: float,
    ) -> None:
        with self.lock:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO links(
                    source_domain, source_version, target_domain, target_version, start_idx, end_idx, quote_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (source_domain, source_version, target_domain, target_version, start_idx, end_idx, quote_sha256, created_at),
            )
            self.conn.commit()

    def search_fts(self, query: str, limit: int = 30) -> list[dict[str, Any]]:
        tokens = _FTS_TOKEN_RE.findall((query or "").lower())
        if not tokens:
            return []
        fts_query = " OR ".join(f'"{t}"' for t in tokens[:12])
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT domain, title, snippet(docs_fts, 2, '', '', '...', 24) AS snip, bm25(docs_fts, 10.0, 1.0) AS rank
                FROM docs_fts
                WHERE docs_fts MATCH ?
                ORDER BY rank ASC
                LIMIT ?
                """,
                (fts_query, max(1, min(100, limit))),
            ).fetchall()
        return [
            {
                "domain": r["domain"],
                "title": r["title"],
                "snippet": r["snip"] or "",
                "score": round(max(0.1, -float(r["rank"]) + 1.0), 3),
            }
            for r in rows
        ]

    def count_unpinned_domains(self) -> int:
        with self.lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS c FROM domains WHERE pinned = 0 AND privkey_hex = ''"
            ).fetchone()
            return int(row["c"]) if row else 0

    def get_evictable_domains(self, limit: int = 100) -> list[str]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT name FROM domains
                WHERE pinned = 0 AND privkey_hex = ''
                ORDER BY last_accessed ASC, updated_at ASC
                LIMIT ?
                """,
                (max(1, limit),),
            ).fetchall()
            return [str(r["name"]) for r in rows]

    def evict_domain(self, domain: str) -> None:
        dom = domain.strip().lower()
        with self.lock:
            self.conn.execute("DELETE FROM docs_fts WHERE domain = ?", (dom,))
            self.conn.execute("DELETE FROM links WHERE source_domain = ?", (dom,))
            self.conn.execute("DELETE FROM versions WHERE domain = ?", (dom,))
            self.conn.execute("DELETE FROM domains WHERE name = ?", (dom,))
            self.conn.commit()

    def list_manifest_page(self, since: float = 0.0, limit: int = 500) -> tuple[dict[str, dict[str, Any]], float, bool]:
        cap = max(1, min(2000, int(limit)))
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT d.name, d.pubkey_hex, d.updated_at, v.version_num, v.sha256
                FROM domains d
                JOIN versions v ON v.domain = d.name
                WHERE d.updated_at > ?
                  AND v.version_num = (SELECT MAX(v2.version_num) FROM versions v2 WHERE v2.domain = d.name)
                ORDER BY d.updated_at ASC, d.name ASC
                LIMIT ?
                """,
                (float(since), cap + 1),
            ).fetchall()
        has_more = len(rows) > cap
        page_rows = rows[:cap]
        dom_map: dict[str, dict[str, Any]] = {}
        next_cursor = float(since)
        for r in page_rows:
            dom_map[r["name"]] = {
                "latest_version": int(r["version_num"]),
                "sha256": str(r["sha256"]),
                "pubkey_hex": str(r["pubkey_hex"]),
                "updated_at": float(r["updated_at"]),
            }
            if float(r["updated_at"]) > next_cursor:
                next_cursor = float(r["updated_at"])
        return dom_map, next_cursor, has_more
