"""Independent Two-Way Xanadu Transclusion & Cryptographic Provenance Engine."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable

# Supports short {{xnd://domain.xnd}}, versioned {{xnd://domain@v1:0-10}}, and cryptographic {{xnd://domain@v1#a1b2c3d4e5f6:0-10}}
TRANSCLUSION_RE = re.compile(
    r"\{\{\s*xnd://([a-z0-9.-]+\.xnd)(?:@v(\d+))?(?:#([0-9a-fA-F]{6,64}))?(?::(\d+)-(\d+))?\s*\}\}",
    re.IGNORECASE,
)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def format_span_pointer(domain: str, version_num: int, version_hash: str, start: int, end: int) -> str:
    h_part = f"#{version_hash[:12]}" if version_hash else ""
    return f"{{{{xnd://{domain}@v{int(version_num)}{h_part}:{int(start)}-{int(end)}}}}}"


def extract_transclusion_links(
    source_domain: str,
    source_version: int,
    content: str,
    get_version_fn: Callable[[str, int | None], dict[str, Any] | None],
) -> list[dict[str, Any]]:
    links: list[dict[str, Any]] = []
    for m in TRANSCLUSION_RE.finditer(content or ""):
        t_domain = m.group(1).lower()
        t_ver = int(m.group(2)) if m.group(2) else None
        expected_hash = (m.group(3) or "").lower()
        target_v = get_version_fn(t_domain, t_ver)
        actual_hash = (target_v.get("sha256") or "").lower() if target_v else ""
        links.append(
            {
                "source_domain": source_domain,
                "source_version": int(source_version),
                "target_domain": t_domain,
                "target_version": int(target_v["version_num"]) if target_v else (t_ver or 1),
                "target_hash": expected_hash or actual_hash[:12],
                "hash_verified": bool(target_v and (not expected_hash or actual_hash.startswith(expected_hash))),
                "source_start": m.start(),
                "source_end": m.end(),
                "target_start": int(m.group(4)) if m.group(4) is not None else 0,
                "target_end": int(m.group(5)) if m.group(5) is not None else 0,
                "link_type": "transclusion",
            }
        )
    return links


def build_segments(
    content: str,
    get_version_fn: Callable[[str, int | None], dict[str, Any] | None],
    get_blob_fn: Callable[[str], str | None],
) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    pos = 0
    for idx, m in enumerate(TRANSCLUSION_RE.finditer(content or "")):
        if m.start() > pos:
            segments.append({"type": "text", "text": content[pos : m.start()], "start": pos, "end": m.start()})
        t_domain = m.group(1).lower()
        t_ver = int(m.group(2)) if m.group(2) else None
        expected_hash = (m.group(3) or "").lower()
        target_v = get_version_fn(t_domain, t_ver)
        t_text = get_blob_fn(target_v["sha256"]) if target_v else None
        if target_v is not None and t_text is not None:
            raw_s = int(m.group(4)) if m.group(4) is not None else 0
            raw_e = int(m.group(5)) if m.group(5) is not None else len(t_text)
            s = max(0, min(raw_s, len(t_text)))
            e = max(s, min(raw_e, len(t_text)))
            actual_hash = (target_v.get("sha256") or "").lower()
            hash_verified = (not expected_hash) or actual_hash.startswith(expected_hash)
            quoted = t_text[s:e]
            segments.append(
                {
                    "type": "transclusion",
                    "bridge_id": f"bridge-{idx}",
                    "target_domain": t_domain,
                    "target_version": int(target_v["version_num"]),
                    "target_hash": actual_hash,
                    "expected_hash": expected_hash,
                    "hash_verified": hash_verified,
                    "span_sha256": sha256_hex(quoted),
                    "target_start": s,
                    "target_end": e,
                    "quoted_text": quoted,
                    "source_start": m.start(),
                    "source_end": m.end(),
                }
            )
        else:
            segments.append({"type": "broken_transclusion", "raw": m.group(0), "target_domain": t_domain})
        pos = m.end()
    if pos < len(content or ""):
        segments.append({"type": "text", "text": content[pos:], "start": pos, "end": len(content)})
    return segments
