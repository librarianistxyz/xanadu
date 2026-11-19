"""Air-gapped Sneakernet (.xndbundle) & Animated QR (`XNDQ1`) delta sync for Xanadu."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import threading
import time
import zlib
from pathlib import Path
from typing import Any

import qrcode
import qrcode.image.svg

SNEAKERNET_FORMAT = "xnd-sneakernet-v1"
QR_FRAME_PREFIX = "XNDQ1"
DEFAULT_QR_CHUNK_BYTES = 480
MAX_QR_FRAMES = 400


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_delta_bundle(
    full_bundle: dict[str, Any],
    since_ts: float = 0.0,
    domain_filter: str = "",
) -> dict[str, Any]:
    """Filter a full sync export to a delta bundle since `since_ts` (optionally for one domain)."""
    dom_q = (domain_filter or "").strip().lower()
    cutoff = float(since_ts or 0.0)

    versions: list[dict[str, Any]] = []
    needed_domains: set[str] = set()
    needed_blobs: set[str] = set()

    for v in full_bundle.get("versions", []):
        v_dom = str(v.get("domain") or "").strip().lower()
        if dom_q and v_dom != dom_q:
            continue
        if float(v.get("created_at") or 0.0) <= cutoff:
            continue
        versions.append(v)
        needed_domains.add(v_dom)
        if v.get("sha256"):
            needed_blobs.add(str(v["sha256"]))

    domains = [
        d for d in full_bundle.get("domains", [])
        if str(d.get("name") or "").strip().lower() in needed_domains
        or (not versions and dom_q and str(d.get("name") or "").strip().lower() == dom_q)
    ]
    blobs = [b for b in full_bundle.get("blobs", []) if str(b.get("sha256") or "") in needed_blobs]

    links = [
        lk for lk in full_bundle.get("links", [])
        if (not dom_q or str(lk.get("source_domain") or "").strip().lower() == dom_q)
        and (not versions or str(lk.get("source_domain") or "").strip().lower() in needed_domains)
    ]

    assets = [
        a for a in full_bundle.get("assets", [])
        if float(a.get("created_at") or 0.0) > cutoff
    ] if not dom_q else []

    crdt_events = [
        ev for ev in full_bundle.get("crdt_events", [])
        if float(ev.get("ts") or 0.0) > cutoff
        and (not dom_q or str(ev.get("domain") or "").strip().lower() == dom_q)
    ]

    forum_posts = [
        p for p in full_bundle.get("forum_posts", [])
        if isinstance(p, dict) and float(p.get("created_at") or 0.0) > cutoff
    ] if (not dom_q or dom_q == "forum.xnd") else []

    wiki_shards = [
        w for w in full_bundle.get("wiki_shards", [])
        if isinstance(w, dict) and float(w.get("created_at") or 0.0) > cutoff
    ] if not dom_q else []

    return {
        "domains": domains,
        "blobs": blobs,
        "versions": versions,
        "links": links,
        "assets": assets,
        "forum_posts": forum_posts,
        "crdt_events": crdt_events,
        "wiki_shards": wiki_shards,
        "qa_patterns": full_bundle.get("qa_patterns", {}) if not cutoff and not dom_q else {},
    }


def pack_sneakernet_envelope(bundle: dict[str, Any], since_ts: float = 0.0) -> dict[str, Any]:
    """Compress a sync bundle with zlib and wrap it in a hash-verified .xndbundle envelope."""
    raw_json = _canonical_json_bytes(bundle)
    bundle_sha256 = hashlib.sha256(raw_json).hexdigest()
    compressed = zlib.compress(raw_json, level=9)
    return {
        "format": SNEAKERNET_FORMAT,
        "created_at": round(time.time(), 3),
        "since_ts": float(since_ts or 0.0),
        "bundle_sha256": bundle_sha256,
        "raw_bytes": len(raw_json),
        "compressed_bytes": len(compressed),
        "encoding": "zlib+b64",
        "payload_b64": base64.b64encode(compressed).decode("ascii"),
    }


def unpack_sneakernet_envelope(data: dict[str, Any] | bytes | str) -> dict[str, Any]:
    """Verify and decompress a .xndbundle envelope (or accept a raw sync bundle dict)."""
    if isinstance(data, (bytes, bytearray)):
        obj = json.loads(data.decode("utf-8"))
    elif isinstance(data, str):
        obj = json.loads(data)
    else:
        obj = data

    if not isinstance(obj, dict):
        raise ValueError("Invalid sneakernet bundle format")

    if obj.get("format") != SNEAKERNET_FORMAT:
        if any(k in obj for k in ("versions", "domains", "crdt_events", "blobs")):
            return obj
        raise ValueError(f"Unsupported sneakernet format: {obj.get('format')}")

    compressed = base64.b64decode(str(obj.get("payload_b64") or ""), validate=True)
    raw_json = zlib.decompress(compressed)
    actual_sha = hashlib.sha256(raw_json).hexdigest()
    expected_sha = str(obj.get("bundle_sha256") or "").strip().lower()
    if not expected_sha or actual_sha != expected_sha:
        raise ValueError("Sneakernet bundle integrity check failed (SHA-256 mismatch)")

    bundle = json.loads(raw_json.decode("utf-8"))
    if not isinstance(bundle, dict):
        raise ValueError("Decompressed sneakernet bundle must be a JSON object")
    return bundle


def list_usb_mounts() -> list[dict[str, Any]]:
    """Discover writable removable/USB mount points and any .xndbundle files on them."""
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    roots: list[Path] = []
    if user:
        roots.extend([Path("/media") / user, Path("/run/media") / user])
    roots.extend([Path("/media"), Path("/mnt")])

    seen: set[str] = set()
    mounts: list[dict[str, Any]] = []
    for root in roots:
        if not root.is_dir():
            continue
        try:
            children = sorted(root.iterdir())
        except Exception:
            continue
        for child in children:
            if not child.is_dir():
                continue
            resolved = str(child.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            writable = os.access(child, os.W_OK)
            sneaker_dir = child / "xanadu_sneakernet"
            bundles: list[str] = []
            if sneaker_dir.is_dir():
                bundles = sorted(p.name for p in sneaker_dir.glob("*.xndbundle"))
            else:
                bundles = sorted(p.name for p in child.glob("*.xndbundle"))
            if writable or bundles:
                mounts.append({
                    "name": child.name,
                    "path": str(child),
                    "writable": writable,
                    "bundles": bundles[:50],
                })
    return mounts


def export_bundle_to_file(target_dir: str, envelope: dict[str, Any], filename: str = "") -> Path:
    """Atomically write a .xndbundle file to `target_dir/xanadu_sneakernet/`."""
    base = Path(target_dir).expanduser().resolve()
    if not base.is_dir():
        raise ValueError(f"Target directory does not exist: {target_dir}")
    out_dir = base / "xanadu_sneakernet"
    out_dir.mkdir(parents=True, exist_ok=True)
    short_hash = str(envelope.get("bundle_sha256") or "bundle")[:10]
    clean_name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in (filename or "").strip())
    if not clean_name:
        clean_name = f"xnd_{int(time.time())}_{short_hash}.xndbundle"
    elif not clean_name.endswith(".xndbundle"):
        clean_name += ".xndbundle"
    dest = out_dir / clean_name
    tmp = out_dir / f".{clean_name}.tmp"
    tmp.write_text(json.dumps(envelope, separators=(",", ":")), encoding="utf-8")
    tmp.replace(dest)
    return dest


def import_bundle_from_file(file_path: str) -> dict[str, Any]:
    """Read and verify a .xndbundle file from disk or USB mount."""
    p = Path(file_path).expanduser().resolve()
    if not p.is_file():
        raise ValueError(f"Bundle file not found: {file_path}")
    return unpack_sneakernet_envelope(p.read_bytes())


def render_qr_svg(frame: str) -> str:
    """Render a single QR frame string to compact SVG markup."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=6,
        border=2,
    )
    qr.add_data(frame)
    qr.make(fit=True)
    img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def encode_animated_qr_frames(
    bundle: dict[str, Any],
    chunk_bytes: int = DEFAULT_QR_CHUNK_BYTES,
    include_svg: bool = True,
) -> dict[str, Any]:
    """Split a compressed sync bundle into self-verifying `XNDQ1` animated QR frames."""
    chunk_sz = max(120, min(1200, int(chunk_bytes or DEFAULT_QR_CHUNK_BYTES)))
    raw_json = _canonical_json_bytes(bundle)
    bundle_sha = hashlib.sha256(raw_json).hexdigest()
    compressed = zlib.compress(raw_json, level=9)

    total = max(1, (len(compressed) + chunk_sz - 1) // chunk_sz)
    if total > MAX_QR_FRAMES:
        raise ValueError(
            f"Delta bundle too large for QR ({total} frames > {MAX_QR_FRAMES}). "
            "Use a narrower domain/since_ts filter or USB file export."
        )

    transfer_id = bundle_sha[:8]
    sha_prefix = bundle_sha[:12]
    frames: list[str] = []
    for idx in range(total):
        part = compressed[idx * chunk_sz : (idx + 1) * chunk_sz]
        part_b64 = base64.b64encode(part).decode("ascii")
        crc_hex = f"{zlib.crc32(part) & 0xFFFFFFFF:08x}"
        frames.append(f"{QR_FRAME_PREFIX}|{transfer_id}|{idx + 1}/{total}|{sha_prefix}|{crc_hex}|{part_b64}")

    svgs = [render_qr_svg(f) for f in frames] if include_svg else []
    return {
        "transfer_id": transfer_id,
        "total_frames": total,
        "bundle_sha256": bundle_sha,
        "raw_bytes": len(raw_json),
        "compressed_bytes": len(compressed),
        "frames": frames,
        "svgs": svgs,
    }


class QrReassemblySession:
    """Thread-safe receiver for out-of-order / looping `XNDQ1` animated QR frames."""

    def __init__(self, max_sessions: int = 16) -> None:
        self._lock = threading.Lock()
        self._max_sessions = max_sessions
        self._sessions: dict[str, dict[str, Any]] = {}

    def add_frame(self, frame_str: str) -> dict[str, Any]:
        parts = (frame_str or "").strip().split("|", 5)
        if len(parts) != 6 or parts[0] != QR_FRAME_PREFIX:
            raise ValueError("Invalid XNDQ1 QR frame header")

        _, transfer_id, idx_tot, sha_prefix, crc_hex, chunk_b64 = parts
        if "/" not in idx_tot:
            raise ValueError("Invalid XNDQ1 frame index/total")
        idx_s, tot_s = idx_tot.split("/", 1)
        idx = int(idx_s)
        total = int(tot_s)
        if total < 1 or total > MAX_QR_FRAMES or idx < 1 or idx > total:
            raise ValueError(f"Invalid XNDQ1 frame bounds: {idx}/{total}")

        raw_chunk = base64.b64decode(chunk_b64, validate=True)
        actual_crc = f"{zlib.crc32(raw_chunk) & 0xFFFFFFFF:08x}"
        if actual_crc != crc_hex.lower():
            raise ValueError(f"QR frame {idx}/{total} CRC32 mismatch")

        with self._lock:
            if transfer_id not in self._sessions and len(self._sessions) >= self._max_sessions:
                oldest = min(self._sessions.items(), key=lambda kv: kv[1]["updated_at"])[0]
                self._sessions.pop(oldest, None)

            sess = self._sessions.get(transfer_id)
            if sess is None or sess["total"] != total or sess["sha_prefix"] != sha_prefix:
                sess = {
                    "total": total,
                    "sha_prefix": sha_prefix,
                    "chunks": {},
                    "updated_at": time.time(),
                }
                self._sessions[transfer_id] = sess

            sess["chunks"][idx] = raw_chunk
            sess["updated_at"] = time.time()
            received = len(sess["chunks"])
            missing = [i for i in range(1, total + 1) if i not in sess["chunks"]]

            if missing:
                return {
                    "complete": False,
                    "transfer_id": transfer_id,
                    "received": received,
                    "total": total,
                    "missing": missing[:20],
                }

            compressed = b"".join(sess["chunks"][i] for i in range(1, total + 1))
            self._sessions.pop(transfer_id, None)

        raw_json = zlib.decompress(compressed)
        actual_sha = hashlib.sha256(raw_json).hexdigest()
        if not actual_sha.startswith(sha_prefix.lower()):
            raise ValueError("Reassembled QR bundle SHA-256 prefix mismatch")

        bundle = json.loads(raw_json.decode("utf-8"))
        if not isinstance(bundle, dict):
            raise ValueError("Reassembled QR bundle is not a JSON object")
        return {
            "complete": True,
            "transfer_id": transfer_id,
            "received": total,
            "total": total,
            "bundle_sha256": actual_sha,
            "bundle": bundle,
        }
