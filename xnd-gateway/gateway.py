#!/usr/bin/env python3
"""
Tiny Read-Only Public Web Gateway for Xanadu (.xnd).
Resolves kind:30078 / kind:1 Nostr events, verifies SHA-256 & Ed25519 signatures,
and renders .xnd sites in any standard browser with a one-click Xanadu Node prompt.
"""

from __future__ import annotations

import hashlib
import html
import json
import mimetypes
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

HUB_DIR = Path(__file__).resolve().parent.parent / "xnd-hub"
if str(HUB_DIR) not in sys.path:
    sys.path.insert(0, str(HUB_DIR))

import abuse_guard  # noqa: E402
from p2p_discovery import lookup_doc_nostr  # noqa: E402

app = FastAPI(title="Xanadu (.xnd) Public Read-Only Gateway")

_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
CACHE_TTL_SEC = float(os.environ.get("XND_GATEWAY_CACHE_TTL", "60"))
NODE_DOWNLOAD_URL = os.environ.get("XND_NODE_DOWNLOAD_URL", "https://github.com/xanadu-net/xanadu/releases")

_GW_IP_LIMITER = abuse_guard.SlidingWindowLimiter(int(os.environ.get("XND_GATEWAY_RATE_PER_MIN", "60")), 60.0)
_GW_BLOCKLIST = abuse_guard.BlocklistManager()
for _d in os.environ.get("XND_GATEWAY_BLOCKED_DOMAINS", "").split(","):
    if _d.strip():
        _GW_BLOCKLIST.blocked_domains.add(_d.strip().lower())
for _p in os.environ.get("XND_GATEWAY_BLOCKED_PUBKEYS", "").split(","):
    if _p.strip():
        _GW_BLOCKLIST.blocked_pubkeys.add(_p.strip().lower())


@app.middleware("http")
async def _gateway_rate_limit_middleware(request: Request, call_next: Any) -> Response:
    xff = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    client_ip = xff or (request.client.host if request.client else "127.0.0.1")
    ok, retry_after = _GW_IP_LIMITER.allow(client_ip)
    if not ok:
        return JSONResponse(
            {"detail": "Gateway rate limit exceeded"},
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )
    return await call_next(request)


def _verify_version(domain: str, ver_num: int, sha256_hex: str, pub_hex: str, sig_hex: str, content: str, prev_sha256: str = "") -> bool:
    try:
        if hashlib.sha256(content.encode("utf-8")).hexdigest() != sha256_hex:
            return False
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        msg = f"{domain}|v{ver_num}|{sha256_hex}|{prev_sha256}" if prev_sha256 else f"{domain}|v{ver_num}|{sha256_hex}"
        pub.verify(bytes.fromhex(sig_hex), msg.encode("utf-8"))
        return True
    except Exception:
        return False


_CANONICAL_DOMAIN_RE = re.compile(r"^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.([0-9a-f]{8,16})\.xnd$")


def _resolve_domain(domain: str) -> dict[str, Any]:
    clean = domain.strip().lower()
    if not clean.endswith(".xnd"):
        clean = f"{clean}.xnd"
    if _GW_BLOCKLIST.is_blocked(clean, ""):
        raise HTTPException(status_code=403, detail=f"Domain '{clean}' is blocked by gateway moderation policy.")
    now = time.time()
    cached = _CACHE.get(clean)
    if cached and (now - cached[0]) < CACHE_TTL_SEC:
        return cached[1]

    m_canon = _CANONICAL_DOMAIN_RE.match(clean)
    sign_dom = clean
    versions: list[dict[str, Any]] = []
    bundle = lookup_doc_nostr(clean)
    versions = [v for v in bundle.get("versions", []) if v.get("domain") == clean]
    if not versions and m_canon:
        base_dom, pub_prefix = f"{m_canon.group(1)}.xnd", m_canon.group(2)
        bundle = lookup_doc_nostr(base_dom)
        versions = [
            v for v in bundle.get("versions", [])
            if v.get("domain") == base_dom and str(v.get("pubkey_hex", "")).lower().startswith(pub_prefix)
        ]
        if versions:
            sign_dom = base_dom
    if not versions:
        raise HTTPException(status_code=404, detail=f"Domain '{clean}' not found on Nostr relays.")
    versions.sort(key=lambda v: int(v.get("version_num", 1)))
    latest = versions[-1]
    sha = str(latest.get("sha256", ""))
    blob_map = {b.get("sha256"): b.get("content", "") for b in bundle.get("blobs", [])}
    content = blob_map.get(sha, "")
    if not content:
        raise HTTPException(status_code=404, detail=f"Content blob missing for '{clean}'.")
    pub_hex = str(latest.get("pubkey_hex", ""))
    if _GW_BLOCKLIST.is_blocked(clean, pub_hex):
        raise HTTPException(status_code=403, detail=f"Publisher for '{clean}' is blocked by gateway moderation policy.")
    max_sz = abuse_guard.MAX_CAPSULE_BYTES if latest.get("kind") == "capsule" else abuse_guard.MAX_BLOB_BYTES
    ok_sz, sz_bytes = abuse_guard.check_blob_size(content, max_sz)
    if not ok_sz:
        raise HTTPException(status_code=413, detail=f"Blob exceeds gateway max size ({sz_bytes} > {max_sz} bytes).")

    verified = _verify_version(
        sign_dom,
        int(latest.get("version_num", 1)),
        sha,
        str(latest.get("pubkey_hex", "")),
        str(latest.get("signature_hex", "")),
        content,
        str(latest.get("prev_sha256", "")),
    )
    if not verified:
        raise HTTPException(status_code=422, detail=f"Signature verification failed for '{clean}'.")

    record = {
        "domain": clean,
        "version_num": int(latest.get("version_num", 1)),
        "title": str(latest.get("title", clean)),
        "kind": str(latest.get("kind", "document")),
        "sha256": sha,
        "pubkey_hex": str(latest.get("pubkey_hex", "")),
        "content": content,
        "verified": True,
    }
    _CACHE[clean] = (now, record)
    return record


def _rewrite_html_paths(raw_html: str, prefix: str) -> str:
    def _repl_attr(m: re.Match[str]) -> str:
        attr, q, path = m.group(1), m.group(2), m.group(3)
        if path.startswith("//"):
            return m.group(0)
        return f"{attr}={q}{prefix}{path}{q}"

    return re.sub(
        r'\b(href|src|action|poster)=(["\'])(/(?!/)[^"\']*)\2',
        _repl_attr,
        raw_html,
        flags=re.IGNORECASE,
    )


CORE_XANADU_DOMAINS = {
    "founder.xnd",
    "home.xnd",
    "justin.xnd",
    "heart.xnd",
    "manifesto.xnd",
    "forum.xnd",
    "xanadu.xnd",
}


def _inject_gateway_banner(page_html: str, domain: str, ver: int, pubkey_hex: str = "", title: str = "", summary: str = "") -> str:
    safe_dom = html.escape(domain)
    safe_dl = html.escape(NODE_DOWNLOAD_URL)
    safe_title = html.escape(title or domain)
    safe_desc = html.escape((summary or f"Verified .xnd decentralized site ({domain} v{ver}) on Xanadu.").strip()[:200])
    og_tags = (
        f'<meta property="og:type" content="website" />'
        f'<meta property="og:title" content="{safe_title}" />'
        f'<meta property="og:description" content="{safe_desc}" />'
        f'<meta name="twitter:card" content="summary" />'
        f'<meta name="twitter:title" content="{safe_title}" />'
        f'<meta name="twitter:description" content="{safe_desc}" />'
    )
    if re.search(r"<head[^>]*>", page_html, flags=re.IGNORECASE):
        page_html = re.sub(r"(<head[^>]*>)", rf"\1{og_tags}", page_html, count=1, flags=re.IGNORECASE)
    else:
        page_html = og_tags + page_html
    is_core = domain.strip().lower() in CORE_XANADU_DOMAINS
    fp = f"{pubkey_hex[:4]}-{pubkey_hex[4:8]}" if len(pubkey_hex) >= 8 else ""
    fp_badge = f' <code style="background:#1e293b;color:#93c5fd;padding:1px 6px;border-radius:4px;">{html.escape(fp)}</code>' if fp else ""
    ver_badge = (
        '<span style="background:linear-gradient(135deg,#fef3c7,#f59e0b);color:#78350f;padding:2px 8px;border-radius:999px;font-weight:700;margin-left:6px;">&#10003; Core Verified</span>'
        if is_core
        else " &middot; Ed25519 Verified"
    )
    banner = (
        '<div id="xnd-gw-bar" style="position:sticky;top:0;z-index:2147483647;'
        "background:#0f172a;color:#e2e8f0;font-family:system-ui,-apple-system,sans-serif;"
        "font-size:12px;padding:7px 14px;display:flex;align-items:center;justify-content:space-between;"
        'gap:10px;border-bottom:1px solid #334155;">'
        f'<span><strong>{safe_dom}</strong> (v{ver}){fp_badge}{ver_badge} &middot; Read-Only Gateway</span>'
        '<span style="display:flex;gap:8px;align-items:center;">'
        f'<a href="http://127.0.0.1:8765/?open={safe_dom}" style="background:#1e293b;border:1px solid #475569;color:#93c5fd;padding:4px 10px;border-radius:6px;text-decoration:none;font-weight:600;">Open in Xanadu App</a>'
        f'<a href="{safe_dl}" target="_blank" rel="noopener" '
        'style="background:#2563eb;color:#fff;padding:4px 10px;border-radius:6px;text-decoration:none;font-weight:600;">'
        "Install Xanadu App</a>"
        "</span></div>"
    )
    if re.search(r"<body[^>]*>", page_html, flags=re.IGNORECASE):
        return re.sub(r"(<body[^>]*>)", rf"\1{banner}", page_html, count=1, flags=re.IGNORECASE)
    return banner + page_html


@app.get("/", response_class=HTMLResponse)
def gateway_home() -> str:
    safe_dl = html.escape(NODE_DOWNLOAD_URL)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Xanadu (.xnd) Read-Only Web Gateway</title>
  <style>
    body {{ margin:0; font-family:system-ui,-apple-system,sans-serif; background:#0b1120; color:#e2e8f0; display:grid; place-items:center; min-height:100vh; }}
    .card {{ width:min(520px,92vw); background:#111827; border:1px solid #1f2937; border-radius:16px; padding:28px; box-shadow:0 20px 50px rgba(0,0,0,.45); }}
    h1 {{ margin:0 0 8px; font-size:22px; }}
    p {{ margin:0 0 18px; color:#94a3b8; font-size:14px; line-height:1.5; }}
    form {{ display:flex; gap:8px; }}
    input {{ flex:1; padding:11px 14px; border-radius:10px; border:1px solid #334155; background:#0f172a; color:#f8fafc; font-size:15px; }}
    button {{ padding:11px 16px; border-radius:10px; border:none; background:#2563eb; color:#fff; font-weight:600; cursor:pointer; }}
    .cta {{ margin-top:18px; padding-top:16px; border-top:1px solid #1f2937; display:flex; justify-content:space-between; align-items:center; font-size:13px; color:#94a3b8; }}
    a {{ color:#60a5fa; text-decoration:none; font-weight:600; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Xanadu (.xnd) Web Gateway</h1>
    <p>Open any decentralized <code>.xnd</code> site directly in your browser. Content is fetched from Nostr <code>kind:30078</code> events and Ed25519-verified before rendering.</p>
    <form onsubmit="event.preventDefault(); const d=document.getElementById('dom').value.trim(); if(d) location.href='/site/'+encodeURIComponent(d.endsWith('.xnd')?d:d+'.xnd');">
      <input id="dom" placeholder="e.g. manifesto.xnd" required />
      <button type="submit">Open</button>
    </form>
    <div class="cta">
      <span>Want to host &amp; publish sites P2P?</span>
      <a href="{safe_dl}" target="_blank" rel="noopener">Install Xanadu Node App &rarr;</a>
    </div>
  </div>
</body>
</html>"""


@app.get("/healthz")
def gateway_healthz() -> JSONResponse:
    return JSONResponse({"ok": True, "service": "xnd-gateway", "cached_sites": len(_CACHE)})


@app.get("/api/resolve/{domain}")
def api_resolve(domain: str) -> JSONResponse:
    return JSONResponse(_resolve_domain(domain))


@app.post("/api/gateway/blocklist/import")
async def gateway_import_blocklist(request: Request) -> JSONResponse:
    admin_tok = os.environ.get("XND_GATEWAY_ADMIN_TOKEN", "").strip()
    if admin_tok and request.headers.get("x-gateway-admin-token", "").strip() != admin_tok:
        raise HTTPException(status_code=403, detail="Unauthorized")
    body = await request.json()
    res = _GW_BLOCKLIST.import_signed(body)
    if not res.get("ok"):
        raise HTTPException(status_code=403, detail=res.get("error", "Invalid blocklist"))
    _CACHE.clear()
    return JSONResponse(res)


_GATEWAY_HTML_HEADERS = {
    "Content-Security-Policy": (
        "sandbox allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox; "
        "default-src 'self' data: blob:; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob: https:; "
        "font-src 'self' data:; "
        "connect-src 'none'; "
        "frame-ancestors 'self'; "
        "base-uri 'self';"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

_GATEWAY_ASSET_HEADERS = {
    "Content-Security-Policy": "sandbox; default-src 'self' data: blob:; style-src 'self' 'unsafe-inline';",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


@app.get("/site/{domain}")
@app.get("/site/{domain}/{asset_path:path}")
def serve_site(domain: str, request: Request, asset_path: str = "index.html") -> Response:
    rec = _resolve_domain(domain)
    clean_dom = rec["domain"]
    content = rec["content"]
    prefix = f"/site/{clean_dom}"
    rel = (asset_path or "index.html").lstrip("/") or "index.html"

    if rec["kind"] == "capsule":
        try:
            bundle = json.loads(content)
            files = bundle.get("files", {})
            rel = re.sub(r"/+", "/", rel)
            while rel.startswith("./"):
                rel = rel[2:]
            if not rel:
                rel = "index.html"
            if rel not in files:
                lower_map = {k.lower(): k for k in files}
                if f"{rel.rstrip('/')}/index.html" in files:
                    rel = f"{rel.rstrip('/')}/index.html"
                elif f"{rel.rstrip('/')}.html" in files:
                    rel = f"{rel.rstrip('/')}.html"
                elif rel.lower() in lower_map:
                    rel = lower_map[rel.lower()]
                elif f"{rel.rstrip('/').lower()}/index.html" in lower_map:
                    rel = lower_map[f"{rel.rstrip('/').lower()}/index.html"]
                elif f"{rel.rstrip('/').lower()}.html" in lower_map:
                    rel = lower_map[f"{rel.rstrip('/').lower()}.html"]
                elif "." not in rel.rsplit("/", 1)[-1] and "index.html" in files:
                    rel = "index.html"
                else:
                    raise HTTPException(status_code=404, detail=f"Asset '{rel}' not found in '{clean_dom}'.")
            raw_val = files[rel]
            mime, _ = mimetypes.guess_type(rel)
            mime = mime or "text/plain; charset=utf-8"
            if isinstance(raw_val, str) and raw_val.startswith("__b64__:"):
                import base64
                return Response(content=base64.b64decode(raw_val[8:]), media_type=mime, headers=_GATEWAY_ASSET_HEADERS)
            if mime.startswith("text/html"):
                out_html = _rewrite_html_paths(str(raw_val), prefix)
                if "<base " not in out_html.lower():
                    base_tag = f'<base href="{prefix}/">'
                    if re.search(r"<head[^>]*>", out_html, flags=re.IGNORECASE):
                        out_html = re.sub(r"(<head[^>]*>)", rf"\1{base_tag}", out_html, count=1, flags=re.IGNORECASE)
                    else:
                        out_html = base_tag + out_html
                out_html = _inject_gateway_banner(out_html, clean_dom, rec["version_num"], rec.get("pubkey_hex", ""), rec.get("title", clean_dom), f"Decentralized app/site {clean_dom} on Xanadu (.xnd)")
                return HTMLResponse(out_html, headers=_GATEWAY_HTML_HEADERS)
            return Response(content=str(raw_val), media_type=mime, headers=_GATEWAY_ASSET_HEADERS)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    doc_html = (
        f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(rec['title'])}</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:780px;margin:24px auto;padding:0 16px;line-height:1.6;}</style>"
        f"</head><body><pre style='white-space:pre-wrap;font-family:inherit;'>{html.escape(content)}</pre></body></html>"
    )
    return HTMLResponse(_inject_gateway_banner(doc_html, clean_dom, rec["version_num"], rec.get("pubkey_hex", ""), rec.get("title", clean_dom), content[:200]), headers=_GATEWAY_HTML_HEADERS)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("XND_GATEWAY_PORT", "8780")))
