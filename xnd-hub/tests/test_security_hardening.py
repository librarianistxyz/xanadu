"""Security hardening tests for SSRF, XFF spoofing, headers, CSRF/DNS-rebinding, and body size caps."""

from __future__ import annotations

import base64
import os
import socket
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

HUB_DIR = Path(__file__).resolve().parent.parent
if str(HUB_DIR) not in sys.path:
    sys.path.insert(0, str(HUB_DIR))

os.environ.setdefault("XND_DATA_DIR", tempfile.mkdtemp(prefix="xnd_sec_pytest_"))
os.environ.setdefault("XND_RATE_LIMIT", "0")

import hub  # noqa: E402


def test_ssrf_blocked_on_www_and_archive() -> None:
    client = TestClient(hub.app, client=("127.0.0.1", 50000))
    for bad in ("http://127.0.0.1:8765/api/storage/stats", "http://169.254.169.254/latest/meta-data/"):
        assert client.get(f"/api/www?url={bad}").status_code == 403
        assert client.post("/api/archive_url", json={"url": bad}).status_code == 403


def test_ssrf_blocks_dns_resolving_to_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    assert hub._is_safe_public_url("https://rebind-test.example.com/secret") is False


def test_security_headers_and_asset_sandbox() -> None:
    client = TestClient(hub.app, client=("127.0.0.1", 50000))
    r = client.get("/api/storage/stats")
    assert r.status_code == 200
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("referrer-policy") == "no-referrer"
    assert r.headers.get("permissions-policy") == "camera=(), microphone=(), geolocation=(), usb=()"
    assert r.headers.get("cross-origin-opener-policy") == "same-origin"
    assert r.headers.get("x-frame-options") == "SAMEORIGIN"

    up = client.post(
        "/api/assets",
        json={
            "filename": "xss.html",
            "mime_type": "text/html",
            "data_b64": base64.b64encode(b"<script>alert(1)</script>").decode("ascii"),
        },
    )
    assert up.status_code == 200
    asset_resp = client.get(up.json()["url"])
    assert asset_resp.status_code == 200
    assert asset_resp.headers.get("content-security-policy") == "sandbox"
    assert asset_resp.headers.get("x-content-type-options") == "nosniff"


def test_csrf_text_plain_and_dns_rebinding_blocked() -> None:
    client = TestClient(hub.app, client=("127.0.0.1", 50000))
    r_plain = client.post(
        "/api/moderation/block",
        content='{"domain":"evil.xnd"}',
        headers={"Content-Type": "text/plain"},
    )
    assert r_plain.status_code == 415

    r_origin = client.post(
        "/api/moderation/block",
        json={"domain": "evil.xnd"},
        headers={"Origin": "https://evil.example.com"},
    )
    assert r_origin.status_code == 403

    r_host = client.get("/api/storage/stats", headers={"Host": "evil.example.com:8765"})
    assert r_host.status_code == 403


def test_body_size_limit_and_xff_untrusted(monkeypatch: pytest.MonkeyPatch) -> None:
    client = TestClient(hub.app, client=("127.0.0.1", 50000))
    r_big = client.post(
        "/api/moderation/block",
        content="{}",
        headers={"Content-Type": "application/json", "Content-Length": str(hub._MAX_BODY_BYTES + 1)},
    )
    assert r_big.status_code == 413

    # Verify X-Forwarded-For: 127.0.0.1 from a non-localhost, non-trusted-proxy IP cannot bypass rate limiting
    monkeypatch.setenv("XND_RATE_LIMIT", "1")
    ext_client = TestClient(hub.app, client=("203.0.113.99", 50000))
    monkeypatch.setattr(hub.ip_limiter, "allow", lambda ip: (False, 42) if ip == "203.0.113.99" else (True, 0))
    r_xff = ext_client.get("/api/storage/stats", headers={"X-Forwarded-For": "127.0.0.1"})
    assert r_xff.status_code == 429
