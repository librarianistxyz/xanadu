"""Unit and integration tests for xnd-hub routers and capsule sandbox."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

HUB_DIR = Path(__file__).resolve().parent.parent
if str(HUB_DIR) not in sys.path:
    sys.path.insert(0, str(HUB_DIR))

os.environ.setdefault("XND_DATA_DIR", tempfile.mkdtemp(prefix="xnd_pytest_"))
os.environ.setdefault("XND_RATE_LIMIT", "0")

import hub  # noqa: E402
from services import capsule_sandbox  # noqa: E402


def test_capsule_sandbox_runs_valid_handler(tmp_path: Path) -> None:
    code = (
        'def handle(action, payload, state):\n'
        '    msg = "hello {}".format(payload.get("name", "world"))\n'
        '    return {"ok": True, "msg": msg}, {**state, "count": state.get("count", 0) + 1}\n'
    )
    resp, new_state = capsule_sandbox.run_capsule_backend(
        tmp_path, code, "greet", {"name": "xanadu"}, {"count": 1}, domain="testapp.xnd"
    )
    assert resp == {"ok": True, "msg": "hello xanadu"}
    assert new_state == {"count": 2}


@pytest.mark.parametrize(
    "bad_code",
    [
        'def handle(a, p, s):\n    return {"x": "{0.__class__}".format(())}, s\n',
        'def handle(a, p, s):\n    return {"x": "{a}".format_map({"a": 1})}, s\n',
        'def handle(a, p, s):\n    return {"x": ().__class__}, s\n',
        'import os\ndef handle(a, p, s):\n    return {}, s\n',
    ],
)
def test_capsule_ast_blocks_escape_vectors(bad_code: str) -> None:
    with pytest.raises(HTTPException) as exc:
        capsule_sandbox.validate_capsule_ast(bad_code)
    assert exc.value.status_code == 403


def test_capsule_no_inprocess_exec_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(capsule_sandbox, "find_python_sandbox_bin", lambda: None)
    code = 'def handle(action, payload, state):\n    return {"ok": True}, state\n'
    with pytest.raises(HTTPException) as exc:
        capsule_sandbox.run_capsule_backend(tmp_path, code, "ping", {}, {}, domain="testapp.xnd")
    assert exc.value.status_code == 503
    assert "In-process execution is disabled" in str(exc.value.detail)


def test_extracted_router_endpoints_registered() -> None:
    paths = set(hub.app.openapi()["paths"].keys())
    expected = {
        "/api/bookmarks",
        "/api/history",
        "/api/clip",
        "/api/trust/pins",
        "/api/trust/pin",
        "/api/trust/petname",
        "/api/moderation",
        "/api/moderation/block",
        "/api/moderation/unblock",
        "/api/moderation/delete_domain",
        "/api/moderation/follow",
        "/api/moderation/blocklist/export",
        "/api/moderation/blocklist/import",
        "/api/github/status",
        "/api/github/connect",
        "/api/github/deploy",
        "/api/github/links",
        "/api/ai/cite",
        "/api/ai/publish_note",
        "/api/ai/tools",
    }
    missing = expected - paths
    assert not missing, f"Missing routes: {missing}"


def test_http_endpoints_smoke() -> None:
    client = TestClient(hub.app, client=("127.0.0.1", 50000))
    assert client.get("/api/storage/stats").status_code == 200
    assert client.get("/api/bookmarks").status_code == 200
    assert client.get("/api/moderation").status_code == 200
    assert client.get("/api/trust/pins").status_code == 200
    tools_resp = client.get("/api/ai/tools")
    assert tools_resp.status_code == 200
    assert tools_resp.json()["ok"] is True
    assert client.get("/api/github/status").status_code == 200
    commons_resp = client.get("/api/home/commons?mode=all")
    assert commons_resp.status_code == 200
    cdata = commons_resp.json()
    assert cdata["ok"] is True
    assert "latest_citations" in cdata
    assert "items" in cdata
