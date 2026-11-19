"""Tests for the WebAssembly (Wasmtime) capsule sandbox and host RPC imports."""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest
import wasmtime
from fastapi import HTTPException

HUB_DIR = Path(__file__).resolve().parent.parent
if str(HUB_DIR) not in sys.path:
    sys.path.insert(0, str(HUB_DIR))

os.environ.setdefault("XND_DATA_DIR", tempfile.mkdtemp(prefix="xnd_wasm_pytest_"))
os.environ.setdefault("XND_RATE_LIMIT", "0")

import capsule_runtime  # noqa: E402
import hub  # noqa: E402
from services import capsule_sandbox, wasm_sandbox  # noqa: E402


def _b64_wat(wat_src: str) -> str:
    return base64.b64encode(wasmtime.wat2wasm(wat_src)).decode("ascii")


def test_wasm_capsule_runs_handler_and_updates_state(tmp_path: Path) -> None:
    out_json = json.dumps({"resp": {"ok": True, "engine": "wasm"}, "state": {"count": 42}})
    out_hex = "".join(f"\\{b:02x}" for b in out_json.encode("utf-8"))
    wat = f"""
    (module
      (memory (export "memory") 1)
      (global $heap (mut i32) (i32.const 1024))
      (data (i32.const 256) "{out_hex}")
      (func (export "alloc") (param $sz i32) (result i32)
        (local $p i32)
        (local.set $p (global.get $heap))
        (global.set $heap (i32.add (global.get $heap) (local.get $sz)))
        (local.get $p))
      (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
        (i64.or
          (i64.shl (i64.const 256) (i64.const 32))
          (i64.const {len(out_json.encode("utf-8"))})))
    )
    """
    b64 = _b64_wat(wat)
    resp, new_state = capsule_sandbox.run_capsule_backend(
        tmp_path,
        "",
        "ping",
        {"hello": "world"},
        {"count": 1},
        domain="wasmapp.xnd",
        backend_wasm_b64=b64,
    )
    assert resp == {"ok": True, "engine": "wasm"}
    assert new_state == {"count": 42}


def test_wasm_capsule_host_db_query_and_auth_verify(tmp_path: Path) -> None:
    sql_create = "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT)"
    sql_insert = "INSERT INTO items (name) VALUES (?)"
    params_insert = json.dumps(["alpha"])
    sql_select = "SELECT name FROM items ORDER BY id DESC LIMIT 1"

    def _esc(s: str) -> tuple[str, int]:
        raw = s.encode("utf-8")
        return "".join(f"\\{b:02x}" for b in raw), len(raw)

    c_hex, c_len = _esc(sql_create)
    i_hex, i_len = _esc(sql_insert)
    p_hex, p_len = _esc(params_insert)
    s_hex, s_len = _esc(sql_select)
    tok_hex, tok_len = _esc("bad-token")

    wat = f"""
    (module
      (import "xnd" "db_query" (func $db_query (param i32 i32 i32 i32) (result i64)))
      (import "xnd" "auth_verify" (func $auth_verify (param i32 i32) (result i64)))
      (memory (export "memory") 1)
      (global $heap (mut i32) (i32.const 4096))
      (data (i32.const 100) "{c_hex}")
      (data (i32.const 300) "{i_hex}")
      (data (i32.const 500) "{p_hex}")
      (data (i32.const 600) "{s_hex}")
      (data (i32.const 800) "{tok_hex}")
      (func (export "alloc") (param $sz i32) (result i32)
        (local $p i32)
        (local.set $p (global.get $heap))
        (global.set $heap (i32.add (global.get $heap) (local.get $sz)))
        (local.get $p))
      (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
        (drop (call $db_query (i32.const 100) (i32.const {c_len}) (i32.const 0) (i32.const 0)))
        (drop (call $db_query (i32.const 300) (i32.const {i_len}) (i32.const 500) (i32.const {p_len})))
        (drop (call $auth_verify (i32.const 800) (i32.const {tok_len})))
        (call $db_query (i32.const 600) (i32.const {s_len}) (i32.const 0) (i32.const 0)))
    )
    """
    b64 = _b64_wat(wat)
    resp, new_state = wasm_sandbox.run_wasm_capsule(
        tmp_path, b64, "test_db", {}, {"keep": True}, domain="wasmdb.xnd"
    )
    assert resp["ok"] is True
    assert resp["rows"] == [{"name": "alpha"}]
    assert new_state == {"keep": True}

    direct = capsule_runtime.db_query(tmp_path, "wasmdb.xnd", "SELECT name FROM items")
    assert direct["rows"] == [{"name": "alpha"}]


def test_wasm_capsule_infinite_loop_traps_on_fuel(tmp_path: Path) -> None:
    wat = """
    (module
      (memory (export "memory") 1)
      (func (export "alloc") (param $sz i32) (result i32) (i32.const 1024))
      (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
        (loop $inf (br $inf))
        (i64.const 0))
    )
    """
    b64 = _b64_wat(wat)
    with pytest.raises(HTTPException) as exc:
        wasm_sandbox.run_wasm_capsule(tmp_path, b64, "loop", {}, {}, domain="wasmloop.xnd")
    assert exc.value.status_code == 504
    assert "fuel" in str(exc.value.detail).lower()


def test_wasm_capsule_rejects_invalid_binary(tmp_path: Path) -> None:
    bad_b64 = base64.b64encode(b"not-a-wasm-binary").decode("ascii")
    with pytest.raises(HTTPException) as exc:
        wasm_sandbox.decode_and_validate_wasm(bad_b64)
    assert exc.value.status_code == 400


def test_publish_and_execute_wasm_capsule_via_hub() -> None:
    out_json = json.dumps({"resp": {"status": 200, "body": {"hello": "wasm-hub"}}, "state": {"ok": 1}})
    out_hex = "".join(f"\\{b:02x}" for b in out_json.encode("utf-8"))
    wat = f"""
    (module
      (memory (export "memory") 1)
      (global $heap (mut i32) (i32.const 1024))
      (data (i32.const 256) "{out_hex}")
      (func (export "alloc") (param $sz i32) (result i32)
        (local $p i32)
        (local.set $p (global.get $heap))
        (global.set $heap (i32.add (global.get $heap) (local.get $sz)))
        (local.get $p))
      (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
        (i64.or
          (i64.shl (i64.const 256) (i64.const 32))
          (i64.const {len(out_json.encode("utf-8"))})))
    )
    """
    b64 = _b64_wat(wat)
    pub = hub.publish_capsule(
        "wasm-e2e-test.xnd",
        "WASM E2E",
        {"index.html": "<h1>WASM</h1>"},
        "",
        backend_wasm_b64=b64,
    )
    assert pub["kind"] == "capsule"
    row = hub.store.get_version("wasm-e2e-test.xnd", None)
    assert row is not None
    bundle = json.loads(hub.store.get_blob(row["sha256"]) or "{}")
    resp, state = hub.run_capsule_backend(
        bundle.get("backend_py", ""),
        "ping",
        {},
        {},
        domain="wasm-e2e-test.xnd",
        backend_wasm_b64=bundle.get("backend_wasm_b64", ""),
    )
    assert resp == {"status": 200, "body": {"hello": "wasm-hub"}}
    assert state == {"ok": 1}
