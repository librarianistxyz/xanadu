"""Capability-based WebAssembly (Wasmtime) sandbox for Xanadu (.xnd) capsule backends."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

from fastapi import HTTPException

import capsule_runtime

try:
    import wasmtime  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    wasmtime = None  # type: ignore[assignment]

WASM_MAGIC = b"\x00asm"
MAX_WASM_BYTES = max(65536, int(os.environ.get("XND_WASM_MAX_BYTES", str(8 * 1024 * 1024))))
DEFAULT_WASM_FUEL = max(10_000, int(os.environ.get("XND_WASM_FUEL", "5000000")))
DEFAULT_WASM_MEM_BYTES = max(1024 * 1024, int(os.environ.get("XND_WASM_MAX_MEM_BYTES", str(64 * 1024 * 1024))))
_MODULE_CACHE_MAX = 64

_ENGINE_LOCK = threading.Lock()
_ENGINE: Any = None
_MODULE_CACHE: OrderedDict[str, Any] = OrderedDict()


def _get_engine() -> Any:
    if wasmtime is None:
        raise HTTPException(
            status_code=503,
            detail="WebAssembly runtime unavailable (install 'wasmtime' package).",
        )
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is None:
            cfg = wasmtime.Config()
            cfg.consume_fuel = True
            _ENGINE = wasmtime.Engine(cfg)
        return _ENGINE


def decode_and_validate_wasm(backend_wasm_b64: str) -> bytes:
    """Decode base64 WASM payload and validate magic header, size, and compilation."""
    raw_b64 = (backend_wasm_b64 or "").strip()
    if not raw_b64:
        raise HTTPException(status_code=400, detail="Empty WASM capsule payload")
    try:
        wasm_bytes = base64.b64decode(raw_b64, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid base64 WASM payload: {exc}") from exc

    if len(wasm_bytes) < 8 or not wasm_bytes.startswith(WASM_MAGIC):
        raise HTTPException(status_code=400, detail="Invalid WASM binary (missing \\0asm header)")
    if len(wasm_bytes) > MAX_WASM_BYTES:
        raise HTTPException(status_code=413, detail=f"WASM capsule exceeds {MAX_WASM_BYTES} byte limit")

    _compile_module_cached(wasm_bytes)
    return wasm_bytes


def _compile_module_cached(wasm_bytes: bytes) -> Any:
    engine = _get_engine()
    digest = hashlib.sha256(wasm_bytes).hexdigest()
    with _ENGINE_LOCK:
        mod = _MODULE_CACHE.get(digest)
        if mod is not None:
            _MODULE_CACHE.move_to_end(digest)
            return mod
    try:
        mod = wasmtime.Module(engine, wasm_bytes)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid WASM module: {exc}") from exc

    with _ENGINE_LOCK:
        _MODULE_CACHE[digest] = mod
        if len(_MODULE_CACHE) > _MODULE_CACHE_MAX:
            _MODULE_CACHE.popitem(last=False)
    return mod


def _pack_ptr_len(ptr: int, length: int) -> int:
    return ((ptr & 0xFFFFFFFF) << 32) | (length & 0xFFFFFFFF)


def _unpack_ptr_len(packed: int) -> tuple[int, int]:
    u = packed & 0xFFFFFFFFFFFFFFFF
    return (u >> 32) & 0xFFFFFFFF, u & 0xFFFFFFFF


def _read_guest(mem: Any, store: Any, ptr: int, length: int) -> bytes:
    if ptr < 0 or length < 0:
        raise ValueError("Negative WASM memory pointer or length")
    if length == 0:
        return b""
    return bytes(mem.read(store, ptr, ptr + length))


def _write_guest(mem: Any, alloc_fn: Any, store: Any, data: bytes) -> tuple[int, int]:
    if not data:
        ptr = int(alloc_fn(store, 0))
        return ptr, 0
    ptr = int(alloc_fn(store, len(data)))
    mem.write(store, data, ptr)
    return ptr, len(data)


def run_wasm_capsule(
    state_dir: Path,
    backend_wasm_b64: str,
    action: str,
    payload: dict[str, Any],
    state: dict[str, Any],
    domain: str = "",
    method: str = "POST",
    req_path: str = "/",
    req_headers: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Execute a WASM capsule `handle(req_ptr, req_len) -> i64` in a capability-sandboxed Store."""
    wasm_bytes = decode_and_validate_wasm(backend_wasm_b64)
    engine = _get_engine()
    mod = _compile_module_cached(wasm_bytes)

    store = wasmtime.Store(engine)
    store.set_fuel(DEFAULT_WASM_FUEL)
    store.set_limits(memory_size=DEFAULT_WASM_MEM_BYTES)

    linker = wasmtime.Linker(engine)
    alloc_holder: dict[str, Any] = {"alloc": None}
    logs: list[str] = []

    def _reply_json(caller: Any, obj: dict[str, Any]) -> int:
        mem = caller["memory"]
        alloc_fn = alloc_holder["alloc"]
        if alloc_fn is None:
            raise RuntimeError("WASM module must export alloc(i32) -> i32 for host RPC")
        raw = json.dumps(obj).encode("utf-8")
        ptr, length = _write_guest(mem, alloc_fn, caller, raw)
        return _pack_ptr_len(ptr, length)

    def _host_db_query(caller: Any, sql_ptr: int, sql_len: int, params_ptr: int, params_len: int) -> int:
        mem = caller["memory"]
        try:
            sql = _read_guest(mem, caller, sql_ptr, sql_len).decode("utf-8")
            params_raw = _read_guest(mem, caller, params_ptr, params_len)
            params = json.loads(params_raw.decode("utf-8")) if params_raw else None
            if not domain:
                res: dict[str, Any] = {"ok": False, "error": "Domain required for db_query"}
            else:
                res = capsule_runtime.db_query(state_dir, domain, sql, params)
        except Exception as exc:
            res = {"ok": False, "error": str(exc)}
        return _reply_json(caller, res)

    def _host_auth_verify(caller: Any, tok_ptr: int, tok_len: int) -> int:
        mem = caller["memory"]
        try:
            token = _read_guest(mem, caller, tok_ptr, tok_len).decode("utf-8")
            if not domain:
                res: dict[str, Any] = {"ok": False, "error": "Domain required for auth_verify"}
            else:
                res = capsule_runtime.verify_session_token(domain, token)
        except Exception as exc:
            res = {"ok": False, "error": str(exc)}
        return _reply_json(caller, res)

    def _host_log(caller: Any, msg_ptr: int, msg_len: int) -> None:
        if len(logs) >= 32:
            return
        mem = caller["memory"]
        try:
            msg = _read_guest(mem, caller, msg_ptr, min(msg_len, 1024)).decode("utf-8", errors="replace")
            logs.append(msg)
        except Exception:
            pass

    i32 = wasmtime.ValType.i32()
    i64 = wasmtime.ValType.i64()
    linker.define_func("xnd", "db_query", wasmtime.FuncType([i32, i32, i32, i32], [i64]), _host_db_query, access_caller=True)
    linker.define_func("xnd", "auth_verify", wasmtime.FuncType([i32, i32], [i64]), _host_auth_verify, access_caller=True)
    linker.define_func("xnd", "log", wasmtime.FuncType([i32, i32], []), _host_log, access_caller=True)

    try:
        instance = linker.instantiate(store, mod)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"WASM capsule instantiation failed: {exc}") from exc

    exports = instance.exports(store)
    mem = exports.get("memory")
    alloc_fn = exports.get("alloc")
    handle_fn = exports.get("handle")
    if mem is None or alloc_fn is None or handle_fn is None:
        raise HTTPException(
            status_code=400,
            detail="WASM capsule must export 'memory', 'alloc(i32)->i32', and 'handle(i32,i32)->i64'",
        )
    alloc_holder["alloc"] = alloc_fn

    cap_secrets = capsule_runtime.load_capsule_secrets(state_dir, domain) if domain else {}
    req_bytes = json.dumps({
        "action": action,
        "method": method,
        "path": req_path,
        "headers": req_headers or {},
        "payload": payload,
        "state": state,
        "secrets": cap_secrets,
    }).encode("utf-8")

    try:
        req_ptr, req_len = _write_guest(mem, alloc_fn, store, req_bytes)
        packed_out = int(handle_fn(store, req_ptr, req_len))
        out_ptr, out_len = _unpack_ptr_len(packed_out)
        out_raw = _read_guest(mem, store, out_ptr, out_len)
    except wasmtime.Trap as trap:
        msg = str(trap)
        if "fuel" in msg.lower():
            raise HTTPException(status_code=504, detail="WASM capsule backend exceeded CPU fuel limit") from trap
        raise HTTPException(status_code=500, detail=f"WASM capsule trapped: {msg[:200]}") from trap
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"WASM capsule execution error: {exc}") from exc

    try:
        out = json.loads(out_raw.decode("utf-8"))
        if not isinstance(out, dict):
            raise ValueError("Output JSON must be an object")
        if "resp" in out and "state" in out:
            return dict(out["resp"]), dict(out["state"])
        return out, dict(state)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Invalid WASM capsule output: {exc}") from exc
