"""Isolated subprocess sandbox for Xanadu (.xnd) capsule backend.py handlers."""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from fastapi import HTTPException

import capsule_runtime

_CAPSULE_FORBIDDEN_NAMES = frozenset({
    "eval", "exec", "compile", "open", "getattr", "setattr", "delattr",
    "globals", "locals", "vars", "dir", "input", "breakpoint", "__import__",
    "type", "object", "super", "classmethod", "staticmethod", "property",
    "memoryview", "bytearray", "format",
})

_FORMAT_TRAVERSAL_RE = re.compile(r"(\._|\.__|\[)")

_CAPSULE_SUBPROC_RUNNER = r"""
import inspect, json, socket, sys
try:
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
except Exception:
    pass

SAFE_BUILTINS = {
    "len": len, "str": str, "int": int, "float": float, "bool": bool,
    "list": list, "dict": dict, "tuple": tuple, "set": set,
    "min": min, "max": max, "sum": sum, "sorted": sorted,
    "enumerate": enumerate, "zip": zip, "range": range, "abs": abs, "round": round,
    "True": True, "False": False, "None": None,
}
req = json.loads(sys.stdin.read())
rpc_fd = req.get("rpc_fd")
rpc_sock = socket.fromfd(int(rpc_fd), socket.AF_UNIX, socket.SOCK_STREAM) if rpc_fd is not None else None
rpc_file = rpc_sock.makefile("rwb", buffering=0) if rpc_sock is not None else None

def _rpc_call(op, args):
    if rpc_file is None:
        return {"ok": False, "error": "Runtime RPC bridge unavailable"}
    rpc_file.write((json.dumps({"op": op, **args}) + "\n").encode("utf-8"))
    line = rpc_file.readline()
    if not line:
        return {"ok": False, "error": "RPC bridge closed"}
    return json.loads(line.decode("utf-8"))

class _CapsuleDB:
    def query(self, sql, params=None):
        res = _rpc_call("db_query", {"sql": str(sql), "params": params})
        if not res.get("ok"):
            raise RuntimeError(res.get("error", "SQL error"))
        return res
    def exec(self, sql, params=None):
        return self.query(sql, params)

class _CapsuleAuth:
    def verify(self, token):
        return _rpc_call("auth_verify", {"token": str(token or "")})

env = {"__builtins__": SAFE_BUILTINS, "json": json, "db": _CapsuleDB(), "auth": _CapsuleAuth(), "secrets": dict(req.get("secrets") or {})}
exec(compile(req["code"], "<xnd-capsule>", "exec"), env, env)
handler = env.get("handle")
if not callable(handler):
    raise RuntimeError("Capsule backend missing handle(...)")
sig_params = len(inspect.signature(handler).parameters)
if sig_params >= 5:
    res = handler(req.get("method", "POST"), req.get("path", "/"), dict(req.get("headers") or {}), req["payload"], dict(req["state"]))
else:
    res = handler(req["action"], req["payload"], dict(req["state"]))
if isinstance(res, tuple) and len(res) == 2:
    out = {"resp": dict(res[0]), "state": dict(res[1])}
else:
    out = {"resp": dict(res), "state": req["state"]}
sys.stdout.write(json.dumps(out))
"""


def validate_capsule_ast(backend_py: str) -> ast.Module:
    """Validate capsule backend.py against disallowed AST constructs."""
    if len(backend_py) > 65536:
        raise HTTPException(status_code=400, detail="Capsule backend exceeds 64 KB limit")
    try:
        tree = ast.parse(backend_py, filename="<xnd-capsule>", mode="exec")
    except SyntaxError as exc:
        raise HTTPException(status_code=400, detail=f"Capsule backend syntax error: {exc.msg}")

    nodes = list(ast.walk(tree))
    if len(nodes) > 2500:
        raise HTTPException(status_code=400, detail="Capsule backend AST complexity limit exceeded")

    for node in nodes:
        if isinstance(
            node,
            (
                ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
                ast.AsyncFunctionDef, ast.AsyncFor, ast.AsyncWith, ast.Await,
                ast.Yield, ast.YieldFrom,
            ),
        ):
            raise HTTPException(status_code=403, detail=f"Disallowed syntax in capsule backend: {type(node).__name__}")
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("_") or node.attr == "format_map":
                raise HTTPException(status_code=403, detail=f"Disallowed attribute access in capsule backend: {node.attr}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            # Prevent "{0.__class__}".format(...) attribute/subscript gadget chains.
            if not (isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str)):
                raise HTTPException(status_code=403, detail="Dynamic str.format() is forbidden in capsule backend")
            if _FORMAT_TRAVERSAL_RE.search(node.func.value.value):
                raise HTTPException(status_code=403, detail="Attribute/index traversal in str.format() is forbidden")
        if isinstance(node, ast.Name):
            if node.id.startswith("_") or node.id in _CAPSULE_FORBIDDEN_NAMES:
                raise HTTPException(status_code=403, detail=f"Disallowed identifier in capsule backend: {node.id}")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
            if isinstance(node.right, ast.Constant) and isinstance(node.right.value, (int, float)) and abs(node.right.value) > 1000:
                raise HTTPException(status_code=403, detail="Exponent too large in capsule backend")
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and node.value.bit_length() > 1024:
            raise HTTPException(status_code=403, detail="Integer literal too large in capsule backend")
    return tree


def find_python_sandbox_bin() -> str | None:
    """Locate an external Python 3 interpreter for isolated capsule execution."""
    override = (os.environ.get("XND_CAPSULE_PYTHON") or "").strip()
    if override:
        return override if os.access(override, os.X_OK) else None
    if not getattr(sys, "frozen", False) and sys.executable:
        return sys.executable
    found = shutil.which("python3")
    if found:
        return found
    if os.access("/usr/bin/python3", os.X_OK):
        return "/usr/bin/python3"
    return None


def run_capsule_backend(
    state_dir: Path,
    backend_py: str,
    action: str,
    payload: dict[str, Any],
    state: dict[str, Any],
    domain: str = "",
    method: str = "POST",
    req_path: str = "/",
    req_headers: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Execute a capsule backend.py in an isolated subprocess with rlimits."""
    if not backend_py.strip():
        return {"ok": True, "state": state}, state
    validate_capsule_ast(backend_py)

    py_bin = find_python_sandbox_bin()
    if not py_bin:
        raise HTTPException(
            status_code=503,
            detail="Isolated capsule Python runtime unavailable (python3 not found). In-process execution is disabled.",
        )

    parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    def _serve_rpc() -> None:
        try:
            f = parent_sock.makefile("rwb", buffering=0)
            while True:
                line = f.readline()
                if not line:
                    break
                msg = json.loads(line.decode("utf-8"))
                op = msg.get("op")
                try:
                    if op == "db_query" and domain:
                        out_r = capsule_runtime.db_query(state_dir, domain, str(msg.get("sql") or ""), msg.get("params"))
                    elif op == "auth_verify" and domain:
                        out_r = capsule_runtime.verify_session_token(domain, str(msg.get("token") or ""))
                    else:
                        out_r = {"ok": False, "error": f"Unknown op: {op}"}
                except Exception as exc:
                    out_r = {"ok": False, "error": str(exc)}
                f.write((json.dumps(out_r) + "\n").encode("utf-8"))
        except Exception:
            pass
        finally:
            try:
                parent_sock.close()
            except Exception:
                pass

    rpc_thr = threading.Thread(target=_serve_rpc, daemon=True)
    rpc_thr.start()
    cap_secrets = capsule_runtime.load_capsule_secrets(state_dir, domain) if domain else {}
    req_json = json.dumps({
        "code": backend_py,
        "action": action,
        "payload": payload,
        "state": state,
        "method": method,
        "path": req_path,
        "headers": req_headers or {},
        "secrets": cap_secrets,
        "rpc_fd": child_sock.fileno(),
    })
    try:
        proc = subprocess.run(
            [py_bin, "-I", "-S", "-c", _CAPSULE_SUBPROC_RUNNER],
            input=req_json,
            capture_output=True,
            text=True,
            timeout=2.5,
            env={},
            close_fds=True,
            pass_fds=(child_sock.fileno(),),
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Capsule backend execution timed out")
    finally:
        try:
            child_sock.close()
        except Exception:
            pass
        try:
            parent_sock.close()
        except Exception:
            pass
    if proc.returncode < 0:
        raise HTTPException(status_code=504, detail="Capsule backend killed by CPU/memory limit")
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "Capsule execution failed").strip().splitlines()[-1][:240]
        raise HTTPException(status_code=500, detail=f"Capsule backend error: {err}")
    try:
        out = json.loads(proc.stdout)
        return dict(out["resp"]), dict(out["state"])
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Invalid capsule backend output: {exc}")
