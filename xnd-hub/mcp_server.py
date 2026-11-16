#!/usr/bin/env python3
"""
Standalone stdio MCP (Model Context Protocol) bridge for Xanadu (.xnd).
Forwards JSON-RPC 2.0 requests (initialize, tools/list, tools/call) to xnd-hub
at XND_HUB_URL (default http://127.0.0.1:8765/api/ai/tools).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

HUB_TOOLS_URL = os.environ.get("XND_HUB_URL", "http://127.0.0.1:8765").rstrip("/") + "/api/ai/tools"


def _forward_rpc(req: dict) -> dict | None:
    if req.get("method") == "notifications/initialized":
        return None
    body = json.dumps(req).encode("utf-8")
    http_req = urllib.request.Request(
        HUB_TOOLS_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(http_req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> None:
    for line in sys.stdin:
        raw = line.strip()
        if not raw:
            continue
        req_id = None
        try:
            req = json.loads(raw)
            req_id = req.get("id")
            out = _forward_rpc(req)
            if out is not None and req_id is not None:
                sys.stdout.write(json.dumps(out) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            if req_id is not None:
                err = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": str(exc)},
                }
                sys.stdout.write(json.dumps(err) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    main()
