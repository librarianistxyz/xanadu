"""Air-gapped Sneakernet (.xndbundle) and Animated QR (`XNDQ1`) sync routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from services import sneakernet_sync


def create_router(hub: Any) -> APIRouter:
    router = APIRouter()
    qr_receiver = sneakernet_sync.QrReassemblySession()

    @router.get("/api/sneakernet/usb/mounts")
    def api_sneakernet_usb_mounts(request: Request) -> dict[str, Any]:
        hub._require_localhost(request)
        return {"ok": True, "mounts": sneakernet_sync.list_usb_mounts()}

    @router.post("/api/sneakernet/export/file")
    async def api_sneakernet_export_file(request: Request) -> dict[str, Any]:
        hub._require_localhost(request)
        body = await request.json() if (await request.body()) else {}
        domain = str((body or {}).get("domain") or "").strip()
        since_ts = float((body or {}).get("since_ts") or 0.0)
        target_dir = str((body or {}).get("target_dir") or "").strip()
        filename = str((body or {}).get("filename") or "").strip()

        full_bundle = hub.sync_export(domain="")
        delta = sneakernet_sync.build_delta_bundle(full_bundle, since_ts=since_ts, domain_filter=domain)
        envelope = sneakernet_sync.pack_sneakernet_envelope(delta, since_ts=since_ts)

        if target_dir:
            try:
                dest = sneakernet_sync.export_bundle_to_file(target_dir, envelope, filename=filename)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            return {
                "ok": True,
                "saved_path": str(dest),
                "bundle_sha256": envelope["bundle_sha256"],
                "raw_bytes": envelope["raw_bytes"],
                "compressed_bytes": envelope["compressed_bytes"],
            }
        return {"ok": True, "envelope": envelope}

    @router.post("/api/sneakernet/import/file")
    async def api_sneakernet_import_file(request: Request) -> dict[str, Any]:
        hub._require_localhost(request)
        body = await request.json()
        file_path = str((body or {}).get("file_path") or "").strip()
        envelope = (body or {}).get("envelope")
        try:
            if file_path:
                bundle = sneakernet_sync.import_bundle_from_file(file_path)
            elif envelope is not None:
                bundle = sneakernet_sync.unpack_sneakernet_envelope(envelope)
            else:
                raise ValueError("Provide either 'file_path' or 'envelope'")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        stats = hub.import_sync_bundle(bundle)
        return {"ok": True, **stats}

    @router.post("/api/sneakernet/qr/encode")
    async def api_sneakernet_qr_encode(request: Request) -> dict[str, Any]:
        hub._require_localhost(request)
        body = await request.json() if (await request.body()) else {}
        domain = str((body or {}).get("domain") or "").strip()
        since_ts = float((body or {}).get("since_ts") or 0.0)
        chunk_bytes = int((body or {}).get("chunk_bytes") or sneakernet_sync.DEFAULT_QR_CHUNK_BYTES)
        include_svg = bool((body or {}).get("include_svg", True))

        full_bundle = hub.sync_export(domain="")
        delta = sneakernet_sync.build_delta_bundle(full_bundle, since_ts=since_ts, domain_filter=domain)
        try:
            encoded = sneakernet_sync.encode_animated_qr_frames(
                delta, chunk_bytes=chunk_bytes, include_svg=include_svg
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"ok": True, **encoded}

    @router.post("/api/sneakernet/qr/receive")
    async def api_sneakernet_qr_receive(request: Request) -> dict[str, Any]:
        hub._require_localhost(request)
        body = await request.json()
        frame = str((body or {}).get("frame") or "").strip()
        try:
            res = qr_receiver.add_frame(frame)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not res["complete"]:
            return {"ok": True, **res}
        stats = hub.import_sync_bundle(res["bundle"])
        return {
            "ok": True,
            "complete": True,
            "transfer_id": res["transfer_id"],
            "received": res["received"],
            "total": res["total"],
            "bundle_sha256": res["bundle_sha256"],
            **stats,
        }

    return router

