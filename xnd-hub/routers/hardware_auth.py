"""Hardware-Gated Domain Signing (Phone Biometric Key Vault / FIDO2) routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from services import hardware_vault


def create_router(hub: Any) -> APIRouter:
    router = APIRouter()

    @router.get("/api/hardware-vault/status")
    def api_hw_vault_status(request: Request) -> dict[str, Any]:
        hub._require_localhost(request)
        state_dir = hub.DATA_DIR / "state"
        return {"ok": True, "domains": hardware_vault.list_hardware_domains(state_dir)}

    @router.post("/api/hardware-vault/enroll")
    async def api_hw_vault_enroll(request: Request) -> dict[str, Any]:
        hub._require_localhost(request)
        body = await request.json()
        dom = hub.normalize_xnd_domain(str(body.get("domain") or ""), append_tld=True)
        if not hub.DOMAIN_RE.match(dom) or len(dom) > 253:
            raise HTTPException(status_code=400, detail="Invalid .xnd domain")
        pub_hex = str(body.get("pubkey_hex") or "").strip().lower()
        device_id = str(body.get("device_id") or "android-biometric-vault")
        mode = str(body.get("mode") or "android_keystore")
        bio_secret_hex = str(body.get("bio_secret_hex") or "")
        strip_local = bool(body.get("strip_local_key", True))

        state_dir = hub.DATA_DIR / "state"
        enrolled = hardware_vault.enroll_hardware_signer(
            state_dir, dom, pub_hex, device_id=device_id, mode=mode, bio_secret_hex=bio_secret_hex
        )
        hub.store.import_domain_key(dom, pub_hex, "")
        hub.trust_store.set_pin(dom, pub_hex, source="hardware_vault")
        stripped = hardware_vault.strip_local_private_key(hub.store, dom) if strip_local else False
        return {"ok": True, "enrolled": enrolled, "local_key_stripped": stripped}

    @router.post("/api/hardware-vault/challenge")
    async def api_hw_vault_challenge(request: Request) -> dict[str, Any]:
        hub._require_localhost(request)
        body = await request.json()
        dom = hub.normalize_xnd_domain(str(body.get("domain") or ""), append_tld=True)
        action = str(body.get("action") or "publish").strip()
        signing_payload = str(body.get("signing_payload") or "")
        extra = body.get("extra") if isinstance(body.get("extra"), dict) else {}
        if not signing_payload:
            raise HTTPException(status_code=400, detail="signing_payload is required")
        state_dir = hub.DATA_DIR / "state"
        ch = hardware_vault.create_signing_challenge(state_dir, dom, action, signing_payload, extra=extra)
        return {"ok": True, **ch}

    @router.post("/api/hardware-vault/rotate")
    async def api_hw_vault_rotate(request: Request) -> dict[str, Any]:
        hub._require_localhost(request)
        body = await request.json()
        challenge_id = str(body.get("challenge_id") or "")
        signature_hex = str(body.get("signature_hex") or "")
        bio_hmac_hex = str(body.get("bio_hmac_hex") or "")
        new_pubkey_hex = str(body.get("new_pubkey_hex") or "").strip().lower()

        state_dir = hub.DATA_DIR / "state"
        rec = hardware_vault.verify_and_consume_challenge(state_dir, challenge_id, signature_hex, bio_hmac_hex)
        if rec["action"] != "rotate":
            raise HTTPException(status_code=400, detail="Challenge action is not 'rotate'")
        dom = rec["domain"]
        enrolled = hardware_vault.enroll_hardware_signer(
            state_dir,
            dom,
            new_pubkey_hex,
            device_id=str(body.get("device_id") or "android-biometric-vault"),
            mode=str(body.get("mode") or "android_keystore"),
            bio_secret_hex=str(body.get("bio_secret_hex") or ""),
        )
        hub.store.import_domain_key(dom, new_pubkey_hex, "")
        hub.trust_store.set_pin(dom, new_pubkey_hex, source="hardware_vault")
        return {"ok": True, "domain": dom, "rotated_to": enrolled["pubkey_hex"]}

    return router
