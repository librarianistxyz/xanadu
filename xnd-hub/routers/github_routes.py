"""GitHub repository hosting and auto-deploy endpoints."""

import json
import threading
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, HTTPException, Request


def create_router(h: Any) -> APIRouter:
    router = APIRouter()
    GitHubConnectRequest = h.GitHubConnectRequest
    GitHubDevicePollRequest = h.GitHubDevicePollRequest
    GitHubDeployRequest = h.GitHubDeployRequest
    GitHubDetachRequest = h.GitHubDetachRequest
    GitHubActionRequest = h.GitHubActionRequest
    GitHubPushRequest = h.GitHubPushRequest

    @router.get("/api/github/status")
    def api_github_status(request: Request) -> dict[str, Any]:
        h._require_localhost(request)
        return h.gh_hosting.get_status()

    @router.post("/api/github/connect")
    def api_github_connect(req: GitHubConnectRequest, request: Request) -> dict[str, Any]:
        h._require_localhost(request)
        try:
            return {"ok": True, **h.gh_hosting.connect(req.token)}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.post("/api/github/disconnect")
    def api_github_disconnect(request: Request) -> dict[str, Any]:
        h._require_localhost(request)
        return h.gh_hosting.disconnect()

    @router.post("/api/github/device/start")
    def api_github_device_start(request: Request) -> dict[str, Any]:
        h._require_localhost(request)
        try:
            return h.gh_hosting.start_device_flow()
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.post("/api/github/device/poll")
    def api_github_device_poll(req: GitHubDevicePollRequest, request: Request) -> dict[str, Any]:
        h._require_localhost(request)
        try:
            return h.gh_hosting.poll_device_flow(req.device_code)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.get("/api/github/repos")
    def api_github_repos(request: Request) -> dict[str, Any]:
        h._require_localhost(request)
        try:
            return {"repos": h.gh_hosting.list_repos()}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.post("/api/github/deploy")
    def api_github_deploy(req: GitHubDeployRequest, request: Request) -> dict[str, Any]:
        h._require_localhost(request)
        dom = h.normalize_xnd_domain(req.domain, append_tld=True)
        if not dom or len(dom) > 253 or not h.DOMAIN_RE.match(dom):
            raise HTTPException(status_code=400, detail="Invalid .xnd domain.")
        links = h.gh_hosting.load_links()
        existing_link = links.get(dom)
        clean_repo_lower = (req.repo or "").strip().lower()
        if existing_link and existing_link.get("repo", "").lower() != clean_repo_lower:
            raise HTTPException(
                status_code=409,
                detail=f"Domain '{dom}' is permanently locked to '{existing_link['repo']}'. Detach it first using the Domain Private Key.",
            )
        for other_dom, link_info in links.items():
            if other_dom != dom and (link_info.get("repo", "").strip().lower() == clean_repo_lower):
                raise HTTPException(
                    status_code=409,
                    detail=f"Repository '{req.repo}' is already locked to '{other_dom}'. Detach '{other_dom}' first using its Domain Private Key.",
                )
        try:
            files, backend_py, used_branch = h.gh_hosting.fetch_repo_bundle(req.repo, req.branch, req.subdir)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

        effective_priv = req.privkey_hex.strip()
        if not effective_priv and dom in h.store.domains:
            effective_priv = h.store.domains[dom].get("privkey_hex", "")
        res = h.publish_capsule(dom, req.title.strip() or dom, files, backend_py, None, "", privkey_hex=effective_priv)
        if h._vault_unlocked:
            h._save_vault()
        try:
            pub_hex = h.store.domains.get(dom, {}).get("pubkey_hex", "")
            blob_txt = h.store.get_blob(res.get("sha256", "")) or ""
            if dom and pub_hex and res.get("signature") and blob_txt:
                threading.Thread(
                    target=h.announce_doc_nostr,
                    args=(dom, int(res["version"]), req.title.strip() or dom, res["sha256"], pub_hex, res["signature"], blob_txt, True),
                    daemon=True,
                ).start()
        except Exception:
            pass
        out_res: dict[str, Any] = {
            "ok": True,
            **res,
            "repo": req.repo,
            "branch": used_branch,
            "files_count": len(files),
            "auto_sync": True,
        }
        sha = ""
        try:
            sha = h.gh_hosting.get_latest_commit_sha(req.repo, used_branch)
        except Exception:
            pass
        try:
            h.gh_hosting.save_link(dom, req.repo, used_branch, req.subdir, sha)
        except Exception:
            pass
        if int(res.get("version", 0)) == 1 and h.store.domains.get(dom, {}).get("privkey_hex"):
            out_res["privkey_hex"] = h.store.domains[dom]["privkey_hex"]
            out_res["is_new_domain"] = True
        return out_res

    @router.get("/api/github/links")
    def api_github_links(request: Request) -> dict[str, Any]:
        h._require_localhost(request)
        return {"links": h.gh_hosting.load_links()}

    @router.post("/api/github/detach")
    def api_github_detach(req: GitHubDetachRequest, request: Request) -> dict[str, Any]:
        h._require_localhost(request)
        dom = h.normalize_xnd_domain(req.domain, append_tld=True)
        if not dom or not h.DOMAIN_RE.match(dom):
            raise HTTPException(status_code=400, detail="Invalid .xnd domain.")
        priv = (req.privkey_hex or "").strip()
        if len(priv) < 64:
            raise HTTPException(status_code=400, detail="Valid Domain Private Key is required to detach.")
        try:
            derived_pub = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv[:64])).public_key().public_bytes_raw().hex()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid Ed25519 private key.")
        expected_pub = h.store.domains.get(dom, {}).get("pubkey_hex", "")
        if not expected_pub:
            row = h.store.get_version(dom, None)
            expected_pub = row.get("pubkey_hex", "") if row else ""
        if not expected_pub or derived_pub != expected_pub:
            raise HTTPException(status_code=403, detail="Private key does not match this domain.")
        h.gh_hosting.remove_link(dom)
        return {"ok": True, "domain": dom, "detached": True}

    @router.post("/api/github/setup-action")
    def api_github_setup_action(req: GitHubActionRequest, request: Request) -> dict[str, Any]:
        h._require_localhost(request)
        try:
            return h.gh_hosting.install_build_workflow(req.repo, req.branch)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.post("/api/github/push")
    def api_github_push(req: GitHubPushRequest, request: Request) -> dict[str, Any]:
        h._require_localhost(request)
        dom = h.normalize_xnd_domain(req.domain, append_tld=True)
        row = h.store.get_version(dom, None)
        if not row:
            raise HTTPException(status_code=404, detail="Domain not found locally")
        blob = h.store.get_blob(row.get("sha256", "")) or ""
        files: dict[str, str] = {}
        backend_py = ""
        if (row.get("kind") or "") == "capsule":
            try:
                parsed = json.loads(blob)
                files = dict(parsed.get("files") or {})
                backend_py = str(parsed.get("backend_py") or "")
            except Exception:
                files = {"index.html": blob}
        else:
            files = {"content.txt": blob}
        try:
            return h.gh_hosting.push_files_to_repo(req.repo, req.branch, req.subdir, files, backend_py, req.message)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    return router
