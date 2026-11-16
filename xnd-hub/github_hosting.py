"""GitHub REST API integration for Xanadu .xnd website hosting (public & private repos, read & write)."""
from __future__ import annotations

import base64
import io
import json
import mimetypes
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import Any

import httpx

GITHUB_API = "https://api.github.com"
GITHUB_CLIENT_ID = os.environ.get("XND_GITHUB_CLIENT_ID", "Ov23lizdQd2tWjV4GOlm")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TEXT_EXTS = {
    ".html", ".htm", ".css", ".js", ".mjs", ".cjs", ".json", ".svg",
    ".txt", ".md", ".xml", ".yaml", ".yml", ".py", ".wasm",
}


BUILD_OUT_DIRS = ("dist", "build", "out", ".output/public", "public", "docs", "_site", "www", "site")


def _is_dev_entry_html(raw_bytes: bytes) -> bool:
    txt = raw_bytes.decode("utf-8", errors="replace").lower()
    return bool(re.search(r'<script[^>]+src=["\'][^"\']*(?:/src/|main\.(?:tsx?|jsx?)|index\.(?:tsx?|jsx?))', txt))


def _pack_raw_files(raw_map: dict[str, bytes], prefix_dir: str) -> tuple[dict[str, str], str]:
    files: dict[str, str] = {}
    total_bytes = 0
    prefix = f"{prefix_dir.strip('/')}/" if prefix_dir.strip("/") else ""
    for path, raw_bytes in raw_map.items():
        if prefix:
            if not path.startswith(prefix):
                continue
            rel_path = path[len(prefix):]
        else:
            rel_path = path
        if not rel_path or ".." in rel_path.split("/"):
            continue
        if len(raw_bytes) > 2_000_000 or total_bytes + len(raw_bytes) > 15_000_000 or len(files) >= 400:
            continue
        total_bytes += len(raw_bytes)
        ext = Path(rel_path).suffix.lower()
        if ext in TEXT_EXTS:
            files[rel_path] = raw_bytes.decode("utf-8", errors="replace")
        else:
            mime, _ = mimetypes.guess_type(rel_path)
            mime = mime or "application/octet-stream"
            files[rel_path] = f"data:{mime};base64,{base64.b64encode(raw_bytes).decode('ascii')}"
    if "index.html" not in files:
        for k in list(files.keys()):
            if k.lower() in ("index.html", "index.htm"):
                files["index.html"] = files.pop(k)
                break
    backend_py = files.pop("backend.py", "")
    return files, backend_py


class GitHubHosting:
    def __init__(self, data_dir: Path) -> None:
        self.auth_path = data_dir / "github_auth.json"
        self.links_path = data_dir / "github_links.json"
        self._active_device_code = ""
        self._poll_lock = threading.Lock()

    def load_links(self) -> dict[str, dict[str, Any]]:
        if not self.links_path.exists():
            return {}
        try:
            data = json.loads(self.links_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def save_link(self, domain: str, repo: str, branch: str, subdir: str, sha: str) -> None:
        links = self.load_links()
        links[domain] = {
            "domain": domain,
            "repo": repo,
            "branch": branch,
            "subdir": subdir,
            "last_sha": sha,
            "locked": True,
            "updated_at": time.time(),
        }
        self.links_path.write_text(json.dumps(links, indent=2), encoding="utf-8")

    def remove_link(self, domain: str) -> bool:
        links = self.load_links()
        if domain in links:
            links.pop(domain, None)
            self.links_path.write_text(json.dumps(links, indent=2), encoding="utf-8")
            return True
        return False

    def get_latest_commit_sha(self, repo: str, branch: str) -> str:
        clean_repo = (repo or "").strip()
        clean_branch = (branch or "").strip() or "main"
        if not REPO_RE.match(clean_repo):
            return ""
        try:
            headers = self._headers()
            headers["Accept"] = "application/vnd.github.sha"
            with httpx.Client(timeout=10.0) as client:
                r = client.get(f"{GITHUB_API}/repos/{clean_repo}/commits/{clean_branch}", headers=headers)
            if r.status_code == 200:
                return r.text.strip().strip('"')
        except Exception:
            pass
        return ""

    def _load_auth(self) -> dict[str, Any]:
        if not self.auth_path.exists():
            return {}
        try:
            return json.loads(self.auth_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _headers(self, token: str | None = None) -> dict[str, str]:
        tok = (token or self._load_auth().get("token") or "").strip()
        if not tok:
            raise ValueError("GitHub account is not connected.")
        return {
            "Authorization": f"Bearer {tok}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Xanadu-Browser/0.1",
        }

    def get_status(self) -> dict[str, Any]:
        auth = self._load_auth()
        if not auth.get("token"):
            return {"connected": False, "username": "", "name": "", "avatar_url": ""}
        return {
            "connected": True,
            "username": auth.get("username", ""),
            "name": auth.get("name", ""),
            "avatar_url": auth.get("avatar_url", ""),
        }

    def connect(self, token: str) -> dict[str, Any]:
        tok = (token or "").strip()
        if not tok:
            raise ValueError("GitHub Personal Access Token is required.")
        with httpx.Client(timeout=12.0) as client:
            r = client.get(f"{GITHUB_API}/user", headers=self._headers(tok))
        if r.status_code != 200:
            raise ValueError(f"GitHub authentication failed ({r.status_code}). Check your token and scopes.")
        u = r.json()
        data = {
            "token": tok,
            "username": u.get("login", ""),
            "name": u.get("name") or u.get("login", ""),
            "avatar_url": u.get("avatar_url", ""),
        }
        self.auth_path.parent.mkdir(parents=True, exist_ok=True)
        self.auth_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        try:
            os.chmod(self.auth_path, 0o600)
        except Exception:
            pass
        return self.get_status()

    def disconnect(self) -> dict[str, Any]:
        if self.auth_path.exists():
            self.auth_path.unlink()
        return {"ok": True, "connected": False}

    def start_device_flow(self) -> dict[str, Any]:
        with httpx.Client(timeout=12.0) as client:
            r = client.post(
                "https://github.com/login/device/code",
                headers={"Accept": "application/json"},
                data={"client_id": GITHUB_CLIENT_ID, "scope": "repo"},
            )
        if r.status_code != 200:
            raise ValueError(f"Failed to start GitHub Device Login ({r.status_code}).")
        d = r.json()
        if d.get("error"):
            raise ValueError(d.get("error_description") or d["error"])
        dev_code = d.get("device_code", "")
        interval = max(5, int(d.get("interval", 5)))
        expires_in = min(900, int(d.get("expires_in", 900)))
        self._active_device_code = dev_code

        def _bg_poll() -> None:
            deadline = time.time() + expires_in
            wait_s = interval
            while time.time() < deadline and self._active_device_code == dev_code:
                time.sleep(wait_s)
                if self._active_device_code != dev_code:
                    break
                try:
                    res = self.poll_device_flow(dev_code)
                    if res.get("status") == "authorized":
                        self._active_device_code = ""
                        break
                    if res.get("status") == "slow_down":
                        wait_s = max(10, int(res.get("interval", 10)))
                except ValueError:
                    break
                except Exception:
                    pass

        threading.Thread(target=_bg_poll, daemon=True).start()
        return {
            "ok": True,
            "device_code": dev_code,
            "user_code": d.get("user_code", ""),
            "verification_uri": d.get("verification_uri", "https://github.com/login/device"),
            "expires_in": expires_in,
            "interval": interval,
        }

    def poll_device_flow(self, device_code: str) -> dict[str, Any]:
        code = (device_code or "").strip()
        if not code:
            raise ValueError("device_code is required.")
        with self._poll_lock:
            st_cur = self.get_status()
            if st_cur.get("connected") and self._active_device_code != code:
                return {"ok": True, "status": "authorized", **st_cur}
            with httpx.Client(timeout=12.0) as client:
                r = client.post(
                    "https://github.com/login/oauth/access_token",
                    headers={"Accept": "application/json"},
                    data={
                        "client_id": GITHUB_CLIENT_ID,
                        "device_code": code,
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    },
                )
            if r.status_code != 200:
                raise ValueError(f"GitHub token poll failed ({r.status_code}).")
            d = r.json()
            if d.get("access_token"):
                st = self.connect(d["access_token"])
                self._active_device_code = ""
                return {"ok": True, "status": "authorized", **st}
            err = d.get("error", "")
            if err == "authorization_pending":
                return {"ok": True, "status": "pending"}
            if err == "slow_down":
                return {"ok": True, "status": "slow_down", "interval": int(d.get("interval", 10))}
            raise ValueError(d.get("error_description") or err or "GitHub authorization denied")

    def list_repos(self) -> list[dict[str, Any]]:
        headers = self._headers()
        with httpx.Client(timeout=15.0) as client:
            r = client.get(
                f"{GITHUB_API}/user/repos",
                params={
                    "per_page": 100,
                    "sort": "updated",
                    "affiliation": "owner,collaborator,organization_member",
                },
                headers=headers,
            )
        if r.status_code != 200:
            raise ValueError(f"Failed to list GitHub repositories ({r.status_code}).")
        out: list[dict[str, Any]] = []
        for item in r.json():
            out.append(
                {
                    "full_name": item.get("full_name", ""),
                    "owner": (item.get("owner") or {}).get("login", ""),
                    "name": item.get("name", ""),
                    "private": bool(item.get("private", False)),
                    "default_branch": item.get("default_branch", "main"),
                    "description": item.get("description") or "",
                    "html_url": item.get("html_url", ""),
                }
            )
        return out

    def fetch_repo_bundle(self, repo: str, branch: str = "", subdir: str = "") -> tuple[dict[str, str], str, str]:
        clean_repo = (repo or "").strip()
        if not REPO_RE.match(clean_repo):
            raise ValueError("Invalid repository format. Expected owner/repo.")
        headers = self._headers()
        clean_branch = (branch or "").strip()
        clean_sub = (subdir or "").strip().strip("/")

        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            if not clean_branch:
                rr = client.get(f"{GITHUB_API}/repos/{clean_repo}", headers=headers)
                if rr.status_code != 200:
                    raise ValueError(f"Repository '{clean_repo}' not accessible ({rr.status_code}).")
                clean_branch = rr.json().get("default_branch") or "main"

            zr = client.get(f"{GITHUB_API}/repos/{clean_repo}/zipball/{clean_branch}", headers=headers)
            if zr.status_code != 200:
                raise ValueError(f"Could not download branch '{clean_branch}' archive ({zr.status_code}).")

        raw_map: dict[str, bytes] = {}
        with zipfile.ZipFile(io.BytesIO(zr.content)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                full_name = info.filename.lstrip("/")
                parts = full_name.split("/", 1)
                path = parts[1] if len(parts) == 2 else full_name
                if not path or path.startswith(".git/") or "/.git/" in path or "node_modules/" in path:
                    continue
                if ".." in path.split("/") or info.file_size > 2_000_000:
                    continue
                raw_map[path] = zf.read(info.filename)

        if clean_sub:
            files, backend_py = _pack_raw_files(raw_map, clean_sub)
            if "index.html" not in files:
                raise ValueError(f"Subfolder '{clean_sub}' must contain an index.html file.")
            return files, backend_py, clean_branch

        lower_keys = {k.lower(): k for k in raw_map}
        root_idx = lower_keys.get("index.html") or lower_keys.get("index.htm")
        root_is_dev = bool(root_idx and _is_dev_entry_html(raw_map[root_idx]))

        chosen_dir: str | None = None
        for d in BUILD_OUT_DIRS:
            if f"{d}/index.html" in lower_keys or f"{d}/index.htm" in lower_keys:
                if not root_idx or root_is_dev:
                    chosen_dir = d
                    break

        if chosen_dir is None and root_idx and not root_is_dev:
            chosen_dir = ""

        # If source repo (e.g. Vite/React/Next/Astro) has package.json and no pre-built output, auto-build silently
        if chosen_dir is None and "package.json" in lower_keys and shutil.which("npm"):
            try:
                pkg = json.loads(raw_map[lower_keys["package.json"]].decode("utf-8", errors="replace"))
                if isinstance(pkg.get("scripts"), dict) and "build" in pkg["scripts"]:
                    with tempfile.TemporaryDirectory(prefix="xnd_gh_build_") as tmpdir:
                        tmp_root = Path(tmpdir)
                        for rel, data in raw_map.items():
                            dest = tmp_root / rel
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            dest.write_bytes(data)
                        subprocess.run(["npm", "install", "--no-audit", "--no-fund"], cwd=tmp_root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
                        subprocess.run(["npm", "run", "build"], cwd=tmp_root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
                        for d in BUILD_OUT_DIRS:
                            cand = tmp_root / d
                            if (cand / "index.html").exists():
                                built_map: dict[str, bytes] = {}
                                for fp in cand.rglob("*"):
                                    if fp.is_file():
                                        built_map[fp.relative_to(cand).as_posix()] = fp.read_bytes()
                                files, backend_py = _pack_raw_files(built_map, "")
                                if "index.html" in files:
                                    return files, backend_py, clean_branch
            except Exception:
                pass

        if chosen_dir is None:
            if root_idx:
                chosen_dir = ""
            else:
                nested = sorted(
                    [k.rsplit("/", 1)[0] for k in raw_map if k.lower().endswith(("/index.html", "/index.htm"))],
                    key=lambda p: (p.count("/"), len(p)),
                )
                if nested:
                    chosen_dir = nested[0]

        if chosen_dir is None:
            raise ValueError("Repository must contain an index.html (or a build output folder like dist/build/out).")

        files, backend_py = _pack_raw_files(raw_map, chosen_dir)
        if "index.html" not in files:
            raise ValueError("Repository must contain an index.html file.")
        return files, backend_py, clean_branch

    def install_build_workflow(self, repo: str, branch: str = "") -> dict[str, Any]:
        clean_repo = (repo or "").strip()
        if not REPO_RE.match(clean_repo):
            raise ValueError("Invalid repository format. Expected owner/repo.")
        headers = self._headers()
        clean_branch = (branch or "").strip()
        with httpx.Client(timeout=20.0) as client:
            if not clean_branch:
                rr = client.get(f"{GITHUB_API}/repos/{clean_repo}", headers=headers)
                if rr.status_code != 200:
                    raise ValueError(f"Repository '{clean_repo}' not accessible ({rr.status_code}).")
                clean_branch = rr.json().get("default_branch") or "main"

            wf_path = ".github/workflows/xanadu-build.yml"
            wf_yaml = (
                "name: Xanadu Build\n"
                "on:\n"
                f"  push:\n    branches: [{clean_branch}]\n"
                "  workflow_dispatch:\n"
                "permissions:\n  contents: write\n"
                "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - uses: actions/setup-node@v4\n        with:\n          node-version: 20\n"
                "      - run: npm ci || npm install\n"
                "      - run: npm run build\n"
                "      - name: Commit build output\n"
                "        run: |\n"
                "          git config user.name \"xanadu-bot\"\n"
                "          git config user.email \"bot@xanadu.xnd\"\n"
                "          git add -f dist build out .output/public 2>/dev/null || true\n"
                "          git diff --cached --quiet || (git commit -m \"chore(xanadu): build static output [skip ci]\" && git push)\n"
            )
            url = f"{GITHUB_API}/repos/{clean_repo}/contents/{wf_path}"
            existing_sha = None
            gr = client.get(url, headers=headers, params={"ref": clean_branch})
            if gr.status_code == 200:
                existing_sha = gr.json().get("sha")
            payload: dict[str, Any] = {
                "message": "chore(xanadu): enable auto-build workflow [skip ci]",
                "content": base64.b64encode(wf_yaml.encode("utf-8")).decode("ascii"),
                "branch": clean_branch,
            }
            if existing_sha:
                payload["sha"] = existing_sha
            pr = client.put(url, headers=headers, json=payload)
            if pr.status_code not in (200, 201):
                raise ValueError(f"Failed to install workflow ({pr.status_code}): {pr.text[:200]}")

            # Trigger workflow immediately
            client.post(
                f"{GITHUB_API}/repos/{clean_repo}/actions/workflows/xanadu-build.yml/dispatches",
                headers=headers,
                json={"ref": clean_branch},
            )
        return {"ok": True, "repo": clean_repo, "branch": clean_branch, "workflow": wf_path}

    def push_files_to_repo(
        self,
        repo: str,
        branch: str,
        subdir: str,
        files: dict[str, str],
        backend_py: str = "",
        message: str = "Update site from Xanadu",
    ) -> dict[str, Any]:
        clean_repo = (repo or "").strip()
        if not REPO_RE.match(clean_repo):
            raise ValueError("Invalid repository format. Expected owner/repo.")
        headers = self._headers()
        clean_branch = (branch or "").strip()
        clean_sub = (subdir or "").strip().strip("/")
        all_files = dict(files)
        if backend_py.strip():
            all_files["backend.py"] = backend_py

        pushed = 0
        last_commit_url = ""
        with httpx.Client(timeout=20.0) as client:
            if not clean_branch:
                rr = client.get(f"{GITHUB_API}/repos/{clean_repo}", headers=headers)
                if rr.status_code != 200:
                    raise ValueError(f"Repository '{clean_repo}' not accessible ({rr.status_code}).")
                clean_branch = rr.json().get("default_branch") or "main"

            for rel_path, val in all_files.items():
                clean_rel = str(rel_path).replace("\\", "/").lstrip("./").lstrip("/")
                if not clean_rel or ".." in clean_rel.split("/"):
                    continue
                target_path = f"{clean_sub}/{clean_rel}" if clean_sub else clean_rel

                existing_sha = None
                gr = client.get(
                    f"{GITHUB_API}/repos/{clean_repo}/contents/{target_path}",
                    params={"ref": clean_branch},
                    headers=headers,
                )
                if gr.status_code == 200:
                    existing_sha = gr.json().get("sha")

                if isinstance(val, str) and val.startswith("data:") and ";base64," in val:
                    b64_content = val.split(";base64,", 1)[1]
                else:
                    b64_content = base64.b64encode(str(val).encode("utf-8")).decode("ascii")

                body: dict[str, Any] = {
                    "message": (message or "Update site from Xanadu").strip(),
                    "content": b64_content,
                    "branch": clean_branch,
                }
                if existing_sha:
                    body["sha"] = existing_sha

                pr = client.put(
                    f"{GITHUB_API}/repos/{clean_repo}/contents/{target_path}",
                    json=body,
                    headers=headers,
                )
                if pr.status_code not in (200, 201):
                    detail = pr.json().get("message", pr.text)
                    raise ValueError(f"Failed pushing '{target_path}' ({pr.status_code}): {detail}")
                pushed += 1
                commit_info = (pr.json().get("commit") or {})
                if commit_info.get("html_url"):
                    last_commit_url = commit_info["html_url"]

        return {
            "ok": True,
            "repo": clean_repo,
            "branch": clean_branch,
            "pushed_count": pushed,
            "commit_url": last_commit_url,
        }
