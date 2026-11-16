# XANADU (`.xnd` Sovereign Hypertext & App Capsule Browser)

A domain-free, content-addressed hypertext network, app capsule runtime, and P2P browser built with **Python (FastAPI) + JavaScript + Rust + Android (Java/WebView) + Electron**.

---

## Core Features

- **Sovereign `.xnd` Domains (Ed25519 + Hash-Chained History):**
  - Register `.xnd` domains without ICANN registrars or yearly fees (`5+` char names free; `1–4` char names guarded by `XND_SHORT_TOKEN`).
  - Every revision is SHA-256 content-addressed and linked with `prev_sha256` and signed with Ed25519.
  - Export/download `.key.json` backups, claim existing domains on any device, and **rotate or replace** domain signing keys from the Dashboard.
  - Key-conflict protection pins first-seen keys and alerts on alternate keys.
- **Two-Way Transclusion & Origin Bridges:**
  - Quote exact character spans (`{{xnd://domain@vN:start-end}}`) with live side-by-side split-pane inspection and bidirectional backlinks.
- **Dynamic App Capsules & Built-In Serverless Backend:**
  - Host multi-file HTML/CSS/JS frontends paired with sandboxed `backend.py` handlers (`SAFE_BUILTINS`).
  - Per-capsule isolated **SQLite** (`xnd.db.query(sql, params)`), **Ed25519 Session Auth** (`xnd.auth` challenge-response), and **REST routing** (`/xnd-app/{domain}/api/*`).
- **External Cloud Backends (`connect_origins`) & Node-Local Secrets:**
  - Declare signed `connect_origins` (e.g., Supabase, Firebase, custom REST APIs) in `xanadu.json` while keeping strict CSP isolation.
  - Store private server keys (`SUPABASE_SERVICE_ROLE_KEY`, etc.) **node-locally** (`0600` permissions, never synced to Nostr or `.xnd` bundles) and read them in `backend.py` via `secrets.get("KEY_NAME")`.
  - Manage and rotate secrets in **Dashboard -> Secrets & Keys** or with the `xnd` CLI.
- **GitHub Hosting:**
  - Connect public or private GitHub repositories to deploy and auto-update `.xnd` websites with repo-lock protection.
- **Multi-Source Live Search & Real-Time News:**
  - Instant local RAM index for `.xnd` domains + parallel live web search (Bing Web RSS, Google News RSS, Wikipedia, DuckDuckGo, StackOverflow, GitHub, OpenAlex) and live RSS news categories.
- **P2P Sync, Nostr Discovery & Mesh Internet Sharing:**
  - Discover and sync `.xnd` sites across public Nostr relays (`kind:30078`), LAN/Wi-Fi mesh (UDP `8766`), and STUN/NAT peers.
  - **Internet Sharing (Mesh Gateway):** Online nodes can share live web browse, search, and news with offline peers on the same Wi-Fi/hotspot (with an ON/OFF toggle in the **Sync** modal).
- **Private E2EE Spaces:**
  - Encrypt `.xnd` content for specific allowed Ed25519 public keys before P2P/Nostr sync.

---

## Architecture

- **`xnd-hub/`:** Python FastAPI local node, Ed25519 signing/verification, capsule runtime, SQLite FTS5/RAM index, Nostr & LAN mesh sync.
- **`xnd-ui/`:** Browser UI (Search, News, Split-Pane Reader, Dashboard, Secrets & Keys, Sync & Internet Sharing modal).
- **`xnd-cli/`:** Wrangler-style Python CLI (`xnd`) for `login`, `secret`, and `deploy`.
- **`xnd-desktop/`:** Electron desktop shell bundling `xnd-hub-bin` and `xnd-ui` (`.deb` / `AppImage`).
- **`xnd-android/`:** Native Android WebView + local Java node (`LocalNodeServer.java`) + Wi-Fi Direct/LAN mesh (`.apk`).
- **`xnd-core/` & `xnd-browser/`:** Rust content-addressing core and native desktop launcher.
- **`xnd-gateway/`:** Public read-only HTTP gateway for sharing `.xnd` links with standard browsers.

---

## Step-by-Step Usage

### 1. Run on Desktop (Linux)

**Option A — Install the `.deb` package (from Releases):**
```bash
sudo dpkg -i xanadu-desktop_0.1.0_amd64.deb
```
Launch **Xanadu Browser** from your applications menu.

**Option B — Run from source:**
```bash
cd /path/to/XANADU/xnd-hub
pip install -r requirements.txt   # if not already installed
python3 hub.py
```
Open `http://127.0.0.1:8765` in your browser.

---

### 2. Run on Android

1. Download `xanadu-browser.apk` from **Releases** (or build via `./xnd-android/build_apk.sh`).
2. Install on your Android device (`adb install -r xanadu-browser.apk` or tap the APK).
3. Open **Xanadu Browser** — the local node starts automatically on-device.

---

### 3. Register, Claim & Back Up a `.xnd` Domain

1. Open **Dashboard** (top nav on Desktop, side menu on Mobile) and create/unlock your local account vault.
2. **Register a new domain:** Go to **Register Domain**, enter a `5+` character name (e.g., `mybrand.xnd`), and click **Check & Register Domain**.
3. **Back up your key:** Immediately click **Download Key JSON** (or go to **Secrets & Keys -> Download Key JSON**) and save `mybrand.xnd.key.json` safely off-device.
4. **Claim on another device:** Go to **Claim Your Website**, enter your domain and `privkey_hex`.
5. **Rotate or change keys:** Go to **Secrets & Keys** for your domain to rotate to a new Ed25519 keypair or import a custom private key.

---

### 4. Deploy Apps & Manage Secrets (`xnd` CLI)

Make `xnd` executable or run it with Python 3 (zero external dependencies):

```bash
# 1. Configure hub URL and default domain
./xnd-cli/xnd login --hub http://127.0.0.1:8765 --domain myapp.xnd

# 2. Store private server secrets locally (never synced or bundled)
./xnd-cli/xnd secret put SUPABASE_SERVICE_ROLE_KEY
./xnd-cli/xnd secret list
./xnd-cli/xnd secret delete SUPABASE_SERVICE_ROLE_KEY

# 3. Deploy static files + backend.py + xanadu.json (connect_origins)
./xnd-cli/xnd deploy ./my-app --domain myapp.xnd --title "My App"
```

Example `xanadu.json`:
```json
{
  "domain": "myapp.xnd",
  "title": "My App",
  "connect_origins": ["https://your-project.supabase.co"]
}
```

Example `backend.py`:
```python
def handle(method, path, headers, body, state):
    service_key = secrets.get("SUPABASE_SERVICE_ROLE_KEY", "")
    return {"status": 200, "body": {"configured": bool(service_key)}}
```

---

### 5. Sync Across Devices & Share Internet on Wi-Fi

1. Connect your Desktop and Android phone to the same Wi-Fi or hotspot.
2. Click **Sync** in the UI to open the Sync modal:
   - Click **Sync LAN Mesh Now** to sync `.xnd` sites, `forum.xnd` posts, and `wikipedia.xnd` shards directly over local Wi-Fi (UDP `8766`).
   - Use **Internet Sharing (Mesh Gateway)** (`Share Internet: ON / OFF`) to allow offline nearby Xanadu nodes to browse live web, search, and news through an online peer.
   - Click **Join Global P2P (Nostr + PEX)** to discover peers globally.

---

## Building from Source

- **Android APK:**
  ```bash
  cd XANADU/xnd-android
  ./build_apk.sh
  ```
- **Desktop Hub Binary + `.deb`:**
  ```bash
  cd XANADU/xnd-hub
  pyinstaller --noconfirm xnd-hub-bin.spec
  cp -f dist/xnd-hub-bin ../xnd-desktop/bin/xnd-hub-bin

  cd ../xnd-desktop
  TMPDIR=/var/tmp npx electron-builder --linux deb
  ```

---

## License

- **Core Platform (`xnd-hub`, `xnd-ui`, `xnd-desktop`, `xnd-android`, `xnd-gateway`, `xnd-core`, `xnd-browser`):** Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see [LICENSE](LICENSE).
- **Developer CLI & Starter `.xnd` App Templates (`xnd-cli/`):** Licensed under the **MIT License** — see [xnd-cli/LICENSE](xnd-cli/LICENSE), so developers can build and publish any open-source or commercial `.xnd` apps without AGPL obligations on their own sites.
