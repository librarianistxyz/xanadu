# XANADU (`.xnd` Sovereign Hypertext & App Capsule Universe)

A domain-free, content-addressed hypertext network and split-pane bridge browser built with **Rust + Python + JavaScript**.

## Architecture

- **`xnd-core/` (Rust):** Zero-dependency release binary for fast SHA-256 content addressing, character-span slicing, and integrity verification.
- **`xnd-hub/` (Python + FastAPI + SQLite FTS5 + Ed25519):**
  - **`.xnd` Domain Registry:** Binds `*.xnd` domains to Ed25519 keys (free 5+ char `.xnd` registration; 1–4 char names guarded by `XND_SHORT_TOKEN`).
  - **Immutable Spans & Two-Way Links:** Parses `{{xnd://domain@vN:start-end}}` transclusions, preserves full version history, and indexes bidirectional backlinks.
  - **Dynamic App Capsules:** Serves multi-file HTML/CSS/JS frontends (`forum.xnd`) backed by sandboxed Python handlers (`SAFE_BUILTINS`) and persistent per-site state.
  - **Media Assets (`/xnd-asset/<sha256>`):** Content-addressed binary asset storage & sync.
  - **Signed P2P Sync & Auto-Gossip:** Exports and verifies signed bundles (`Ed25519` + `SHA-256`) across peer nodes and bootstrap IPs (`XND_BOOTSTRAP_PEERS`).
  - **Web-to-`.xnd` Snapshot Archiver:** Snapshots `http(s)://` pages into permanent `.xnd` documents.
- **`xnd-ui/` (HTML + CSS + JS):** Tactile archival instrument & Swiss editorial split-pane browser with live SVG bridge lines, constellation graph map, key backup/import, and capsule studio.
- **`xnd-browser/` (Rust):** Standalone desktop launcher that starts `xnd-hub` and opens an isolated native app window.
- **`xnd-android/` (Android APK):** Native WebView client for Galaxy S9+ / Android devices.

## Quick Start

### Desktop (Linux)
```bash
/home/librarianist/pcGDM/XANADU/xnd-browser/target/release/xnd-browser
```
Or start the hub directly:
```bash
python3 /home/librarianist/pcGDM/XANADU/xnd-hub/hub.py
```
Open `http://127.0.0.1:8765` on your PC or `http://<your-lan-ip>:8765` on your phone.

### Public VPS Node (Docker)
```bash
cd /home/librarianist/pcGDM/XANADU
docker compose up -d --build
```

## License

- **Core Platform (`xnd-hub`, `xnd-ui`, `xnd-desktop`, `xnd-android`, `xnd-gateway`, `xnd-core`, `xnd-browser`):** Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see [LICENSE](LICENSE).
- **Developer CLI & Starter `.xnd` App Templates (`xnd-cli/`):** Licensed under the **MIT License** — see [xnd-cli/LICENSE](xnd-cli/LICENSE), so developers can build and publish any open-source or commercial `.xnd` apps without AGPL obligations on their own sites.
