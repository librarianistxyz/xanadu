/**
 * Xanadu Programmable .xnd Capsule SDK (Zero-Server Web Apps)
 * Auto-injected into every .xnd capsule HTML page.
 * Provides sandboxed: xnd.store, xnd.sign, xnd.peers, xnd.search
 */
(function () {
  const scriptEl = document.currentScript;
  let domain = (scriptEl && scriptEl.getAttribute("data-domain")) || "";
  const capToken = (scriptEl && scriptEl.getAttribute("data-cap-token")) || "";
  if (!domain) {
    const m = location.pathname.match(/^\/xnd-app\/([^/]+)/);
    if (m) domain = decodeURIComponent(m[1]).toLowerCase();
  }

  async function apiJson(url, opts = {}) {
    const headers = Object.assign({}, opts.headers || {});
    if (capToken && !headers["X-Xnd-Cap-Token"]) {
      headers["X-Xnd-Cap-Token"] = capToken;
    }
    const r = await fetch(url, Object.assign({}, opts, { headers }));
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.detail || `Xanadu SDK error (${r.status})`);
    return data;
  }

  const store = {
    async get(key) {
      const d = await apiJson(`/api/sdk/store?domain=${encodeURIComponent(domain)}&key=${encodeURIComponent(key)}`);
      return d.value;
    },
    async set(key, value) {
      return apiJson("/api/sdk/store", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, key, value }),
      });
    },
    async del(key) {
      return apiJson("/api/sdk/store", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, key, delete: true }),
      });
    },
    async all() {
      const d = await apiJson(`/api/sdk/store?domain=${encodeURIComponent(domain)}`);
      return d.state || {};
    },
  };

  const sign = {
    async identity() {
      return apiJson(`/api/sdk/identity?domain=${encodeURIComponent(domain)}`);
    },
    async message(message) {
      return apiJson("/api/sdk/sign", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, message: String(message ?? "") }),
      });
    },
    async verify(message, pubkey_hex, signature_hex) {
      return apiJson("/api/sdk/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: String(message ?? ""), pubkey_hex, signature_hex }),
      });
    },
  };

  const peers = {
    async list() {
      const [p, l] = await Promise.all([
        apiJson("/api/peers").catch(() => ({ peers: [] })),
        apiJson("/api/lan/peers").catch(() => ({ peers: [] })),
      ]);
      return { p2p: p.peers || [], lan: l.peers || [] };
    },
    async syncLan() {
      return apiJson("/api/lan/sync", { method: "POST" });
    },
  };

  const search = {
    async query(q) {
      return apiJson(`/api/search?q=${encodeURIComponent(q || "")}`);
    },
    async fast(q) {
      return apiJson(`/api/search?fast=1&q=${encodeURIComponent(q || "")}`);
    },
  };

  const db = {
    async query(sql, params = []) {
      return apiJson("/api/sdk/db", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, sql: String(sql || ""), params }),
      });
    },
    async exec(sql, params = []) {
      return db.query(sql, params);
    },
  };

  let _sessionToken = "";
  const auth = {
    token() {
      return _sessionToken;
    },
    logout() {
      _sessionToken = "";
    },
    async login() {
      const ch = await apiJson("/api/sdk/auth/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      const signed = await sign.message(`xnd-auth-v1|${domain}|${ch.nonce}`);
      const res = await apiJson("/api/sdk/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain,
          nonce: ch.nonce,
          pubkey_hex: signed.pubkey_hex,
          signature_hex: signed.signature_hex,
        }),
      });
      _sessionToken = res.token || "";
      return res;
    },
    async verify(tok) {
      return apiJson("/api/sdk/auth/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, token: tok || _sessionToken }),
      });
    },
  };

  window.xnd = Object.freeze({
    version: "1.1",
    domain,
    store,
    sign,
    db,
    auth,
    peers,
    search,
  });
})();
