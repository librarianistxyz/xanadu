const RELAYS = ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net", "wss://relay.nostr.band"];

async function sha256Hex(text) {
  const buf = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function queryRelay(relayUrl, filters, timeoutMs = 2600) {
  return new Promise((resolve) => {
    const events = [];
    let settled = false;
    let ws;
    const finish = () => {
      if (settled) return;
      settled = true;
      try { if (ws) ws.close(); } catch (_) {}
      resolve(events);
    };
    const timer = setTimeout(finish, timeoutMs);
    try {
      ws = new WebSocket(relayUrl);
      const subId = "xext-" + Math.floor(Math.random() * 100000);
      ws.onopen = () => {
        ws.send(JSON.stringify(["REQ", subId, ...filters]));
      };
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data);
          if (msg[0] === "EOSE") {
            clearTimeout(timer);
            finish();
          } else if (msg[0] === "EVENT" && msg[2]) {
            events.push(msg[2]);
          }
        } catch (_) {}
      };
      ws.onerror = () => { clearTimeout(timer); finish(); };
    } catch (_) {
      clearTimeout(timer);
      finish();
    }
  });
}

async function resolveFromNostr(domain) {
  const filters = [
    { kinds: [30078, 1], "#t": [`xnd-${domain}`], limit: 10 },
    { kinds: [30078, 1], "#t": ["xanadu-doc-v1"], "#d": [domain], limit: 10 },
    { kinds: [30078, 1], "#t": ["xanadu-doc-v1"], limit: 50 },
  ];
  const allBatches = await Promise.all(RELAYS.map((r) => queryRelay(r, filters)));
  const candidates = [];
  for (const ev of allBatches.flat()) {
    try {
      const data = JSON.parse(ev.content || "{}");
      if (data.type === "xanadu-doc" && (data.domain || "").toLowerCase() === domain) {
        candidates.push({ ...data, _ev_pubkey: ev.pubkey || "" });
      }
    } catch (_) {}
  }
  if (!candidates.length) return null;
  candidates.sort((a, b) => (b.version_num || 1) - (a.version_num || 1));

  for (const latest of candidates) {
    let rawContent = latest.content || "";
    if (!latest.chunked) {
      if (rawContent) return { ...latest, content: rawContent };
      continue;
    }
    if (!Array.isArray(latest.chunks) || !latest.chunks.length) continue;
    const cFilters = [
      { kinds: [1], "#t": ["xanadu-chunk-v1"], "#x": latest.chunks, limit: 50 },
    ];
    if (latest._ev_pubkey) {
      cFilters.push({ kinds: [1], authors: [latest._ev_pubkey], limit: 50 });
    }
    const cBatches = await Promise.all(RELAYS.map((r) => queryRelay(r, cFilters, 3200)));
    const chunkMap = new Map();
    for (const ev of cBatches.flat()) {
      try {
        const c = JSON.parse(ev.content || "{}");
        if (c.type === "xanadu-chunk" && c.sha256 && c.data_b64) {
          chunkMap.set(c.sha256, c.data_b64);
        }
      } catch (_) {}
    }
    const byteChunks = [];
    let complete = true;
    for (const cSha of latest.chunks) {
      const b64 = chunkMap.get(cSha);
      if (!b64) {
        complete = false;
        break;
      }
      const bin = atob(b64);
      const arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      byteChunks.push(arr);
    }
    if (!complete) continue;
    const totalLen = byteChunks.reduce((acc, a) => acc + a.length, 0);
    const merged = new Uint8Array(totalLen);
    let offset = 0;
    for (const a of byteChunks) {
      merged.set(a, offset);
      offset += a.length;
    }
    rawContent = new TextDecoder().decode(merged);
    return { ...latest, content: rawContent };
  }
  return null;
}

async function resolveFromLocalNode(domain) {
  try {
    const res = await fetch(`http://127.0.0.1:8765/api/resolve/${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(800),
    });
    if (!res.ok) return null;
    const data = await res.json();
    const raw = data && (data.raw_content || data.content || "");
    if (!raw) return null;
    return {
      domain,
      version_num: data.version_num || data.version || 1,
      sha256: data.sha256 || "",
      is_app: data.kind === "capsule",
      content: raw,
      source: "Local Xanadu Node",
    };
  } catch (_) {
    return null;
  }
}

function renderHtml(htmlText) {
  const frame = document.getElementById("site-frame");
  const statusEl = document.getElementById("status");
  const blobUrl = URL.createObjectURL(new Blob([htmlText], { type: "text/html" }));
  frame.src = blobUrl;
  frame.style.display = "block";
  statusEl.style.display = "none";
}

(async function main() {
  const params = new URLSearchParams(location.search);
  const domain = (params.get("domain") || "").trim().toLowerCase();
  const domLabel = document.getElementById("dom-label");
  const badge = document.getElementById("badge");
  const statusEl = document.getElementById("status");

  if (!domain) {
    domLabel.textContent = "No domain specified";
    statusEl.textContent = "Open the Xanadu popup or type `xnd mysite.xnd` in the address bar.";
    return;
  }
  domLabel.textContent = domain;

  let doc = await resolveFromLocalNode(domain);
  if (!doc) {
    doc = await resolveFromNostr(domain);
  }
  if (!doc || !doc.content) {
    badge.textContent = "Not Found";
    statusEl.textContent = `Could not find '${domain}' on local node or public Nostr relays.`;
    return;
  }

  const CORE_XANADU_DOMAINS = new Set([
    "founder.xnd",
    "home.xnd",
    "justin.xnd",
    "heart.xnd",
    "manifesto.xnd",
    "forum.xnd",
    "xanadu.xnd",
  ]);
  const computedSha = await sha256Hex(doc.content);
  const shaOk = !doc.sha256 || computedSha === doc.sha256;
  if (CORE_XANADU_DOMAINS.has(domain)) {
    badge.style.background = "linear-gradient(135deg, #fef3c7, #f59e0b)";
    badge.style.color = "#78350f";
    badge.textContent = `✓ Core Verified · v${doc.version_num || 1}`;
  } else {
    badge.textContent = `v${doc.version_num || 1} · ${shaOk ? "SHA-256 Verified" : "Unverified"} (${doc.source || "Nostr kind:30078"})`;
  }

  if (doc.is_app || (doc.content.trim().startsWith("{") && doc.content.includes('"files"'))) {
    try {
      const bundle = JSON.parse(doc.content);
      const indexHtml = (bundle.files && bundle.files["index.html"]) || "<p>No index.html in capsule.</p>";
      renderHtml(indexHtml);
      return;
    } catch (_) {}
  }

  const escaped = doc.content.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  renderHtml(`<!doctype html><html><body style="font-family:system-ui,sans-serif;max-width:760px;margin:24px auto;padding:0 16px;line-height:1.6;"><pre style="white-space:pre-wrap;font-family:inherit;">${escaped}</pre></body></html>`);
})();
