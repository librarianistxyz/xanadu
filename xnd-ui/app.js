const omniboxForm = document.getElementById("omnibox-form");
const omniboxInput = document.getElementById("omnibox-input");
const primaryPane = document.getElementById("primary-pane");
const tabStrip = document.getElementById("tab-strip");
let primaryContent = null;
const secondaryPane = document.getElementById("secondary-pane");
const secondaryContent = document.getElementById("secondary-content");
const secondaryLabel = document.getElementById("secondary-label");
const bridgeSvg = document.getElementById("bridge-svg");
const coreStatus = document.getElementById("core-status");
const quoteBar = document.getElementById("quote-bar");
const quotePreview = document.getElementById("quote-preview");
const publishModal = document.getElementById("publish-modal");

let currentDoc = null;
let activeBridge = null;
let pendingTransclusionPointer = "";
let publishMode = "document";

const tabs = [];

const CORE_XANADU_DOMAINS = new Set([
  "founder.xnd",
  "home.xnd",
  "justin.xnd",
  "heart.xnd",
  "manifesto.xnd",
  "forum.xnd",
  "xanadu.xnd",
]);

function isCoreXanaduDomain(domain) {
  const clean = (domain || "").trim().toLowerCase();
  return CORE_XANADU_DOMAINS.has(clean.endsWith(".xnd") ? clean : `${clean}.xnd`);
}

function goldTickBadge(domain) {
  return isCoreXanaduDomain(domain)
    ? `<span class="gold-tick" title="Official Core Xanadu Domain">✓ Verified</span>`
    : "";
}
let activeTabId = null;
let tabSeq = 0;
let isRestoringNav = false;

const btnNavBack = document.getElementById("btn-nav-back");
const btnNavFwd = document.getElementById("btn-nav-fwd");
const btnNavRefresh = document.getElementById("btn-nav-refresh");
const ptrIndicator = document.getElementById("ptr-indicator");

const XND_DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,62}\.)+xnd$/;

function normalizeXndDomain(raw, appendTld = true) {
  let dom = String(raw || "").trim().toLowerCase();
  dom = dom.replace(/^(?:xnd|https?):\/\//, "");
  dom = dom.split("/")[0].split("?")[0].split("#")[0].trim();
  if (appendTld && dom && !dom.endsWith(".xnd")) {
    dom = `${dom}.xnd`;
  }
  return dom;
}

function isValidXndDomain(dom) {
  return Boolean(dom) && dom.length <= 253 && XND_DOMAIN_RE.test(dom);
}

function encodeRouteHash(route) {
  if (!route) return "#domain=home.xnd";
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(route)) {
    if (v !== null && v !== undefined && v !== "") p.set(k, String(v));
  }
  return "#" + p.toString();
}

function decodeRouteHash(hash) {
  if (!hash || hash.length < 2) return null;
  try {
    const p = new URLSearchParams(hash.slice(1));
    const type = p.get("type");
    if (!type) return null;
    const route = { type };
    if (p.has("domain")) route.domain = p.get("domain");
    if (p.has("version")) route.version = Number(p.get("version"));
    if (p.has("query")) route.query = p.get("query");
    if (p.has("tab")) route.tab = p.get("tab");
    if (p.has("url")) route.url = p.get("url");
    if (p.has("view")) route.view = p.get("view");
    if (p.has("filter")) route.filter = p.get("filter");
    if (p.has("mode")) route.mode = p.get("mode");
    return route;
  } catch (_) {
    return null;
  }
}

function updateNavButtons() {
  const t = tabs.find((x) => x.id === activeTabId);
  if (btnNavBack) btnNavBack.disabled = !t || t.historyIdx <= 0;
  if (btnNavFwd) btnNavFwd.disabled = !t || t.historyIdx >= t.history.length - 1;
}

function recordNav(route) {
  if (isRestoringNav) return;
  const t = tabs.find((x) => x.id === activeTabId);
  if (!t) return;
  const cur = t.history[t.historyIdx];
  if (cur && JSON.stringify(cur) === JSON.stringify(route)) {
    updateNavButtons();
    return;
  }
  t.history = t.history.slice(0, t.historyIdx + 1);
  t.history.push(route);
  t.historyIdx = t.history.length - 1;
  const hash = encodeRouteHash(route);
  try {
    if (t.history.length === 1 && !window.location.hash) {
      window.history.replaceState({ tabId: t.id, idx: t.historyIdx, route }, "", hash);
    } else {
      window.history.pushState({ tabId: t.id, idx: t.historyIdx, route }, "", hash);
    }
  } catch (_) {}
  updateNavButtons();
}

async function navigateRoute(route) {
  if (!route) return;
  isRestoringNav = true;
  try {
    if (route.type === "domain") {
      await openDomain(route.domain || "home.xnd", route.version ?? null);
    } else if (route.type === "search") {
      lastSearchData = null;
      await runSearch(route.query || "", route.tab || "all");
    } else if (route.type === "web") {
      openLiveWebsite(route.url || "");
    } else if (route.type === "repo") {
      await openRepoView(route.domain || "", route.version ?? null);
    } else if (route.type === "dash") {
      await openCloudflareDashboard(route.domain || "", route.tab || "overview", route.mode || "capsule", route.version ?? null, route.filter || "");
    } else if (route.type === "view") {
      if (route.view === "graph") await openGraphView();
      else if (route.view === "library") await openLibraryView(route.query || "");
      else if (route.view === "registry") await openRegistryView(route.filter || "");
    }
  } finally {
    isRestoringNav = false;
    updateNavButtons();
  }
}

function navBack() {
  const t = tabs.find((x) => x.id === activeTabId);
  if (!t || t.historyIdx <= 0) return;
  t.historyIdx -= 1;
  const route = t.history[t.historyIdx];
  try {
    window.history.replaceState({ tabId: t.id, idx: t.historyIdx, route }, "", encodeRouteHash(route));
  } catch (_) {}
  navigateRoute(route);
}

function navForward() {
  const t = tabs.find((x) => x.id === activeTabId);
  if (!t || t.historyIdx >= t.history.length - 1) return;
  t.historyIdx += 1;
  const route = t.history[t.historyIdx];
  try {
    window.history.replaceState({ tabId: t.id, idx: t.historyIdx, route }, "", encodeRouteHash(route));
  } catch (_) {}
  navigateRoute(route);
}

async function refreshCurrentRoute() {
  const t = tabs.find((x) => x.id === activeTabId);
  const route = (t && t.history[t.historyIdx]) || decodeRouteHash(window.location.hash) || { type: "domain", domain: "home.xnd" };
  await navigateRoute(route);
}

if (btnNavBack) btnNavBack.addEventListener("click", navBack);
if (btnNavFwd) btnNavFwd.addEventListener("click", navForward);
if (btnNavRefresh) btnNavRefresh.addEventListener("click", refreshCurrentRoute);

window.addEventListener("popstate", (e) => {
  const state = e.state;
  const t = tabs.find((x) => x.id === activeTabId);
  if (state && state.route) {
    if (t && typeof state.idx === "number" && t.history[state.idx]) {
      t.historyIdx = state.idx;
    }
    navigateRoute(state.route);
    return;
  }
  const decoded = decodeRouteHash(window.location.hash);
  if (decoded) {
    if (t && t.historyIdx > 0) t.historyIdx -= 1;
    navigateRoute(decoded);
  }
});

// Mobile Pull-Down-to-Refresh
let ptrStartY = 0;
let ptrPulling = false;
let ptrDistance = 0;
if (primaryPane && ptrIndicator) {
  primaryPane.addEventListener("touchstart", (e) => {
    const t = tabs.find((x) => x.id === activeTabId);
    const scroller = t ? t.el : primaryPane;
    if (scroller.scrollTop <= 0 && e.touches.length === 1) {
      ptrStartY = e.touches[0].clientY;
      ptrPulling = true;
      ptrDistance = 0;
    } else {
      ptrPulling = false;
    }
  }, { passive: true });

  primaryPane.addEventListener("touchmove", (e) => {
    if (!ptrPulling || e.touches.length !== 1) return;
    const t = tabs.find((x) => x.id === activeTabId);
    const scroller = t ? t.el : primaryPane;
    if (scroller.scrollTop > 0) {
      ptrPulling = false;
      ptrIndicator.style.height = "0px";
      ptrIndicator.classList.remove("active");
      return;
    }
    const dy = e.touches[0].clientY - ptrStartY;
    if (dy > 12) {
      ptrDistance = Math.min(84, dy * 0.65);
      ptrIndicator.style.height = `${Math.round(ptrDistance)}px`;
      ptrIndicator.classList.add("active");
      ptrIndicator.textContent = ptrDistance >= 52 ? "↻ Release to refresh" : "↓ Pull to refresh";
    }
  }, { passive: true });

  primaryPane.addEventListener("touchend", async () => {
    if (!ptrPulling) return;
    ptrPulling = false;
    if (ptrDistance >= 52) {
      ptrIndicator.style.height = "40px";
      ptrIndicator.textContent = "↻ Refreshing...";
      await refreshCurrentRoute();
    }
    ptrIndicator.style.height = "0px";
    ptrIndicator.classList.remove("active");
    ptrDistance = 0;
  });
}

function renderTabStrip() {
  if (!tabStrip) return;
  const itemsHtml = tabs
    .map(
      (t) => `
    <div class="tab-item ${t.id === activeTabId ? "active" : ""}" onclick="switchTab('${t.id}')" title="${escapeHtml(t.title)}">
      <span class="tab-title">${escapeHtml(t.title)}</span>
      <button class="tab-close" onclick="closeTab('${t.id}', event)" title="Close tab">×</button>
    </div>`
    )
    .join("");
  tabStrip.innerHTML = `${itemsHtml}<button class="tab-add" onclick="createTab('home.xnd', true, true)" title="New Tab (Ctrl+T)">+</button>`;
}

function setActiveTabMeta({ title, omniboxValue, doc }) {
  const t = tabs.find((x) => x.id === activeTabId);
  if (!t) return;
  if (title !== undefined) t.title = title;
  if (omniboxValue !== undefined) t.omniboxValue = omniboxValue;
  if (doc !== undefined) t.doc = doc;
  renderTabStrip();
}

function switchTab(tabId) {
  closeSplit();
  const target = tabs.find((x) => x.id === tabId);
  if (!target) return;
  const cur = tabs.find((x) => x.id === activeTabId);
  if (cur) {
    const modes = ["in-dashboard", "in-site-view", "in-search-view", "in-doc-view"];
    cur.viewMode = modes.find((m) => document.body.classList.contains(m)) || "";
  }
  activeTabId = tabId;
  for (const t of tabs) {
    t.el.classList.toggle("hidden", t.id !== tabId);
  }
  document.body.classList.remove("in-dashboard", "in-site-view", "in-search-view", "in-doc-view");
  if (target.viewMode) {
    document.body.classList.add(target.viewMode);
  }
  primaryContent = target.el;
  omniboxInput.value = target.omniboxValue || "";
  currentDoc = target.doc || null;
  applySmartColorEngine(currentDoc);
  renderTabStrip();
  updateNavButtons();
}

function createTab(initialTarget = "home.xnd", activate = true, focusOmnibox = false) {
  tabSeq += 1;
  const id = `tab-${tabSeq}`;
  const el = document.createElement("div");
  el.id = `tab-view-${id}`;
  el.className = "pane-scroll tab-view";
  el.addEventListener("scroll", drawBridgeLine);
  primaryPane.appendChild(el);
  const tab = { id, title: initialTarget || "Xanadu", omniboxValue: initialTarget || "", doc: null, el, history: [], historyIdx: -1 };
  tabs.push(tab);
  if (activate) {
    switchTab(id);
    if (initialTarget) {
      if (initialTarget.toLowerCase().endsWith(".xnd")) {
        openDomain(initialTarget);
      } else {
        openLiveWebsite(initialTarget);
      }
    }
    if (focusOmnibox) {
      omniboxInput.focus();
      omniboxInput.select();
    }
  } else {
    el.classList.add("hidden");
    renderTabStrip();
  }
  return tab;
}

function closeTab(tabId, event) {
  if (event) event.stopPropagation();
  const idx = tabs.findIndex((x) => x.id === tabId);
  if (idx === -1) return;
  const [removed] = tabs.splice(idx, 1);
  removed.el.remove();

  if (tabs.length === 0) {
    createTab("home.xnd", true, false);
    return;
  }
  if (activeTabId === tabId) {
    const next = tabs[Math.max(0, idx - 1)];
    switchTab(next.id);
  } else {
    renderTabStrip();
  }
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function formatTextSegment(text) {
  const lines = String(text).split("\n");
  return lines
    .map((line) => {
      if (line.startsWith("Archived from: ")) {
        const url = line.slice("Archived from: ".length).trim();
        return `<div class="archive-banner"><span>WEB SNAPSHOT ARCHIVE</span><span>Source: ${escapeHtml(url)}</span></div>`;
      }
      if (line.startsWith("# ")) {
        return `<span class="arch-h1">${escapeHtml(line.slice(2))}</span>`;
      }
      if (line.startsWith("## ")) {
        return `<span class="arch-h2">${escapeHtml(line.slice(3))}</span>`;
      }
      if (line.startsWith("> ")) {
        return `<span class="arch-quote">${escapeHtml(line.slice(2))}</span>`;
      }
      if (line.startsWith("• ")) {
        return `<span class="arch-li">${escapeHtml(line)}</span>`;
      }
      return escapeHtml(line);
    })
    .join("\n");
}

let homeNewsTimer = null;
let homeRotationClockTimer = null;
let homeEventSource = null;
let homeNewsHover = false;
let homeStoriesPool = [];

function stopHomeNewsRotation() {
  if (homeNewsTimer) {
    clearInterval(homeNewsTimer);
    homeNewsTimer = null;
  }
  if (homeRotationClockTimer) {
    clearInterval(homeRotationClockTimer);
    homeRotationClockTimer = null;
  }
  if (homeEventSource) {
    try { homeEventSource.close(); } catch (_) {}
    homeEventSource = null;
  }
}

function shuffleArray(arr) {
  const copy = [...arr];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

function openRandomCommonsSite() {
  if (!homeStoriesPool || !homeStoriesPool.length) return;
  const pick = homeStoriesPool[Math.floor(Math.random() * homeStoriesPool.length)];
  if (pick && pick.domain) openDomain(pick.domain);
}

async function toggleFollowFromCommons(pubHex, btnEl, event) {
  if (event) event.stopPropagation();
  if (!pubHex) return;
  try {
    const r = await fetch("/api/moderation/follow", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pubkey_hex: pubHex }),
    });
    if (r.ok && btnEl) {
      const data = await r.json();
      const followed = (data.followed_pubkeys || []).includes(pubHex.toLowerCase());
      btnEl.textContent = followed ? "Following" : "Follow";
      btnEl.classList.toggle("active", followed);
    }
  } catch (_) {}
}

function renderNewsCardsAnimated(items) {
  const grid = document.getElementById("home-news-grid");
  if (!grid) return;
  const slice = shuffleArray(items).slice(0, 12);
  grid.classList.add("news-fading");
  setTimeout(() => {
    const g = document.getElementById("home-news-grid");
    if (!g) return;
    g.innerHTML = slice
      .map(
        (s, idx) => `
      <article class="news-card news-card-anim" style="animation-delay:${idx * 35}ms;" onclick="openDomain('${escapeHtml(s.domain)}')">
        <div>
          <div class="news-source">
            <span>${escapeHtml(s.domain)}</span>
            <span class="news-fresh-badge">${escapeHtml(s.reason || "Verified .xnd")}</span>
          </div>
          <h3 class="news-headline" style="margin-top:6px;">${escapeHtml(s.title || s.domain)}</h3>
          ${s.snippet ? `<p class="news-summary">${escapeHtml(s.snippet)}</p>` : ""}
        </div>
        <div class="news-meta" style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
          <span>${escapeHtml(s.kind === "capsule" ? "App Capsule" : (s.kind === "citation" ? "Citation" : "Document"))}${s.backlinks ? ` · ${s.backlinks} citation${s.backlinks === 1 ? "" : "s"}` : ""}${s.fingerprint ? ` · ${escapeHtml(s.fingerprint)}` : ""}</span>
          ${s.pubkey_hex ? `<button type="button" class="ver-btn ${s.followed ? "active" : ""}" style="padding:2px 8px;font-size:11px;" onclick="toggleFollowFromCommons('${escapeHtml(s.pubkey_hex)}', this, event)">${s.followed ? "Following" : "Follow"}</button>` : ""}
        </div>
      </article>`
      )
      .join("");
    g.classList.remove("news-fading");
  }, 260);
}

function _formatRotationCountdown() {
  const rem = 900 - (Math.floor(Date.now() / 1000) % 900);
  const m = String(Math.floor(rem / 60)).padStart(2, "0");
  const s = String(rem % 60).padStart(2, "0");
  return `${m}:${s}`;
}

async function openHomeFeed(category = "all") {
  document.body.classList.remove("in-dashboard");
  document.body.classList.remove("in-site-view");
  document.body.classList.remove("in-search-view");
  closeSplit();
  stopHomeNewsRotation();
  document.body.classList.remove("in-doc-view");
  const modeMap = { top: "all", trending: "cited", all: "all", cited: "cited", followed: "followed", capsules: "capsules" };
  const mode = modeMap[(category || "all").toLowerCase()] || "all";
  setActiveTabMeta({ title: "Xanadu", omniboxValue: "home.xnd", doc: null });
  omniboxInput.value = "";
  currentDoc = null;
  applySmartColorEngine(null);

  const cats = [
    ["all", "All Commons"],
    ["cited", "Most Cited"],
    ["followed", "Followed Keys"],
    ["capsules", "App Capsules"],
  ];
  const pillsHtml = cats
    .map(
      ([id, label]) =>
        `<button class="ver-btn ${id === mode ? "active" : ""}" onclick="openHomeFeed('${id}')">${label}</button>`
    )
    .join("");

  const homeSk = `<div class="skeleton-card">
      <div class="skeleton-line short"></div>
      <div class="skeleton-line title"></div>
      <div class="skeleton-line wide"></div>
    </div>`;
  primaryContent.innerHTML = `<div class="doc-sheet">
    <div class="doc-header" style="border-bottom:none;padding-bottom:8px;">
      <h1 class="doc-title" style="font-size:clamp(28px,4vw,38px);margin-bottom:10px;">Xanadu Commons</h1>
      <div class="news-cats">${pillsHtml}</div>
    </div>
    <div class="news-grid">${homeSk.repeat(6)}</div>
  </div>`;

  try {
    window._xndMeshGatewayLabel = null;
    try {
      const gr = await fetch("/api/gateway/status");
      if (gr.ok) {
        const gs = await gr.json();
        if (!gs.has_wan && gs.active_gateway) window._xndMeshGatewayLabel = gs.active_gateway.label || "LAN Peer";
      }
    } catch (_) {}
    const res = await fetch(`/api/home/commons?mode=${encodeURIComponent(mode)}&limit=30`);
    const data = await res.json();
    const baseItems = data.items || [];
    const citeMixed = (data.latest_citations || []).map((c) => ({
      domain: c.source_domain,
      title: `${c.source_domain} -> ${c.target_domain}`,
      snippet: c.quote ? `"${c.quote}"` : `Span ${c.start}-${c.end}`,
      kind: "citation",
      reason: c.reason || `Quoted by ${c.source_domain}`,
      backlinks: 1,
      pubkey_hex: "",
      fingerprint: "",
    }));
    homeStoriesPool = [...baseItems, ...citeMixed];

    const gwBadge = window._xndMeshGatewayLabel ? `<span class="news-fresh-badge" style="margin-left:8px;">Mesh Internet via ${escapeHtml(window._xndMeshGatewayLabel)}</span>` : "";
    const hostSiteBtn = `<button type="button" class="ver-btn" style="display:inline-flex;align-items:center;gap:6px;" onclick="openCloudflareDashboard('', 'register')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14"/><path d="M5 12h14"/></svg>Host Free .xnd Site</button>`;
    const randomBtn = `<button type="button" class="ver-btn" onclick="openRandomCommonsSite()">Random Walk</button>`;
    const shuffleBtn = `<button type="button" class="ver-btn" onclick="renderNewsCardsAnimated(homeStoriesPool)">Rotate View</button>`;
    const heartbeatHtml = `<div id="commons-heartbeat" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin:4px 0 12px;">
      <span>${Number(data.lan_peers || 0)} Wi-Fi peer(s)</span>
      <span>·</span>
      <span>${homeStoriesPool.length} active items</span>
      <span>·</span>
      <span>Next rotation in <strong id="commons-rot-clock" style="color:var(--ink);">${_formatRotationCountdown()}</strong></span>
      <span id="commons-live-pulse" style="color:var(--accent);font-weight:600;"></span>
    </div>`;

    if (!homeStoriesPool.length) {
      primaryContent.innerHTML = `<div class="doc-sheet">
        <div class="doc-header" style="border-bottom:none;padding-bottom:8px;">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:10px;">
            <h1 class="doc-title" style="font-size:clamp(28px,4vw,38px);margin:0;">Xanadu Commons${gwBadge}</h1>
            ${hostSiteBtn}
          </div>
          <div class="news-cats">${pillsHtml}</div>
          ${heartbeatHtml}
        </div>
        <p style="color:var(--muted);">No .xnd sites in this filter yet. Publish a site or sync with peers.</p>
      </div>`;
      return;
    }

    primaryContent.innerHTML = `<div class="doc-sheet">
      <div class="doc-header" style="border-bottom:none;padding-bottom:8px;">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:10px;">
          <h1 class="doc-title" style="font-size:clamp(28px,4vw,38px);margin:0;">Xanadu Commons${gwBadge}</h1>
          ${hostSiteBtn}
        </div>
        <div class="news-cats">${pillsHtml}${randomBtn}${shuffleBtn}</div>
        ${heartbeatHtml}
      </div>
      <div id="home-news-grid" class="news-grid"></div>
    </div>`;

    const gridEl = document.getElementById("home-news-grid");
    if (gridEl) {
      gridEl.addEventListener("mouseenter", () => { homeNewsHover = true; });
      gridEl.addEventListener("mouseleave", () => { homeNewsHover = false; });
    }

    renderNewsCardsAnimated(homeStoriesPool);
    homeRotationClockTimer = setInterval(() => {
      const clk = document.getElementById("commons-rot-clock");
      if (!clk) {
        stopHomeNewsRotation();
        return;
      }
      clk.textContent = _formatRotationCountdown();
    }, 1000);

    try {
      homeEventSource = new EventSource("/api/events/stream");
      homeEventSource.addEventListener("domain_updated", (ev) => {
        try {
          const payload = JSON.parse(ev.data || "{}");
          const dom = payload.domain;
          if (!dom) return;
          const pulseEl = document.getElementById("commons-live-pulse");
          if (pulseEl) pulseEl.textContent = `· Just synced: ${dom}`;
          if (!homeStoriesPool.some((x) => x.domain === dom)) {
            homeStoriesPool.unshift({
              domain: dom,
              title: dom,
              snippet: "Live update synced from peer mesh",
              kind: "document",
              reason: "Just synced live",
              backlinks: 0,
            });
            if (!homeNewsHover) renderNewsCardsAnimated(homeStoriesPool);
          }
        } catch (_) {}
      });
    } catch (_) {}

    homeNewsTimer = setInterval(() => {
      if (!document.getElementById("home-news-grid")) {
        stopHomeNewsRotation();
        return;
      }
      if (!homeNewsHover && homeStoriesPool.length > 0) {
        renderNewsCardsAnimated(homeStoriesPool);
      }
    }, 15000);
  } catch (_) {
    primaryContent.innerHTML = `<div class="doc-sheet">
      <div class="doc-header" style="border-bottom:none;padding-bottom:8px;">
        <h1 class="doc-title">Xanadu Commons</h1>
        <div class="news-cats">${pillsHtml}</div>
      </div>
      <p style="color:var(--muted);">Could not load Xanadu Commons. Try searching above or entering any .xnd domain.</p>
    </div>`;
  }
}

async function openDomain(domain, version = null) {
  document.body.classList.remove("in-dashboard");
  document.body.classList.remove("in-site-view");
  document.body.classList.remove("in-search-view");
  document.body.classList.remove("in-doc-view");
  closeSplit();
  const clean = normalizeXndDomain(domain, false);
  recordNav({ type: "domain", domain: clean, version });
  if (clean === "home.xnd" && !version) {
    return openHomeFeed("top");
  }
  document.body.classList.add("in-doc-view");
  omniboxInput.value = clean.endsWith(".xnd") ? `xnd://${clean}` : clean;

  if (!clean.endsWith(".xnd")) {
  primaryContent.innerHTML = `
      <div class="notice-box">
        <h2>Xanadu-Only Namespace</h2>
        <p><code>${escapeHtml(clean)}</code> is not a <strong>.xnd</strong> address.</p>
        <p>This browser only resolves sovereign <code>.xnd</code> sites (no ICANN <code>.com/.org</code> domains).</p>
      </div>`;
    return;
  }

  const url = version
    ? `/api/resolve/${encodeURIComponent(clean)}?version=${version}&_t=${Date.now()}`
    : `/api/resolve/${encodeURIComponent(clean)}?_t=${Date.now()}`;
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Not found" }));
  primaryContent.innerHTML = `
      <div class="notice-box">
        <h2>${escapeHtml(clean)} not registered yet</h2>
        <p>${escapeHtml(err.detail || "Domain not found")}</p>
        <button class="btn-accent" onclick="prefillPublish('${escapeHtml(clean)}')">Claim ${escapeHtml(clean)}</button>
      </div>`;
    return;
  }

  const doc = await res.json();
  currentDoc = doc;
  setActiveTabMeta({ title: doc.domain, omniboxValue: clean, doc });
  recordHistory(clean, doc.title, "xnd");
  applySmartColorEngine(doc);
  if (coreStatus) {
    coreStatus.textContent = doc.rust_core_active
      ? "Rust Core + Ed25519 Active"
      : "Python Hash + Ed25519 Active";
  }

  renderPrimaryDoc(doc);
}

function renderPrimaryDoc(doc) {
  if (doc.kind === "capsule") {
    document.body.classList.remove("in-doc-view");
    document.body.classList.add("in-site-view");
    primaryContent.innerHTML = `<iframe class="capsule-frame capsule-frame-full" sandbox="allow-scripts allow-forms allow-modals" src="/xnd-app/${encodeURIComponent(doc.domain)}?_t=${Date.now()}"></iframe><button type="button" class="site-floating-home" onclick="openDomain('home.xnd')">← Home</button>`;
    return;
  }
  document.body.classList.remove("in-site-view");
  const versions = Array.isArray(doc.versions) && doc.versions.length
    ? doc.versions
    : [{ version_num: doc.version || 1 }];
  const versionButtons = versions
    .map(
      (v) =>
        `<button class="ver-btn ${v.version_num === doc.version ? "active" : ""}"
          onclick="openDomain('${escapeHtml(doc.domain)}', ${v.version_num})">
          v${v.version_num}
        </button>`
    )
    .join("");

  const kind = (doc.kind || "document").toUpperCase();
  const segments = Array.isArray(doc.segments)
    ? doc.segments
    : doc.raw_content
      ? [{ type: "text", text: doc.raw_content, start: 0 }]
      : [];
  const backlinks = Array.isArray(doc.backlinks) ? doc.backlinks : [];
  const sha = doc.sha256 || "";
  const pubkey = doc.pubkey || doc.pubkey_hex || "";

  const bodyHtml =
    doc.kind === "capsule"
      ? `<iframe class="capsule-frame" sandbox="allow-scripts allow-forms allow-modals" src="/xnd-app/${encodeURIComponent(doc.domain)}?_t=${Date.now()}"></iframe>`
      : segments
          .map((seg) => {
            if (seg.type === "text") {
              return `<span class="text-seg" data-start="${seg.start}">${formatTextSegment(seg.text)}</span>`;
            }
            if (seg.type === "transclusion") {
              if (window.XndTransclusion) {
                return window.XndTransclusion.renderCard(seg);
              }
              return `<span
                id="left-${seg.bridge_id}"
                class="transclusion-card"
                title="Click to open origin span side-by-side"
                onclick="openBridge('${seg.bridge_id}', '${escapeHtml(seg.target_domain)}', ${seg.target_version}, ${seg.target_start}, ${seg.target_end})"
              >
                <span class="transclusion-meta">⟐ transcluded from ${escapeHtml(seg.target_domain)}@v${seg.target_version} [${seg.target_start}:${seg.target_end}]</span>
                ${escapeHtml(seg.quoted_text)}
              </span>`;
            }
            return `<span class="meta-tag">${escapeHtml(seg.raw)}</span>`;
          })
          .join("");

  const backlinksHtml = backlinks.length
    ? backlinks
        .map(
          (b) => `
          <div class="backlink-item" onclick="openBacklink('${escapeHtml(b.source_domain)}', ${b.source_version}, ${b.source_start}, ${b.source_end})">
            <div>
              <strong>${escapeHtml(b.source_domain)}</strong> (v${b.source_version})
              <span style="color:var(--faded-ink);font-size:12px;">quoted chars ${b.target_start}–${b.target_end}</span>
            </div>
            <span class="tld-badge">Open Side-by-Side →</span>
          </div>`
        )
        .join("")
    : `<p style="color:var(--faded-ink);font-size:13px;">No other .xnd nodes cite this page yet.</p>`;

  primaryContent.innerHTML = `<div class="doc-sheet">
    <div class="doc-header">
      <div class="doc-domain">xnd://${escapeHtml(doc.domain)} · ${escapeHtml(kind)}</div>
      <h1 class="doc-title">${escapeHtml(doc.title || doc.domain)}</h1>
      <div class="meta-row">
        <span class="meta-tag ${isCoreXanaduDomain(doc.domain) ? "gold-verified" : (doc.verified ? "verified" : "")}">
          ${isCoreXanaduDomain(doc.domain) ? "✓ Verified · Core Xanadu" : (doc.verified ? "✓ Verified" : "✕ Unverified")}
        </span>
        <span class="meta-tag">${doc.owned_locally ? "LOCAL KEY" : "PEER KEY"}</span>
        ${doc.key_fingerprint ? `<span class="meta-tag" title="Canonical: ${escapeHtml(doc.canonical_domain || doc.domain)} · Status: ${escapeHtml(doc.trust_status || 'first_seen')}">🔑 ${escapeHtml(doc.key_fingerprint)} · ${escapeHtml((doc.trust_status || 'first_seen').toUpperCase())}${doc.petname ? ` (${escapeHtml(doc.petname)})` : ""}</span>` : ""}
        ${Array.isArray(doc.connect_origins) && doc.connect_origins.length ? `<span class="meta-tag" title="Signed External APIs: ${escapeHtml(doc.connect_origins.join(', '))}" style="display:inline-flex;align-items:center;gap:5px;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg> External APIs (${doc.connect_origins.length})</span>` : ""}
        ${doc.encrypted ? `<span class="meta-tag verified">🔒 E2EE Private (${(doc.allowed_pubkeys || []).length} key${(doc.allowed_pubkeys || []).length === 1 ? "" : "s"})</span>` : ""}
        ${doc.source_url ? `<button class="btn-accent" style="padding:4px 10px;font-size:12px;" onclick="openLiveWebsite('${escapeHtml(doc.source_url)}')">🌐 Open Live Website in Xanadu</button>` : ""}
        ${pubkey ? `<button class="btn-tool" style="padding:4px 10px;font-size:12px;" onclick="toggleFollowPubkey('${escapeHtml(pubkey)}')">★ Follow Author</button>` : ""}
        ${pubkey ? `<button class="btn-tool" style="padding:4px 10px;font-size:12px;" onclick="setDomainPetname('${escapeHtml(doc.domain)}', '${escapeHtml(doc.petname || '')}')">🏷 Petname</button>` : ""}
        <button class="btn-tool" style="padding:4px 10px;font-size:12px;" onclick="shareWebLink('${escapeHtml(doc.domain)}')">🔗 Share Web Link</button>
      </div>
      ${Array.isArray(doc.conflicts) && doc.conflicts.length ? `
      <div style="margin-top:8px;padding:8px 10px;border-radius:8px;border:1px solid #f59e0b;background:rgba(245,158,11,0.1);font-size:12px;">
        <strong>⚠ Key Conflict Protected:</strong> ${escapeHtml(doc.domain)} is pinned to <code>${escapeHtml(doc.key_fingerprint || '')}</code>. Alternate keys seen on network:
        ${doc.conflicts.map((c) => `<button class="ver-btn" style="margin-left:6px;" onclick="openDomain('${escapeHtml(c.domain)}')">${escapeHtml(c.domain)} (${escapeHtml(c.fingerprint)})</button>`).join("")}
      </div>` : ""}
      ${doc.encrypted && !doc.decrypted ? `
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;">
        <input id="e2ee-unlock-key" type="password" placeholder="Paste your invited 64-char Ed25519 private key to decrypt..." style="flex:1;min-width:220px;padding:7px 10px;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--fg);font-family:var(--font-mono);font-size:12px;" />
        <button class="btn-accent" onclick="unlockE2eeSpace('${escapeHtml(doc.domain)}')">🔓 Decrypt Space</button>
      </div>` : ""}
    </div>

    <div class="desktop-grid">
      <div class="doc-body" id="doc-body-raw">${bodyHtml}</div>
      <aside class="desktop-aside">
        <div class="backlinks-box" style="margin-top:0;">
          <h3>Two-Way Backlink Radar (${backlinks.length})</h3>
          ${backlinksHtml}
        </div>
      </aside>
    </div>
  </div>`;
}

async function openGraphView() {
  document.body.classList.remove("in-dashboard");
  document.body.classList.remove("in-site-view");
  document.body.classList.remove("in-search-view");
  closeSplit();
  recordNav({ type: "view", view: "graph" });
  const res = await fetch("/api/graph");
  if (!res.ok) return;
  const { nodes, edges } = await res.json();

  const width = 760;
  const height = 460;
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(width, height) * 0.34;

  const posMap = {};
  nodes.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(1, nodes.length) - Math.PI / 2;
    posMap[n.id] = {
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
      ...n,
    };
  });

  const edgeSvg = edges
    .map((e) => {
      const s = posMap[e.source];
      const t = posMap[e.target];
      if (!s || !t) return "";
      return `<line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke="#a62626" stroke-width="2" stroke-dasharray="5 4" />`;
    })
    .join("");

  const nodeSvg = nodes
    .map((n) => {
      const p = posMap[n.id];
      const fill = n.kind === "capsule" ? "#232528" : "#faf7f0";
      const textFill = n.kind === "capsule" ? "#faf7f0" : "#1c1b18";
      return `
        <g style="cursor:pointer" onclick="openDomain('${escapeHtml(n.id)}')">
          <circle cx="${p.x}" cy="${p.y}" r="34" fill="${fill}" stroke="#1c1b18" stroke-width="2" />
          <text x="${p.x}" y="${p.y + 4}" text-anchor="middle" font-family="monospace" font-size="11" font-weight="bold" fill="${textFill}">
            ${escapeHtml(n.id)}
          </text>
        </g>`;
    })
    .join("");

  setActiveTabMeta({ title: "Universe Graph", omniboxValue: "graph://universe", doc: null });
  primaryContent.innerHTML = `
    <div class="doc-header">
      <div class="doc-domain">Xanadu Constellation</div>
      <h1 class="doc-title">Universe Two-Way Link Map</h1>
      <p style="margin:0;color:var(--faded-ink);font-size:13px;">Click any .xnd node to open it. Dashed cinnabar lines show live two-way transclusions.</p>
    </div>
    <svg viewBox="0 0 ${width} ${height}" style="width:100%;max-width:780px;background:#faf7f0;border:1px solid var(--hairline-dark);">
      ${edgeSvg}
      ${nodeSvg}
    </svg>
  `;
}

async function openBridge(bridgeId, targetDomain, version, start, end) {
  document.querySelectorAll(".transclusion-card").forEach((el) => el.classList.remove("active"));
  const leftEl = document.getElementById(`left-${bridgeId}`);
  if (leftEl) leftEl.classList.add("active");

  const res = await fetch(`/api/resolve/${encodeURIComponent(targetDomain)}?version=${version}`);
  if (!res.ok) return;
  const targetDoc = await res.json();

  secondaryPane.classList.remove("hidden");
  secondaryLabel.textContent = `Origin: ${targetDoc.domain}@v${targetDoc.version} [${start}:${end}]`;

  const raw = targetDoc.raw_content;
  const before = escapeHtml(raw.slice(0, start));
  const match = escapeHtml(raw.slice(start, end));
  const after = escapeHtml(raw.slice(end));

  secondaryContent.innerHTML = `
    <div class="doc-header">
      <div class="doc-domain">xnd://${escapeHtml(targetDoc.domain)} @ v${targetDoc.version}</div>
      <h2 class="doc-title" style="font-size:20px;">${escapeHtml(targetDoc.title)}</h2>
      <div class="meta-row">
        <span class="meta-tag verified">✓ Immutable Span Verified</span>
      </div>
    </div>
    <div class="doc-body">${before}<span id="right-target-span" class="highlight-span">${match}</span>${after}</div>
  `;

  activeBridge = { leftId: `left-${bridgeId}`, rightId: "right-target-span" };
  requestAnimationFrame(() => {
    document.getElementById("right-target-span")?.scrollIntoView({ behavior: "smooth", block: "center" });
    setTimeout(drawBridgeLine, 120);
  });
}

async function openBacklink(sourceDomain, version, start, end) {
  const res = await fetch(`/api/resolve/${encodeURIComponent(sourceDomain)}?version=${version}`);
  if (!res.ok) return;
  const srcDoc = await res.json();

  secondaryPane.classList.remove("hidden");
  secondaryLabel.textContent = `Citing Node: ${srcDoc.domain}@v${srcDoc.version}`;

  const raw = srcDoc.raw_content;
  const before = escapeHtml(raw.slice(0, start));
  const match = escapeHtml(raw.slice(start, end));
  const after = escapeHtml(raw.slice(end));

  secondaryContent.innerHTML = `
    <div class="doc-header">
      <div class="doc-domain">xnd://${escapeHtml(srcDoc.domain)} @ v${srcDoc.version}</div>
      <h2 class="doc-title" style="font-size:20px;">${escapeHtml(srcDoc.title)}</h2>
    </div>
    <div class="doc-body">${before}<span id="right-target-span" class="highlight-span">${match}</span>${after}</div>
  `;
  activeBridge = null;
  bridgeSvg.innerHTML = "";
}

function drawBridgeLine() {
  bridgeSvg.innerHTML = "";
  if (!activeBridge || secondaryPane.classList.contains("hidden")) return;

  const leftEl = document.getElementById(activeBridge.leftId);
  const rightEl = document.getElementById(activeBridge.rightId);
  if (!leftEl || !rightEl) return;

  const wsRect = document.getElementById("workspace").getBoundingClientRect();
  const lRect = leftEl.getBoundingClientRect();
  const rRect = rightEl.getBoundingClientRect();

  const x1 = lRect.right - wsRect.left;
  const y1 = lRect.top + lRect.height / 2 - wsRect.top;
  const x2 = rRect.left - wsRect.left;
  const y2 = rRect.top + rRect.height / 2 - wsRect.top;
  const cx = (x1 + x2) / 2;

  const accentColor =
    getComputedStyle(document.documentElement).getPropertyValue("--accent").trim() || "#1a73e8";
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", `M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`);
  path.setAttribute("stroke", accentColor);
  path.setAttribute("stroke-width", "2.2");
  path.setAttribute("fill", "none");
  path.setAttribute("stroke-dasharray", "6 4");
  bridgeSvg.appendChild(path);
}

function closeSplit() {
  secondaryPane.classList.add("hidden");
  activeBridge = null;
  bridgeSvg.innerHTML = "";
}

function normalizeLiveUrl(target) {
  const clean = (target || "").trim();
  if (!clean) return "";
  if (/^https?:\/\//i.test(clean)) return clean;
  return `https://${clean}`;
}

const wwwHistory = [];
const isXanaduDesktop = navigator.userAgent.includes("XanaduDesktop");
const isXanaduAndroid = navigator.userAgent.includes("XanaduAndroid");

function closeImageViewer() {
  const el = document.getElementById("xnd-img-lightbox");
  if (el) el.remove();
}

function openImageViewer(imgUrl, title, pageUrl, source) {
  closeImageViewer();
  const wrap = document.createElement("div");
  wrap.id = "xnd-img-lightbox";
  wrap.className = "img-lightbox-backdrop";
  wrap.onclick = (e) => {
    if (e.target === wrap) closeImageViewer();
  };
  wrap.innerHTML = `
    <div class="img-lightbox-card" role="dialog" aria-modal="true">
      <div class="img-lightbox-meta">
        <span style="font-family:var(--font-mono);font-size:11px;color:var(--accent);text-transform:uppercase;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;">${escapeHtml(source || "Image")}</span>
        <div style="display:flex;gap:8px;align-items:center;">
          ${pageUrl ? `<button class="ver-btn" style="padding:4px 10px;font-size:12px;" onclick="closeImageViewer(); openLiveWebsite('${escapeHtml(pageUrl)}')">Open Page ↗</button>` : ""}
          <button class="ver-btn" style="padding:4px 10px;font-size:12px;" onclick="closeImageViewer()">✕ Close</button>
        </div>
      </div>
      <img class="img-lightbox-img" src="${escapeHtml(imgUrl)}" alt="${escapeHtml(title || "")}" />
      <div style="width:100%;font-size:13px;color:var(--fg);line-height:1.4;text-align:center;">${escapeHtml(title || "")}</div>
    </div>`;
  document.body.appendChild(wrap);
}

async function openLiveWebsite(target, pushHistory = true) {
  document.body.classList.remove("in-dashboard");
  document.body.classList.remove("in-site-view");
  document.body.classList.remove("in-search-view");
  document.body.classList.remove("in-doc-view");
  closeSplit();
  if (pushHistory) recordNav({ type: "web", url: target });
  const liveUrl = normalizeLiveUrl(target);
  if (!liveUrl) return;
  let gwInfo = null;
  try {
    const gr = await fetch("/api/gateway/status");
    if (gr.ok) gwInfo = await gr.json();
  } catch (_) {}
  if (gwInfo && !gwInfo.has_wan && gwInfo.active_gateway) {
    omniboxInput.value = liveUrl;
    recordHistory(liveUrl, liveUrl, "www");
    const gwLabel = gwInfo.active_gateway.label || "LAN Peer";
    primaryContent.innerHTML = `<div class="doc-sheet" style="padding:10px 14px;">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:8px;padding-bottom:8px;border-bottom:1px solid var(--border);">
        <span style="font-size:12px;color:#059669;font-weight:600;">🌐 Mesh Internet via ${escapeHtml(gwLabel)}</span>
        <span style="font-family:var(--font-mono);font-size:12px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(liveUrl)}</span>
      </div>
      <iframe src="/api/web/browse?url=${encodeURIComponent(liveUrl)}" style="width:100%;height:calc(100vh - 150px);min-height:580px;border:1px solid var(--border);border-radius:10px;background:#fff;"></iframe>
    </div>`;
    return;
  }
  if (isXanaduAndroid) {
    recordHistory(liveUrl, liveUrl, "www");
    window.location.href = liveUrl;
    return;
  }
  if (pushHistory && wwwHistory[wwwHistory.length - 1] !== liveUrl) {
    wwwHistory.push(liveUrl);
  }
  omniboxInput.value = liveUrl;
  let hostTitle = liveUrl;
  try { hostTitle = new URL(liveUrl).hostname.replace(/^www\./, ""); } catch (_) {}
  setActiveTabMeta({ title: hostTitle, omniboxValue: liveUrl, doc: null });
  recordHistory(liveUrl, hostTitle, "www");

  if (isXanaduDesktop) {
    primaryContent.innerHTML = `<div class="doc-sheet" style="padding:12px 16px;">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border);">
        <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;">
          <button class="ver-btn" title="Back" onclick="wwwBack()">←</button>
          <button class="ver-btn" title="Forward" onclick="wwwForward()">→</button>
          <button class="ver-btn" title="Reload" onclick="wwwReload()">↻</button>
          <span id="www-url-label" style="font-family:var(--font-mono);font-size:12px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(liveUrl)}</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;">
          <button class="ver-btn" onclick="clipLiveSelection()">✂ Quote into .xnd</button>
          <button class="ver-btn" onclick="visitAnyDomain(document.getElementById('www-webview')?.getURL() || '${escapeHtml(liveUrl)}')">Archive .xnd</button>
        </div>
      </div>
      <webview
        id="www-webview"
        src="${escapeHtml(liveUrl)}"
        partition="persist:xanadu-www"
        allowpopups
        style="width:100%;height:calc(100vh - 150px);min-height:580px;border:1px solid var(--border);border-radius:10px;background:#ffffff;"
      ></webview>
    </div>`;

    const wv = document.getElementById("www-webview");
    if (wv) {
      const syncUrl = (u) => {
        if (!u) return;
        omniboxInput.value = u;
        const lbl = document.getElementById("www-url-label");
        if (lbl) lbl.textContent = u;
      };
      wv.addEventListener("did-navigate", (e) => syncUrl(e.url));
      wv.addEventListener("did-navigate-in-page", (e) => syncUrl(e.url));
    }
    return;
  }

  primaryContent.innerHTML = `<div class="doc-sheet" style="padding:14px 18px;">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border);">
      <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1;">
        <button class="ver-btn" title="Back" onclick="wwwBack()">←</button>
        <button class="ver-btn" title="Reload" onclick="openLiveWebsite('${escapeHtml(liveUrl)}', false)">↻</button>
        <span style="font-family:var(--font-mono);font-size:12px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(liveUrl)}</span>
      </div>
      <div style="display:flex;align-items:center;gap:8px;">
        <button class="ver-btn" onclick="clipLiveSelection()">✂ Quote into .xnd</button>
        <button class="ver-btn" onclick="visitAnyDomain('${escapeHtml(liveUrl)}')">Archive .xnd</button>
        <a class="ver-btn" style="text-decoration:none;" href="${escapeHtml(liveUrl)}" target="_blank" rel="noopener noreferrer" title="Open outside Xanadu">↗</a>
      </div>
    </div>
    <iframe
      id="www-frame"
      class="capsule-frame"
      style="width:100%;height:calc(100vh - 190px);min-height:540px;border:1px solid var(--border);border-radius:10px;background:#ffffff;"
      src="/api/www?url=${encodeURIComponent(liveUrl)}"
    ></iframe>
  </div>`;
}

function wwwBack() {
  const wv = document.getElementById("www-webview");
  if (wv && typeof wv.canGoBack === "function" && wv.canGoBack()) {
    wv.goBack();
    return;
  }
  if (wwwHistory.length > 1) {
    wwwHistory.pop();
    const prev = wwwHistory[wwwHistory.length - 1];
    openLiveWebsite(prev, false);
  } else {
    openHomeFeed("top");
  }
}

function wwwForward() {
  const wv = document.getElementById("www-webview");
  if (wv && typeof wv.canGoForward === "function" && wv.canGoForward()) {
    wv.goForward();
  }
}

function wwwReload() {
  const wv = document.getElementById("www-webview");
  if (wv && typeof wv.reload === "function") {
    wv.reload();
  }
}

let lastWwwSelection = { text: "", url: "", title: "" };

window.addEventListener("message", (event) => {
  if (event.data && event.data.type === "xnd-www-navigate" && event.data.url) {
    openLiveWebsite(event.data.url, true);
  } else if (event.data && event.data.type === "xnd-www-selection" && event.data.text) {
    lastWwwSelection = {
      text: event.data.text,
      url: event.data.url || omniboxInput.value,
      title: event.data.title || "",
    };
  }
});

async function clipLiveSelection() {
  let quote = "";
  let url = omniboxInput.value.trim();
  let title = "";
  const wv = document.getElementById("www-webview");
  if (wv && typeof wv.executeJavaScript === "function") {
    try {
      const res = await wv.executeJavaScript(
        "({ text: (window.getSelection ? window.getSelection().toString() : '').trim(), url: location.href, title: document.title })"
      );
      if (res) {
        quote = res.text || "";
        url = res.url || url;
        title = res.title || "";
      }
    } catch (_) {}
  } else if (lastWwwSelection.text) {
    quote = lastWwwSelection.text;
    url = lastWwwSelection.url || url;
    title = lastWwwSelection.title || "";
  }

  if (!quote) {
    quote = prompt("Select text on the page first, or paste a quote to clip into .xnd:") || "";
  }
  if (!quote.trim()) return;

  const targetDomain = prompt("Target .xnd domain (leave blank for auto clip-xxxxxxxx.xnd):", "") || "";
  const resp = await fetch("/api/clip", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, title, quote: quote.trim(), domain: targetDomain }),
  });
  const data = await resp.json();
  if (!resp.ok) {
    alert(data.detail || "Clip failed");
    return;
  }
  createTab(data.domain, true, false);
}

function recordHistory(url, title, kind) {
  fetch("/api/history", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, title: title || url, kind }),
  }).catch(() => {});
}

async function toggleCurrentBookmark() {
  const url = omniboxInput.value.trim();
  if (!url) return;
  const kind = url.toLowerCase().endsWith(".xnd") ? "xnd" : "www";
  const title = currentDoc?.title || url;
  const res = await fetch("/api/bookmarks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, title, kind }),
  });
  if (res.ok) {
    const btn = document.getElementById("btn-bookmark");
    if (btn) {
      btn.textContent = "★ Saved";
      setTimeout(() => { btn.textContent = "★"; }, 1400);
    }
  }
}

async function removeBookmark(url) {
  await fetch(`/api/bookmarks?url=${encodeURIComponent(url)}`, { method: "DELETE" });
  openLibraryView(document.getElementById("lib-history-q")?.value || "");
}

async function openLibraryView(query = "") {
  document.body.classList.remove("in-dashboard");
  document.body.classList.remove("in-site-view");
  document.body.classList.remove("in-search-view");
  closeSplit();
  recordNav({ type: "view", view: "library", query });
  setActiveTabMeta({ title: "Library", omniboxValue: "xnd://library", doc: null });
  const [bRes, hRes] = await Promise.all([
    fetch("/api/bookmarks"),
    fetch(`/api/history?q=${encodeURIComponent(query)}`),
  ]);
  const bData = await bRes.json();
  const hData = await hRes.json();

  const bHtml = (bData.bookmarks || []).length
    ? bData.bookmarks
        .map(
          (b) => `
      <div class="search-result" style="display:flex;justify-content:space-between;align-items:center;gap:12px;" onclick="${b.kind === "xnd" ? `openDomain('${escapeHtml(b.url)}')` : `openLiveWebsite('${escapeHtml(b.url)}')`}">
        <div>
          <div class="doc-domain">${escapeHtml(b.kind.toUpperCase())} · ${escapeHtml(b.url)}</div>
          <h3 style="margin:2px 0 0 0;">${escapeHtml(b.title)}</h3>
        </div>
        <button class="ver-btn" onclick="event.stopPropagation(); removeBookmark('${escapeHtml(b.url)}')">Remove</button>
      </div>`
        )
        .join("")
    : `<p style="color:var(--muted);">No bookmarks yet. Click ★ in the top bar on any .xnd or .com site.</p>`;

  const hHtml = (hData.history || []).length
    ? hData.history
        .map(
          (h) => `
      <div class="search-result" onclick="${h.kind === "xnd" ? `openDomain('${escapeHtml(h.url)}')` : `openLiveWebsite('${escapeHtml(h.url)}')`}">
        <div class="doc-domain">${escapeHtml(h.kind.toUpperCase())} · ${new Date(h.visited_at * 1000).toLocaleString()}</div>
        <h3 style="margin:2px 0 0 0;">${escapeHtml(h.title)}</h3>
        <div style="font-size:12px;color:var(--muted);">${escapeHtml(h.url)}</div>
      </div>`
        )
        .join("")
    : `<p style="color:var(--muted);">No matching history entries.</p>`;

  primaryContent.innerHTML = `<div class="doc-sheet">
    <div class="doc-header">
      <div class="doc-domain">Xanadu Zero-DB Library</div>
      <h1 class="doc-title">Bookmarks &amp; History</h1>
    </div>
    <div>
      <h2 style="font-size:15px;margin-bottom:10px;">★ Bookmarks</h2>
      ${bHtml}
      <h2 style="font-size:15px;margin:24px 0 10px 0;">History</h2>
      <div style="display:flex;gap:8px;margin-bottom:12px;">
        <input id="lib-history-q" type="text" value="${escapeHtml(query)}" placeholder="Filter history..." style="flex:1;padding:8px 12px;border-radius:8px;border:1px solid rgba(128,128,128,0.25);background:var(--surface);color:var(--ink);" onkeydown="if(event.key==='Enter') openLibraryView(this.value)" />
        <button class="btn-accent" onclick="openLibraryView(document.getElementById('lib-history-q').value)">Filter</button>
      </div>
      ${hHtml}
    </div>
  </div>`;
}

async function refreshStorageStats() {}

if (window.xanaduDesktop && typeof window.xanaduDesktop.onDownload === "function") {
  window.xanaduDesktop.onDownload((dl) => {
    const el = document.getElementById("dl-status");
    if (!el) return;
    el.classList.remove("hidden");
    const pct = dl.totalBytes > 0 ? ` (${Math.round((dl.receivedBytes / dl.totalBytes) * 100)}%)` : "";
    if (dl.state === "completed") {
      el.textContent = `✓ Downloaded ${dl.filename} → Downloads/`;
      setTimeout(() => el.classList.add("hidden"), 6000);
    } else if (dl.state === "interrupted" || dl.state === "cancelled") {
      el.textContent = `✕ Download ${dl.state}: ${dl.filename}`;
    } else {
      el.textContent = `⬇ Downloading ${dl.filename}${pct}`;
    }
  });
}

async function visitAnyDomain(target) {
  closeSplit();
  primaryContent.innerHTML = `<div class="doc-sheet"><p style="color:var(--muted);font-family:var(--font-mono);">Crawling & indexing <strong>${escapeHtml(target)}</strong> into .xnd...</p></div>`;
  const res = await fetch("/api/visit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: target, domain: "" }),
  });
  const d = await res.json();
  if (!res.ok) {
  primaryContent.innerHTML = `<div class="doc-sheet"><div class="notice-box"><h2>Could not reach ${escapeHtml(target)}</h2><p>${escapeHtml(d.detail || "Fetch failed")}</p></div></div>`;
    return;
  }
  openDomain(d.domain);
}

let lastSearchData = null;

function renderSkeletonCards(count = 3) {
  return Array.from({ length: count })
    .map(
      () => `<div class="skeleton-card" aria-hidden="true">
        <div class="skeleton-line short"></div>
        <div class="skeleton-line title"></div>
        <div class="skeleton-line med"></div>
        <div class="skeleton-line" style="width:62%;"></div>
      </div>`
    )
    .join("");
}

async function runSearch(query, activeTab = "all") {
  document.body.classList.remove("in-dashboard");
  document.body.classList.remove("in-site-view");
  document.body.classList.remove("in-doc-view");
  document.body.classList.add("in-search-view");
  closeSplit();
  recordNav({ type: "search", query, tab: activeTab });
  setActiveTabMeta({ title: `Search: ${query}`, omniboxValue: query, doc: null });
  if (!lastSearchData || lastSearchData.query !== query || lastSearchData.fast) {
    if (!lastSearchData || lastSearchData.query !== query) {
      primaryContent.innerHTML = `<div class="doc-sheet">
        <div class="doc-header">
          <div class="doc-domain">Xanadu Search</div>
          <h1 class="doc-title">Results for "${escapeHtml(query)}"</h1>
        </div>
        <div class="search-layout">
          <div class="search-main">${renderSkeletonCards(3)}</div>
          <aside class="desktop-aside"><div class="xnd-side-panel">${renderSkeletonCards(2)}</div></aside>
        </div>
      </div>`;
      try {
        const fastRes = await fetch(`/api/search?q=${encodeURIComponent(query)}&fast=1`);
        if (fastRes.ok) {
          lastSearchData = await fastRes.json();
          renderSearchResults(query, activeTab, lastSearchData, Boolean(lastSearchData.fast));
          if (!lastSearchData.fast) {
            return;
          }
        }
      } catch (_) {}
    }
    const res = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
    if (res.ok) {
      lastSearchData = await res.json();
    }
  }
  if (lastSearchData) {
    renderSearchResults(query, activeTab, lastSearchData, false);
  }
}

window.sendSearchFeedback = async function (query, domain, helpful, btn) {
  try {
    await fetch("/api/search/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, domain, helpful }),
    });
    if (btn && btn.parentElement) {
      btn.parentElement.innerHTML = `<span style="color:var(--accent);font-weight:600;">✓ Thanks — Xanadu pattern memory updated!</span>`;
    }
  } catch (_) {}
};

function renderSearchResults(query, activeTab, data, isLoadingExternal = false) {
  const items = data.results || data.domains || [];
  const senses = data.disambiguation || [];
  const images = data.images || [];
  const forums = data.forums || [];
  const coreTerm = data.core_term || query;
  const intentLabel = data.intent ? ` · ${escapeHtml(data.intent)} (${escapeHtml(data.scope || "external")})` : "";
  const indexMs = data.index_ms != null ? `${data.index_ms} ms` : "instant";

  const isDomainQuery =
    /^(https?:\/\/)?[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(query.trim()) &&
    !query.trim().toLowerCase().endsWith(".xnd");
  const directBannerHtml = isDomainQuery
    ? `<div class="notice-box" style="margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;">
        <div>
          <div style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;">Direct WWW Match</div>
          <div style="font-size:16px;font-weight:600;margin-top:4px;">${escapeHtml(normalizeLiveUrl(query))}</div>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
          <button class="btn-accent" onclick="openLiveWebsite('${escapeHtml(query)}')">Open Live Website ↗</button>
          <button class="ver-btn" onclick="visitAnyDomain('${escapeHtml(query)}')">Archive .xnd Snapshot</button>
        </div>
      </div>`
    : "";

  const tabBtns = [
    ["all", `All`],
    ["web", `Web (${senses.length + items.length})`],
    ["images", `Images (${images.length})`],
    ...(forums.length ? [["forums", `Forums (${forums.length})`]] : []),
    ["news", `News`],
  ]
    .map(
      ([id, label]) =>
        `<button class="ver-btn ${activeTab === id ? "active" : ""}" onclick="runSearch('${escapeHtml(query)}', '${id}')">${label}</button>`
    )
    .join("");

  const xndSideHtml = `
    <div class="xnd-side-panel">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:12px;">
        <span style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:0.06em;">
          ⚡ Indexed .xnd Pages (${items.length})
        </span>
        <span style="font-family:var(--font-mono);font-size:11px;color:var(--muted);">${indexMs}</span>
      </div>
      ${items.length
        ? items
            .map((r) => {
              const dom = r.domain || r.name;
              const isSite = r.kind === "capsule";
              const badge = isSite ? `<span class="badge badge-blue">SITE / APP</span>` : `<span class="badge">DOC</span>`;
              if (r.source_url) {
                return `
          <div class="xnd-side-card" onclick="openLiveWebsite('${escapeHtml(r.source_url)}')">
            <div class="doc-domain" style="margin-bottom:4px;">${escapeHtml(dom)} · ${badge}</div>
            <h3 style="margin:0 0 4px 0;font-size:15px;">${escapeHtml(r.title)}</h3>
            <p style="margin:0 0 8px 0;color:var(--muted);font-size:12.5px;line-height:1.45;">${escapeHtml(r.snippet || "")}</p>
            <button class="ver-btn" style="padding:3px 9px;font-size:11px;" onclick="event.stopPropagation(); openDomain('${escapeHtml(dom)}')">View .xnd Snapshot</button>
          </div>`;
              }
              return `
          <div class="xnd-side-card" onclick="openDomain('${escapeHtml(dom)}')">
            <div class="doc-domain" style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:4px;">
              <span>xnd://${escapeHtml(dom)}</span>
              ${goldTickBadge(dom)}
              ${badge}
              <span>· ${r.backlinks_count || 0} links</span>
            </div>
            <h3 style="margin:0 0 4px 0;font-size:15px;">${escapeHtml(r.title)}</h3>
            <p style="margin:0 0 8px 0;color:var(--muted);font-size:12.5px;line-height:1.45;">${escapeHtml(r.snippet || "")}</p>
            <div style="display:flex;gap:6px;flex-wrap:wrap;">
              <button class="btn-accent" style="padding:4px 10px;font-size:11px;" onclick="event.stopPropagation(); openDomain('${escapeHtml(dom)}')">${isSite ? "Launch Site" : "Open"}</button>
              <button class="ver-btn" style="padding:4px 10px;font-size:11px;" onclick="event.stopPropagation(); openRepoView('${escapeHtml(dom)}')">Inspect Repo</button>
            </div>
          </div>`;
            })
            .join("")
        : (isLoadingExternal
            ? renderSkeletonCards(2)
            : `<p style="margin:0;color:var(--muted);font-size:13px;">No local .xnd pages matched this term yet.</p>`)}
    </div>`;

  const imagesHtml = images.length
    ? `<div style="margin-bottom:24px;">
        <div style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:10px;">
          High-Resolution Images for "${escapeHtml(coreTerm)}"
        </div>
        <div class="img-grid">
          ${(activeTab === "images" ? images : images.slice(0, 4))
            .map(
              (im) => `
            <div class="img-card" onclick="openImageViewer('${escapeHtml(im.image)}', '${escapeHtml(im.title)}', '${escapeHtml(im.url || im.image)}', '${escapeHtml(im.source || "Web")}')">
              <img src="${escapeHtml(im.image)}" alt="${escapeHtml(im.title)}" loading="lazy" onerror="this.parentElement.style.display='none'" />
              <div class="img-card-cap" title="${escapeHtml(im.title)}">${escapeHtml(im.title)} · ${escapeHtml(im.source)}</div>
            </div>`
            )
            .join("")}
        </div>
      </div>`
    : (isLoadingExternal && activeTab === "images"
        ? renderSkeletonCards(3)
        : (activeTab === "images" ? `<p style="color:var(--muted);">No images found for "${escapeHtml(query)}".</p>` : ""));

  const forumsHtml = forums.length
    ? `<div style="margin-bottom:24px;">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px;">
          <span style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:0.06em;">
            Forums &amp; Stories (${forums.length})
          </span>
        </div>
        ${forums
          .map((f) => {
            const isLocalXnd = f.is_xnd || (f.url || "").startsWith("xnd://");
            const clickAction = isLocalXnd
              ? `openDomain('${escapeHtml((f.url || "forum.xnd").replace(/^xnd:\/\//, ""))}')`
              : `openLiveWebsite('${escapeHtml(f.url)}')`;
            return `
          <div class="search-result" ${isLocalXnd ? `style="border-left:3px solid var(--accent);"` : ""} onclick="${clickAction}">
            <div class="doc-domain">${escapeHtml(f.forum)}${f.author ? ` · @${escapeHtml(f.author)}` : ""} · ${f.points} points · ${f.comments} comments</div>
            <h3>${escapeHtml(f.title)}</h3>
            ${f.snippet ? `<p style="margin:0;color:var(--muted);font-size:13.5px;">${escapeHtml(f.snippet)}</p>` : ""}
          </div>`;
          })
          .join("")}
      </div>`
    : (isLoadingExternal
        ? renderSkeletonCards(3)
        : (activeTab === "forums" ? `<p style="color:var(--muted);">No forum discussions found for "${escapeHtml(query)}".</p>` : ""));

  const webSenses = activeTab === "news"
    ? senses.filter((s) => (s.category || "").toLowerCase().includes("news"))
    : senses;

  const sensesHtml = webSenses.length
    ? `<div style="margin-bottom:26px;">
        <div style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:10px;">
          Internet Web Results for "${escapeHtml(coreTerm)}"
        </div>
        ${webSenses
          .map(
            (s) => `
          <div class="search-result" style="background:var(--surface);" onclick="openLiveWebsite('${escapeHtml(s.url)}')">
            <div class="doc-domain">${escapeHtml(s.category || "Live Web")} · Open Live Website</div>
            <h3>${escapeHtml(s.title)}</h3>
            <p style="margin:0 0 8px 0;color:var(--muted);font-size:14px;">${escapeHtml(s.summary || "")}</p>
            <button class="ver-btn" onclick="event.stopPropagation(); visitAnyDomain('${escapeHtml(s.url)}')">Archive .xnd</button>
          </div>`
          )
          .join("")}
      </div>`
    : "";

  const kc = data.knowledge_card || null;
  const kcIsExt = Boolean(kc && kc.url && kc.url.startsWith("http"));
  const kcClick = kcIsExt
    ? `openLiveWebsite('${escapeHtml(kc.url)}')`
    : `openDomain('${escapeHtml((kc && kc.domain) || "founder.xnd")}')`;
  const kcSourceLabel = kcIsExt ? escapeHtml(kc.url) : `xnd://${escapeHtml((kc && kc.domain) || "founder.xnd")}`;
  const knowledgeCardHtml = kc
    ? `<div class="search-result" style="border-left:3px solid var(--accent);background:var(--surface);margin-bottom:20px;" onclick="${kcClick}">
        <div class="doc-domain" style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;">
          <span>${kcSourceLabel} · ${escapeHtml(kc.subtitle || "")}</span>
          <span style="font-family:var(--font-mono);font-size:11px;color:var(--accent);">⚡ ${indexMs}</span>
        </div>
        <div style="display:flex;align-items:flex-start;gap:14px;margin-top:4px;">
          ${kc.image ? `<img src="${escapeHtml(kc.image)}" alt="${escapeHtml(kc.title)}" style="width:72px;height:72px;object-fit:cover;border-radius:10px;flex-shrink:0;border:1px solid var(--border);" onerror="this.style.display='none'" />` : ""}
          <div style="min-width:0;flex:1;">
            <h3 style="margin:0 0 6px 0;font-size:19px;">${escapeHtml(kc.title)}</h3>
            <p style="margin:0;font-size:14.5px;line-height:1.58;color:var(--fg);">${escapeHtml(kc.summary || "")}</p>
          </div>
        </div>
        ${(kc.facts || []).length
          ? `<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px;">
              ${kc.facts
                .map(
                  (f) => `<span style="font-size:12px;padding:4px 10px;border-radius:999px;background:var(--bg);border:1px solid var(--border);"><strong style="color:var(--muted);font-weight:600;">${escapeHtml(f.label)}:</strong> ${escapeHtml(f.value)}</span>`
                )
                .join("")}
            </div>`
          : ""}
        ${kc.domain
          ? `<div style="display:flex;align-items:center;gap:8px;margin-top:10px;font-size:12px;color:var(--muted);" onclick="event.stopPropagation()">
              <span>Helpful answer?</span>
              <button type="button" class="ver-btn" style="padding:2px 8px;font-size:11px;" onclick="sendSearchFeedback('${escapeHtml(query)}','${escapeHtml(kc.domain)}',true,this)">👍 Yes</button>
              <button type="button" class="ver-btn" style="padding:2px 8px;font-size:11px;" onclick="sendSearchFeedback('${escapeHtml(query)}','${escapeHtml(kc.domain)}',false,this)">👎 No</button>
            </div>`
          : ""}
      </div>`
    : "";

  const deepPassages = (data.deep_passages && data.deep_passages.length)
    ? data.deep_passages
    : ((data.details_card && data.details_card.deep_passages) || []);
  const deepPassagesHtml = deepPassages.length
    ? `<div style="margin-bottom:20px;padding:12px 14px;border-radius:12px;border:1px solid var(--border);background:var(--card-bg,var(--bg));">
        <div style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:8px;">
          🔎 Deep-Extracted Web Context (${deepPassages.length})
        </div>
        ${deepPassages
          .map(
            (dp) => `<div style="padding:8px 0;border-top:1px solid var(--border);cursor:pointer;" onclick="openLiveWebsite('${escapeHtml(dp.url)}')">
              <div style="font-weight:600;font-size:14px;">${escapeHtml(dp.title)}</div>
              <div style="font-size:13px;color:var(--muted);line-height:1.48;margin-top:3px;">${escapeHtml(dp.excerpt)}</div>
            </div>`
          )
          .join("")}
      </div>`
    : "";

  const alts = Array.isArray(data.alternatives) ? data.alternatives : [];
  const alternativesHtml = alts.length
    ? `<div style="margin-bottom:20px;">
        <div style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:8px;">
          ⇄ Alternatives &amp; Related
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:8px;">
          ${alts
            .map(
              (a) => `<button type="button" class="ver-btn" title="${escapeHtml(a.description || a.name)}" onclick="runSearch('${escapeHtml(a.name)}')">${escapeHtml(a.name)}</button>`
            )
            .join("")}
        </div>
      </div>`
    : "";

  const externalSkeletonHtml = isLoadingExternal && !webSenses.length ? renderSkeletonCards(3) : "";

  let bodyContent = "";
  if (activeTab === "images") {
    bodyContent = imagesHtml;
  } else if (activeTab === "forums") {
    bodyContent = forumsHtml;
  } else if (activeTab === "news") {
    bodyContent = sensesHtml || (isLoadingExternal ? renderSkeletonCards(3) : `<p style="color:var(--muted);">No live news matched "${escapeHtml(query)}".</p>`);
  } else if (activeTab === "web") {
    bodyContent = `
      <div class="search-layout">
        <div class="search-main">${knowledgeCardHtml}${alternativesHtml}${deepPassagesHtml}${sensesHtml || (isLoadingExternal ? renderSkeletonCards(3) : `<p style="color:var(--muted);">No web knowledge results matched "${escapeHtml(query)}".</p>`)}</div>
        ${items.length || isLoadingExternal ? `<aside class="desktop-aside">${xndSideHtml}</aside>` : ""}
      </div>`;
  } else {
    bodyContent = `
      <div class="search-layout">
        <div class="search-main">
          ${knowledgeCardHtml}
          ${alternativesHtml}
          ${deepPassagesHtml}
          ${sensesHtml}
          ${externalSkeletonHtml}
          ${imagesHtml}
        </div>
        ${items.length || isLoadingExternal ? `<aside class="desktop-aside">${xndSideHtml}</aside>` : ""}
      </div>`;
  }

  primaryContent.innerHTML = `<div class="doc-sheet">
    <div class="doc-header">
      <div class="doc-domain">Xanadu Search · "${escapeHtml(coreTerm)}"${intentLabel}</div>
      <h1 class="doc-title">Results for "${escapeHtml(query)}"</h1>
      <div class="search-tabs">${tabBtns}</div>
    </div>
    ${directBannerHtml}
    ${bodyContent}
  </div>`;
}

async function refreshQuickbar() {
  const quickbar = document.getElementById("quickbar");
  if (!quickbar) return;
}

let stagedSiteFiles = {};

function renderStagedSiteFilesSummary() {
  const el = document.getElementById("site-files-summary");
  if (!el) return;
  const keys = Object.keys(stagedSiteFiles).sort();
  if (!keys.length) {
    el.textContent = "No folder/files staged yet (using inline index.html below).";
    return;
  }
  el.textContent = `Staged ${keys.length} file(s): ${keys.slice(0, 8).join(", ")}${keys.length > 8 ? ` (+${keys.length - 8} more)` : ""}`;
}

async function stageSiteFiles(fileList) {
  if (!fileList || !fileList.length) return;
  const textExt = /\.(html?|css|m?js|ts|json|svg|txt|md|py|xml|csv|yaml|yml)$/i;
  const filesArr = Array.from(fileList);
  for (const f of filesArr) {
    let rel = (f.webkitRelativePath || f.name || "").replace(/\\/g, "/");
    if (f.webkitRelativePath && rel.includes("/")) {
      rel = rel.substring(rel.indexOf("/") + 1);
    }
    rel = rel.replace(/^\/+/, "");
    if (!rel) continue;
    const isText = textExt.test(rel) || (f.type && f.type.startsWith("text/"));
    const content = await new Promise((resolve) => {
      const r = new FileReader();
      r.onload = () => resolve(String(r.result || ""));
      if (isText) r.readAsText(f);
      else r.readAsDataURL(f);
    });
    stagedSiteFiles[rel] = content;
    if (rel === "index.html") {
      const htmlBox = document.getElementById("pub-html");
      if (htmlBox && !htmlBox.value.trim()) htmlBox.value = content;
    }
  }
  renderStagedSiteFilesSummary();
}

document.getElementById("site-folder-input")?.addEventListener("change", (e) => {
  stageSiteFiles(e.target.files);
});
document.getElementById("site-files-input")?.addEventListener("change", (e) => {
  stageSiteFiles(e.target.files);
});
document.getElementById("btn-clear-site-files")?.addEventListener("click", () => {
  stagedSiteFiles = {};
  const f1 = document.getElementById("site-folder-input");
  const f2 = document.getElementById("site-files-input");
  if (f1) f1.value = "";
  if (f2) f2.value = "";
  renderStagedSiteFilesSummary();
});

function prefillPublish(domain = "", mode = "capsule") {
  openCloudflareDashboard(domain, "deploy", mode);
}

function setPublishMode(mode) {
  publishMode = mode;
  document.getElementById("tab-doc").classList.toggle("active", mode === "document");
  document.getElementById("tab-cap").classList.toggle("active", mode === "capsule");
  document.getElementById("doc-fields").classList.toggle("hidden", mode !== "document");
  document.getElementById("cap-fields").classList.toggle("hidden", mode !== "capsule");
  if (mode === "capsule" && !document.getElementById("pub-html").value.trim()) {
    document.getElementById("pub-html").value =
      `<!DOCTYPE html><html><body style="font-family:Georgia,serif;background:#faf7f0;padding:24px;">\n<h1>My .xnd App</h1>\n<button onclick="ping()">Ping Backend</button>\n<pre id="out"></pre>\n<script>\nasync function ping(){\n  const d = prompt('Domain?', 'myapp.xnd');\n  const r = await fetch('/api/app/' + d + '/ping', {method:'POST', body:'{}'});\n  document.getElementById('out').textContent = JSON.stringify(await r.json());\n}\n</script></body></html>`;
    document.getElementById("pub-backend").value =
      `def handle(action, payload, state):\n    hits = state.get("hits", 0) + 1\n    state["hits"] = hits\n    return {"ok": True, "hits": hits}, state`;
  }
}

document.getElementById("tab-doc").addEventListener("click", () => setPublishMode("document"));
document.getElementById("tab-cap").addEventListener("click", () => setPublishMode("capsule"));

document.getElementById("btn-upload-asset").addEventListener("click", async () => {
  const input = document.getElementById("asset-file");
  const file = input.files && input.files[0];
  if (!file) {
    alert("Choose an image or media file first.");
    return;
  }
  const reader = new FileReader();
  reader.onload = async () => {
    const b64 = String(reader.result).split(",")[1] || "";
    const res = await fetch("/api/assets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: file.name,
        mime_type: file.type || "application/octet-stream",
        data_b64: b64,
      }),
    });
    const d = await res.json();
    if (!res.ok) {
      alert(d.detail || "Upload failed");
      return;
    }
    const htmlBox = document.getElementById("pub-html");
    const tag = file.type.startsWith("image/")
      ? `\n<img src="${d.url}" alt="${escapeHtml(file.name)}" style="max-width:100%;" />`
      : `\n<a href="${d.url}">${escapeHtml(file.name)}</a>`;
    htmlBox.value += tag;
  };
  reader.readAsDataURL(file);
});

omniboxForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const val = omniboxInput.value.trim();
  if (!val) return;
  const low = val.toLowerCase();
  const xndHost = normalizeXndDomain(val, false);
  if (low.startsWith("xnd://") || xndHost.endsWith(".xnd")) {
    openDomain(xndHost || val);
  } else if (val.includes(".") && !val.includes(" ")) {
    openLiveWebsite(val);
  } else {
    runSearch(val);
  }
});

const omniboxClearBtn = document.getElementById("btn-omnibox-clear");
function syncOmniboxClearBtn() {
  if (!omniboxClearBtn || !omniboxInput) return;
  omniboxClearBtn.classList.toggle("hidden", !omniboxInput.value);
}
omniboxInput?.addEventListener("input", syncOmniboxClearBtn);
omniboxInput?.addEventListener("focus", syncOmniboxClearBtn);
omniboxClearBtn?.addEventListener("click", () => {
  if (!omniboxInput) return;
  omniboxInput.value = "";
  syncOmniboxClearBtn();
  omniboxInput.focus();
});

const mobileDrawer = document.getElementById("mobile-drawer");
const mobileBackdrop = document.getElementById("mobile-drawer-backdrop");
function setMobileDrawer(open) {
  mobileDrawer?.classList.toggle("hidden", !open);
  mobileBackdrop?.classList.toggle("hidden", !open);
}
document.getElementById("btn-mobile-menu")?.addEventListener("click", () => setMobileDrawer(true));
document.getElementById("btn-mobile-drawer-close")?.addEventListener("click", () => setMobileDrawer(false));
mobileBackdrop?.addEventListener("click", () => setMobileDrawer(false));
document.querySelectorAll("[data-proxy-btn]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const targetId = btn.getAttribute("data-proxy-btn");
    setMobileDrawer(false);
    if (targetId) document.getElementById(targetId)?.click();
  });
});

document.getElementById("btn-home").addEventListener("click", () => openDomain("home.xnd"));
document.getElementById("btn-bookmark").addEventListener("click", toggleCurrentBookmark);
document.getElementById("btn-registry")?.addEventListener("click", () => openCloudflareDashboard("", "overview", "capsule"));
document.getElementById("btn-library").addEventListener("click", () => openLibraryView(""));
document.getElementById("btn-graph-view").addEventListener("click", openGraphView);
document.getElementById("btn-close-split").addEventListener("click", closeSplit);
document.getElementById("btn-publish-modal").addEventListener("click", () => openCloudflareDashboard("", "deploy", "capsule"));
document.getElementById("btn-close-modal").addEventListener("click", () =>
  publishModal.classList.add("hidden")
);

document.getElementById("publish-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const domain = document.getElementById("pub-domain").value.trim().toLowerCase();
  const title = document.getElementById("pub-title").value.trim();
  const privkey_hex = (document.getElementById("pub-key")?.value || "").trim();

  let res;
  if (publishMode === "capsule") {
    const html = document.getElementById("pub-html").value;
    const backend_py = document.getElementById("pub-backend").value;
    res = await fetch("/api/publish_capsule", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, title, html, files: stagedSiteFiles, backend_py, privkey_hex }),
    });
  } else {
    const content = document.getElementById("pub-content").value;
    const private_space = Boolean(document.getElementById("pub-e2ee-toggle")?.checked);
    const allowed_pubkeys = document.getElementById("pub-e2ee-keys")?.value || "";
    res = await fetch("/api/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, title, content, privkey_hex, private_space, allowed_pubkeys }),
    });
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Publish failed" }));
    alert(err.detail || "Publish failed");
    return;
  }
  const pubData = await res.json().catch(() => ({}));
  publishModal.classList.add("hidden");
  const targetDomain = pubData.domain || domain;
  if (pubData.privkey_hex) {
    showCreatedKeyModal(targetDomain, pubData.privkey_hex);
  } else {
    openDomain(targetDomain);
  }
});

const createdKeyModal = document.getElementById("created-key-modal");
let pendingCreatedDomain = "";
let pendingCreatedPrivkey = "";

function showCreatedKeyModal(domain, privkeyHex) {
  pendingCreatedDomain = domain;
  pendingCreatedPrivkey = privkeyHex;
  const domEl = document.getElementById("created-key-domain");
  const hexEl = document.getElementById("created-key-hex");
  const statusEl = document.getElementById("created-key-status");
  if (domEl) domEl.textContent = domain;
  if (hexEl) hexEl.textContent = privkeyHex;
  if (statusEl) statusEl.textContent = "";
  if (createdKeyModal) createdKeyModal.classList.remove("hidden");
}

function closeCreatedKeyModal() {
  if (createdKeyModal) createdKeyModal.classList.add("hidden");
  if (pendingCreatedDomain) openDomain(pendingCreatedDomain);
}

document.getElementById("btn-close-created-key")?.addEventListener("click", closeCreatedKeyModal);
document.getElementById("btn-done-created-key")?.addEventListener("click", closeCreatedKeyModal);
document.getElementById("btn-copy-created-key")?.addEventListener("click", async () => {
  const statusEl = document.getElementById("created-key-status");
  try {
    await navigator.clipboard.writeText(pendingCreatedPrivkey);
    if (statusEl) statusEl.textContent = "✓ Private key copied to clipboard.";
  } catch (_) {
    if (statusEl) statusEl.textContent = "Select the key text above and copy it manually.";
  }
});
document.getElementById("btn-download-created-key")?.addEventListener("click", () => {
  if (!pendingCreatedDomain) return;
  const a = document.createElement("a");
  a.href = `/api/keys/download/${encodeURIComponent(pendingCreatedDomain)}`;
  a.download = `${pendingCreatedDomain}.key.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  const statusEl = document.getElementById("created-key-status");
  if (statusEl) statusEl.textContent = `Downloading ${pendingCreatedDomain}.key.json...`;
});

// Web-to-.xnd Archiver Modal
const archiveModal = document.getElementById("archive-modal");
const archiveStatus = document.getElementById("archive-status");
document.getElementById("btn-archive-modal").addEventListener("click", () =>
  archiveModal.classList.remove("hidden")
);
document.getElementById("btn-close-archive").addEventListener("click", () =>
  archiveModal.classList.add("hidden")
);
document.getElementById("archive-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  archiveStatus.textContent = "Fetching & snapshotting URL...";
  const url = document.getElementById("arch-url").value.trim();
  const domain = document.getElementById("arch-domain").value.trim().toLowerCase();
  const r = await fetch("/api/archive_url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, domain }),
  });
  const d = await r.json();
  if (!r.ok) {
    archiveStatus.textContent = "Error: " + (d.detail || "Archive failed");
    return;
  }
  archiveModal.classList.add("hidden");
  openDomain(d.domain);
});

// Key Export / Import Modal
const keysModal = document.getElementById("keys-modal");
const keyStatus = document.getElementById("key-status");
document.getElementById("btn-keys-modal").addEventListener("click", () =>
  keysModal.classList.remove("hidden")
);
document.getElementById("btn-close-keys").addEventListener("click", () =>
  keysModal.classList.add("hidden")
);
document.getElementById("btn-export-current-key").addEventListener("click", async () => {
  if (!currentDoc) return;
  const r = await fetch(`/api/keys/export/${encodeURIComponent(currentDoc.domain)}`);
  const d = await r.json();
  document.getElementById("key-export-out").textContent = JSON.stringify(d, null, 2);
});
document.getElementById("key-import-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const domain = document.getElementById("imp-domain").value.trim().toLowerCase();
  const privkey_hex = document.getElementById("imp-privkey").value.trim();
  const r = await fetch("/api/keys/import", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, privkey_hex }),
  });
  const d = await r.json();
  keyStatus.textContent = r.ok ? `Imported key for ${d.domain}` : `Error: ${d.detail}`;
});

document.getElementById("btn-sync-key-export")?.addEventListener("click", async () => {
  const passphrase = (document.getElementById("sync-key-pass")?.value || "").trim();
  const tokEl = document.getElementById("sync-key-token");
  const copyBtn = document.getElementById("btn-sync-key-copy");
  const r = await fetch("/api/keys/sync-export", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ passphrase }),
  });
  const d = await r.json();
  if (r.ok && d.token) {
    if (tokEl) tokEl.value = d.token;
    if (copyBtn) copyBtn.style.display = "inline-block";
    keyStatus.textContent = `Exported ${d.count} encrypted domain key(s). Paste into your other device with the same passphrase.`;
  } else {
    keyStatus.textContent = `Error: ${d.detail || "Export failed"}`;
  }
});

document.getElementById("btn-sync-key-copy")?.addEventListener("click", async () => {
  const tok = (document.getElementById("sync-key-token")?.value || "").trim();
  if (tok && navigator.clipboard) {
    await navigator.clipboard.writeText(tok);
    keyStatus.textContent = "Encrypted XNDKEY1 token copied to clipboard.";
  }
});

document.getElementById("btn-sync-key-import")?.addEventListener("click", async () => {
  const passphrase = (document.getElementById("sync-key-pass")?.value || "").trim();
  const token = (document.getElementById("sync-key-token")?.value || "").trim();
  const r = await fetch("/api/keys/sync-import", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, passphrase }),
  });
  const d = await r.json();
  keyStatus.textContent = r.ok ? `Imported ${d.imported} domain key(s) from encrypted sync token!` : `Error: ${d.detail || "Import failed"}`;
});

// P2P Sync & Auto-Gossip Modal
const syncModal = document.getElementById("sync-modal");
const syncStatus = document.getElementById("sync-status");
const syncPeersList = document.getElementById("sync-peers-list");
const syncModerationList = document.getElementById("sync-moderation-list");

async function refreshSyncModal() {
  const [pr, mr, lr, gr, sr] = await Promise.all([
    fetch("/api/peers"),
    fetch("/api/moderation"),
    fetch("/api/lan/peers"),
    fetch("/api/gateway/status").catch(() => null),
    fetch("/api/seeds").catch(() => null),
  ]);
  if (sr && sr.ok) {
    const sd = await sr.json().catch(() => null);
    const seedsEl = document.getElementById("sync-seeds-list");
    if (sd && seedsEl) {
      const seeds = sd.seeds || [];
      const selfNote = sd.self_seed_active ? "This node is acting as an active Always-On Seed & DHT relay." : "Add an always-on community seed node for NAT/offline reachability.";
      seedsEl.innerHTML = `<div style="margin-bottom:4px;">${escapeHtml(selfNote)}</div>` +
        (seeds.length
          ? seeds.map((s) => `<div style="font-family:var(--font-mono);font-size:11.5px;padding:2px 0;">• ${escapeHtml(s.label || "Community Seed")}</div>`).join("")
          : "");
    }
  }
  if (gr && gr.ok) {
    const gs = await gr.json().catch(() => null);
    const gwSt = document.getElementById("sync-gateway-status");
    const gwBtn = document.getElementById("btn-toggle-gateway");
    if (gs && gwSt && gwBtn) {
      gwBtn.dataset.enabled = gs.share_gateway ? "1" : "0";
      gwBtn.textContent = gs.share_gateway ? "Share Internet: ON" : "Share Internet: OFF";
      if (gs.has_wan) {
        gwSt.textContent = gs.share_gateway
          ? "Online — sharing web, search & news with offline LAN peers."
          : "Online — internet sharing paused.";
      } else if (gs.active_gateway) {
        gwSt.textContent = `Offline — browsing via ${gs.active_gateway.label || "LAN Peer"}.`;
      } else {
        gwSt.textContent = "Offline — no online LAN peer sharing internet yet.";
      }
    }
  }
  if (lr && lr.ok) {
    const ld = await lr.json();
    const lanEl = document.getElementById("sync-lan-list");
    if (lanEl) {
      const lp = ld.peers || [];
      lanEl.innerHTML = lp.length
        ? lp
            .map(
              (p) => `<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding:4px 0;border-bottom:1px solid rgba(128,128,128,0.12);">
                <span style="font-family:var(--font-mono);"><span style="color:#22c55e;">●</span> ${escapeHtml(p.label || "LAN Peer")}</span>
                <button type="button" class="btn-tool" style="padding:2px 8px;font-size:11px;" onclick="pullPeerUrl('${escapeHtml(p.url)}')">Sync</button>
              </div>`
            )
            .join("")
        : `<div style="color:var(--faded-ink);">No nearby Xanadu nodes on this Wi-Fi yet (open Xanadu on Desktop &amp; Android on the same Wi-Fi).</div>`;
    }
  }
  if (pr.ok) {
    const d = await pr.json();
    const g = d.gossip || {};
    const subCount = (d.peers || []).filter((p) => p.subscribed).length;
    syncStatus.textContent =
      `${d.peers.length} peers (${subCount} subscribed for auto-gossip) | Interval: ${g.interval_sec || 15}s | Imported: ${g.total_imported || 0}`;
    if (syncPeersList) {
      syncPeersList.innerHTML = (d.peers || []).length
        ? (d.peers || [])
            .map(
              (p) => `<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 0;border-bottom:1px solid rgba(128,128,128,0.15);">
                <span style="font-family:var(--font-mono);word-break:break-all;">${escapeHtml(p.label || "Peer")}</span>
                <span style="display:flex;gap:6px;flex-shrink:0;">
                  <button type="button" class="btn-tool" style="padding:3px 8px;font-size:11px;" onclick="pullPeerUrl('${escapeHtml(p.url)}')">Sync</button>
                  <button type="button" class="btn-tool" style="padding:3px 8px;font-size:11px;" onclick="togglePeerSubscribe('${escapeHtml(p.url)}', ${!p.subscribed})">${p.subscribed ? "✓ Subscribed" : "+ Subscribe"}</button>
                </span>
              </div>`
            )
            .join("")
        : `<div style="color:var(--faded-ink);">No peers discovered yet.</div>`;
    }
  }
  if (mr.ok && syncModerationList) {
    const m = await mr.json();
    const fp = m.followed_pubkeys || [];
    syncModerationList.innerHTML = `<div style="font-weight:600;margin-bottom:4px;">Followed Pubkeys (${fp.length})</div>`;
  }
}

async function addCommunitySeed() {
  const inp = document.getElementById("seed-node-url");
  const url = (inp?.value || "").trim();
  if (!url) return;
  const r = await fetch("/api/seeds", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, label: "Community Seed" }),
  });
  if (r.ok && inp) {
    inp.value = "";
    await refreshSyncModal();
  }
}

async function syncLanMeshNow() {
  syncStatus.textContent = "Syncing over Offline LAN / Wi-Fi Mesh...";
  try {
    const r = await fetch("/api/lan/sync", { method: "POST" });
    const d = await r.json();
    syncStatus.textContent = r.ok
      ? `LAN Mesh synced ${d.synced_peers || 0} peer(s): ${d.imported_versions || 0} .xnd versions, ${d.imported_forum_posts || 0} forum.xnd posts, ${d.imported_wiki_shards || 0} wikipedia.xnd shards.`
      : "Error: " + (d.detail || "LAN sync failed");
  } catch (e) {
    syncStatus.textContent = "Error: " + e.message;
  }
  refreshSyncModal();
}

async function pullPeerUrl(url) {
  syncStatus.textContent = "Syncing...";
  const r = await fetch("/api/peers/pull", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  const d = await r.json();
  syncStatus.textContent = r.ok
    ? `Synced ${d.imported_versions} verified versions (rejected: ${d.rejected}).`
    : "Error: " + (d.detail || "Sync failed");
  refreshSyncModal();
}

async function togglePeerSubscribe(url, subscribed) {
  await fetch("/api/peers/subscribe", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, subscribed }),
  });
  refreshSyncModal();
}

async function toggleFollowPubkey(pubkey_hex) {
  const r = await fetch("/api/moderation/follow", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pubkey_hex }),
  });
  if (r.ok) {
    const d = await r.json();
    const followed = (d.followed_pubkeys || []).includes(pubkey_hex.toLowerCase());
    alert(followed ? "Author followed! Opt-in sync will prioritize this key." : "Author unfollowed.");
  }
}

document.getElementById("btn-sync-modal").addEventListener("click", async () => {
  syncModal.classList.remove("hidden");
  refreshSyncModal();
});
document.getElementById("btn-close-sync").addEventListener("click", () =>
  syncModal.classList.add("hidden")
);
syncModal.addEventListener("click", (e) => {
  if (e.target === syncModal) syncModal.classList.add("hidden");
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !syncModal.classList.contains("hidden")) {
    syncModal.classList.add("hidden");
  }
});
document.getElementById("btn-toggle-gateway")?.addEventListener("click", async () => {
  const btn = document.getElementById("btn-toggle-gateway");
  const nextVal = btn?.dataset.enabled !== "1";
  const r = await fetch("/api/gateway/toggle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ share_gateway: nextVal }),
  });
  if (r.ok) refreshSyncModal();
});
async function joinGlobalP2P() {
  const statusEl = document.getElementById("sync-status");
  const pubInput = document.getElementById("p2p-public-url");
  const public_url = pubInput ? pubInput.value.trim() : "";
  if (statusEl) statusEl.textContent = "Discovering peers via public Nostr relays & PEX...";
  try {
    const r = await fetch("/api/p2p/join", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_url }),
    });
    const d = await r.json();
    if (statusEl) {
      statusEl.textContent = `Global P2P: discovered ${d.discovered} peers, announced to ${d.announced_relays} Nostr relays, synced ${d.synced_peers} peers.`;
    }
  } catch (e) {
    if (statusEl) statusEl.textContent = "Error joining global P2P: " + e;
  }
}

document.getElementById("sync-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = document.getElementById("sync-peer-url").value.trim();
  syncStatus.textContent = "Syncing & verifying Ed25519 signatures...";
  const r = await fetch("/api/peers/pull", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  const d = await r.json();
  if (!r.ok) {
    syncStatus.textContent = "Error: " + (d.detail || "Sync failed");
    return;
  }
  syncStatus.textContent = `Synced ${d.imported_versions} verified versions (rejected: ${d.rejected}). Added to auto-gossip.`;
  refreshQuickbar();
});

// Selection-to-transclude helper (delegated via independent XndTransclusion module)
if (window.XndTransclusion) {
  window.XndTransclusion.attachSelectionHook(
    primaryPane,
    quoteBar,
    quotePreview,
    () => currentDoc,
    (ptr) => { pendingTransclusionPointer = ptr; }
  );
} else {
  primaryPane.addEventListener("mouseup", () => {
    const sel = window.getSelection();
    const txt = sel ? sel.toString() : "";
    if (!currentDoc || currentDoc.kind !== "document" || txt.trim().length < 4) {
      quoteBar.classList.add("hidden");
      return;
    }
    const idx = currentDoc.raw_content.indexOf(txt);
    if (idx === -1) {
      quoteBar.classList.add("hidden");
      return;
    }
    pendingTransclusionPointer = `{{xnd://${currentDoc.domain}@v${currentDoc.version}:${idx}-${idx + txt.length}}}`;
    quotePreview.textContent = `Quote [${idx}:${idx + txt.length}]`;
    quoteBar.classList.remove("hidden");
  });
}

document.getElementById("btn-quote-into").addEventListener("click", () => {
  quoteBar.classList.add("hidden");
  setPublishMode("document");
  document.getElementById("pub-content").value =
    `Quoting ${currentDoc.domain}:\n${pendingTransclusionPointer}\n\nMy notes: `;
  prefillPublish("");
});

secondaryContent.addEventListener("scroll", drawBridgeLine);
window.addEventListener("resize", drawBridgeLine);

document.getElementById("pub-e2ee-toggle")?.addEventListener("change", (e) => {
  const el = document.getElementById("pub-e2ee-keys");
  if (el) el.classList.toggle("hidden", !e.target.checked);
});

async function apiJson(url, opts = {}) {
  const r = await fetch(url, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || `Request failed (${r.status})`);
  return data;
}

async function shareWebLink(domain) {
  try {
    const cfg = await apiJson("/api/config/public-gateway");
    let gwUrl = (cfg.url || window.location.origin).replace(/\/+$/, "");
    if (gwUrl.includes("127.0.0.1") || gwUrl.includes("localhost")) {
      const custom = prompt(
        "Your Public Gateway URL is currently local.\nEnter your public xnd-gateway URL (or keep localhost to preview):",
        gwUrl
      );
      if (custom === null) return;
      const clean = custom.trim().replace(/\/+$/, "");
      if (clean && clean !== gwUrl && (clean.startsWith("http://") || clean.startsWith("https://"))) {
        await apiJson("/api/config/public-gateway", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: clean }),
        });
        gwUrl = clean;
      }
    }
    const shareUrl = `${gwUrl}/site/${encodeURIComponent(domain)}`;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(shareUrl);
    }
    alert(`Shareable Web Link copied!\n\n${shareUrl}\n\nAnyone on WhatsApp, X, Chrome, or Safari can open this link instantly.`);
  } catch (e) {
    alert(e.message || "Failed to generate share link");
  }
}

async function setDomainPetname(domain, currentPetname) {
  const next = prompt(`Local petname for ${domain} (leave blank to clear):`, currentPetname || "");
  if (next === null) return;
  try {
    await apiJson("/api/trust/petname", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: domain, petname: next.trim() }),
    });
    openDomain(domain);
  } catch (e) {
    alert(e.message || "Failed to update petname");
  }
}

async function unlockE2eeSpace(domain) {
  const inp = document.getElementById("e2ee-unlock-key");
  const privkey_hex = inp ? inp.value.trim() : "";
  if (!privkey_hex) return;
  const r = await fetch("/api/e2ee/unlock", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, privkey_hex }),
  });
  const d = await r.json();
  if (!r.ok) {
    alert(d.detail || "Unlock failed");
    return;
  }
  if (currentDoc && currentDoc.domain === domain) {
    currentDoc.raw_content = d.raw_content;
    currentDoc.segments = d.segments;
    currentDoc.decrypted = true;
    currentDoc.allowed_pubkeys = d.allowed_pubkeys || currentDoc.allowed_pubkeys;
    renderDocumentView(currentDoc);
  }
}
const darkMq = window.matchMedia("(prefers-color-scheme: dark)");

function hashHue(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return Math.abs(h) % 360;
}

function applySmartColorEngine(doc) {
  const isDark = darkMq.matches;
  const r = document.documentElement.style;

  if (isDark) {
    r.setProperty("--bg", "#111318");
    r.setProperty("--surface", "#1a1d24");
    r.setProperty("--surface-hover", "#232732");
    r.setProperty("--ink", "#e8eaed");
    r.setProperty("--muted", "#9aa0a6");
    r.setProperty("--badge-emerald", "#81c995");
    r.setProperty("--badge-emerald-bg", "rgba(129, 201, 149, 0.14)");
    r.setProperty("--badge-blue", "#8ab4f8");
    r.setProperty("--badge-blue-bg", "rgba(138, 180, 248, 0.14)");
    r.setProperty("--badge-violet", "#c58af9");
    r.setProperty("--badge-violet-bg", "rgba(197, 138, 249, 0.14)");
  } else {
    r.setProperty("--bg", "#ffffff");
    r.setProperty("--surface", "#f8f9fa");
    r.setProperty("--surface-hover", "#f1f3f4");
    r.setProperty("--ink", "#202124");
    r.setProperty("--muted", "#5f6368");
    r.setProperty("--badge-emerald", "#137333");
    r.setProperty("--badge-emerald-bg", "#e6f4ea");
    r.setProperty("--badge-blue", "#1967d2");
    r.setProperty("--badge-blue-bg", "#e8f0fe");
    r.setProperty("--badge-violet", "#7627bb");
    r.setProperty("--badge-violet-bg", "#f3e8fd");
  }

  if (!doc) return;
  const seed = doc.domain === "home.xnd" ? "google-blue-215" : doc.pubkey || doc.domain;
  const hue = doc.domain === "home.xnd" ? 214 : hashHue(seed);
  const sat = isDark ? 78 : 74;
  const light = isDark ? 64 : 44;
  const accent = `hsl(${hue}, ${sat}%, ${light}%)`;
  const accentSoft = `hsla(${hue}, ${sat}%, ${light}%, ${isDark ? 0.16 : 0.1})`;

  r.setProperty("--accent", accent);
  r.setProperty("--accent-soft", accentSoft);
  r.setProperty("--accent-ink", isDark ? "#111318" : "#ffffff");
}

darkMq.addEventListener("change", () => applySmartColorEngine(currentDoc));
applySmartColorEngine(null);

window.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "t") {
    e.preventDefault();
    createTab("home.xnd", true, true);
  } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "w") {
    e.preventDefault();
    if (activeTabId) closeTab(activeTabId);
  }
});

async function openRegistryView(filter = "") {
  return openCloudflareDashboard("", "overview", "capsule", null, filter);
}

async function openRepoView(domain, version = null) {
  return openCloudflareDashboard(domain, "repo", "capsule", version, "");
}

let cfDeployDraft = { domain: "", title: "", html: "", backend_py: "", content: "", privkey_hex: "" };

async function openCloudflareDashboard(
  selectedDomain = "",
  activeSection = "overview",
  deployMode = "capsule",
  version = null,
  filter = ""
) {
  document.body.classList.remove("in-site-view");
  document.body.classList.remove("in-search-view");
  document.body.classList.add("in-dashboard");
  closeSplit();
  recordNav({ type: "dash", domain: selectedDomain, tab: activeSection, mode: deployMode, version, filter });
  const cleanDom = (selectedDomain || "").trim().toLowerCase();
  if (publishModal) publishModal.classList.add("hidden");

  omniboxInput.value = cleanDom ? `xnd://dashboard/${cleanDom}` : "xnd://dashboard";
  setActiveTabMeta({
    title: cleanDom ? `Dashboard · ${cleanDom}` : "Domain & Repo Dashboard",
    omniboxValue: omniboxInput.value,
    doc: null,
  });

  let auth = { configured: false, unlocked: false, username: "", username_hash: "" };
  try {
    const ar = await fetch("/api/auth/status");
    if (ar.ok) auth = await ar.json();
  } catch (_) {}

  if (!auth.unlocked) {
    const defaultTab = auth.configured ? "login" : "create";
    renderCenteredAuthGate(auth, defaultTab, () =>
      openCloudflareDashboard(selectedDomain, activeSection, deployMode, version, filter)
    );
    return;
  }

  const [res, ghRes, linksRes] = await Promise.all([
    fetch("/api/domains", { cache: "no-store" }),
    fetch("/api/github/status", { cache: "no-store" }).catch(() => null),
    fetch("/api/github/links", { cache: "no-store" }).catch(() => null),
  ]);
  const data = await res.json().catch(() => ({ domains: [] }));
  const ghStatus = ghRes && ghRes.ok ? await ghRes.json().catch(() => ({ connected: false })) : { connected: false };
  const ghLinksData = linksRes && linksRes.ok ? await linksRes.json().catch(() => ({ links: {} })) : { links: {} };
  const ghLinks = ghLinksData.links || {};
  const domains = Array.isArray(data.domains) ? data.domains : [];
  const totalCount = domains.length;
  const sitesCount = domains.filter((d) => d.kind === "capsule").length;
  const docsCount = totalCount - sitesCount;
  const ownedDomains = domains.filter((d) => d.owned_locally);
  const ownedCount = ownedDomains.length;

  let repoDoc = null;
  if (cleanDom && activeSection === "repo") {
    const rUrl = version
      ? `/api/resolve/${encodeURIComponent(cleanDom)}?version=${version}`
      : `/api/resolve/${encodeURIComponent(cleanDom)}`;
    const rRes = await fetch(rUrl);
    if (rRes.ok) repoDoc = await rRes.json();
  }

  let secretTargetDom = "";
  let secretKeys = [];
  let domainKeyInfo = null;
  if (activeSection === "secrets") {
    secretTargetDom = cleanDom || (ownedDomains[0]?.name || "");
    if (secretTargetDom) {
      const [secRes, keyRes] = await Promise.all([
        fetch(`/api/secrets/${encodeURIComponent(secretTargetDom)}`).catch(() => null),
        fetch(`/api/keys/export/${encodeURIComponent(secretTargetDom)}`).catch(() => null),
      ]);
      if (secRes && secRes.ok) {
        const sData = await secRes.json().catch(() => ({}));
        secretKeys = Array.isArray(sData.keys) ? sData.keys : [];
      }
      if (keyRes && keyRes.ok) {
        domainKeyInfo = await keyRes.json().catch(() => null);
      }
    }
  }

  let mainHtml = "";

  if (activeSection === "deploy") {
    const dDomain = cleanDom || cfDeployDraft.domain || "";
    mainHtml = `
      <div class="cf-card">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:14px;">
          <div>
            <h2 style="margin:0;font-size:18px;">GitHub Hosting (Public &amp; Private Repos)</h2>
            <p style="margin:4px 0 0;font-size:12px;color:var(--muted);">One-way GitHub hosting: deploy your <code>.xnd</code> website from any public or private repository and automatically update whenever you push new commits.</p>
          </div>
          ${
            ghStatus.connected
              ? `<div style="display:flex;align-items:center;gap:8px;">
                  <span class="badge badge-emerald">GitHub: @${escapeHtml(ghStatus.username || "")}</span>
                  <button type="button" class="ver-btn" id="cf-gh-disconnect-btn">Disconnect</button>
                </div>`
              : `<span class="badge">Not Connected</span>`
          }
        </div>

        ${
          !ghStatus.connected
            ? `
        <div class="cf-form-grid">
          <div style="font-size:13px;color:var(--muted);">
            Sign in with GitHub in one click—no tokens to copy or paste. Grants read &amp; write access to your public and private repositories.
          </div>
          <div id="cf-gh-device-box" style="display:none;padding:14px;border:1px solid var(--accent);border-radius:10px;background:var(--bg);">
            <div style="font-size:12px;color:var(--muted);margin-bottom:8px;">Step 1: Copy this one-time code. Step 2: Tap <strong>Copy &amp; Open GitHub</strong> and paste it.</div>
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
              <code id="cf-gh-device-code" style="font-size:22px;font-weight:800;letter-spacing:0.14em;padding:6px 12px;border-radius:8px;background:rgba(37,99,235,0.1);color:var(--accent);user-select:all;"></code>
              <button type="button" id="cf-gh-copy-code-btn" class="ver-btn">Copy Code</button>
              <a id="cf-gh-device-link" href="https://github.com/login/device" target="_blank" rel="noopener" class="btn-accent" style="text-decoration:none;">Copy &amp; Open GitHub →</a>
            </div>
          </div>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:4px;flex-wrap:wrap;">
            <span id="cf-gh-connect-status" style="font-family:var(--font-mono);font-size:12px;color:var(--muted);"></span>
            <button type="button" id="cf-gh-device-btn" class="btn-accent">Sign in with GitHub →</button>
          </div>
        </div>`
            : `
        <form id="cf-gh-deploy-form" class="cf-form-grid">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <label>
              GitHub Repository (Public &amp; Private)
              <select id="cf-gh-repo" style="width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);">
                <option value="">Loading repositories...</option>
              </select>
            </label>
            <label>
              Target .xnd Domain
              <input id="cf-gh-domain" type="text" value="${escapeHtml(dDomain)}" placeholder="e.g. mysite.xnd" required />
            </label>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <label>
              Branch (auto-detected)
              <input id="cf-gh-branch" type="text" value="" placeholder="Auto (repo default branch)" />
            </label>
            <label>
              Subfolder (auto-detected)
              <input id="cf-gh-subdir" type="text" value="" placeholder="Auto (root, dist, build, out...)" />
            </label>
          </div>
          <label>
            Domain Private Key (optional — auto-used if owned in your dashboard)
            <input id="cf-gh-key" type="password" value="${escapeHtml(cfDeployDraft.privkey_hex || "")}" placeholder="Leave blank for new domain or owned domain" />
          </label>
          <div id="cf-gh-deploy-status" style="font-family:var(--font-mono);font-size:12px;color:var(--muted);"></div>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-top:4px;">
            <button type="button" id="cf-gh-action-btn" class="ver-btn" title="Install GitHub Action for Vite/Next/React repos">Enable Auto-Build Action</button>
            <button type="submit" class="btn-accent">Host from GitHub →</button>
          </div>
        </form>`
        }
      </div>`;
  } else if (activeSection === "repo" && repoDoc) {
    const isSite = repoDoc.kind === "capsule";
    const files = isSite
      ? [...(Array.isArray(repoDoc.files) ? repoDoc.files : ["index.html"]), ...(repoDoc.has_backend ? ["backend.py"] : [])]
      : ["content.txt"];
    const versions = Array.isArray(repoDoc.versions)
      ? repoDoc.versions
      : [{ version_num: repoDoc.version || 1, title: repoDoc.title }];

    const filesHtml = files
      .map(
        (f) =>
          `<button class="ver-btn" style="text-align:left;width:100%;font-family:var(--font-mono);font-size:12px;" onclick="viewRepoFile('${escapeHtml(repoDoc.domain)}', '${escapeHtml(f)}', ${repoDoc.version})">${escapeHtml(f)}</button>`
      )
      .join("");
    const commitsHtml = versions
      .slice()
      .reverse()
      .map(
        (v) =>
          `<button class="ver-btn ${v.version_num === repoDoc.version ? "active" : ""}" onclick="openCloudflareDashboard('${escapeHtml(repoDoc.domain)}', 'repo', 'capsule', ${v.version_num})">v${v.version_num} · ${escapeHtml(v.title || repoDoc.domain)}</button>`
      )
      .join("");

    mainHtml = `
      ${
        !auth.configured
          ? `
      <div class="cf-card" style="border-left:3px solid var(--accent);">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
          <div>
            <strong style="font-size:14px;">Protect Your Private Dashboard</strong>
            <div style="font-size:12px;color:var(--muted);margin-top:2px;">Set a local account &amp; password to encrypt your domain keys with AES-256-GCM.</div>
          </div>
          <form id="cf-setup-form" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
            <input id="cf-setup-user" type="text" placeholder="Username" required style="padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font-size:12px;" />
            <input id="cf-setup-pass" type="password" placeholder="Password (4+ chars)" required style="padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font-size:12px;" />
            <button type="submit" class="btn-accent" style="padding:7px 12px;font-size:12px;">Create Vault</button>
          </form>
        </div>
      </div>`
          : ""
      }
      <div class="cf-card">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
          <div>
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
              <span class="cf-status-dot"></span>
              <h2 style="margin:0;font-family:var(--font-mono);font-size:20px;">${escapeHtml(repoDoc.domain)}</h2>
              <span class="badge ${isSite ? "badge-blue" : ""}">${isSite ? "SITE / APP" : "DOCUMENT"}</span>
              ${repoDoc.verified ? `<span class="badge badge-emerald">✓ Ed25519 Signed</span>` : ""}
              ${ghLinks[repoDoc.domain] ? `<span class="badge">🔒 Locked: ${escapeHtml(ghLinks[repoDoc.domain].repo)}</span>` : ""}
            </div>
            <div style="font-size:13px;color:var(--muted);margin-top:4px;">${escapeHtml(repoDoc.title || repoDoc.domain)}</div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button class="btn-accent" onclick="openDomain('${escapeHtml(repoDoc.domain)}')">${isSite ? "Launch Live Site" : "Open Document"}</button>
            <button class="ver-btn" onclick="pushUpdateFromRepo('${escapeHtml(repoDoc.domain)}', '${escapeHtml(repoDoc.title || "")}', '${isSite ? "capsule" : "document"}')">Push Update</button>
            <button class="ver-btn" onclick="openCloudflareDashboard('${escapeHtml(repoDoc.domain)}', 'secrets')">Secrets &amp; Keys</button>
            ${ghLinks[repoDoc.domain] ? `<button class="ver-btn" style="color:#dc2626;border-color:rgba(220,38,38,0.4);" onclick="detachLockedDomain('${escapeHtml(repoDoc.domain)}')">Detach Repo</button>` : ""}
          </div>
        </div>
      </div>

      <div class="cf-card">
        <div style="display:grid;grid-template-columns:220px 1fr;gap:14px;">
          <div style="display:flex;flex-direction:column;gap:6px;">
            <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--muted);">Repository Files</div>
            ${filesHtml}
          </div>
          <div>
            <div id="repo-file-header" style="font-family:var(--font-mono);font-size:12px;color:var(--muted);margin-bottom:6px;">Select a file to inspect</div>
            <pre id="repo-file-viewer" style="margin:0;padding:12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);overflow:auto;max-height:500px;font-family:var(--font-mono);font-size:12px;white-space:pre-wrap;"></pre>
          </div>
        </div>
      </div>`;
  } else if (activeSection === "claim") {
    const preDom = cleanDom || "";
    mainHtml = `
      <div class="cf-card">
        <div style="margin-bottom:14px;">
          <h2 style="margin:0;font-size:18px;">Claim Your Website</h2>
          <p style="margin:4px 0 0;font-size:12px;color:var(--muted);">Enter your .xnd website name and its Ed25519 private key to add it to your dashboard in seconds.</p>
        </div>
        <form id="cf-claim-form" class="cf-form-grid">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <label>
              Website Name
              <input id="cf-claim-domain" type="text" value="${escapeHtml(preDom)}" placeholder="e.g. mysite.xnd" required />
            </label>
            <label>
              Private Key (Ed25519 Hex)
              <input id="cf-claim-key" type="password" placeholder="Paste your 64-char private key hex" required />
            </label>
          </div>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:4px;flex-wrap:wrap;">
            <span id="cf-claim-status" style="font-family:var(--font-mono);font-size:12px;color:var(--muted);"></span>
            <button type="submit" class="btn-accent">Claim Website →</button>
          </div>
        </form>
      </div>`;
  } else if (activeSection === "register") {
    const preDom = cleanDom || "";
    mainHtml = `
      <div class="cf-card">
        <div style="margin-bottom:14px;">
          <h2 style="margin:0;font-size:18px;">Register a New .xnd Domain</h2>
          <p style="margin:4px 0 0;font-size:12px;color:var(--muted);">Enter a website name below. We check availability and generate your Ed25519 keys ready to download.</p>
        </div>
        <form id="cf-reg-form" class="cf-form-grid">
          <label>
            Website Name
            <input id="cf-reg-domain" type="text" value="${escapeHtml(preDom)}" placeholder="e.g. mybrand.xnd" required />
          </label>
          <div id="cf-reg-status" style="font-family:var(--font-mono);font-size:12px;"></div>
          <div style="display:flex;align-items:center;justify-content:flex-end;gap:10px;margin-top:4px;">
            <button type="submit" class="btn-accent">Check &amp; Register Domain</button>
          </div>
        </form>
        <div id="cf-reg-keys-box" style="display:none;margin-top:16px;padding:14px;border:1px solid #86efac;border-radius:10px;background:rgba(16,185,129,0.08);"></div>
      </div>`;
  } else if (activeSection === "hypertext") {
    const targetDom = cleanDom || (ownedDomains[0]?.name || "");
    const existingDoc = targetDom ? domains.find((d) => d.name === targetDom) : null;
    const domainOpts = ownedDomains
      .map((d) => `<option value="${escapeHtml(d.name)}" ${d.name === targetDom ? "selected" : ""}>${escapeHtml(d.name)}</option>`)
      .join("");
    mainHtml = `
      <div class="cf-card">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px;">
          <div>
            <h2 style="margin:0;font-size:18px;">Instant Hypertext Update (News / Message / Post)</h2>
            <p style="margin:4px 0 0;font-size:12px;color:var(--muted);">Type any message, news update, or transclusion hypertext (<code>{{xnd://...}}</code>) and publish to your <code>.xnd</code> domain in milliseconds — no website files or GitHub repo needed.</p>
          </div>
          ${targetDom ? `<button type="button" class="ver-btn" onclick="openDomain('${escapeHtml(targetDom)}')">View Current Page</button>` : ""}
        </div>
        <form id="cf-hypertext-form" class="cf-form-grid">
          <label>
            Target .xnd Domain
            ${ownedDomains.length
              ? `<div style="display:flex;gap:8px;flex-wrap:wrap;">
                  <select id="cf-ht-domain-select" style="flex:1;min-width:180px;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font-family:var(--font-mono);" onchange="document.getElementById('cf-ht-domain').value=this.value">
                    ${domainOpts}
                  </select>
                  <input id="cf-ht-domain" type="text" value="${escapeHtml(targetDom)}" placeholder="mybrand.xnd" required style="flex:1;min-width:180px;" />
                </div>`
              : `<input id="cf-ht-domain" type="text" value="${escapeHtml(targetDom)}" placeholder="mybrand.xnd" required />`}
          </label>
          <label>
            Headline / Title
            <input id="cf-ht-title" type="text" value="${escapeHtml((existingDoc && existingDoc.title) || "")}" placeholder="Breaking Update, Status, or Post Title" />
          </label>
          <label>
            Hypertext Message / News Content
            <textarea id="cf-ht-content" rows="9" placeholder="Write news, announcements, notes, or link/quote any .xnd page with {{xnd://domain.xnd}}..." required></textarea>
          </label>
          <label>
            Ed25519 Private Key (optional if already claimed on this node)
            <input id="cf-ht-privkey" type="password" placeholder="Leave blank to sign with your unlocked node key" />
          </label>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:6px;">
            <span id="cf-ht-status" style="font-family:var(--font-mono);font-size:12px;color:var(--muted);"></span>
            <button type="submit" class="btn-accent">Publish Hypertext Now</button>
          </div>
        </form>
      </div>`;
  } else if (activeSection === "secrets") {
    const keySvg = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>`;
    const rotateSvg = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>`;
    const trashSvg = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>`;

    const domainOptions = ownedDomains
      .map((d) => `<option value="${escapeHtml(d.name)}" ${d.name === secretTargetDom ? "selected" : ""}>${escapeHtml(d.name)}</option>`)
      .join("");

    const secretRowsHtml = secretKeys.length
      ? secretKeys
          .map(
            (k) => `
          <div class="cf-domain-row" style="padding:10px 12px;">
            <div style="display:flex;align-items:center;gap:8px;min-width:0;">
              ${keySvg}
              <strong style="font-family:var(--font-mono);font-size:13px;">${escapeHtml(k)}</strong>
              <span class="badge badge-emerald">Node-Local</span>
            </div>
            <div style="display:flex;gap:8px;flex-shrink:0;">
              <button type="button" class="ver-btn cf-secret-rotate-btn" data-key="${escapeHtml(k)}">${rotateSvg} Rotate / Change</button>
              <button type="button" class="ver-btn cf-secret-del-btn" data-key="${escapeHtml(k)}" style="color:#dc2626;border-color:rgba(220,38,38,0.4);">${trashSvg} Delete</button>
            </div>
          </div>`
          )
          .join("")
      : `<p style="color:var(--muted);margin:6px 0;font-size:13px;">No node-local API secrets configured for <strong>${escapeHtml(secretTargetDom || "this domain")}</strong> yet.</p>`;

    mainHtml = !secretTargetDom
      ? `
        <div class="cf-card">
          <h2 style="margin:0 0 6px;font-size:18px;">${keySvg} Secrets &amp; Domain Keys</h2>
          <p style="margin:0 0 12px;font-size:13px;color:var(--muted);">Claim or register a <code>.xnd</code> domain first to manage its node-local API secrets and Ed25519 signing keys.</p>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button class="ver-btn" onclick="openCloudflareDashboard('', 'claim')">Claim Website</button>
            <button class="btn-accent" onclick="openCloudflareDashboard('', 'register')">Register Domain</button>
          </div>
        </div>`
      : `
        <div class="cf-card" style="margin-bottom:14px;">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
            <div>
              <h2 style="margin:0;font-size:18px;">${keySvg} Secrets &amp; Keys</h2>
              <p style="margin:4px 0 0;font-size:12px;color:var(--muted);">Manage node-local backend secrets (Supabase, REST APIs) and rotate or change your Ed25519 domain keypair.</p>
            </div>
            ${
              ownedDomains.length > 0
                ? `<label style="display:flex;align-items:center;gap:8px;font-size:12px;font-weight:600;">
                    Domain
                    <select id="cf-secrets-domain-select" style="padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font-family:var(--font-mono);font-size:12px;">
                      ${domainOptions}
                    </select>
                  </label>`
                : ""
            }
          </div>
        </div>

        <div class="cf-card" style="margin-bottom:14px;">
          <div style="margin-bottom:12px;">
            <h3 style="margin:0;font-size:16px;">Node-Local API &amp; Database Secrets</h3>
            <p style="margin:4px 0 0;font-size:12px;color:var(--muted);">Stored locally in <code>0600</code> permissions — never bundled into <code>.xnd</code> files or synced to Nostr. Read them in <code>backend.py</code> via <code>secrets.get("KEY_NAME")</code>.</p>
          </div>
          <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:14px;">
            ${secretRowsHtml}
          </div>
          <form id="cf-secret-add-form" class="cf-form-grid" style="border-top:1px solid var(--line);padding-top:12px;">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
              <label>
                Secret Key Name
                <input id="cf-secret-key-input" type="text" placeholder="e.g. SUPABASE_SERVICE_ROLE_KEY" pattern="[A-Za-z_][A-Za-z0-9_]{0,63}" required />
              </label>
              <label>
                Secret Value
                <input id="cf-secret-val-input" type="password" placeholder="Paste secret value to store or rotate" required />
              </label>
            </div>
            <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:4px;">
              <span id="cf-secret-status" style="font-family:var(--font-mono);font-size:12px;color:var(--muted);"></span>
              <button type="submit" class="btn-accent">Save / Rotate Secret</button>
            </div>
          </form>
        </div>

        <div class="cf-card">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px;">
            <div>
              <h3 style="margin:0;font-size:16px;">Ed25519 Domain Signing Key</h3>
              <p style="margin:4px 0 0;font-size:12px;color:var(--muted);">Export your current key, rotate to a freshly generated Ed25519 keypair, or replace it with an existing private key.</p>
            </div>
            ${
              domainKeyInfo
                ? `<a class="ver-btn" href="/api/keys/download/${encodeURIComponent(secretTargetDom)}" download="${escapeHtml(secretTargetDom)}.key.json" style="text-decoration:none;">Download Key JSON</a>`
                : ""
            }
          </div>
          ${
            domainKeyInfo
              ? `
            <div style="font-family:var(--font-mono);font-size:12px;word-break:break-all;background:var(--bg);padding:10px 12px;border:1px solid var(--line);border-radius:8px;margin-bottom:12px;">
              <div><strong>Public Key:</strong> ${escapeHtml(domainKeyInfo.pubkey_hex || "")}</div>
            </div>
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
              <button type="button" id="cf-key-rotate-btn" class="btn-accent">${rotateSvg} Rotate to New Ed25519 Keypair</button>
              <span id="cf-key-rotate-status" style="font-family:var(--font-mono);font-size:12px;color:var(--muted);"></span>
            </div>
            <div id="cf-key-rotated-box" style="display:none;margin-bottom:14px;padding:12px;border:1px solid #86efac;border-radius:8px;background:rgba(16,185,129,0.08);"></div>
            <form id="cf-key-change-form" class="cf-form-grid" style="border-top:1px solid var(--line);padding-top:12px;">
              <label>
                Change to Custom Ed25519 Private Key (Hex)
                <input id="cf-key-change-input" type="password" placeholder="Paste 64-char Ed25519 private key hex" required />
              </label>
              <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:4px;">
                <span id="cf-key-change-status" style="font-family:var(--font-mono);font-size:12px;color:var(--muted);"></span>
                <button type="submit" class="ver-btn">Change Domain Key</button>
              </div>
            </form>`
              : `<p style="color:var(--muted);font-size:13px;margin:0;">This node does not hold the Ed25519 private key for <strong>${escapeHtml(secretTargetDom)}</strong>. Claim it first to manage or rotate its signing key.</p>`
          }
        </div>`;
  } else {
    const renderDomainRow = (d) => {
      const isSite = d.kind === "capsule";
      const badge = isSite ? `<span class="badge badge-blue">SITE / APP</span>` : `<span class="badge">DOC</span>`;
      const own = d.owned_locally ? `<span class="badge badge-emerald">Claimed</span>` : `<span class="badge">Network</span>`;
      const ghLock = ghLinks[d.name] ? `<span class="badge">🔒 ${escapeHtml(ghLinks[d.name].repo)}</span>` : "";
      return `
        <div class="cf-domain-row">
          <div style="min-width:0;">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
              <span class="cf-status-dot"></span>
              <strong style="font-family:var(--font-mono);font-size:14px;cursor:pointer;color:var(--accent);" onclick="openCloudflareDashboard('${escapeHtml(d.name)}', 'repo')">${escapeHtml(d.name)}</strong>
              ${badge}
              ${own}
              ${ghLock}
            </div>
            <div style="font-size:13px;color:var(--muted);margin-top:4px;">${escapeHtml(d.title || d.name)}</div>
          </div>
          <div style="display:flex;gap:8px;flex-shrink:0;flex-wrap:wrap;">
            ${d.owned_locally ? `<button class="ver-btn" onclick="openCloudflareDashboard('${escapeHtml(d.name)}', 'hypertext')">Post Hypertext</button>` : ""}
            <button class="ver-btn" onclick="openCloudflareDashboard('${escapeHtml(d.name)}', 'deploy', 'capsule')">Host / GitHub</button>
            <button class="ver-btn" onclick="openCloudflareDashboard('${escapeHtml(d.name)}', 'repo')">Repo</button>
            ${d.owned_locally ? `<button class="ver-btn" onclick="openCloudflareDashboard('${escapeHtml(d.name)}', 'secrets')">Secrets &amp; Keys</button>` : ""}
            <button class="btn-accent" onclick="openDomain('${escapeHtml(d.name)}')">${isSite ? "Launch Site" : "Open"}</button>
          </div>
        </div>`;
    };

    const claimedDomains = domains.filter((d) => d.owned_locally);
    const claimedRowsHtml = claimedDomains.map(renderDomainRow).join("");

    if (activeSection === "claimed") {
      mainHtml = `
        <div class="cf-card">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px;">
            <div>
              <h2 style="margin:0;font-size:18px;">Claimed Websites by You (${claimedDomains.length})</h2>
              <p style="margin:4px 0 0;font-size:12px;color:var(--muted);">Websites registered or claimed with your Ed25519 private keys on this node.</p>
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <button class="ver-btn" onclick="openCloudflareDashboard('', 'claim')">+ Claim Website</button>
              <button class="btn-accent" onclick="openCloudflareDashboard('', 'register')">+ Register Domain</button>
            </div>
          </div>
          <div style="display:flex;flex-direction:column;gap:10px;">
            ${claimedRowsHtml || `<p style="color:var(--muted);margin:6px 0;">You haven't claimed or registered any websites yet. Click <strong>Claim Website</strong> or <strong>Register Domain</strong> above.</p>`}
          </div>
        </div>`;
    } else {
      const q = filter.trim().toLowerCase();
      const filtered = q
        ? domains.filter((d) => d.name.toLowerCase().includes(q) || (d.title || "").toLowerCase().includes(q))
        : domains;
      const rowsHtml = filtered.map(renderDomainRow).join("");

      mainHtml = `
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin-bottom:14px;">
          <div class="cf-card" style="margin:0;">
            <h3 style="margin:0 0 6px;font-size:15px;">Claim Your Website</h3>
            <p style="margin:0 0 12px;font-size:12px;color:var(--muted);">Already have a domain &amp; private key? Claim it into your dashboard in seconds.</p>
            <button class="btn-accent" onclick="openCloudflareDashboard('', 'claim')">Claim Your Website</button>
          </div>
          <div class="cf-card" style="margin:0;">
            <h3 style="margin:0 0 6px;font-size:15px;">Register Domain</h3>
            <p style="margin:0 0 12px;font-size:12px;color:var(--muted);">Check if a .xnd website name is available and download your new Ed25519 keys.</p>
            <button class="btn-accent" onclick="openCloudflareDashboard('', 'register')">Register Domain</button>
          </div>
        </div>
        <div class="cf-card" style="margin-bottom:14px;">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px;">
            <div>
              <h2 style="margin:0;font-size:18px;">Claimed Websites by You (${claimedDomains.length})</h2>
              <p style="margin:4px 0 0;font-size:12px;color:var(--muted);">Your sovereignly owned .xnd websites ready to host via GitHub or launch.</p>
            </div>
            <button class="ver-btn" onclick="openCloudflareDashboard('', 'claimed')">View All Claimed →</button>
          </div>
          <div style="display:flex;flex-direction:column;gap:10px;">
            ${claimedRowsHtml || `<p style="color:var(--muted);margin:6px 0;">No claimed websites yet. Claim one with its private key or register a new domain above.</p>`}
          </div>
        </div>
        <div class="cf-card">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px;">
            <div>
              <h2 style="margin:0;font-size:18px;">All Network .xnd Domains &amp; Repositories</h2>
              <p style="margin:4px 0 0;font-size:12px;color:var(--muted);">Browse all discovered domains, inspect repositories, or launch live sites.</p>
            </div>
            <button class="btn-accent" onclick="openCloudflareDashboard('', 'deploy', 'capsule')">+ Host with GitHub</button>
          </div>
          <input id="cf-domain-filter" type="text" value="${escapeHtml(filter)}" placeholder="Search domains or titles..." style="width:100%;box-sizing:border-box;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);margin-bottom:12px;" />
          <div style="display:flex;flex-direction:column;gap:10px;">
            ${rowsHtml || `<p style="color:var(--muted);margin:6px 0;">No matching .xnd domains yet.</p>`}
          </div>
        </div>`;
    }
  }

  const userHashLabel = auth.username_hash || auth.username || "guest@xnd";

  primaryContent.innerHTML = `
    <div class="cf-shell">
      <div class="dash-topbar">
        <button type="button" id="dash-go-home-btn" class="dash-nav-btn">← Go Home</button>
        <div>${auth.configured ? `<button type="button" id="cf-lock-btn" class="dash-nav-btn dash-logout-btn">Log Out</button>` : ""}</div>
      </div>

      <div class="gd-hero">
        <div class="gd-hero-inner">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
            <div>
              <div style="font-family:var(--font-mono);font-size:11px;font-weight:700;letter-spacing:0.06em;opacity:0.9;">USER HASH: ${escapeHtml(userHashLabel)}</div>
              <h1 style="margin:4px 0 0;font-size:24px;">Welcome to XND New Internet</h1>
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
              <button class="ver-btn" style="background:rgba(255,255,255,0.16);color:#fff;border-color:rgba(255,255,255,0.32);" onclick="openCloudflareDashboard('${escapeHtml(cleanDom || ownedDomains[0]?.name || "")}', 'hypertext')">Post Hypertext</button>
              <button class="ver-btn" style="background:rgba(255,255,255,0.16);color:#fff;border-color:rgba(255,255,255,0.32);" onclick="openCloudflareDashboard('', 'claim')">Claim Website</button>
              <button class="ver-btn" style="background:#fff;color:#0f172a;border-color:#fff;font-weight:700;" onclick="openCloudflareDashboard('', 'register')">Register Domain</button>
            </div>
          </div>
          <form id="gd-check-form" class="gd-search-bar">
            <input id="gd-check-input" type="text" placeholder="Search domain availability (e.g. mybrand.xnd)..." />
            <button type="submit" class="gd-search-btn">Check Availability</button>
          </form>
          <div id="gd-check-result" style="margin-top:10px;font-family:var(--font-mono);font-size:12px;"></div>
        </div>
      </div>

      <div class="cf-body">
        <div class="cf-stats">
          <div class="cf-stat-card"><div class="cf-stat-label">Registered Domains</div><div class="cf-stat-value">${totalCount}</div></div>
          <div class="cf-stat-card"><div class="cf-stat-label">Sites &amp; Apps</div><div class="cf-stat-value">${sitesCount}</div></div>
          <div class="cf-stat-card"><div class="cf-stat-label">Documents</div><div class="cf-stat-value">${docsCount}</div></div>
          <div class="cf-stat-card"><div class="cf-stat-label">Owned Locally</div><div class="cf-stat-value">${ownedCount}</div></div>
        </div>

        <div class="cf-layout">
          <aside class="cf-sidebar">
            <div class="cf-nav-section">Dashboard</div>
            <button class="cf-nav-btn ${activeSection === "overview" ? "active" : ""}" onclick="openCloudflareDashboard('', 'overview')">My Dashboard <span>${totalCount}</span></button>
            <button class="cf-nav-btn ${activeSection === "claimed" ? "active" : ""}" onclick="openCloudflareDashboard('', 'claimed')">Claimed Websites <span>${ownedCount}</span></button>
            <button class="cf-nav-btn ${activeSection === "claim" ? "active" : ""}" onclick="openCloudflareDashboard('', 'claim')">Claim Your Website</button>
            <button class="cf-nav-btn ${activeSection === "register" ? "active" : ""}" onclick="openCloudflareDashboard('', 'register')">Register Domain</button>
            <button class="cf-nav-btn ${activeSection === "hypertext" && !cleanDom ? "active" : ""}" onclick="openCloudflareDashboard('', 'hypertext')">Post Hypertext</button>
            <button class="cf-nav-btn ${activeSection === "deploy" && !cleanDom ? "active" : ""}" onclick="openCloudflareDashboard('', 'deploy', 'capsule')">Host / Push Site</button>
            <button class="cf-nav-btn ${activeSection === "secrets" && !cleanDom ? "active" : ""}" onclick="openCloudflareDashboard('${escapeHtml(ownedDomains[0]?.name || "")}', 'secrets')">Secrets &amp; Keys</button>
            ${
              cleanDom
                ? `
            <div class="cf-nav-section">${escapeHtml(cleanDom)}</div>
            <button class="cf-nav-btn ${activeSection === "repo" ? "active" : ""}" onclick="openCloudflareDashboard('${escapeHtml(cleanDom)}', 'repo')">Files &amp; Commits</button>
            <button class="cf-nav-btn ${activeSection === "hypertext" ? "active" : ""}" onclick="openCloudflareDashboard('${escapeHtml(cleanDom)}', 'hypertext')">Post Hypertext</button>
            <button class="cf-nav-btn ${activeSection === "deploy" ? "active" : ""}" onclick="openCloudflareDashboard('${escapeHtml(cleanDom)}', 'deploy', '${escapeHtml(deployMode)}')">Push Update</button>
            <button class="cf-nav-btn ${activeSection === "secrets" ? "active" : ""}" onclick="openCloudflareDashboard('${escapeHtml(cleanDom)}', 'secrets')">Secrets &amp; Keys</button>
            <button class="cf-nav-btn" onclick="openDomain('${escapeHtml(cleanDom)}')">Launch Site ↗</button>`
                : ""
            }
          </aside>
          <section class="cf-main">
            ${mainHtml}
          </section>
        </div>
      </div>
    </div>`;

  if (activeSection === "hypertext") {
    document.getElementById("cf-hypertext-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const status = document.getElementById("cf-ht-status");
      const dom = normalizeXndDomain(document.getElementById("cf-ht-domain")?.value || "", true);
      const title = (document.getElementById("cf-ht-title")?.value || "").trim() || dom;
      const content = document.getElementById("cf-ht-content")?.value || "";
      const privkey_hex = (document.getElementById("cf-ht-privkey")?.value || "").trim();
      if (!dom || !content.trim()) return;
      if (!isValidXndDomain(dom)) {
        if (status) {
          status.style.color = "#ef4444";
          status.textContent = "Invalid .xnd domain.";
        }
        return;
      }
      if (status) {
        status.style.color = "var(--muted)";
        status.textContent = "Signing & indexing hypertext...";
      }
      const t0 = performance.now();
      const r = await fetch("/api/publish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: dom, title, content, privkey_hex }),
      });
      const elapsed = Math.max(1, Math.round(performance.now() - t0));
      const d = await r.json().catch(() => ({ detail: "Publish failed" }));
      if (!r.ok) {
        if (status) {
          status.style.color = "#ef4444";
          status.textContent = d.detail || "Publish failed";
        }
        return;
      }
      if (status) {
        status.style.color = "#10b981";
        status.innerHTML = `Published v${escapeHtml(String(d.version_num || d.version || 1))} to <strong>${escapeHtml(d.domain || dom)}</strong> in ${elapsed} ms · <a href="#" onclick="event.preventDefault();openDomain('${escapeHtml(d.domain || dom)}')">Open Live Page</a>`;
      }
    });
  }

  if (activeSection === "claim") {
    document.getElementById("cf-claim-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const status = document.getElementById("cf-claim-status");
      let dom = normalizeXndDomain(document.getElementById("cf-claim-domain")?.value || "", true);
      const privkeyHex = (document.getElementById("cf-claim-key")?.value || "").trim();
      if (!dom || !privkeyHex) return;
      if (!isValidXndDomain(dom)) {
        if (status) {
          status.style.color = "#ef4444";
          status.textContent = "✕ Invalid .xnd domain. Only letters, numbers, '-' and '.' between labels are allowed.";
        }
        return;
      }
      if (status) status.textContent = "Verifying key & claiming website...";
      const r = await fetch("/api/keys/import", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: dom, privkey_hex: privkeyHex }),
      });
      const d = await r.json().catch(() => ({ detail: "Claim failed" }));
      if (!r.ok) {
        if (status) {
          status.style.color = "#ef4444";
          status.textContent = `✕ ${d.detail || "Invalid domain or private key"}`;
        }
        return;
      }
      if (status) {
        status.style.color = "#10b981";
        status.textContent = `✓ Claimed ${d.domain}! Adding to your dashboard...`;
      }
      setTimeout(() => openCloudflareDashboard(d.domain, "overview"), 450);
    });
  } else if (activeSection === "register") {
    document.getElementById("cf-reg-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const status = document.getElementById("cf-reg-status");
      const keysBox = document.getElementById("cf-reg-keys-box");
      let dom = normalizeXndDomain(document.getElementById("cf-reg-domain")?.value || "", true);
      if (!dom) return;
      if (keysBox) keysBox.style.display = "none";
      if (!isValidXndDomain(dom)) {
        if (status) {
          status.style.color = "#ef4444";
          status.textContent = "✕ Invalid .xnd domain. Only letters, numbers, '-' and '.' between labels are allowed (e.g. domain-name.xnd or sub.domain.xnd).";
        }
        return;
      }
      if (status) {
        status.style.color = "var(--muted)";
        status.textContent = `Checking availability for ${dom}...`;
      }
      const r = await fetch("/api/domain/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: dom }),
      });
      const d = await r.json().catch(() => ({ detail: "Registration failed" }));
      if (!r.ok) {
        if (status) {
          status.style.color = "#ef4444";
          status.innerHTML =
            r.status === 409
              ? `⚠️ <strong>Name taken — claim another</strong> (${escapeHtml(dom)} is already registered). <button type="button" class="ver-btn" style="margin-left:8px;" onclick="openCloudflareDashboard('${escapeHtml(dom)}', 'claim')">Claim with Key →</button>`
              : `✕ ${escapeHtml(d.detail || "Registration failed")}`;
        }
        return;
      }
      if (status) {
        status.style.color = "#10b981";
        status.textContent = `✓ ${d.domain} is yours! Your Ed25519 keys are ready below.`;
      }
      if (keysBox) {
        keysBox.style.display = "block";
        keysBox.innerHTML = `
          <div style="font-weight:700;margin-bottom:6px;">🔑 Keys Ready for ${escapeHtml(d.domain)}</div>
          <div style="font-family:var(--font-mono);font-size:11px;word-break:break-all;margin-bottom:10px;background:var(--bg);padding:8px 10px;border-radius:8px;border:1px solid var(--line);">
            <div><strong>Domain:</strong> ${escapeHtml(d.domain)}</div>
            <div><strong>Public Key:</strong> ${escapeHtml(d.pubkey_hex || "")}</div>
            <div><strong>Private Key:</strong> ${escapeHtml(d.privkey_hex || "")}</div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button type="button" class="btn-accent" id="cf-reg-dl-btn">Download Key JSON</button>
            <button type="button" class="ver-btn" id="cf-reg-copy-btn">Copy Private Key</button>
            <button type="button" class="ver-btn" onclick="openCloudflareDashboard('${escapeHtml(d.domain)}', 'deploy', 'capsule')">Host Website Files →</button>
          </div>`;
        document.getElementById("cf-reg-dl-btn")?.addEventListener("click", () => {
          const payload = JSON.stringify({ domain: d.domain, pubkey_hex: d.pubkey_hex || "", privkey_hex: d.privkey_hex || "" }, null, 2);
          const blob = new Blob([payload], { type: "application/json" });
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = `${d.domain}.key.json`;
          document.body.appendChild(a);
          a.click();
          a.remove();
        });
        document.getElementById("cf-reg-copy-btn")?.addEventListener("click", async () => {
          try { await navigator.clipboard.writeText(d.privkey_hex || ""); } catch (_) {}
          const btn = document.getElementById("cf-reg-copy-btn");
          if (btn) btn.textContent = "Copied!";
        });
      }
      if (d.privkey_hex) showCreatedKeyModal(d.domain, d.privkey_hex);
    });
  } else if (activeSection === "overview") {
    document.getElementById("cf-domain-filter")?.addEventListener("input", (e) => {
      openCloudflareDashboard("", "overview", "capsule", null, e.target.value);
    });
    document.getElementById("cf-setup-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const username = document.getElementById("cf-setup-user")?.value.trim() || "";
      const password = document.getElementById("cf-setup-pass")?.value || "";
      const sr = await fetch("/api/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!sr.ok) {
        const err = await sr.json().catch(() => ({ detail: "Setup failed" }));
        alert(err.detail || "Setup failed");
        return;
      }
      openCloudflareDashboard(selectedDomain, activeSection, deployMode, version, filter);
    });
  } else if (activeSection === "secrets" && secretTargetDom) {
    document.getElementById("cf-secrets-domain-select")?.addEventListener("change", (e) => {
      openCloudflareDashboard(e.target.value, "secrets");
    });

    document.querySelectorAll(".cf-secret-rotate-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const keyName = btn.getAttribute("data-key") || "";
        const keyInput = document.getElementById("cf-secret-key-input");
        const valInput = document.getElementById("cf-secret-val-input");
        const st = document.getElementById("cf-secret-status");
        if (keyInput) keyInput.value = keyName;
        if (st) {
          st.style.color = "var(--muted)";
          st.textContent = `Enter new value for ${keyName} and click Save / Rotate Secret.`;
        }
        valInput?.focus();
      });
    });

    document.querySelectorAll(".cf-secret-del-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const keyName = btn.getAttribute("data-key") || "";
        if (!keyName || !confirm(`Delete secret '${keyName}' from ${secretTargetDom}?`)) return;
        const r = await fetch(`/api/secrets/${encodeURIComponent(secretTargetDom)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ key: keyName, delete: true }),
        });
        if (!r.ok) {
          const err = await r.json().catch(() => ({ detail: "Delete failed" }));
          alert(err.detail || "Delete failed");
          return;
        }
        openCloudflareDashboard(secretTargetDom, "secrets");
      });
    });

    document.getElementById("cf-secret-add-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const keyName = (document.getElementById("cf-secret-key-input")?.value || "").trim();
      const val = document.getElementById("cf-secret-val-input")?.value || "";
      const st = document.getElementById("cf-secret-status");
      if (!keyName || !val) return;
      if (st) {
        st.style.color = "var(--muted)";
        st.textContent = `Saving ${keyName}...`;
      }
      const r = await fetch(`/api/secrets/${encodeURIComponent(secretTargetDom)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: keyName, value: val }),
      });
      const d = await r.json().catch(() => ({ detail: "Save failed" }));
      if (!r.ok) {
        if (st) {
          st.style.color = "#ef4444";
          st.textContent = d.detail || "Failed to save secret";
        }
        return;
      }
      openCloudflareDashboard(secretTargetDom, "secrets");
    });

    document.getElementById("cf-key-rotate-btn")?.addEventListener("click", async () => {
      if (!confirm(`Rotate Ed25519 signing key for ${secretTargetDom}? Download the new key backup immediately after rotating.`)) return;
      const st = document.getElementById("cf-key-rotate-status");
      const box = document.getElementById("cf-key-rotated-box");
      if (st) {
        st.style.color = "var(--muted)";
        st.textContent = "Generating new Ed25519 keypair...";
      }
      const r = await fetch(`/api/keys/rotate/${encodeURIComponent(secretTargetDom)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const d = await r.json().catch(() => ({ detail: "Key rotation failed" }));
      if (!r.ok) {
        if (st) {
          st.style.color = "#ef4444";
          st.textContent = d.detail || "Key rotation failed";
        }
        return;
      }
      if (st) {
        st.style.color = "#10b981";
        st.textContent = "Rotated! Download your new key backup below.";
      }
      if (box) {
        box.style.display = "block";
        box.innerHTML = `
          <div style="font-weight:700;margin-bottom:6px;">New Ed25519 Keypair for ${escapeHtml(d.domain)}</div>
          <div style="font-family:var(--font-mono);font-size:11px;word-break:break-all;background:var(--bg);padding:8px 10px;border-radius:8px;border:1px solid var(--line);margin-bottom:10px;">
            <div><strong>Public Key:</strong> ${escapeHtml(d.pubkey_hex || "")}</div>
            <div><strong>Private Key:</strong> ${escapeHtml(d.privkey_hex || "")}</div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <a class="btn-accent" href="/api/keys/download/${encodeURIComponent(d.domain)}" download="${escapeHtml(d.domain)}.key.json" style="text-decoration:none;">Download New Key JSON</a>
            <button type="button" class="ver-btn" id="cf-rotated-copy-btn">Copy Private Key</button>
          </div>`;
        document.getElementById("cf-rotated-copy-btn")?.addEventListener("click", async () => {
          try { await navigator.clipboard.writeText(d.privkey_hex || ""); } catch (_) {}
          const cb = document.getElementById("cf-rotated-copy-btn");
          if (cb) cb.textContent = "Copied!";
        });
      }
    });

    document.getElementById("cf-key-change-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const newPriv = (document.getElementById("cf-key-change-input")?.value || "").trim();
      const st = document.getElementById("cf-key-change-status");
      if (!newPriv) return;
      if (st) {
        st.style.color = "var(--muted)";
        st.textContent = "Updating domain key...";
      }
      const r = await fetch(`/api/keys/rotate/${encodeURIComponent(secretTargetDom)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ new_privkey_hex: newPriv }),
      });
      const d = await r.json().catch(() => ({ detail: "Key update failed" }));
      if (!r.ok) {
        if (st) {
          st.style.color = "#ef4444";
          st.textContent = d.detail || "Failed to change domain key";
        }
        return;
      }
      openCloudflareDashboard(secretTargetDom, "secrets");
    });
  }

  document.getElementById("gd-check-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const rawName = (document.getElementById("gd-check-input")?.value || "").trim();
    const resEl = document.getElementById("gd-check-result");
    if (!rawName || !resEl) return;
    resEl.textContent = "Checking network...";
    const cr = await fetch(`/api/domain/check?name=${encodeURIComponent(rawName)}`);
    const cd = await cr.json().catch(() => ({ available: false, reason: "Check failed" }));
    if (cd.available) {
      resEl.innerHTML = `✓ <strong>${escapeHtml(cd.domain)}</strong> is available! <button type="button" class="gd-search-btn" style="padding:5px 12px;font-size:12px;margin-left:8px;" onclick="openCloudflareDashboard('${escapeHtml(cd.domain)}', 'register')">Register Now →</button>`;
    } else {
      resEl.innerHTML = `✕ <strong>${escapeHtml(cd.domain || rawName)}</strong> — ${escapeHtml(cd.reason || "Unavailable")} <button type="button" class="ver-btn" style="padding:4px 10px;font-size:11px;margin-left:8px;background:rgba(255,255,255,0.16);color:#fff;border-color:rgba(255,255,255,0.32);" onclick="openCloudflareDashboard('${escapeHtml(cd.domain || rawName)}', 'claim')">Claim with Key →</button>`;
    }
  });

  document.getElementById("dash-go-home-btn")?.addEventListener("click", () => {
    document.body.classList.remove("in-dashboard");
    openDomain("home.xnd");
  });

  document.getElementById("cf-lock-btn")?.addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    openCloudflareDashboard(selectedDomain, activeSection, deployMode, version, filter);
  });

  if (activeSection === "repo" && repoDoc) {
    const firstFile =
      repoDoc.kind === "capsule"
        ? (Array.isArray(repoDoc.files) && repoDoc.files.length ? repoDoc.files[0] : "index.html")
        : "content.txt";
    viewRepoFile(repoDoc.domain, firstFile, repoDoc.version);
  }

  document.getElementById("cf-gh-detach-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const privkey_hex = (document.getElementById("cf-gh-detach-key")?.value || "").trim();
    const st = document.getElementById("cf-gh-detach-status");
    if (!cleanDom || !privkey_hex) return;
    if (st) { st.style.color = "var(--muted)"; st.textContent = "Verifying Domain Private Key..."; }
    const r = await fetch("/api/github/detach", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: cleanDom, privkey_hex }),
    });
    const d = await r.json().catch(() => ({ detail: "Detach failed" }));
    if (!r.ok) {
      if (st) { st.style.color = "#ef4444"; st.textContent = `✕ ${d.detail || "Detach failed"}`; }
      return;
    }
    openCloudflareDashboard(cleanDom, "deploy");
  });

  if (activeSection === "deploy") {
    let ghPollTimer = null;
    document.getElementById("cf-gh-device-btn")?.addEventListener("click", async () => {
      const btn = document.getElementById("cf-gh-device-btn");
      const box = document.getElementById("cf-gh-device-box");
      const codeEl = document.getElementById("cf-gh-device-code");
      const linkEl = document.getElementById("cf-gh-device-link");
      const st = document.getElementById("cf-gh-connect-status");
      if (btn) btn.disabled = true;
      if (st) {
        st.style.color = "var(--muted)";
        st.textContent = "Starting GitHub Device Login...";
      }
      const r = await fetch("/api/github/device/start", { method: "POST" });
      const d = await r.json().catch(() => ({ detail: "Could not start GitHub login" }));
      if (!r.ok || !d.device_code) {
        if (btn) btn.disabled = false;
        if (st) {
          st.style.color = "#ef4444";
          st.textContent = `✕ ${d.detail || "Could not start GitHub login"}`;
        }
        return;
      }
      if (codeEl) codeEl.textContent = d.user_code || "";
      if (linkEl) linkEl.href = d.verification_uri || "https://github.com/login/device";
      if (box) box.style.display = "block";
      const copyUserCode = async () => {
        const val = d.user_code || "";
        try {
          await navigator.clipboard.writeText(val);
        } catch (_) {
          const ta = document.createElement("textarea");
          ta.value = val;
          ta.style.position = "fixed";
          ta.style.opacity = "0";
          document.body.appendChild(ta);
          ta.select();
          try { document.execCommand("copy"); } catch (_) {}
          ta.remove();
        }
      };
      await copyUserCode();
      document.getElementById("cf-gh-copy-code-btn")?.addEventListener("click", async () => {
        await copyUserCode();
        const cb = document.getElementById("cf-gh-copy-code-btn");
        if (cb) cb.textContent = "Copied!";
      });
      linkEl?.addEventListener("click", () => { copyUserCode(); });
      if (st) {
        st.style.color = "var(--muted)";
        st.textContent = "Copy the code above, tap 'Copy & Open GitHub', and approve access.";
      }

      let intervalMs = Math.max(5, Number(d.interval || 5)) * 1000;
      const pollOnce = async () => {
        if (!document.getElementById("cf-gh-device-box")) return;
        const pr = await fetch("/api/github/device/poll", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ device_code: d.device_code }),
        });
        const pd = await pr.json().catch(() => ({ detail: "Poll failed" }));
        if (!pr.ok) {
          if (btn) btn.disabled = false;
          if (st) {
            st.style.color = "#ef4444";
            st.textContent = `✕ ${pd.detail || "GitHub login cancelled or expired"}`;
          }
          return;
        }
        if (pd.status === "authorized") {
          openCloudflareDashboard(selectedDomain, "deploy");
          return;
        }
        if (pd.status === "slow_down" && pd.interval) {
          intervalMs = Math.max(10, Number(pd.interval)) * 1000;
        }
        ghPollTimer = setTimeout(pollOnce, intervalMs);
      };
      if (ghPollTimer) clearTimeout(ghPollTimer);
      ghPollTimer = setTimeout(pollOnce, intervalMs);
      const onFocusRefresh = async () => {
        if (!document.getElementById("cf-gh-device-box")) return;
        const sr = await fetch("/api/github/status", { cache: "no-store" }).catch(() => null);
        const sd = sr && sr.ok ? await sr.json().catch(() => null) : null;
        if (sd && sd.connected) {
          window.removeEventListener("focus", onFocusRefresh);
          openCloudflareDashboard(selectedDomain, "deploy");
        }
      };
      window.addEventListener("focus", onFocusRefresh);
    });

    document.getElementById("cf-gh-disconnect-btn")?.addEventListener("click", async () => {
      await fetch("/api/github/disconnect", { method: "POST" });
      openCloudflareDashboard(selectedDomain, "deploy");
    });

    const repoSel = document.getElementById("cf-gh-repo");
    const branchInput = document.getElementById("cf-gh-branch");
    if (repoSel && ghStatus.connected) {
      fetch("/api/github/repos")
        .then((r) => r.json())
        .then((d) => {
          const repos = Array.isArray(d.repos) ? d.repos : [];
          if (!repos.length) {
            repoSel.innerHTML = `<option value="">No repositories found</option>`;
            return;
          }
          const repoToDom = {};
          Object.entries(ghLinks).forEach(([domName, info]) => {
            if (info && info.repo) repoToDom[info.repo.toLowerCase()] = domName;
          });
          repoSel.innerHTML = repos
            .map((rp) => {
              const boundDom = repoToDom[(rp.full_name || "").toLowerCase()] || "";
              const lockTag = boundDom ? ` — 🔒 ${boundDom}` : "";
              return `<option value="${escapeHtml(rp.full_name)}" data-branch="${escapeHtml(rp.default_branch || "main")}">${escapeHtml(rp.full_name)} ${rp.private ? "(Private)" : "(Public)"}${escapeHtml(lockTag)}</option>`;
            })
            .join("");
          const firstOpt = repoSel.options[0];
          if (firstOpt && branchInput) branchInput.value = firstOpt.dataset.branch || "";
        })
        .catch(() => {
          repoSel.innerHTML = `<option value="">Failed to load repositories</option>`;
        });
      repoSel.addEventListener("change", () => {
        const opt = repoSel.options[repoSel.selectedIndex];
        if (opt && branchInput) branchInput.value = opt.dataset.branch || "main";
      });
    }

    document.getElementById("cf-gh-deploy-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const repo = document.getElementById("cf-gh-repo")?.value || "";
      const domain = normalizeXndDomain(document.getElementById("cf-gh-domain")?.value || "", true);
      const branch = (document.getElementById("cf-gh-branch")?.value || "").trim();
      const subdir = (document.getElementById("cf-gh-subdir")?.value || "").trim();
      const privkey_hex = (document.getElementById("cf-gh-key")?.value || "").trim();
      const st = document.getElementById("cf-gh-deploy-status");
      if (!repo) {
        if (st) { st.style.color = "#ef4444"; st.textContent = "✕ Please select a GitHub repository."; }
        return;
      }
      if (!isValidXndDomain(domain)) {
        if (st) { st.style.color = "#ef4444"; st.textContent = "✕ Invalid .xnd domain."; }
        return;
      }
      if (st) { st.style.color = "var(--muted)"; st.textContent = `Fetching ${repo} & signing Ed25519 capsule...`; }
      const r = await fetch("/api/github/deploy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo, branch, subdir, domain, privkey_hex }),
      });
      const rawTxt = await r.text();
      let d = {};
      try { d = JSON.parse(rawTxt); } catch (_) { d = { detail: rawTxt || "GitHub deploy failed" }; }
      if (!r.ok) {
        const msg = d.detail || "Deploy failed";
        if (st) { st.style.color = "#ef4444"; st.textContent = `✕ ${msg.replace("NEEDS_BUILD_ACTION: ", "")}`; }
        const actBtn = document.getElementById("cf-gh-action-btn");
        if (actBtn && msg.includes("NEEDS_BUILD_ACTION")) {
          actBtn.style.borderColor = "#f59e0b";
          actBtn.style.color = "#d97706";
          actBtn.style.fontWeight = "700";
        }
        return;
      }
      if (d.privkey_hex) {
        showCreatedKeyModal(d.domain || domain, d.privkey_hex);
      } else {
        openDomain(d.domain || domain);
      }
    });

    document.getElementById("cf-gh-action-btn")?.addEventListener("click", async () => {
      const repo = document.getElementById("cf-gh-repo")?.value || "";
      const branch = (document.getElementById("cf-gh-branch")?.value || "").trim();
      const st = document.getElementById("cf-gh-deploy-status");
      if (!repo) {
        if (st) { st.style.color = "#ef4444"; st.textContent = "✕ Select a repository first."; }
        return;
      }
      if (st) { st.style.color = "var(--muted)"; st.textContent = `Installing Xanadu Auto-Build Action on ${repo}...`; }
      const r = await fetch("/api/github/setup-action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo, branch }),
      });
      const d = await r.json().catch(() => ({ detail: "Workflow setup failed" }));
      if (!r.ok) {
        if (st) { st.style.color = "#ef4444"; st.textContent = `✕ ${d.detail || "Workflow setup failed"}`; }
        return;
      }
      if (st) {
        st.style.color = "#10b981";
        st.textContent = `✓ Auto-Build Action installed on ${d.repo} (${d.branch}) & building now! Tap 'Host from GitHub →' in ~30s once dist/ is ready.`;
      }
    });
  }
}

async function detachLockedDomain(domain) {
  const privkey_hex = (window.prompt(`Enter the 64-char Domain Private Key for ${domain} to detach its GitHub repo:`) || "").trim();
  if (!privkey_hex) return;
  const r = await fetch("/api/github/detach", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, privkey_hex }),
  });
  const d = await r.json().catch(() => ({ detail: "Detach failed" }));
  if (!r.ok) {
    alert(d.detail || "Detach failed");
    return;
  }
  openCloudflareDashboard(domain, "deploy");
}

async function viewRepoFile(domain, path, version) {
  const hdr = document.getElementById("repo-file-header");
  const viewer = document.getElementById("repo-file-viewer");
  if (hdr) hdr.textContent = `${domain} / ${path} (v${version})`;
  if (viewer) viewer.textContent = "Loading...";
  const res = await fetch(`/api/repo/${encodeURIComponent(domain)}/file?path=${encodeURIComponent(path)}&version=${version}`);
  if (!res.ok) {
    if (viewer) viewer.textContent = "Could not load file.";
    return;
  }
  const d = await res.json();
  if (viewer) viewer.textContent = d.content || "";
}

function renderCenteredAuthGate(auth, activeCol, onUnlocked) {
  const isCreate = activeCol !== "login";
  primaryContent.innerHTML = `
    <div class="auth-center-wrap" style="flex-direction:column;align-items:center;">
      <div style="width:100%;max-width:860px;margin-bottom:12px;display:flex;justify-content:flex-start;">
        <button type="button" class="ver-btn" id="auth-gate-back">← Back</button>
      </div>
      <div class="auth-split-card">
        <div class="auth-col ${isCreate ? "is-active" : "is-dimmed"}" id="auth-col-create" style="cursor:${isCreate ? "default" : "pointer"};">
          <div style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:0.06em;">STEP 1 · NEW VAULT</div>
          <h2 style="margin:6px 0 4px;font-size:20px;">Create Private Vault</h2>
          <p style="margin:0 0 14px;font-size:12px;color:var(--muted);">Generates a lowercase hashed username &amp; Ed25519 login hex key encrypted on your device.</p>
          ${
            auth.configured
              ? `<p style="font-size:12px;color:var(--muted);padding:10px;border:1px solid var(--line);border-radius:8px;">A vault (<code>${escapeHtml(auth.username_hash || auth.username)}</code>) already exists on this node. Use <strong>Sign In</strong> →</p>`
              : `<form id="gate-create-form" class="cf-form-grid">
                  <label>Username <input id="gate-create-user" type="text" placeholder="e.g. alice" required /></label>
                  <label>Password <input id="gate-create-pass" type="password" placeholder="4+ characters" required style="width:100%;box-sizing:border-box;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);" /></label>
                  <div id="gate-create-err" style="font-size:12px;color:#d93025;"></div>
                  <button type="submit" class="btn-accent">Create Vault &amp; Generate Keys</button>
                </form>`
          }
        </div>

        <div class="auth-col ${!isCreate ? "is-active" : "is-dimmed"}" id="auth-col-login" style="cursor:${!isCreate ? "default" : "pointer"};">
          <div style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:0.06em;">SIGN IN · ED25519 VERIFIED</div>
          <h2 style="margin:6px 0 4px;font-size:20px;">Sign In to Dashboard</h2>
          <p style="margin:0 0 14px;font-size:12px;color:var(--muted);">Strictly verifies your hashed username, password, and Ed25519 account key.</p>
          <form id="gate-login-form" class="cf-form-grid">
            <label>Hashed Username <input id="gate-login-uhash" type="text" value="${escapeHtml(auth.username_hash || "")}" placeholder="e.g. xnd-a1b2c3d4e5" required /></label>
            <label>Password <input id="gate-login-pass" type="password" placeholder="Your vault password" required style="width:100%;box-sizing:border-box;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);" /></label>
            <label>Login Hex Key (Ed25519) <input id="gate-login-hex" type="text" placeholder="64-char Ed25519 login hex key (optional if local)" /></label>
            <div id="gate-login-err" style="font-size:12px;color:#d93025;"></div>
            <button type="submit" class="btn-accent">Verify &amp; Unlock Dashboard</button>
          </form>
        </div>
      </div>
    </div>`;

  document.getElementById("auth-gate-back")?.addEventListener("click", () => {
    const t = tabs.find((x) => x.id === activeTabId);
    if (t && t.historyIdx > 0) {
      navBack();
    } else if (t && t.history.length > 0 && t.history[t.historyIdx]) {
      navigateRoute(t.history[t.historyIdx]);
    } else {
      openDomain("home.xnd");
    }
  });

  document.getElementById("auth-col-create")?.addEventListener("click", (e) => {
    if (!isCreate && !e.target.closest("form")) renderCenteredAuthGate(auth, "create", onUnlocked);
  });
  document.getElementById("auth-col-login")?.addEventListener("click", (e) => {
    if (isCreate && !e.target.closest("form")) renderCenteredAuthGate(auth, "login", onUnlocked);
  });

  document.getElementById("gate-create-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("gate-create-user")?.value.trim() || "";
    const password = document.getElementById("gate-create-pass")?.value || "";
    const sr = await fetch("/api/auth/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const sd = await sr.json().catch(() => ({}));
    if (!sr.ok) {
      const el = document.getElementById("gate-create-err");
      if (el) el.textContent = sd.detail || "Vault creation failed";
      return;
    }
    primaryContent.innerHTML = `
      <div class="auth-center-wrap">
        <div class="cf-card" style="max-width:540px;width:100%;padding:26px;">
          <div style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:#188038;text-transform:uppercase;">✓ VAULT CREATED &amp; ED25519 SIGNED</div>
          <h2 style="margin:6px 0 8px;">Save Your Private Account Credentials</h2>
          <p style="font-size:13px;color:var(--muted);margin:0 0 14px;">Use your lowercase hashed username and login hex key to sign into your Dashboard.</p>
          <div style="font-family:var(--font-mono);font-size:12px;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px;margin-bottom:14px;word-break:break-all;">
            <div><strong>Hashed Username:</strong> ${escapeHtml(sd.username_hash || "")}</div>
            <div style="margin-top:8px;"><strong>Login Hex Key:</strong> ${escapeHtml(sd.account_privkey_hex || "")}</div>
          </div>
          <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <a class="ver-btn" style="text-decoration:none;" href="/api/auth/download-account">Download Account Key JSON</a>
            <button class="btn-accent" id="btn-enter-dashboard">Continue to Dashboard →</button>
          </div>
        </div>
      </div>`;
    document.getElementById("btn-enter-dashboard")?.addEventListener("click", onUnlocked);
  });

  document.getElementById("gate-login-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username_hash = document.getElementById("gate-login-uhash")?.value.trim().toLowerCase() || "";
    const password = document.getElementById("gate-login-pass")?.value || "";
    const account_privkey_hex = document.getElementById("gate-login-hex")?.value.trim() || "";
    const lr = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username_hash, password, account_privkey_hex }),
    });
    const ld = await lr.json().catch(() => ({}));
    if (!lr.ok) {
      const el = document.getElementById("gate-login-err");
      if (el) el.textContent = ld.detail || "Sign in failed";
      return;
    }
    onUnlocked();
  });
}

function pushUpdateFromRepo(domain, title, mode) {
  cfDeployDraft.domain = domain;
  cfDeployDraft.title = title || domain;
  openCloudflareDashboard(domain, "deploy", mode === "capsule" ? "capsule" : "document");
}

function startRealtimeSyncStream() {
  if (typeof EventSource === "undefined") return;
  let es = null;
  let reconnectTimer = null;
  const connect = () => {
    try {
      es = new EventSource("/api/events/stream");
      es.addEventListener("domain_update", (ev) => {
        try {
          const data = JSON.parse(ev.data || "{}");
          if (!data.domain || !currentDoc || currentDoc.domain !== data.domain) return;
          const curVer = Number(currentDoc.version_num || currentDoc.version || 0);
          if (Number(data.version || 0) <= curVer) return;
          if (document.body.classList.contains("in-doc-view") || document.body.classList.contains("in-site-view")) {
            openDomain(data.domain);
          }
        } catch (_) {}
      });
      es.onerror = () => {
        try { es.close(); } catch (_) {}
        if (!reconnectTimer) {
          reconnectTimer = setTimeout(() => {
            reconnectTimer = null;
            connect();
          }, 4000);
        }
      };
    } catch (_) {}
  };
  connect();
}

startRealtimeSyncStream();

const openParam = new URLSearchParams(window.location.search).get("open");
const initialRoute = decodeRouteHash(window.location.hash);
if (openParam && openParam.trim()) {
  createTab(openParam.trim());
} else if (initialRoute) {
  const t = createTab("", true);
  t.history = [initialRoute];
  t.historyIdx = 0;
  navigateRoute(initialRoute);
} else {
  createTab("home.xnd");
}

let _qrAnimTimer = null;

async function downloadSneakernetBundle() {
  const dom = (document.getElementById("sneaker-domain")?.value || "").trim();
  const st = document.getElementById("sneaker-status");
  if (st) st.textContent = "Packing delta .xndbundle...";
  try {
    const r = await fetch("/api/sneakernet/export/file", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: dom }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "Export failed");
    const env = data.envelope;
    const blob = new Blob([JSON.stringify(env)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${dom || "xanadu-delta"}-${String(env.bundle_sha256 || "").slice(0, 8)}.xndbundle`;
    a.click();
    if (st) st.textContent = `Exported ${env.compressed_bytes} bytes (SHA-256: ${String(env.bundle_sha256).slice(0, 12)}...)`;
  } catch (e) {
    if (st) st.textContent = `Export error: ${e.message}`;
  }
}

async function importSneakernetFile(input) {
  const file = input?.files?.[0];
  if (!file) return;
  const st = document.getElementById("sneaker-status");
  if (st) st.textContent = "Verifying & importing .xndbundle...";
  try {
    const text = await file.text();
    const r = await fetch("/api/sneakernet/import/file", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ envelope: JSON.parse(text) }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "Import failed");
    if (st) st.textContent = `Imported ${data.imported_versions || 0} versions, ${data.imported_forum_posts || 0} forum posts (rejected: ${data.rejected || 0})`;
  } catch (e) {
    if (st) st.textContent = `Import error: ${e.message}`;
  } finally {
    input.value = "";
  }
}

let _ttMinTs = 0;
let _ttMaxTs = 0;

async function openTimeTravelModal() {
  const modal = document.getElementById("timetravel-modal");
  if (modal) modal.classList.remove("hidden");
  await fetchTimeTravelGraph(null);
}

async function fetchTimeTravelGraph(ts) {
  const url = ts == null ? "/api/graph/timetravel" : `/api/graph/timetravel?ts=${encodeURIComponent(ts)}`;
  const r = await fetch(url);
  if (!r.ok) return;
  const data = await r.json();
  _ttMinTs = Number(data.min_ts || 0);
  _ttMaxTs = Number(data.max_ts || Date.now() / 1000);
  const lbl = document.getElementById("tt-date-label");
  if (lbl) lbl.textContent = new Date(Number(data.ts || _ttMaxTs) * 1000).toLocaleString();
  const cnt = document.getElementById("tt-counts");
  if (cnt) cnt.textContent = `${(data.nodes || []).length} nodes • ${(data.edges || []).length} transclusion edges`;
  const box = document.getElementById("tt-graph-list");
  if (box) {
    const nodesHtml = (data.nodes || []).map((n) =>
      `<div style="padding:4px 0;border-bottom:1px solid rgba(128,128,128,0.12);">
        <strong>${n.id}</strong>@v${n.version} <span style="opacity:0.7;">(${n.kind})</span>
        <span style="font-family:var(--font-mono);font-size:10px;opacity:0.75;">ed25519:${String(n.pubkey_hex || "").slice(0, 12)}</span>
      </div>`
    ).join("");
    const edgesHtml = (data.edges || []).map((e) =>
      `<div style="font-family:var(--font-mono);font-size:11px;padding:2px 0;">${e.source} ⟶ ${e.target} ${e.hash_verified ? "✓" : "⚠"}</div>`
    ).join("");
    box.innerHTML = nodesHtml + (edgesHtml ? `<div style="margin-top:8px;font-weight:700;">Links at this timestamp:</div>${edgesHtml}` : "");
  }
}

let _ttDebounce = null;
function onTimeTravelSlide(pct) {
  const ratio = Number(pct) / 100;
  const targetTs = _ttMinTs + (_ttMaxTs - _ttMinTs) * ratio;
  clearTimeout(_ttDebounce);
  _ttDebounce = setTimeout(() => fetchTimeTravelGraph(targetTs), 120);
}

async function inspectDomainBlame() {
  const dom = (document.getElementById("tt-blame-domain")?.value || "").trim();
  const out = document.getElementById("tt-blame-out");
  if (!dom || !out) return;
  const r = await fetch(`/api/blame/${encodeURIComponent(dom)}`);
  const data = await r.json();
  if (!r.ok) {
    out.textContent = data.detail || "Not found";
    return;
  }
  const quotes = (data.segments || []).filter((s) => s.type === "transclusion");
  if (!quotes.length) {
    out.textContent = `${dom}@v${data.version} has no transcluded quotes.`;
    return;
  }
  out.innerHTML = quotes.map((q) =>
    `<div style="padding:4px 0;border-bottom:1px solid rgba(128,128,128,0.15);">
      [${q.target_domain}@v${q.target_version} -> latest v${q.latest_version}]
      <strong>${q.source_status}</strong> · ed25519:${String(q.author_pubkey || "").slice(0, 12)}
    </div>`
  ).join("");
}

function stopAnimatedQrSync() {
  if (_qrAnimTimer) {
    clearInterval(_qrAnimTimer);
    _qrAnimTimer = null;
  }
  const stage = document.getElementById("sneaker-qr-stage");
  if (stage) stage.classList.add("hidden");
}

async function startAnimatedQrSync() {
  stopAnimatedQrSync();
  const dom = (document.getElementById("sneaker-domain")?.value || "").trim();
  const st = document.getElementById("sneaker-status");
  if (st) st.textContent = "Encoding animated QR frames...";
  try {
    const r = await fetch("/api/sneakernet/qr/encode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: dom, include_svg: true }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "QR encode failed");
    const svgs = data.svgs || [];
    if (!svgs.length) throw new Error("No QR frames generated");
    const stage = document.getElementById("sneaker-qr-stage");
    const svgBox = document.getElementById("sneaker-qr-svg");
    const meta = document.getElementById("sneaker-qr-meta");
    if (stage) stage.classList.remove("hidden");
    let idx = 0;
    const render = () => {
      if (svgBox) svgBox.innerHTML = svgs[idx];
      if (meta) meta.textContent = `Transfer ${data.transfer_id} • Frame ${idx + 1} / ${svgs.length} (${data.compressed_bytes} B)`;
      idx = (idx + 1) % svgs.length;
    };
    render();
    if (svgs.length > 1) _qrAnimTimer = setInterval(render, 450);
    if (st) st.textContent = `Streaming ${svgs.length} QR frame(s). Scan with receiver.`;
  } catch (e) {
    if (st) st.textContent = `QR encode error: ${e.message}`;
  }
}

async function submitScannedQrFrame() {
  const inp = document.getElementById("sneaker-qr-input");
  const frame = (inp?.value || "").trim();
  if (!frame) return;
  const st = document.getElementById("sneaker-status");
  try {
    const r = await fetch("/api/sneakernet/qr/receive", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ frame }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "QR receive failed");
    if (data.complete) {
      if (st) st.textContent = `QR Sync Complete! Imported ${data.imported_versions || 0} versions.`;
    } else {
      if (st) st.textContent = `QR Progress: ${data.received}/${data.total} frames (missing: ${(data.missing || []).join(",")})`;
    }
    if (inp) inp.value = "";
  } catch (e) {
    if (st) st.textContent = `QR receive error: ${e.message}`;
  }
}
