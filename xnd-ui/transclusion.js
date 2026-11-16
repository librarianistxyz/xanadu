/**
 * Independent Two-Way Xanadu Transclusion & Provenance UI Module.
 * Strictly isolated from search/news/sync logic so future edits cannot break it.
 */
(function () {
  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function formatPointer(doc, start, end) {
    const hash12 = (doc.sha256 || "").slice(0, 12);
    const hPart = hash12 ? `#${hash12}` : "";
    return `{{xnd://${doc.domain}@v${doc.version || 1}${hPart}:${start}-${end}}}`;
  }

  function renderCard(seg) {
    const hashShort = (seg.target_hash || "").slice(0, 12);
    const verified = seg.hash_verified !== false;
    const badge = verified
      ? `<span style="color:#22c55e;font-weight:700;">✓ Provenance Verified</span>`
      : `<span style="color:#ef4444;font-weight:700;">⚠ Hash Mismatch</span>`;
    return `<span
      id="left-${esc(seg.bridge_id)}"
      class="transclusion-card"
      title="Click to verify & open Origin Span side-by-side"
      onclick="window.XndTransclusion.openOriginSplit('${esc(seg.bridge_id)}', '${esc(seg.target_domain)}', ${Number(seg.target_version || 1)}, ${Number(seg.target_start || 0)}, ${Number(seg.target_end || 0)}, '${esc(seg.expected_hash || hashShort)}')"
    >
      <span class="transclusion-meta">⟐ ${esc(seg.target_domain)}@v${Number(seg.target_version || 1)}${hashShort ? `#${esc(hashShort)}` : ""} [${Number(seg.target_start || 0)}:${Number(seg.target_end || 0)}] · ${badge}</span>
      ${esc(seg.quoted_text || "")}
    </span>`;
  }

  async function openOriginSplit(bridgeId, targetDomain, version, start, end, expectedHash) {
    document.querySelectorAll(".transclusion-card").forEach((el) => el.classList.remove("active"));
    const leftEl = document.getElementById(`left-${bridgeId}`);
    if (leftEl) leftEl.classList.add("active");

    const res = await fetch(`/api/resolve/${encodeURIComponent(targetDomain)}?version=${version}`);
    if (!res.ok) return;
    const targetDoc = await res.json();

    const secondaryPane = document.getElementById("secondary-pane");
    const secondaryLabel = document.getElementById("secondary-label");
    const secondaryContent = document.getElementById("secondary-content");
    if (!secondaryPane || !secondaryLabel || !secondaryContent) return;

    const actualHash = (targetDoc.sha256 || "").toLowerCase();
    const exp = (expectedHash || "").toLowerCase();
    const hashOk = !exp || actualHash.startsWith(exp);

    secondaryPane.classList.remove("hidden");
    secondaryLabel.textContent = `Origin: ${targetDoc.domain}@v${targetDoc.version} [${start}:${end}]`;

    const raw = targetDoc.raw_content || "";
    const before = esc(raw.slice(0, start));
    const match = esc(raw.slice(start, end));
    const after = esc(raw.slice(end));

    secondaryContent.innerHTML = `
      <div class="doc-header">
        <div class="doc-domain">xnd://${esc(targetDoc.domain)} @ v${targetDoc.version}</div>
        <h2 class="doc-title" style="font-size:20px;">${esc(targetDoc.title || targetDoc.domain)}</h2>
        <div class="meta-row">
          <span class="meta-tag ${hashOk ? "verified" : ""}">
            ${hashOk ? "✓ Immutable Origin & Hash Verified" : "⚠ Origin Hash Mismatch"}
          </span>
          ${actualHash ? `<span class="meta-tag" style="font-family:var(--font-mono);">sha256:${esc(actualHash.slice(0, 12))}</span>` : ""}
        </div>
      </div>
      <div class="doc-body">${before}<span id="right-target-span" class="highlight-span">${match}</span>${after}</div>
    `;

    if (typeof activeBridge !== "undefined") {
      activeBridge = { leftId: `left-${bridgeId}`, rightId: "right-target-span" };
    }
    requestAnimationFrame(() => {
      document.getElementById("right-target-span")?.scrollIntoView({ behavior: "smooth", block: "center" });
      if (typeof drawBridgeLine === "function") setTimeout(drawBridgeLine, 120);
    });
  }

  function attachSelectionHook(primaryPane, quoteBar, quotePreview, getCurrentDoc, onPointerReady) {
    if (!primaryPane || !quoteBar || !quotePreview) return;
    const checkSel = () => {
      const doc = getCurrentDoc();
      const sel = window.getSelection();
      const txt = sel ? sel.toString() : "";
      if (!doc || doc.kind !== "document" || txt.trim().length < 4) {
        quoteBar.classList.add("hidden");
        return;
      }
      const idx = (doc.raw_content || "").indexOf(txt);
      if (idx === -1) {
        quoteBar.classList.add("hidden");
        return;
      }
      const ptr = formatPointer(doc, idx, idx + txt.length);
      onPointerReady(ptr);
      quotePreview.textContent = `Quote [${idx}:${idx + txt.length}] · #${(doc.sha256 || "").slice(0, 8)}`;
      quoteBar.classList.remove("hidden");
    };
    primaryPane.addEventListener("mouseup", checkSel);
    primaryPane.addEventListener("touchend", () => setTimeout(checkSel, 80));
  }

  window.XndTransclusion = {
    formatPointer,
    renderCard,
    openOriginSplit,
    attachSelectionHook,
  };
})();
