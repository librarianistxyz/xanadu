function normalizeDomain(raw) {
  let d = (raw || "").trim().toLowerCase();
  d = d.replace(/^(?:xnd|https?):\/\//, "").split(/[/?#]/)[0];
  if (d && !d.endsWith(".xnd")) d += ".xnd";
  return d;
}

function viewerUrl(domain) {
  return chrome.runtime.getURL(`viewer.html?domain=${encodeURIComponent(domain)}`);
}

chrome.omnibox.onInputEntered.addListener(async (text) => {
  const dom = normalizeDomain(text);
  if (!dom) return;
  await chrome.tabs.update({ url: viewerUrl(dom) });
});

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  try {
    const u = new URL(details.url);
    if (u.hostname && u.hostname.toLowerCase().endsWith(".xnd")) {
      await chrome.tabs.update(details.tabId, { url: viewerUrl(u.hostname.toLowerCase()) });
    }
  } catch (_) {
    // ignore malformed URLs
  }
});
