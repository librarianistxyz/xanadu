document.getElementById("open-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  let dom = document.getElementById("dom-input").value.trim().toLowerCase();
  dom = dom.replace(/^(?:xnd|https?):\/\//, "").split(/[/?#]/)[0];
  if (!dom) return;
  if (!dom.endsWith(".xnd")) dom += ".xnd";
  await chrome.tabs.create({
    url: chrome.runtime.getURL(`viewer.html?domain=${encodeURIComponent(dom)}`),
  });
  window.close();
});

document.getElementById("local-node-link").addEventListener("click", async (e) => {
  e.preventDefault();
  await chrome.tabs.create({ url: "http://127.0.0.1:8765/" });
  window.close();
});
