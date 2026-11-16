const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("xanaduDesktop", {
  onDownload: (cb) => ipcRenderer.on("xnd-download", (_event, info) => cb(info)),
});
