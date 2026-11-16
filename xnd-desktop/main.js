const { app, BrowserWindow, session } = require("electron");
const { spawn } = require("child_process");
const http = require("http");
const path = require("path");

const fs = require("fs");
const HUB_URL = process.env.XND_HUB_URL || "http://127.0.0.1:8765/";
const HUB_DIR = app.isPackaged
  ? path.join(process.resourcesPath, "xnd-hub")
  : path.resolve(__dirname, "..", "xnd-hub");
const UI_DIR = app.isPackaged
  ? path.join(process.resourcesPath, "xnd-ui")
  : path.resolve(__dirname, "..", "xnd-ui");
const BIN_DIR = app.isPackaged
  ? path.join(process.resourcesPath, "bin")
  : path.resolve(__dirname, "bin");

let hubProc = null;
let crawlerProc = null;
let mainWin = null;
let dlSeq = 0;

function isHubUp() {
  return new Promise((resolve) => {
    const req = http.get(`${HUB_URL.replace(/\/$/, "")}/api/storage/stats`, { timeout: 800 }, (res) => {
      res.resume();
      resolve(res.statusCode >= 200 && res.statusCode < 500);
    });
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function ensureNodeRunning() {
  if (await isHubUp()) {
    return;
  }

  const pyBin = process.env.XND_PYTHON || "python3";
  const env = {
    ...process.env,
    XND_UI_DIR: UI_DIR,
    XND_DATA_DIR: app.isPackaged
      ? path.join(app.getPath("userData"), "node_data")
      : path.join(HUB_DIR, "node_data"),
  };

  const hubBin = path.join(BIN_DIR, "xnd-hub-bin");
  const crawlerBin = path.join(BIN_DIR, "xnd-crawler-bin");

  if (fs.existsSync(hubBin)) {
    hubProc = spawn(hubBin, [], { cwd: path.dirname(env.XND_DATA_DIR), env, stdio: "ignore" });
  } else {
    hubProc = spawn(pyBin, [path.join(HUB_DIR, "hub.py")], { cwd: HUB_DIR, env, stdio: "ignore" });
  }

  if (fs.existsSync(crawlerBin)) {
    crawlerProc = spawn(crawlerBin, [], { cwd: path.dirname(env.XND_DATA_DIR), env, stdio: "ignore" });
  } else {
    crawlerProc = spawn(pyBin, [path.join(HUB_DIR, "crawler.py")], { cwd: HUB_DIR, env, stdio: "ignore" });
  }

  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (await isHubUp()) return;
    await new Promise((r) => setTimeout(r, 250));
  }
}

function stopSpawnedNode() {
  if (crawlerProc && !crawlerProc.killed) {
    try { crawlerProc.kill("SIGTERM"); } catch (_) {}
    crawlerProc = null;
  }
  if (hubProc && !hubProc.killed) {
    try { hubProc.kill("SIGTERM"); } catch (_) {}
    hubProc = null;
  }
}

function attachDownloadManager(ses) {
  ses.on("will-download", (_event, item) => {
    dlSeq += 1;
    const id = `dl-${dlSeq}`;
    const filename = item.getFilename();
    const savePath = path.join(app.getPath("downloads"), filename);
    item.setSavePath(savePath);

    const notify = (state) => {
      if (mainWin && !mainWin.isDestroyed()) {
        mainWin.webContents.send("xnd-download", {
          id,
          filename,
          savePath,
          state,
          receivedBytes: item.getReceivedBytes(),
          totalBytes: item.getTotalBytes(),
        });
      }
    };

    notify("progressing");
    item.on("updated", (_e, state) => notify(state));
    item.once("done", (_e, state) => notify(state));
  });
}

function createWindow() {
  mainWin = new BrowserWindow({
    width: 1380,
    height: 880,
    minWidth: 960,
    minHeight: 640,
    title: "Xanadu Browser",
    icon: path.join(__dirname, "build", "icon.png"),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: false,
      contextIsolation: true,
      webviewTag: true,
    },
  });

  const ua = mainWin.webContents.getUserAgent() + " XanaduDesktop/1.0";
  mainWin.webContents.setUserAgent(ua);

  mainWin.webContents.on("did-attach-webview", (_event, webviewContents) => {
    webviewContents.setWindowOpenHandler(() => ({
      action: "allow",
      overrideBrowserWindowOptions: {
        width: 520,
        height: 700,
        autoHideMenuBar: true,
        webPreferences: {
          partition: "persist:xanadu-www",
          contextIsolation: true,
          nodeIntegration: false,
        },
      },
    }));
  });

  mainWin.loadURL(HUB_URL);
}

app.whenReady().then(async () => {
  const wwwSession = session.fromPartition("persist:xanadu-www");
  attachDownloadManager(wwwSession);
  attachDownloadManager(session.defaultSession);

  await ensureNodeRunning();
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("before-quit", stopSpawnedNode);

app.on("window-all-closed", () => {
  stopSpawnedNode();
  if (process.platform !== "darwin") app.quit();
});
