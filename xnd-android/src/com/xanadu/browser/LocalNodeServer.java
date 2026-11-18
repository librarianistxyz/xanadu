package com.xanadu.browser;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class LocalNodeServer {
    private final Context context;
    private final AssetManager assets;
    private final File dataDir;
    private final int port;
    private final ExecutorService pool = Executors.newCachedThreadPool();
    private volatile boolean running = false;
    private ServerSocket serverSocket;

    private final Map<String, JSONObject> docs = Collections.synchronizedMap(new HashMap<>());
    private final Map<String, JSONObject> domainKeys = Collections.synchronizedMap(new HashMap<>());
    private final Map<String, Integer> nostrSyncedVersions = Collections.synchronizedMap(new HashMap<>());
    private volatile boolean wanOk = false;
    private volatile long wanCheckedMs = 0L;
    private volatile boolean shareGateway = true;
    private volatile JSONObject meshGatewayPeer = null;
    private final List<JSONObject> bookmarks = Collections.synchronizedList(new ArrayList<>());
    private final List<JSONObject> history = Collections.synchronizedList(new ArrayList<>());
    private final List<JSONObject> peers = Collections.synchronizedList(new ArrayList<>());
    private final Set<String> blockedDomains = Collections.synchronizedSet(new HashSet<>());
    private final Set<String> blockedPubkeys = Collections.synchronizedSet(new HashSet<>());
    private final Set<String> followedPubkeys = Collections.synchronizedSet(new HashSet<>());
    private volatile int gossipImported = 0;
    private final String lanNodeId = Long.toHexString(new SecureRandom().nextLong());
    private final Map<String, JSONObject> lanPeers = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, JSONObject> wikiShards = new java.util.concurrent.ConcurrentHashMap<>();
    private final GitHubHosting ghHosting;
    private static volatile Context staticContext;
    private WifiDirectMesh wifiDirectMesh;
    private final Map<String, JSONObject> trustPins = Collections.synchronizedMap(new HashMap<>());
    private final Map<String, String> trustPetnames = Collections.synchronizedMap(new HashMap<>());
    private final Map<String, Map<String, String>> trustConflicts = Collections.synchronizedMap(new HashMap<>());
    private final byte[] capTokenSecret = new byte[32];
    private static final int MAX_CACHED_DOMAINS = 5000;
    private final Map<String, Long> domainLastAccess = new java.util.concurrent.ConcurrentHashMap<>();
    private static final Pattern CANONICAL_DOMAIN_RE = Pattern.compile("^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\\.([0-9a-f]{8,16})\\.xnd$");

    public LocalNodeServer(Context ctx, int port) {
        this.context = ctx.getApplicationContext();
        new SecureRandom().nextBytes(capTokenSecret);
        staticContext = this.context;
        this.assets = this.context.getAssets();
        this.dataDir = new File(this.context.getFilesDir(), "node_data");
        this.port = port;
        if (!this.dataDir.exists()) this.dataDir.mkdirs();
        this.ghHosting = new GitHubHosting(this.dataDir);
        loadState();
        ensureFounderDoc();
    }

    public void start() {
        startAndWait(0);
    }

    public boolean startAndWait(long timeoutMs) {
        if (running) return true;
        running = true;
        CountDownLatch ready = new CountDownLatch(1);
        new Thread(() -> {
            try {
                serverSocket = new ServerSocket();
                serverSocket.setReuseAddress(true);
                serverSocket.bind(new InetSocketAddress(InetAddress.getByName("0.0.0.0"), port), 128);
                ready.countDown();
                startLanDiscovery();
                startNatTunnel();
                startWifiDirectMesh();
                startAutoGossip();
                startGithubAutoSync();
                while (running) {
                    Socket client = serverSocket.accept();
                    pool.submit(() -> handleClient(client));
                }
            } catch (Exception e) {
                Log.e("LocalNodeServer", "Server loop stopped", e);
                ready.countDown();
            }
        }, "xnd-local-node").start();
        if (timeoutMs > 0) {
            try {
                return ready.await(timeoutMs, TimeUnit.MILLISECONDS);
            } catch (InterruptedException ignored) {
            }
        }
        return true;
    }

    public void stop() {
        running = false;
        try {
            if (wifiDirectMesh != null) wifiDirectMesh.stop();
        } catch (Exception ignored) {
        }
        try {
            if (natTunnel != null) natTunnel.stop();
        } catch (Exception ignored) {
        }
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (Exception ignored) {
        }
    }

    private void loadState() {
        try {
            File bf = new File(dataDir, "bookmarks.json");
            if (bf.exists()) {
                JSONArray arr = new JSONArray(readFileText(bf));
                for (int i = 0; i < arr.length(); i++) bookmarks.add(arr.getJSONObject(i));
            }
            File hf = new File(dataDir, "history.jsonl");
            if (hf.exists()) {
                for (String ln : readFileText(hf).split("\n")) {
                    if (!ln.trim().isEmpty()) history.add(new JSONObject(ln));
                }
            }
            File df = new File(dataDir, "docs.json");
            if (df.exists()) {
                JSONObject obj = new JSONObject(readFileText(df));
                JSONArray names = obj.names();
                if (names != null) {
                    for (int i = 0; i < names.length(); i++) {
                        String k = names.getString(i);
                        docs.put(k, obj.getJSONObject(k));
                    }
                }
            }
            File pf = new File(dataDir, "peers.json");
            if (pf.exists()) {
                JSONArray arr = new JSONArray(readFileText(pf));
                for (int i = 0; i < arr.length(); i++) peers.add(arr.getJSONObject(i));
            }
            File kf = new File(dataDir, "keys.json");
            if (kf.exists()) {
                JSONObject obj = new JSONObject(readFileText(kf));
                JSONArray names = obj.names();
                if (names != null) {
                    for (int i = 0; i < names.length(); i++) {
                        String k = names.getString(i);
                        domainKeys.put(k, obj.getJSONObject(k));
                    }
                }
            }
            File mf = new File(dataDir, "moderation.json");
            if (mf.exists()) {
                JSONObject mod = new JSONObject(readFileText(mf));
                JSONArray bd = mod.optJSONArray("blocked_domains");
                if (bd != null) for (int i = 0; i < bd.length(); i++) blockedDomains.add(bd.getString(i));
                JSONArray bp = mod.optJSONArray("blocked_pubkeys");
                if (bp != null) for (int i = 0; i < bp.length(); i++) blockedPubkeys.add(bp.getString(i));
                JSONArray fp = mod.optJSONArray("followed_pubkeys");
                if (fp != null) for (int i = 0; i < fp.length(); i++) followedPubkeys.add(fp.getString(i));
            }
            loadTrustPins();
        } catch (Exception ignored) {
        }
    }

    private synchronized void saveBookmarks() {
        try {
            JSONArray arr = new JSONArray();
            for (JSONObject b : bookmarks) arr.put(b);
            writeFileText(new File(dataDir, "bookmarks.json"), arr.toString());
        } catch (Exception ignored) {
        }
    }

    private synchronized void saveDocs() {
        try {
            JSONObject obj = new JSONObject();
            for (Map.Entry<String, JSONObject> e : docs.entrySet()) obj.put(e.getKey(), e.getValue());
            writeFileText(new File(dataDir, "docs.json"), obj.toString());
        } catch (Exception ignored) {
        }
    }

    private synchronized void savePeers() {
        try {
            JSONArray arr = new JSONArray();
            for (JSONObject p : peers) arr.put(p);
            writeFileText(new File(dataDir, "peers.json"), arr.toString());
        } catch (Exception ignored) {
        }
    }

    private synchronized void saveKeys() {
        try {
            JSONObject obj = new JSONObject();
            for (Map.Entry<String, JSONObject> e : domainKeys.entrySet()) obj.put(e.getKey(), e.getValue());
            writeFileText(new File(dataDir, "keys.json"), obj.toString());
        } catch (Exception ignored) {
        }
    }

    private synchronized void saveModeration() {
        try {
            JSONObject mod = new JSONObject();
            mod.put("blocked_domains", new JSONArray(blockedDomains));
            mod.put("blocked_pubkeys", new JSONArray(blockedPubkeys));
            mod.put("followed_pubkeys", new JSONArray(followedPubkeys));
            writeFileText(new File(dataDir, "moderation.json"), mod.toString());
        } catch (Exception ignored) {
        }
    }

    private JSONObject moderationJson() {
        JSONObject m = new JSONObject();
        try {
            m.put("blocked_domains", new JSONArray(blockedDomains));
            m.put("blocked_pubkeys", new JSONArray(blockedPubkeys));
            m.put("followed_pubkeys", new JSONArray(followedPubkeys));
        } catch (Exception ignored) {
        }
        return m;
    }

    private static String readHeaderLine(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int prev = -1;
        while (true) {
            int b = in.read();
            if (b < 0) {
                return bos.size() == 0 ? null : new String(bos.toByteArray(), StandardCharsets.UTF_8);
            }
            if (b == '\n') {
                byte[] arr = bos.toByteArray();
                int len = (arr.length > 0 && arr[arr.length - 1] == '\r') ? arr.length - 1 : arr.length;
                return new String(arr, 0, len, StandardCharsets.UTF_8);
            }
            bos.write(b);
            prev = b;
        }
    }

    private void handleClient(Socket sock) {
        OutputStream out = null;
        try (Socket s = sock) {
            s.setSoTimeout(15000);
            InputStream in = s.getInputStream();
            out = s.getOutputStream();

            String reqLine = readHeaderLine(in);
            if (reqLine == null || reqLine.isEmpty()) return;
            Log.d("LocalNodeServer", reqLine);
            String[] parts = reqLine.split(" ");
            String method = parts.length > 0 ? parts[0] : "GET";
            String fullPath = parts.length > 1 ? parts[1] : "/";

            int contentLen = 0;
            String line;
            String reqOrigin = "";
            String reqReferer = "";
            String reqCapToken = "";
            while ((line = readHeaderLine(in)) != null && !line.isEmpty()) {
                String low = line.toLowerCase(Locale.US);
                if (low.startsWith("content-length:")) {
                    contentLen = Integer.parseInt(line.substring(15).trim());
                } else if (low.startsWith("origin:")) {
                    reqOrigin = line.substring(7).trim();
                } else if (low.startsWith("referer:")) {
                    reqReferer = line.substring(8).trim();
                } else if (low.startsWith("x-xnd-cap-token:")) {
                    reqCapToken = line.substring(16).trim();
                }
            }
            String bodyStr = "";
            if (contentLen > 0) {
                byte[] buf = new byte[contentLen];
                int read = 0;
                while (read < contentLen) {
                    int r = in.read(buf, read, contentLen - read);
                    if (r < 0) break;
                    read += r;
                }
                bodyStr = new String(buf, 0, read, StandardCharsets.UTF_8);
            }

            String path = fullPath;
            String query = "";
            int qIdx = fullPath.indexOf('?');
            if (qIdx >= 0) {
                path = fullPath.substring(0, qIdx);
                query = fullPath.substring(qIdx + 1);
            }
            Map<String, String> qp = parseQuery(query);
            boolean fromSandboxedCapsule = "null".equalsIgnoreCase(reqOrigin) || reqReferer.toLowerCase(Locale.US).contains("/xnd-app/");
            boolean isSensitivePath = path.startsWith("/api/keys") || path.startsWith("/api/auth")
                    || path.startsWith("/api/publish") || path.startsWith("/api/domain")
                    || path.startsWith("/api/github") || path.startsWith("/api/e2ee")
                    || path.startsWith("/api/trust");
            if (fromSandboxedCapsule && isSensitivePath) {
                sendJson(out, 403, "{\"detail\":\"Blocked: sandboxed capsule origin cannot access node key/auth/trust endpoints\"}");
                return;
            }
            if (method.equals("OPTIONS")) {
                Map<String, String> corsHdrs = new HashMap<>();
                corsHdrs.put("Access-Control-Allow-Origin", "null".equalsIgnoreCase(reqOrigin) ? "null" : "*");
                corsHdrs.put("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                corsHdrs.put("Access-Control-Allow-Headers", "Content-Type, X-Xnd-Cap-Token");
                sendBytesWithHeaders(out, 204, "text/plain", new byte[0], corsHdrs);
                return;
            }

            if (method.equals("GET") && !path.startsWith("/api/") && !path.startsWith("/static/") && !path.startsWith("/xnd-app/") && !path.startsWith("/xnd-asset/")) {
                Matcher refM = Pattern.compile("/xnd-app/([^/?#]+)").matcher(reqReferer);
                if (refM.find()) {
                    String refDom = URLDecoder.decode(refM.group(1), "UTF-8").trim().toLowerCase(Locale.US);
                    String relP = path.replaceFirst("^/+", "");
                    if (relP.isEmpty()) relP = "index.html";
                    path = "/xnd-app/" + refDom + "/" + relP;
                }
            }

            if (path.equals("/")) {
                sendBytes(out, 200, "text/html; charset=utf-8", readAsset("xnd-ui/index.html"));
            } else if (path.equals("/static/app.js")) {
                sendBytes(out, 200, "application/javascript; charset=utf-8", readAsset("xnd-ui/app.js"));
            } else if (path.equals("/static/transclusion.js")) {
                sendBytes(out, 200, "application/javascript; charset=utf-8", readAsset("xnd-ui/transclusion.js"));
            } else if (path.equals("/static/xnd-sdk.js")) {
                sendBytes(out, 200, "application/javascript; charset=utf-8", readAsset("xnd-ui/xnd-sdk.js"));
            } else if (path.equals("/static/logo.svg")) {
                sendBytes(out, 200, "image/svg+xml", readAsset("xnd-ui/logo.svg"));
            } else if (path.equals("/static/logo.png")) {
                sendBytes(out, 200, "image/png", readAsset("xnd-ui/logo.png"));
            } else if (path.equals("/static/mathematical.png")) {
                sendBytes(out, 200, "image/png", readAsset("xnd-ui/mathematical.png"));
            } else if (path.equals("/static/style.css")) {
                sendBytes(out, 200, "text/css; charset=utf-8", readAsset("xnd-ui/style.css"));
            } else if (path.startsWith("/static/founder/") && !path.contains("..")) {
                String fname = path.substring("/static/founder/".length());
                if (fname.equals("image2.png")) {
                    sendBytes(out, 200, "image/png", readAsset("xnd-ui/founder/" + fname));
                } else {
                    sendJson(out, 404, "{\"detail\":\"Not found\"}");
                }
            } else if (path.equals("/api/storage/stats")) {
                long bytes = dirSize(dataDir);
                JSONObject res = new JSONObject();
                res.put("mode", "zero-db-android-peer");
                res.put("domains_in_ram", docs.size());
                res.put("pinned_kb", Math.round((bytes / 1024.0) * 100.0) / 100.0);
                res.put("cache_kb", 0.0);
                res.put("max_cache_mb", 64.0);
                sendJson(out, 200, res.toString());
            } else if (path.equals("/api/news")) {
                String cat = qp.getOrDefault("category", "top");
                sendJson(out, 200, fetchNewsJson(cat).toString());
            } else if (path.equals("/api/search")) {
                String q = qp.getOrDefault("q", "");
                boolean fast = "1".equals(qp.getOrDefault("fast", "")) || "true".equalsIgnoreCase(qp.getOrDefault("fast", ""));
                sendJson(out, 200, searchAll(q, fast).toString());
            } else if (path.equals("/api/search/federated") && method.equals("POST")) {
                JSONObject req = bodyStr != null && !bodyStr.trim().isEmpty() ? new JSONObject(bodyStr) : new JSONObject();
                String q = req.optString("query", "").trim();
                int limit = Math.max(1, Math.min(20, req.optInt("limit", 8)));
                JSONArray fedHits = new JSONArray();
                if (!q.isEmpty()) {
                    JSONArray allHits = searchAll(q, true).optJSONArray("results");
                    if (allHits != null) {
                        for (int i = 0; i < Math.min(limit, allHits.length()); i++) {
                            fedHits.put(allHits.getJSONObject(i));
                        }
                    }
                }
                sendJson(out, 200, new JSONObject().put("ok", true).put("node_id", lanNodeId).put("results", fedHits).toString());
            } else if (path.equals("/api/trust/pins") && method.equals("GET")) {
                JSONObject pinsObj = new JSONObject();
                for (Map.Entry<String, JSONObject> e : trustPins.entrySet()) pinsObj.put(e.getKey(), e.getValue());
                JSONObject petsObj = new JSONObject();
                for (Map.Entry<String, String> e : trustPetnames.entrySet()) petsObj.put(e.getKey(), e.getValue());
                sendJson(out, 200, new JSONObject().put("ok", true).put("pins", pinsObj).put("petnames", petsObj).toString());
            } else if (path.equals("/api/trust/pin") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String dom = req.optString("domain", "").trim().toLowerCase(Locale.US);
                String pub = req.optString("pubkey_hex", "").trim().toLowerCase(Locale.US);
                String pet = req.optString("petname", "").trim();
                if (!dom.endsWith(".xnd") || pub.length() != 64) {
                    sendJson(out, 400, "{\"detail\":\"Valid .xnd domain and 64-char hex pubkey_hex are required\"}");
                    return;
                }
                trustPins.put(dom, new JSONObject().put("pubkey_hex", pub).put("pinned_at", System.currentTimeMillis() / 1000.0).put("source", "manual"));
                if (!pet.isEmpty()) trustPetnames.put(dom, pet);
                saveTrustPins();
                sendJson(out, 200, new JSONObject().put("ok", true).put("domain", dom).put("pubkey_hex", pub).put("key_fingerprint", formatFingerprint(pub)).put("canonical_domain", canonicalDomainFor(dom, pub)).toString());
            } else if (path.equals("/api/trust/petname") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String key = req.optString("key", req.optString("domain", "")).trim().toLowerCase(Locale.US);
                String pet = req.optString("petname", "").trim();
                if (key.isEmpty()) {
                    sendJson(out, 400, "{\"detail\":\"key or domain is required\"}");
                    return;
                }
                if (pet.isEmpty()) trustPetnames.remove(key);
                else trustPetnames.put(key, pet);
                saveTrustPins();
                sendJson(out, 200, new JSONObject().put("ok", true).put("key", key).put("petname", pet).toString());
            } else if (path.equals("/api/search/feedback") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                sendJson(out, 200, recordPatternFeedback(
                        req.optString("query", ""),
                        req.optString("domain", ""),
                        req.optBoolean("helpful", true) ? 1.0 : -0.8).toString());
            } else if (path.equals("/api/bookmarks")) {
                if (method.equals("POST")) {
                    JSONObject b = new JSONObject(bodyStr);
                    String url = b.optString("url", "").trim();
                    bookmarks.removeIf(x -> x.optString("url", "").equals(url));
                    b.put("created_at", System.currentTimeMillis() / 1000.0);
                    bookmarks.add(0, b);
                    saveBookmarks();
                    JSONObject res = new JSONObject().put("ok", true).put("bookmarks", new JSONArray(bookmarks));
                    sendJson(out, 200, res.toString());
                } else if (method.equals("DELETE")) {
                    String url = qp.getOrDefault("url", "");
                    bookmarks.removeIf(x -> x.optString("url", "").equals(url));
                    saveBookmarks();
                    JSONObject res = new JSONObject().put("ok", true).put("bookmarks", new JSONArray(bookmarks));
                    sendJson(out, 200, res.toString());
                } else {
                    sendJson(out, 200, new JSONObject().put("bookmarks", new JSONArray(bookmarks)).toString());
                }
            } else if (path.equals("/api/history")) {
                if (method.equals("POST")) {
                    JSONObject h = new JSONObject(bodyStr);
                    h.put("visited_at", System.currentTimeMillis() / 1000.0);
                    history.add(h);
                    try (FileOutputStream fos = new FileOutputStream(new File(dataDir, "history.jsonl"), true)) {
                        fos.write((h.toString() + "\n").getBytes(StandardCharsets.UTF_8));
                    }
                    sendJson(out, 200, "{\"ok\":true}");
                } else {
                    String ql = qp.getOrDefault("q", "").toLowerCase(Locale.US);
                    JSONArray arr = new JSONArray();
                    for (int i = history.size() - 1; i >= 0 && arr.length() < 100; i--) {
                        JSONObject h = history.get(i);
                        if (ql.isEmpty() || h.optString("url").toLowerCase(Locale.US).contains(ql)
                                || h.optString("title").toLowerCase(Locale.US).contains(ql)) {
                            arr.put(h);
                        }
                    }
                    sendJson(out, 200, new JSONObject().put("history", arr).toString());
                }
            } else if (path.equals("/api/clip") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String quote = req.optString("quote", "").trim();
                String src = req.optString("url", "https://unknown");
                String title = req.optString("title", src);
                String dom = req.optString("domain", "").trim().toLowerCase(Locale.US);
                if (dom.isEmpty()) dom = "clip-" + sha256Hex(src + quote).substring(0, 8) + ".xnd";
                if (!dom.endsWith(".xnd")) dom = dom + ".xnd";
                String content = "Archived from: " + src + "\n\n# " + title + "\n\n> " + quote + "\n";
                JSONObject res = publishLocalDoc(dom, "[Clip] " + title, content, src);
                sendJson(out, 200, res.toString());
            } else if (path.equals("/api/publish") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String dom = req.optString("domain", "").trim().toLowerCase(Locale.US);
                String title = req.optString("title", dom);
                String content = req.optString("content", "");
                String privkeyHex = req.optString("privkey_hex", "").trim();
                if (privkeyHex.isEmpty() && vaultUnlocked && domainKeys.containsKey(dom)) {
                    privkeyHex = domainKeys.get(dom).optString("privkey_hex", "");
                }
                if (dom.isEmpty() || content.trim().isEmpty()) {
                    sendJson(out, 400, "{\"detail\":\"Domain and content are required\"}");
                    return;
                }
                dom = normalizeXndDomain(dom);
                if (!isValidXndDomain(dom)) {
                    sendJson(out, 400, "{\"detail\":\"Invalid .xnd domain. Only letters, numbers, '-' and '.' between labels are allowed.\"}");
                    return;
                }
                if (privkeyHex.isEmpty() && vaultUnlocked && domainKeys.containsKey(dom)) {
                    privkeyHex = domainKeys.get(dom).optString("privkey_hex", "");
                }
                if (privkeyHex.isEmpty() && docs.containsKey(dom)) {
                    privkeyHex = docs.get(dom).optString("privkey_hex", "");
                }
                boolean privateSpace = req.optBoolean("private_space", false);
                String contentToStore = content;
                if (privateSpace) {
                    if (privkeyHex.isEmpty()) {
                        privkeyHex = Ed25519.toHex(Ed25519.generatePrivateKey());
                    }
                    List<String> allowed = E2eeSpaces.parseAllowedPubkeys(req.optString("allowed_pubkeys", ""));
                    contentToStore = E2eeSpaces.encryptForPeers(content, privkeyHex, allowed);
                }
                try {
                    JSONObject res = publishLocalDoc(dom, title, contentToStore, "", privkeyHex, true);
                    if (vaultUnlocked) saveVault();
                    sendJson(out, 200, res.toString());
                } catch (IllegalStateException ise) {
                    sendJson(out, 403, new JSONObject().put("detail", ise.getMessage()).toString());
                }
            } else if (path.equals("/api/e2ee/unlock") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String dom = req.optString("domain", "").trim().toLowerCase(Locale.US);
                String privHex = req.optString("privkey_hex", "").trim();
                JSONObject d = docs.get(dom);
                if (d == null) {
                    sendJson(out, 404, "{\"detail\":\"Domain not found\"}");
                    return;
                }
                E2eeSpaces.DecryptResult dec = E2eeSpaces.decryptWithPrivkeys(
                        d.optString("raw_content", ""),
                        java.util.Collections.singletonList(privHex));
                if (!dec.decrypted) {
                    sendJson(out, 403, "{\"detail\":\"Key is not in the invited E2EE recipient list.\"}");
                    return;
                }
                JSONArray segs;
                synchronized (docs) {
                    segs = TransclusionEngine.buildSegments(dec.plaintext, docs);
                }
                sendJson(out, 200, new JSONObject()
                        .put("ok", true)
                        .put("domain", dom)
                        .put("raw_content", dec.plaintext)
                        .put("segments", segs)
                        .put("allowed_pubkeys", new JSONArray(dec.recipients))
                        .toString());
            } else if (path.equals("/api/publish_capsule") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String dom = req.optString("domain", "").trim().toLowerCase(Locale.US);
                String title = req.optString("title", dom);
                String html = req.optString("html", "");
                String backendPy = req.optString("backend_py", "");
                String privkeyHex = req.optString("privkey_hex", "").trim();
                JSONObject filesObj = req.optJSONObject("files");
                if (filesObj == null) filesObj = new JSONObject();
                if (!html.trim().isEmpty()) {
                    filesObj.put("index.html", html);
                }
                if (dom.isEmpty() || !filesObj.has("index.html")) {
                    sendJson(out, 400, "{\"detail\":\"Domain and index.html are required\"}");
                    return;
                }
                dom = normalizeXndDomain(dom);
                if (!isValidXndDomain(dom)) {
                    sendJson(out, 400, "{\"detail\":\"Invalid .xnd domain. Only letters, numbers, '-' and '.' between labels are allowed.\"}");
                    return;
                }
                if (privkeyHex.isEmpty() && vaultUnlocked && domainKeys.containsKey(dom)) {
                    privkeyHex = domainKeys.get(dom).optString("privkey_hex", "");
                }
                try {
                    JSONObject res = publishLocalCapsule(dom, title, filesObj, backendPy, privkeyHex);
                    if (vaultUnlocked) saveVault();
                    sendJson(out, 200, res.toString());
                } catch (IllegalStateException ise) {
                    sendJson(out, 403, new JSONObject().put("detail", ise.getMessage()).toString());
                }
            } else if (path.startsWith("/api/resolve/")) {
                String dom = URLDecoder.decode(path.substring("/api/resolve/".length()), "UTF-8").toLowerCase(Locale.US);
                String[] parsedCanon = parseCanonicalDomain(dom);
                String storageDom = dom;
                JSONObject d = docs.get(dom);
                if (d == null && parsedCanon != null) {
                    JSONObject bd = docs.get(parsedCanon[0]);
                    if (bd != null && bd.optString("pubkey_hex", bd.optString("pubkey", "")).toLowerCase(Locale.US).startsWith(parsedCanon[1])) {
                        d = bd;
                        storageDom = parsedCanon[0];
                    }
                }
                if (d == null && dom.endsWith(".xnd") && !blockedDomains.contains(dom)) {
                    String lookupTarget = parsedCanon != null ? parsedCanon[0] : dom;
                    if (!tryResolveFromPeers(lookupTarget)) {
                        lookupDocNostr(lookupTarget);
                    }
                    d = docs.get(dom);
                    if (d == null && parsedCanon != null) {
                        JSONObject bd = docs.get(parsedCanon[0]);
                        if (bd != null && bd.optString("pubkey_hex", bd.optString("pubkey", "")).toLowerCase(Locale.US).startsWith(parsedCanon[1])) {
                            d = bd;
                            storageDom = parsedCanon[0];
                        }
                    }
                }
                if (d == null) {
                    sendJson(out, 404, "{\"detail\":\"Domain not found locally\"}");
                } else {
                    domainLastAccess.put(storageDom, System.currentTimeMillis());
                    JSONObject outDoc = new JSONObject(d.toString());
                    outDoc.put("domain", dom);
                    int vNum = outDoc.optInt("version", outDoc.optInt("version_num", 1));
                    if (!outDoc.has("version")) outDoc.put("version", vNum);
                    if (!outDoc.has("kind") || outDoc.optString("kind").isEmpty()) outDoc.put("kind", "document");
                    String resolvedPub = outDoc.optString("pubkey_hex", outDoc.optString("pubkey", "")).toLowerCase(Locale.US);
                    if (!outDoc.has("pubkey")) outDoc.put("pubkey", resolvedPub);
                    if (!outDoc.has("sha256")) outDoc.put("sha256", "");
                    String baseForTrust = parsedCanon != null ? parsedCanon[0] : dom;
                    if (!resolvedPub.isEmpty() && parsedCanon == null) {
                        ensureFirstSeenPin(dom, resolvedPub, outDoc.optBoolean("owned_locally", false) ? "self" : "first_seen");
                    }
                    String pinnedPub = getPinnedPubkey(baseForTrust);
                    String trustStatus = parsedCanon != null ? "canonical"
                            : (outDoc.optBoolean("owned_locally", false) ? "self_owned"
                            : (!pinnedPub.isEmpty() && !resolvedPub.isEmpty() && !pinnedPub.equals(resolvedPub) ? "conflict"
                            : (!pinnedPub.isEmpty() && pinnedPub.equals(resolvedPub) ? "pinned" : "first_seen")));
                    outDoc.put("key_fingerprint", formatFingerprint(resolvedPub));
                    outDoc.put("canonical_domain", canonicalDomainFor(baseForTrust, resolvedPub));
                    outDoc.put("pinned_pubkey", pinnedPub);
                    outDoc.put("trust_status", trustStatus);
                    String pet = trustPetnames.getOrDefault(dom, trustPetnames.getOrDefault(resolvedPub, ""));
                    outDoc.put("petname", pet);
                    outDoc.put("conflicts", getTrustConflictsArray(baseForTrust));
                    String rawContent = outDoc.optString("raw_content", "");
                    boolean isEnc = "document".equals(outDoc.optString("kind", "document")) && E2eeSpaces.isEncryptedBlob(rawContent);
                    boolean isDec = !isEnc;
                    List<String> recips = new ArrayList<>();
                    if (isEnc) {
                        List<String> candidates = new ArrayList<>();
                        if (!outDoc.optString("privkey_hex", "").isEmpty()) candidates.add(outDoc.optString("privkey_hex"));
                        for (JSONObject dk : domainKeys.values()) {
                            String pk = dk.optString("privkey_hex", "");
                            if (!pk.isEmpty()) candidates.add(pk);
                        }
                        synchronized (docs) {
                            for (JSONObject docItem : docs.values()) {
                                String pk = docItem.optString("privkey_hex", "");
                                if (!pk.isEmpty()) candidates.add(pk);
                            }
                        }
                        E2eeSpaces.DecryptResult dec = E2eeSpaces.decryptWithPrivkeys(rawContent, candidates);
                        isDec = dec.decrypted;
                        recips = dec.recipients;
                        rawContent = dec.decrypted ? dec.plaintext : "🔒 End-to-End Encrypted Private .xnd Space.\n\nOnly invited Ed25519 keyholders can decrypt this document.";
                        outDoc.put("raw_content", rawContent);
                    }
                    outDoc.put("encrypted", isEnc);
                    outDoc.put("decrypted", isDec);
                    outDoc.put("allowed_pubkeys", new JSONArray(recips));
                    synchronized (docs) {
                        outDoc.put("backlinks", TransclusionEngine.computeBacklinks(dom, docs));
                        outDoc.put("segments", TransclusionEngine.buildSegments(rawContent, docs));
                    }
                    if (!outDoc.has("versions") || outDoc.getJSONArray("versions").length() == 0) {
                        outDoc.put("versions", new JSONArray().put(
                            new JSONObject()
                                .put("version_num", vNum)
                                .put("sha256", outDoc.optString("sha256", ""))
                                .put("title", outDoc.optString("title", dom))
                                .put("signature_hex", outDoc.optString("signature_hex", ""))
                        ));
                    }
                    String rawDocStr = outDoc.optString("raw_content", "").trim();
                    if (!"capsule".equals(outDoc.optString("kind")) && rawDocStr.startsWith("{") && rawDocStr.contains("\"files\"")) {
                        try {
                            JSONObject testB = new JSONObject(rawDocStr);
                            if (testB.optJSONObject("files") != null) outDoc.put("kind", "capsule");
                        } catch (Exception ignored) {}
                    }
                    if ("capsule".equals(outDoc.optString("kind"))) {
                        try {
                            JSONObject b = new JSONObject(outDoc.optString("raw_content", "{}"));
                            JSONObject filesObj = b.optJSONObject("files");
                            JSONArray fArr = new JSONArray();
                            if (filesObj != null) {
                                java.util.Iterator<String> it = filesObj.keys();
                                while (it.hasNext()) fArr.put(it.next());
                            }
                            outDoc.put("files", fArr);
                            outDoc.put("has_backend", !b.optString("backend_py", "").trim().isEmpty());
                            outDoc.put("raw_content", "");
                        } catch (Exception ignored) {}
                    }
                    sendJson(out, 200, outDoc.toString());
                }
            } else if (path.equals("/api/domains")) {
                JSONArray arr = new JSONArray();
                Set<String> seen = new HashSet<>();
                for (JSONObject d : docs.values()) {
                    String dn = d.optString("domain");
                    seen.add(dn);
                    arr.put(new JSONObject()
                            .put("name", dn)
                            .put("title", d.optString("title", dn))
                            .put("kind", d.optString("kind", "document"))
                            .put("latest_version", d.optInt("version_num", d.optInt("version", 1)))
                            .put("owned_locally", domainKeys.containsKey(dn))
                            .put("backlinks_count", 0));
                }
                for (String dn : domainKeys.keySet()) {
                    if (seen.contains(dn)) continue;
                    arr.put(new JSONObject()
                            .put("name", dn)
                            .put("title", dn)
                            .put("kind", "capsule")
                            .put("latest_version", 0)
                            .put("owned_locally", true)
                            .put("backlinks_count", 0));
                }
                sendJson(out, 200, new JSONObject().put("domains", arr).toString());
            } else if (path.startsWith("/api/repo/") && path.endsWith("/file")) {
                String dom = URLDecoder.decode(path.substring("/api/repo/".length(), path.length() - "/file".length()), "UTF-8").trim().toLowerCase(Locale.US);
                String filePath = parseQuery(query).getOrDefault("path", "index.html");
                JSONObject d = docs.get(dom);
                if (d == null) {
                    sendJson(out, 404, "{\"detail\":\"Domain not found\"}");
                } else if (!"capsule".equals(d.optString("kind"))) {
                    sendJson(out, 200, new JSONObject().put("domain", dom).put("path", "content.txt").put("content", d.optString("raw_content", "")).put("is_binary", false).toString());
                } else {
                    JSONObject b = new JSONObject(d.optString("raw_content", "{}"));
                    if ("backend.py".equals(filePath)) {
                        sendJson(out, 200, new JSONObject().put("domain", dom).put("path", "backend.py").put("content", b.optString("backend_py", "")).put("is_binary", false).toString());
                    } else {
                        JSONObject filesObj = b.optJSONObject("files");
                        if (filesObj == null || !filesObj.has(filePath)) {
                            sendJson(out, 404, "{\"detail\":\"File not found\"}");
                        } else {
                            String val = filesObj.optString(filePath, "");
                            boolean isBin = val.startsWith("data:") && val.contains(";base64,");
                            sendJson(out, 200, new JSONObject().put("domain", dom).put("path", filePath).put("content", isBin ? "(binary asset)" : val).put("is_binary", isBin).toString());
                        }
                    }
                }
            } else if (path.startsWith("/xnd-app/")) {
                String rest = path.substring("/xnd-app/".length());
                int slash = rest.indexOf('/');
                String dom = URLDecoder.decode(slash >= 0 ? rest.substring(0, slash) : rest, "UTF-8").trim().toLowerCase(Locale.US);
                String rel = slash >= 0 ? rest.substring(slash + 1) : "index.html";
                rel = rel.replaceAll("/+", "/");
                while (rel.startsWith("./")) rel = rel.substring(2);
                while (rel.startsWith("/")) rel = rel.substring(1);
                if (rel.isEmpty()) rel = "index.html";
                JSONObject d = docs.get(dom);
                boolean isCap = d != null && ("capsule".equals(d.optString("kind")) || (d.optString("raw_content", "").trim().startsWith("{") && d.optString("raw_content", "").contains("\"files\"")));
                if (!isCap) {
                    sendJson(out, 404, "{\"detail\":\"Site/Capsule not found\"}");
                } else {
                    JSONObject b = new JSONObject(d.optString("raw_content", "{}"));
                    JSONObject filesObj = b.optJSONObject("files");
                    if (filesObj != null && !filesObj.has(rel)) {
                        String trimmed = rel.replaceAll("/+$", "");
                        if (filesObj.has(trimmed + "/index.html")) rel = trimmed + "/index.html";
                        else if (filesObj.has(trimmed + ".html")) rel = trimmed + ".html";
                        else {
                            String relLow = rel.toLowerCase(Locale.US);
                            String trimLow = trimmed.toLowerCase(Locale.US);
                            java.util.Iterator<String> ki = filesObj.keys();
                            String matched = null;
                            while (ki.hasNext()) {
                                String k = ki.next();
                                String kl = k.toLowerCase(Locale.US);
                                if (kl.equals(relLow) || kl.equals(trimLow + "/index.html") || kl.equals(trimLow + ".html")) {
                                    matched = k;
                                    break;
                                }
                            }
                            if (matched != null) rel = matched;
                            else {
                                int ls = rel.lastIndexOf('/');
                                String leaf = ls >= 0 ? rel.substring(ls + 1) : rel;
                                if (!leaf.contains(".") && filesObj.has("index.html")) rel = "index.html";
                            }
                        }
                    }
                    if (filesObj == null || !filesObj.has(rel)) {
                        sendJson(out, 404, "{\"detail\":\"File not found\"}");
                    } else {
                        String val = filesObj.optString(rel, "");
                        if (val.startsWith("data:") && val.contains(";base64,")) {
                            int idx = val.indexOf(";base64,");
                            String mime = val.substring(5, idx);
                            byte[] rawBytes = android.util.Base64.decode(val.substring(idx + 8), android.util.Base64.DEFAULT);
                            sendBytes(out, 200, mime.isEmpty() ? "application/octet-stream" : mime, rawBytes);
                        } else {
                            String mime = guessMimeType(rel);
                            String appPrefix = "/xnd-app/" + dom + "/";
                            if (mime.startsWith("text/html")) {
                                val = Pattern.compile("(?i)\\b(href|src|action|poster|data-src)\\s*=\\s*([\"'])/(?!(/|xnd-app/|static/|api/))([^\"']*)\\2")
                                        .matcher(val)
                                        .replaceAll("$1=$2" + Matcher.quoteReplacement(appPrefix) + "$4$2");
                                String capToken = mintCapsuleToken(dom);
                                String baseTag = !val.toLowerCase(Locale.US).contains("<base ") ? "<base href=\"" + appPrefix + "\">" : "";
                                String shim = "<script>(function(){var p=" + nostrJsonString(appPrefix) + ",tok=" + nostrJsonString(capToken) + ";"
                                        + "function rw(u){return (typeof u==='string'&&u.startsWith('/')&&!u.startsWith('//')&&!u.startsWith('/xnd-app/')&&!u.startsWith('/api/')&&!u.startsWith('/static/'))?p+u.slice(1):u;}"
                                        + "function needsTok(u){return typeof u==='string'&&(u.indexOf('/api/app/')!==-1||u.indexOf('/api/sdk/')!==-1);}"
                                        + "var _f=window.fetch;if(_f){window.fetch=function(i,o){var u=(typeof i==='string')?rw(i):i;var us=(typeof u==='string')?u:(u&&u.url?u.url:'');if(needsTok(us)){o=Object.assign({},o||{});var h=new Headers(o.headers||(typeof i!=='string'&&i&&i.headers)||{});if(!h.has('X-Xnd-Cap-Token'))h.set('X-Xnd-Cap-Token',tok);o.headers=h;}return _f.call(this,u,o);};}"
                                        + "var _o=XMLHttpRequest.prototype.open,_s=XMLHttpRequest.prototype.send;"
                                        + "XMLHttpRequest.prototype.open=function(m,u){var ru=rw(u);this._xndUrl=ru;arguments[1]=ru;return _o.apply(this,arguments);};"
                                        + "XMLHttpRequest.prototype.send=function(){try{if(needsTok(this._xndUrl))this.setRequestHeader('X-Xnd-Cap-Token',tok);}catch(e){}return _s.apply(this,arguments);};"
                                        + "document.addEventListener('click',function(e){var a=e.target&&e.target.closest?e.target.closest('a[href]'):null;if(!a)return;var h=a.getAttribute('href');if(h&&h.startsWith('/')&&!h.startsWith('//')&&!h.startsWith('/xnd-app/')&&!h.startsWith('/api/')&&!h.startsWith('/static/')){a.setAttribute('href',rw(h));}},true);"
                                        + "})();</script>";
                                String sdkTag = "<script src=\"/static/xnd-sdk.js\" data-domain=\"" + dom + "\" data-cap-token=\"" + capToken + "\"></script>";
                                String inject = baseTag + shim + sdkTag;
                                Matcher hm = Pattern.compile("(?i)<head\\b[^>]*>").matcher(val);
                                if (hm.find()) {
                                    val = val.substring(0, hm.end()) + inject + val.substring(hm.end());
                                } else {
                                    val = inject + val;
                                }
                            } else if (mime.startsWith("text/css")) {
                                val = Pattern.compile("url\\(\\s*([\"']?)/(?!(/|xnd-app/|static/|api/))([^\"')]+)\\1\\s*\\)")
                                        .matcher(val)
                                        .replaceAll("url($1" + Matcher.quoteReplacement(appPrefix) + "$3$1)");
                                val = Pattern.compile("@import\\s+([\"'])/(?!(/|xnd-app/|static/|api/))([^\"']+)\\1")
                                        .matcher(val)
                                        .replaceAll("@import $1" + Matcher.quoteReplacement(appPrefix) + "$3$1");
                            }
                            Map<String, String> capHdrs = new HashMap<>();
                            capHdrs.put("X-Content-Type-Options", "nosniff");
                            capHdrs.put("Referrer-Policy", "no-referrer");
                            if (mime.startsWith("text/html")) {
                                capHdrs.put("Content-Security-Policy",
                                    "sandbox allow-scripts allow-forms allow-modals; default-src 'self' data: blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self' data:; connect-src 'self' data: blob:; frame-ancestors 'self'; base-uri 'self';");
                            } else {
                                capHdrs.put("Content-Security-Policy", "sandbox; default-src 'self' data: blob:; style-src 'self' 'unsafe-inline';");
                            }
                            sendBytesWithHeaders(out, 200, mime, val.getBytes(StandardCharsets.UTF_8), capHdrs);
                        }
                    }
                }
            } else if (path.equals("/api/sdk/store") && method.equals("GET")) {
                String dom = qp.getOrDefault("domain", "").trim().toLowerCase(Locale.US);
                if (!isCapsuleTokenAllowed(dom, reqCapToken, reqOrigin, reqReferer)) {
                    sendJson(out, 403, "{\"detail\":\"Invalid or missing X-Xnd-Cap-Token for this domain\"}");
                    return;
                }
                String key = qp.getOrDefault("key", "").trim();
                JSONObject st = loadCapsuleState(dom);
                JSONObject kv = st.optJSONObject("sdk_kv");
                if (kv == null) kv = new JSONObject();
                if (!key.isEmpty()) {
                    sendJson(out, 200, new JSONObject().put("ok", true).put("domain", dom).put("key", key).put("value", kv.opt(key)).toString());
                } else {
                    sendJson(out, 200, new JSONObject().put("ok", true).put("domain", dom).put("state", kv).toString());
                }
            } else if (path.equals("/api/sdk/store") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String dom = req.optString("domain", "").trim().toLowerCase(Locale.US);
                String key = req.optString("key", "").trim();
                if (!isCapsuleTokenAllowed(dom, reqCapToken, reqOrigin, reqReferer)) {
                    sendJson(out, 403, "{\"detail\":\"Invalid or missing X-Xnd-Cap-Token for this domain\"}");
                    return;
                }
                if (dom.isEmpty() || key.isEmpty()) {
                    sendJson(out, 400, "{\"detail\":\"domain and key are required\"}");
                    return;
                }
                JSONObject st = loadCapsuleState(dom);
                JSONObject kv = st.optJSONObject("sdk_kv");
                if (kv == null) kv = new JSONObject();
                if (req.optBoolean("delete", false)) kv.remove(key);
                else kv.put(key, req.opt("value"));
                st.put("sdk_kv", kv);
                saveCapsuleState(dom, st);
                sendJson(out, 200, new JSONObject().put("ok", true).put("domain", dom).put("key", key).toString());
            } else if (path.equals("/api/sdk/identity") && method.equals("GET")) {
                String dom = qp.getOrDefault("domain", "").trim().toLowerCase(Locale.US);
                if (!isCapsuleTokenAllowed(dom, reqCapToken, reqOrigin, reqReferer)) {
                    sendJson(out, 403, "{\"detail\":\"Invalid or missing X-Xnd-Cap-Token for this domain\"}");
                    return;
                }
                String[] kp = getOrCreateSdkSigningKey(dom);
                sendJson(out, 200, new JSONObject().put("ok", true).put("domain", dom).put("pubkey_hex", kp[0]).toString());
            } else if (path.equals("/api/sdk/sign") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String dom = req.optString("domain", "").trim().toLowerCase(Locale.US);
                if (!isCapsuleTokenAllowed(dom, reqCapToken, reqOrigin, reqReferer)) {
                    sendJson(out, 403, "{\"detail\":\"Invalid or missing X-Xnd-Cap-Token for this domain\"}");
                    return;
                }
                String msg = req.optString("message", "");
                String[] kp = getOrCreateSdkSigningKey(dom);
                String digest = TransclusionEngine.sha256Hex(msg);
                byte[] sk = Ed25519.fromHex(kp[1]);
                byte[] pk = Ed25519.fromHex(kp[0]);
                String sigHex = Ed25519.toHex(Ed25519.sign(digest.getBytes(StandardCharsets.UTF_8), sk, pk));
                sendJson(out, 200, new JSONObject().put("ok", true).put("domain", dom).put("pubkey_hex", kp[0]).put("sha256", digest).put("signature_hex", sigHex).toString());
            } else if (path.equals("/api/sdk/verify") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String msg = req.optString("message", "");
                String pub = req.optString("pubkey_hex", "").trim();
                String sig = req.optString("signature_hex", "").trim();
                String digest = TransclusionEngine.sha256Hex(msg);
                boolean valid = false;
                try {
                    valid = Ed25519.verify(digest.getBytes(StandardCharsets.UTF_8), Ed25519.fromHex(sig), Ed25519.fromHex(pub));
                } catch (Exception ignored) {}
                sendJson(out, 200, new JSONObject().put("ok", true).put("valid", valid).put("sha256", digest).toString());
            } else if (path.startsWith("/api/app/") && method.equals("POST")) {
                String rest = path.substring("/api/app/".length());
                int slash = rest.indexOf('/');
                if (slash <= 0 || slash >= rest.length() - 1) {
                    sendJson(out, 400, "{\"detail\":\"Invalid app action path\"}");
                    return;
                }
                String dom = URLDecoder.decode(rest.substring(0, slash), "UTF-8").trim().toLowerCase(Locale.US);
                if (!isCapsuleTokenAllowed(dom, reqCapToken, reqOrigin, reqReferer)) {
                    sendJson(out, 403, "{\"detail\":\"Invalid or missing X-Xnd-Cap-Token for this domain\"}");
                    return;
                }
                String action = URLDecoder.decode(rest.substring(slash + 1), "UTF-8").trim().toLowerCase(Locale.US);
                JSONObject payload = bodyStr != null && !bodyStr.trim().isEmpty() ? new JSONObject(bodyStr) : new JSONObject();
                JSONObject state = loadCapsuleState(dom);
                JSONObject resp;
                if ("forum.xnd".equals(dom)) {
                    JSONArray posts = state.optJSONArray("posts");
                    if (posts == null || posts.length() == 0) {
                        posts = new JSONArray().put(new JSONObject().put("id", 1).put("author", "@xanadu").put("text", "Zero-DB cryptographic app capsule online."));
                        state.put("posts", posts);
                    }
                    if ("post".equals(action)) {
                        String author = payload.optString("author", "anon").trim();
                        if (author.length() > 32) author = author.substring(0, 32);
                        if (author.isEmpty()) author = "anon";
                        String text = payload.optString("text", "").trim();
                        if (text.length() > 280) text = text.substring(0, 280);
                        if (!text.isEmpty()) {
                            JSONArray updated = new JSONArray();
                            updated.put(new JSONObject().put("id", posts.length() + 1).put("author", author).put("text", text));
                            for (int i = 0; i < posts.length(); i++) updated.put(posts.get(i));
                            posts = updated;
                            state.put("posts", posts);
                        }
                    }
                    saveCapsuleState(dom, state);
                    resp = new JSONObject().put("ok", true).put("posts", posts);
                } else {
                    int hits = state.optInt("hits", 0) + 1;
                    state.put("hits", hits);
                    saveCapsuleState(dom, state);
                    resp = new JSONObject().put("ok", true).put("action", action).put("hits", hits).put("state", state);
                }
                sendJson(out, 200, resp.toString());
            } else if (path.equals("/api/auth/status")) {
                File af = accountFile();
                if (!af.exists()) {
                    sendJson(out, 200, new JSONObject().put("configured", false).put("unlocked", false).put("username", "").put("username_hash", "").toString());
                } else {
                    String uname = "";
                    String uhash = "";
                    try {
                        JSONObject acct = new JSONObject(readFileStr(af));
                        uname = acct.optString("username", "");
                        uhash = acct.optString("username_hash", "");
                    } catch (Exception ignored) {}
                    sendJson(out, 200, new JSONObject().put("configured", true).put("unlocked", vaultUnlocked).put("username", uname).put("username_hash", uhash).toString());
                }
            } else if (path.equals("/api/auth/setup") && method.equals("POST")) {
                File af = accountFile();
                if (af.exists()) {
                    sendJson(out, 409, "{\"detail\":\"Private account already configured. Use Sign In.\"}");
                    return;
                }
                JSONObject req = new JSONObject(bodyStr);
                String uname = req.optString("username", "").trim();
                String pw = req.optString("password", "");
                if (uname.length() < 2 || pw.length() < 4) {
                    sendJson(out, 400, "{\"detail\":\"Username (2+ chars) and password (4+ chars) required.\"}");
                    return;
                }
                byte[] acctSk = Ed25519.generatePrivateKey();
                byte[] acctPk = Ed25519.publicKey(acctSk);
                String acctPrivHex = Ed25519.toHex(acctSk);
                String acctPubHex = Ed25519.toHex(acctPk);
                String uHash = "xnd-" + sha256Hex(uname + "|" + acctPubHex).substring(0, 10);
                byte[] sigPayload = ("xnd-account|" + uHash + "|" + acctPubHex).getBytes(StandardCharsets.UTF_8);
                String acctSigHex = Ed25519.toHex(Ed25519.sign(sigPayload, acctSk, acctPk));

                byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                byte[][] dk = deriveAccountKeys(pw, salt);
                JSONObject acct = new JSONObject()
                        .put("username", uname)
                        .put("username_hash", uHash)
                        .put("account_pubkey_hex", acctPubHex)
                        .put("account_sig_hex", acctSigHex)
                        .put("salt_hex", Ed25519.toHex(salt))
                        .put("auth_hash_hex", Ed25519.toHex(dk[0]));
                writeFileStr(af, acct.toString(2));
                vaultKey = dk[1];
                vaultUsername = uname;
                vaultUsernameHash = uHash;
                vaultAccountPrivkey = acctPrivHex;
                vaultUnlocked = true;
                saveVault();
                sendJson(out, 200, new JSONObject()
                        .put("ok", true)
                        .put("configured", true)
                        .put("unlocked", true)
                        .put("username", uname)
                        .put("username_hash", uHash)
                        .put("account_pubkey_hex", acctPubHex)
                        .put("account_privkey_hex", acctPrivHex)
                        .put("account_sig_hex", acctSigHex)
                        .toString());
            } else if (path.equals("/api/auth/login") && method.equals("POST")) {
                File af = accountFile();
                if (!af.exists()) {
                    sendJson(out, 404, "{\"detail\":\"No private account configured yet.\"}");
                    return;
                }
                JSONObject req = new JSONObject(bodyStr);
                String providedUhash = req.optString("username_hash", "").trim().toLowerCase(Locale.US);
                String pw = req.optString("password", "");
                String providedPriv = req.optString("account_privkey_hex", "").trim();
                JSONObject acct = new JSONObject(readFileStr(af));
                String expectedUhash = acct.optString("username_hash", "");
                if (!expectedUhash.isEmpty() && !MessageDigest.isEqual(providedUhash.getBytes(StandardCharsets.UTF_8), expectedUhash.getBytes(StandardCharsets.UTF_8))) {
                    sendJson(out, 401, "{\"detail\":\"Hashed username does not match this vault.\"}");
                    return;
                }
                byte[] salt = Ed25519.fromHex(acct.getString("salt_hex"));
                byte[] expectedHash = Ed25519.fromHex(acct.getString("auth_hash_hex"));
                byte[][] dk = deriveAccountKeys(pw, salt);
                if (!MessageDigest.isEqual(dk[0], expectedHash)) {
                    sendJson(out, 401, "{\"detail\":\"Incorrect password.\"}");
                    return;
                }
                String acctPubHex = acct.optString("account_pubkey_hex", "");
                String acctSigHex = acct.optString("account_sig_hex", "");
                if (!acctPubHex.isEmpty() && !acctSigHex.isEmpty()) {
                    byte[] msg = ("xnd-account|" + expectedUhash + "|" + acctPubHex).getBytes(StandardCharsets.UTF_8);
                    if (!Ed25519.verify(msg, Ed25519.fromHex(acctSigHex), Ed25519.fromHex(acctPubHex))) {
                        sendJson(out, 403, "{\"detail\":\"Account Ed25519 signature verification failed.\"}");
                        return;
                    }
                }
                if (!providedPriv.isEmpty()) {
                    try {
                        String derivedPub = Ed25519.toHex(Ed25519.publicKey(Ed25519.fromHex(providedPriv)));
                        if (!derivedPub.equals(acctPubHex)) {
                            sendJson(out, 401, "{\"detail\":\"Login hex key does not match account Ed25519 public key.\"}");
                            return;
                        }
                    } catch (Exception e) {
                        sendJson(out, 400, "{\"detail\":\"Invalid login hex key format.\"}");
                        return;
                    }
                }
                if (acct.has("vault_nonce_hex") && acct.has("vault_ct_hex")) {
                    byte[] nonce = Ed25519.fromHex(acct.getString("vault_nonce_hex"));
                    byte[] ct = Ed25519.fromHex(acct.getString("vault_ct_hex"));
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(dk[1], "AES"), new GCMParameterSpec(128, nonce));
                    JSONObject vaultObj = new JSONObject(new String(cipher.doFinal(ct), StandardCharsets.UTF_8));
                    JSONObject keyring = vaultObj.has("keyring") ? vaultObj.getJSONObject("keyring") : vaultObj;
                    if (vaultObj.has("account_privkey_hex")) {
                        vaultAccountPrivkey = vaultObj.optString("account_privkey_hex", "");
                    }
                    java.util.Iterator<String> it = keyring.keys();
                    while (it.hasNext()) {
                        String dName = it.next();
                        JSONObject kd = keyring.optJSONObject(dName);
                        if (kd != null && !kd.optString("privkey_hex", "").isEmpty()) {
                            domainKeys.put(dName, kd);
                        }
                    }
                    saveKeys();
                }
                vaultKey = dk[1];
                vaultUsername = acct.optString("username", "");
                vaultUsernameHash = expectedUhash;
                vaultUnlocked = true;
                sendJson(out, 200, new JSONObject().put("ok", true).put("configured", true).put("unlocked", true).put("username", vaultUsername).put("username_hash", vaultUsernameHash).toString());
            } else if (path.equals("/api/auth/download-account")) {
                File af = accountFile();
                if (!af.exists() || !vaultUnlocked || vaultAccountPrivkey.isEmpty()) {
                    sendJson(out, 403, "{\"detail\":\"Unlock your private account vault first.\"}");
                    return;
                }
                JSONObject acct = new JSONObject(readFileStr(af));
                String uhash = acct.optString("username_hash", vaultUsernameHash);
                byte[] payload = new JSONObject()
                        .put("username_hash", uhash)
                        .put("account_pubkey_hex", acct.optString("account_pubkey_hex", ""))
                        .put("account_privkey_hex", vaultAccountPrivkey)
                        .put("account_sig_hex", acct.optString("account_sig_hex", ""))
                        .toString(2)
                        .getBytes(StandardCharsets.UTF_8);
                sendDownload(out, 200, "application/json; charset=utf-8", uhash + ".xnd-account.json", payload);
            } else if (path.equals("/api/auth/logout") && method.equals("POST")) {
                vaultKey = null;
                vaultAccountPrivkey = "";
                vaultUnlocked = false;
                sendJson(out, 200, "{\"ok\":true,\"unlocked\":false}");
            } else if (path.equals("/api/domain/check")) {
                String dom = normalizeXndDomain(qp.getOrDefault("name", ""));
                if (!isValidXndDomain(dom)) {
                    sendJson(out, 200, new JSONObject().put("domain", dom).put("available", false).put("reason", "Invalid .xnd domain. Only letters, numbers, '-' and '.' between labels are allowed (e.g. domain-name.xnd or sub.domain.xnd).").toString());
                } else {
                    String label = dom.substring(0, dom.length() - 4);
                    if (label.length() <= 4) {
                        sendJson(out, 200, new JSONObject().put("domain", dom).put("available", false).put("reason", "Reserved 1–4 character .xnd domain").toString());
                    } else if (docs.containsKey(dom)) {
                        sendJson(out, 200, new JSONObject().put("domain", dom).put("available", false).put("reason", "Already registered on the .xnd network").toString());
                    } else {
                        lookupDocNostr(dom);
                        boolean taken = docs.containsKey(dom);
                        sendJson(out, 200, new JSONObject().put("domain", dom).put("available", !taken).put("reason", taken ? "Already registered on the .xnd network" : "Available for registration").toString());
                    }
                }
            } else if (path.equals("/api/domain/register") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String dom = normalizeXndDomain(req.optString("domain", ""));
                if (!isValidXndDomain(dom)) {
                    sendJson(out, 400, "{\"detail\":\"Invalid .xnd domain. Only letters, numbers, '-' and '.' between labels are allowed (e.g. domain-name.xnd or sub.domain.xnd).\"}");
                } else {
                    String label = dom.substring(0, dom.length() - 4);
                    if (label.length() <= 4) {
                        sendJson(out, 400, "{\"detail\":\"Reserved 1–4 character .xnd domain\"}");
                    } else {
                        if (!docs.containsKey(dom)) lookupDocNostr(dom);
                        if (docs.containsKey(dom) || domainKeys.containsKey(dom)) {
                            sendJson(out, 409, "{\"detail\":\"Name taken — claim another\"}");
                        } else {
                            String starterHtml = "<!doctype html><html><head><meta charset='utf-8'><title>" + dom + "</title>"
                                    + "<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:64px auto;padding:0 20px;line-height:1.6;color:#0f172a;}"
                                    + "code{background:#f1f5f9;padding:2px 6px;border-radius:6px;}</style></head>"
                                    + "<body><h1>" + dom + "</h1><p>Welcome to <code>" + dom + "</code> on the XND New Internet.</p>"
                                    + "<p>This domain is sovereignly registered with an Ed25519 keypair. Push your website files from the Xanadu Dashboard.</p>"
                                    + "</body></html>";
                            JSONObject filesObj = new JSONObject().put("index.html", starterHtml);
                            JSONObject res = publishLocalCapsule(dom, dom, filesObj, "", "");
                            if (vaultUnlocked) saveVault();
                            JSONObject kd = domainKeys.get(dom);
                            res.put("ok", true);
                            res.put("domain", dom);
                            res.put("pubkey_hex", kd != null ? kd.optString("pubkey_hex", "") : "");
                            res.put("privkey_hex", kd != null ? kd.optString("privkey_hex", "") : "");
                            res.put("is_new_domain", true);
                            sendJson(out, 200, res.toString());
                        }
                    }
                }
            } else if (path.startsWith("/api/keys/export/")) {
                if (accountFile().exists() && !vaultUnlocked) {
                    sendJson(out, 403, "{\"detail\":\"Account vault is locked. Unlock your Dashboard first.\"}");
                    return;
                }
                String dom = URLDecoder.decode(path.substring("/api/keys/export/".length()), "UTF-8").trim().toLowerCase(Locale.US);
                JSONObject k = domainKeys.get(dom);
                if (k == null || k.optString("privkey_hex", "").isEmpty()) {
                    sendJson(out, 403, "{\"detail\":\"This node does not hold the private key for this domain\"}");
                } else {
                    sendJson(out, 200, new JSONObject()
                            .put("domain", dom)
                            .put("pubkey_hex", k.optString("pubkey_hex", ""))
                            .put("privkey_hex", k.optString("privkey_hex", ""))
                            .toString());
                }
            } else if (path.startsWith("/api/keys/download/")) {
                if (accountFile().exists() && !vaultUnlocked) {
                    sendJson(out, 403, "{\"detail\":\"Account vault is locked. Unlock your Dashboard first.\"}");
                    return;
                }
                String dom = URLDecoder.decode(path.substring("/api/keys/download/".length()), "UTF-8").trim().toLowerCase(Locale.US);
                JSONObject k = domainKeys.get(dom);
                if (k == null || k.optString("privkey_hex", "").isEmpty()) {
                    sendJson(out, 403, "{\"detail\":\"This node does not hold the private key for this domain\"}");
                } else {
                    String safeName = dom.replaceAll("[^a-z0-9._-]", "_") + ".key.json";
                    byte[] payload = new JSONObject()
                            .put("domain", dom)
                            .put("pubkey_hex", k.optString("pubkey_hex", ""))
                            .put("privkey_hex", k.optString("privkey_hex", ""))
                            .toString(2)
                            .getBytes(StandardCharsets.UTF_8);
                    sendDownload(out, 200, "application/json; charset=utf-8", safeName, payload);
                }
            } else if (path.equals("/api/keys/import") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String dom = normalizeXndDomain(req.optString("domain", ""));
                String privHex = req.optString("privkey_hex", "").trim();
                if (!isValidXndDomain(dom) || privHex.length() < 64) {
                    sendJson(out, 400, "{\"detail\":\"Invalid .xnd domain or Ed25519 private key hex\"}");
                } else {
                    try {
                        byte[] sk = Ed25519.fromHex(privHex);
                        byte[] pk = Ed25519.publicKey(sk);
                        String derivedPub = Ed25519.toHex(pk);
                        if (!docs.containsKey(dom)) lookupDocNostr(dom);
                        JSONObject existing = docs.get(dom);
                        String existingPub = existing != null ? existing.optString("pubkey_hex", existing.optString("pubkey", "")) : "";
                        if (!existingPub.isEmpty() && !existingPub.equals(derivedPub)) {
                            sendJson(out, 403, "{\"detail\":\"Private key does not match the registered public key\"}");
                        } else {
                            JSONObject kd = new JSONObject().put("pubkey_hex", derivedPub).put("privkey_hex", privHex);
                            domainKeys.put(dom, kd);
                            saveKeys();
                            if (vaultUnlocked) saveVault();
                            if (existing != null) {
                                existing.put("owned_locally", true);
                                existing.put("pubkey", derivedPub);
                                existing.put("pubkey_hex", derivedPub);
                                saveDocs();
                            }
                            sendJson(out, 200, new JSONObject().put("ok", true).put("domain", dom).put("pubkey_hex", derivedPub).toString());
                        }
                } catch (Exception e) {
                    sendJson(out, 400, "{\"detail\":\"Invalid Ed25519 private key hex\"}");
                }
            }
        } else if (path.equals("/api/github/status")) {
            sendJson(out, 200, ghHosting.getStatus().toString());
        } else if (path.equals("/api/github/connect") && method.equals("POST")) {
            try {
                JSONObject req = new JSONObject(bodyStr);
                JSONObject st = ghHosting.connect(req.optString("token", ""));
                st.put("ok", true);
                sendJson(out, 200, st.toString());
            } catch (Exception e) {
                sendJson(out, 400, new JSONObject().put("detail", e.getMessage() != null ? e.getMessage() : "GitHub auth failed").toString());
            }
        } else if (path.equals("/api/github/disconnect") && method.equals("POST")) {
            sendJson(out, 200, ghHosting.disconnect().toString());
        } else if (path.equals("/api/github/device/start") && method.equals("POST")) {
            try {
                sendJson(out, 200, ghHosting.startDeviceFlow().toString());
            } catch (Exception e) {
                sendJson(out, 400, new JSONObject().put("detail", e.getMessage() != null ? e.getMessage() : "Device login start failed").toString());
            }
        } else if (path.equals("/api/github/device/poll") && method.equals("POST")) {
            try {
                JSONObject req = new JSONObject(bodyStr);
                sendJson(out, 200, ghHosting.pollDeviceFlow(req.optString("device_code", "")).toString());
            } catch (Exception e) {
                sendJson(out, 400, new JSONObject().put("detail", e.getMessage() != null ? e.getMessage() : "Device login poll failed").toString());
            }
        } else if (path.equals("/api/github/repos")) {
            try {
                sendJson(out, 200, new JSONObject().put("repos", ghHosting.listRepos()).toString());
            } catch (Exception e) {
                sendJson(out, 400, new JSONObject().put("detail", e.getMessage() != null ? e.getMessage() : "Failed listing repos").toString());
            }
        } else if (path.equals("/api/github/deploy") && method.equals("POST")) {
            try {
                JSONObject req = new JSONObject(bodyStr);
                String dom = normalizeXndDomain(req.optString("domain", ""));
                if (!isValidXndDomain(dom)) {
                    sendJson(out, 400, "{\"detail\":\"Invalid .xnd domain.\"}");
                    return;
                }
                String repoReq = req.optString("repo", "").trim();
                JSONObject existingLinks = ghHosting.loadLinks();
                JSONObject existingLink = existingLinks.optJSONObject(dom);
                if (existingLink != null) {
                    String lockedRepo = existingLink.optString("repo", "").trim();
                    if (!lockedRepo.isEmpty() && !lockedRepo.equalsIgnoreCase(repoReq)) {
                        sendJson(out, 409, new JSONObject().put("detail", "Domain '" + dom + "' is permanently locked to '" + lockedRepo + "'. Detach it first using the Domain Private Key.").toString());
                        return;
                    }
                }
                java.util.Iterator<String> linkKeys = existingLinks.keys();
                while (linkKeys.hasNext()) {
                    String otherDom = linkKeys.next();
                    if (otherDom.equals(dom)) continue;
                    JSONObject otherInfo = existingLinks.optJSONObject(otherDom);
                    if (otherInfo != null && otherInfo.optString("repo", "").trim().equalsIgnoreCase(repoReq)) {
                        sendJson(out, 409, new JSONObject().put("detail", "Repository '" + repoReq + "' is already locked to '" + otherDom + "'. Detach '" + otherDom + "' first using its Domain Private Key.").toString());
                        return;
                    }
                }
                GitHubHosting.RepoBundle bundle = ghHosting.fetchRepoBundle(
                        req.optString("repo", ""),
                        req.optString("branch", ""),
                        req.optString("subdir", "")
                );
                String privkeyHex = req.optString("privkey_hex", "").trim();
                if (privkeyHex.isEmpty() && domainKeys.containsKey(dom)) {
                    privkeyHex = domainKeys.get(dom).optString("privkey_hex", "");
                }
                String title = req.optString("title", "").trim();
                if (title.isEmpty()) title = dom;
                String repoName = req.optString("repo", "").trim();
                String subDir = req.optString("subdir", "").trim();
                JSONObject res = publishLocalCapsule(dom, title, bundle.files, bundle.backendPy, privkeyHex);
                if (vaultUnlocked) saveVault();
                String commitSha = "";
                try { commitSha = ghHosting.getLatestCommitSha(repoName, bundle.branch); } catch (Exception ignored) {}
                ghHosting.saveLink(dom, repoName, bundle.branch, subDir, commitSha);
                res.put("ok", true).put("repo", repoName).put("branch", bundle.branch).put("files_count", bundle.files.length()).put("auto_sync", true);
                sendJson(out, 200, res.toString());
            } catch (Exception e) {
                sendJson(out, 400, new JSONObject().put("detail", e.getMessage() != null ? e.getMessage() : "GitHub deploy failed").toString());
            }
        } else if (path.equals("/api/github/links") && method.equals("GET")) {
            sendJson(out, 200, new JSONObject().put("links", ghHosting.loadLinks()).toString());
        } else if (path.equals("/api/github/detach") && method.equals("POST")) {
            try {
                JSONObject req = new JSONObject(bodyStr);
                String dom = normalizeXndDomain(req.optString("domain", ""));
                String privHex = req.optString("privkey_hex", "").trim();
                if (!isValidXndDomain(dom)) {
                    sendJson(out, 400, "{\"detail\":\"Invalid .xnd domain.\"}");
                    return;
                }
                if (privHex.length() < 64) {
                    sendJson(out, 400, "{\"detail\":\"Valid Domain Private Key is required to detach.\"}");
                    return;
                }
                String derivedPub = Ed25519.toHex(Ed25519.publicKey(Ed25519.fromHex(privHex)));
                String expectedPub = "";
                if (domainKeys.containsKey(dom)) expectedPub = domainKeys.get(dom).optString("pubkey_hex", "");
                if (expectedPub.isEmpty() && docs.containsKey(dom)) expectedPub = docs.get(dom).optString("pubkey_hex", "");
                if (expectedPub.isEmpty() || !expectedPub.equals(derivedPub)) {
                    sendJson(out, 403, "{\"detail\":\"Private key does not match this domain.\"}");
                    return;
                }
                ghHosting.removeLink(dom);
                sendJson(out, 200, new JSONObject().put("ok", true).put("domain", dom).put("detached", true).toString());
            } catch (Exception e) {
                sendJson(out, 400, "{\"detail\":\"Invalid Ed25519 private key.\"}");
            }
        } else if (path.equals("/api/github/setup-action") && method.equals("POST")) {
            try {
                JSONObject req = new JSONObject(bodyStr);
                JSONObject res = ghHosting.installBuildWorkflow(req.optString("repo", ""), req.optString("branch", ""));
                sendJson(out, 200, res.toString());
            } catch (Exception e) {
                sendJson(out, 400, new JSONObject().put("detail", e.getMessage() != null ? e.getMessage() : "Workflow setup failed").toString());
            }
        } else if (path.equals("/api/github/push") && method.equals("POST")) {
            try {
                JSONObject req = new JSONObject(bodyStr);
                String dom = normalizeXndDomain(req.optString("domain", ""));
                JSONObject d = docs.get(dom);
                if (d == null) {
                    sendJson(out, 404, "{\"detail\":\"Domain not found locally\"}");
                    return;
                }
                JSONObject filesObj = new JSONObject();
                String backendPy = "";
                if ("capsule".equals(d.optString("kind"))) {
                    JSONObject b = new JSONObject(d.optString("raw_content", "{}"));
                    if (b.optJSONObject("files") != null) filesObj = b.getJSONObject("files");
                    backendPy = b.optString("backend_py", "");
                } else {
                    filesObj.put("content.txt", d.optString("raw_content", ""));
                }
                JSONObject pushed = ghHosting.pushFilesToRepo(
                        req.optString("repo", ""),
                        req.optString("branch", ""),
                        req.optString("subdir", ""),
                        filesObj,
                        backendPy,
                        req.optString("message", "Update site from Xanadu")
                );
                sendJson(out, 200, pushed.toString());
            } catch (Exception e) {
                sendJson(out, 400, new JSONObject().put("detail", e.getMessage() != null ? e.getMessage() : "GitHub push failed").toString());
            }
        } else if (path.equals("/api/keys/sync-export") && method.equals("POST")) {
            JSONObject req = new JSONObject(bodyStr);
            String pw = req.optString("passphrase", "").trim();
            if (pw.length() < 4) {
                sendJson(out, 400, "{\"detail\":\"Passphrase must be at least 4 characters.\"}");
                return;
            }
            String domFilter = req.optString("domain", "").trim().toLowerCase(Locale.US);
            if (!domFilter.isEmpty() && !domFilter.endsWith(".xnd")) domFilter += ".xnd";
            JSONArray ids = new JSONArray();
            for (Map.Entry<String, JSONObject> e : domainKeys.entrySet()) {
                if (!domFilter.isEmpty() && !domFilter.equals(e.getKey())) continue;
                JSONObject kd = e.getValue();
                ids.put(new JSONObject()
                        .put("domain", e.getKey())
                        .put("pubkey_hex", kd.optString("pubkey_hex", ""))
                        .put("privkey_hex", kd.optString("privkey_hex", "")));
            }
            if (ids.length() == 0) {
                sendJson(out, 404, "{\"detail\":\"No owned domain keys available to export.\"}");
                return;
            }
            byte[] plain = new JSONObject().put("identities", ids).put("ts", System.currentTimeMillis() / 1000L).toString().getBytes(StandardCharsets.UTF_8);
            byte[] salt = new byte[16];
            byte[] nonce = new byte[12];
            SecureRandom rng = new SecureRandom();
            rng.nextBytes(salt);
            rng.nextBytes(nonce);
            PBEKeySpec spec = new PBEKeySpec(pw.toCharArray(), salt, 100000, 256);
            byte[] keyBytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new GCMParameterSpec(128, nonce));
            byte[] ct = c.doFinal(plain);
            byte[] combined = new byte[salt.length + nonce.length + ct.length];
            System.arraycopy(salt, 0, combined, 0, 16);
            System.arraycopy(nonce, 0, combined, 16, 12);
            System.arraycopy(ct, 0, combined, 28, ct.length);
            String token = "XNDKEY1:" + Base64.getEncoder().encodeToString(combined);
            sendJson(out, 200, new JSONObject().put("ok", true).put("token", token).put("count", ids.length()).toString());
        } else if (path.equals("/api/keys/sync-import") && method.equals("POST")) {
            JSONObject req = new JSONObject(bodyStr);
            String tok = req.optString("token", "").trim();
            String pw = req.optString("passphrase", "").trim();
            if (!tok.startsWith("XNDKEY1:") || pw.isEmpty()) {
                sendJson(out, 400, "{\"detail\":\"Invalid XNDKEY1 token or passphrase.\"}");
                return;
            }
            try {
                byte[] raw = Base64.getDecoder().decode(tok.substring("XNDKEY1:".length()));
                byte[] salt = java.util.Arrays.copyOfRange(raw, 0, 16);
                byte[] nonce = java.util.Arrays.copyOfRange(raw, 16, 28);
                byte[] ct = java.util.Arrays.copyOfRange(raw, 28, raw.length);
                PBEKeySpec spec = new PBEKeySpec(pw.toCharArray(), salt, 100000, 256);
                byte[] keyBytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new GCMParameterSpec(128, nonce));
                String plain = new String(c.doFinal(ct), StandardCharsets.UTF_8);
                JSONArray ids = new JSONObject(plain).optJSONArray("identities");
                int imported = 0;
                if (ids != null) {
                    for (int i = 0; i < ids.length(); i++) {
                        JSONObject item = ids.getJSONObject(i);
                        String dom = item.optString("domain", "").trim().toLowerCase(Locale.US);
                        String privHex = item.optString("privkey_hex", "").trim();
                        if (dom.isEmpty() || privHex.isEmpty()) continue;
                        byte[] pubB = Ed25519.publicKey(Ed25519.fromHex(privHex));
                        String pubHex = Ed25519.toHex(pubB);
                        JSONObject exDoc = docs.get(dom);
                        if (exDoc != null && !exDoc.optString("pubkey_hex", "").isEmpty() && !pubHex.equals(exDoc.optString("pubkey_hex", ""))) continue;
                        domainKeys.put(dom, new JSONObject().put("domain", dom).put("pubkey_hex", pubHex).put("privkey_hex", privHex));
                        imported++;
                    }
                    saveKeys();
                }
                sendJson(out, 200, new JSONObject().put("ok", true).put("imported", imported).toString());
            } catch (Exception e) {
                sendJson(out, 400, "{\"detail\":\"Failed to decrypt key sync token (wrong passphrase or corrupted token).\"}");
            }
        } else if (path.equals("/api/keys/bundle")) {
                if (method.equals("POST")) {
                    JSONObject req = new JSONObject(bodyStr);
                    JSONArray ids = req.optJSONArray("identities");
                    int imported = 0;
                    if (ids != null) {
                        for (int i = 0; i < ids.length(); i++) {
                            JSONObject item = ids.optJSONObject(i);
                            if (item == null) continue;
                            String dom = item.optString("domain", "").trim().toLowerCase(Locale.US);
                            String privHex = item.optString("privkey_hex", "").trim();
                            if (!dom.matches("^[a-z0-9][a-z0-9\\-]{0,62}\\.xnd$") || privHex.length() < 64) continue;
                            try {
                                byte[] sk = Ed25519.fromHex(privHex);
                                String derivedPub = Ed25519.toHex(Ed25519.publicKey(sk));
                                JSONObject existing = docs.get(dom);
                                String existingPub = existing != null ? existing.optString("pubkey_hex", existing.optString("pubkey", "")) : "";
                                if (!existingPub.isEmpty() && !existingPub.equals(derivedPub)) continue;
                                domainKeys.put(dom, new JSONObject().put("pubkey_hex", derivedPub).put("privkey_hex", privHex));
                                if (existing != null) {
                                    existing.put("owned_locally", true);
                                    existing.put("pubkey", derivedPub);
                                    existing.put("pubkey_hex", derivedPub);
                                }
                                imported++;
                            } catch (Exception ignored) {
                            }
                        }
                        if (imported > 0) {
                            saveKeys();
                            saveDocs();
                        }
                    }
                    sendJson(out, 200, new JSONObject().put("ok", true).put("imported_keys", imported).toString());
                } else {
                    JSONArray ids = new JSONArray();
                    for (Map.Entry<String, JSONObject> entry : domainKeys.entrySet()) {
                        JSONObject kd = entry.getValue();
                        String privHex = kd.optString("privkey_hex", "");
                        if (privHex.isEmpty()) continue;
                        ids.put(new JSONObject()
                                .put("domain", entry.getKey())
                                .put("pubkey_hex", kd.optString("pubkey_hex", ""))
                                .put("privkey_hex", privHex));
                    }
                    sendJson(out, 200, new JSONObject().put("identities", ids).toString());
                }
            } else if (path.equals("/api/moderation")) {
                sendJson(out, 200, moderationJson().toString());
            } else if (path.equals("/api/moderation/block") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String dom = req.optString("domain", "").trim().toLowerCase(Locale.US);
                String pub = req.optString("pubkey_hex", "").trim().toLowerCase(Locale.US);
                if (!dom.isEmpty()) {
                    blockedDomains.add(dom);
                    docs.remove(dom);
                }
                if (!pub.isEmpty()) {
                    blockedPubkeys.add(pub);
                    synchronized (docs) {
                        docs.entrySet().removeIf(e -> pub.equalsIgnoreCase(e.getValue().optString("pubkey_hex", e.getValue().optString("pubkey", ""))));
                    }
                }
                saveDocs();
                saveModeration();
                sendJson(out, 200, moderationJson().put("ok", true).toString());
            } else if (path.equals("/api/moderation/unblock") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String dom = req.optString("domain", "").trim().toLowerCase(Locale.US);
                String pub = req.optString("pubkey_hex", "").trim().toLowerCase(Locale.US);
                if (!dom.isEmpty()) blockedDomains.remove(dom);
                if (!pub.isEmpty()) blockedPubkeys.remove(pub);
                saveModeration();
                sendJson(out, 200, moderationJson().put("ok", true).toString());
            } else if (path.equals("/api/moderation/delete_domain") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String dom = req.optString("domain", "").trim().toLowerCase(Locale.US);
                boolean removed = !dom.isEmpty() && docs.remove(dom) != null;
                if (removed) saveDocs();
                sendJson(out, 200, new JSONObject().put("ok", true).put("deleted", removed).put("domain", dom).toString());
            } else if (path.equals("/api/moderation/follow") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String pub = req.optString("pubkey_hex", "").trim().toLowerCase(Locale.US);
                if (!pub.isEmpty()) {
                    if (followedPubkeys.contains(pub)) followedPubkeys.remove(pub);
                    else followedPubkeys.add(pub);
                    saveModeration();
                }
                sendJson(out, 200, moderationJson().put("ok", true).toString());
            } else if (path.equals("/api/peers/subscribe") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String u = req.optString("url", "").trim().replaceAll("/+$", "");
                boolean sub = req.optBoolean("subscribed", true);
                for (JSONObject p : peers) {
                    if (u.equals(p.optString("url", ""))) {
                        p.put("subscribed", sub);
                        savePeers();
                        break;
                    }
                }
                sendJson(out, 200, new JSONObject().put("ok", true).put("peers", new JSONArray(peers)).toString());
            } else if (path.equals("/api/peers")) {
                JSONObject g = new JSONObject().put("interval_sec", 15).put("total_imported", gossipImported);
                sendJson(out, 200, new JSONObject().put("peers", new JSONArray(peers)).put("gossip", g).toString());
            } else if (path.equals("/api/peers/pull") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String peerUrl = req.optString("url", "").trim().replaceAll("/+$", "");
                if (!peerUrl.startsWith("http://") && !peerUrl.startsWith("https://")) {
                    sendJson(out, 400, "{\"detail\":\"Peer URL must start with http:// or https://\"}");
                    return;
                }
                try {
                    int[] stats = pullFromPeer(peerUrl, req.optString("label", "Peer Node"));
                    sendJson(out, 200, new JSONObject()
                            .put("ok", true)
                            .put("peer", peerUrl)
                            .put("imported_versions", stats[0])
                            .put("rejected", stats[1])
                            .toString());
                } catch (Exception e) {
                    sendJson(out, 502, new JSONObject().put("detail", "Failed to reach peer " + peerUrl + ": " + e.getMessage()).toString());
                }
            } else if (path.equals("/api/peers/announce") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr);
                String peerUrl = req.optString("url", "").trim().replaceAll("/+$", "");
                if (!peerUrl.startsWith("http://") && !peerUrl.startsWith("https://")) {
                    sendJson(out, 400, "{\"detail\":\"Peer URL must start with http:// or https://\"}");
                    return;
                }
                upsertPeer(peerUrl, req.optString("label", "PEX Peer"), 0.0);
                sendJson(out, 200, new JSONObject().put("ok", true).put("known_peers", new JSONArray(peers)).toString());
            } else if (path.equals("/api/nat/status")) {
                sendJson(out, 200, (natTunnel != null ? natTunnel.status() : new JSONObject().put("ok", false).put("stun_ok", false)).toString());
            } else if (path.equals("/api/home/commons")) {
                Map<String, String> qm = parseQuery(query);
                String modeVal = qm.getOrDefault("mode", "all");
                int limitVal = 24;
                if (qm.containsKey("limit")) {
                    try { limitVal = Math.max(1, Math.min(60, Integer.parseInt(qm.get("limit")))); } catch (Exception ignored) {}
                }
                sendJson(out, 200, exportHomeCommons(modeVal, limitVal).toString());
            } else if (path.equals("/api/sync/manifest")) {
                Map<String, String> qm = parseQuery(query);
                double sinceVal = 0.0;
                int limitVal = 500;
                boolean hasSince = qm.containsKey("since");
                if (hasSince) {
                    try { sinceVal = Double.parseDouble(qm.get("since")); } catch (Exception ignored) {}
                }
                if (qm.containsKey("limit")) {
                    try { limitVal = Math.max(1, Math.min(2000, Integer.parseInt(qm.get("limit")))); } catch (Exception ignored) {}
                }
                sendJson(out, 200, (hasSince ? exportManifest(sinceVal, limitVal) : exportManifest()).toString());
            } else if (path.equals("/api/config/public-gateway") && method.equals("GET")) {
                String gwUrl = "http://127.0.0.1:" + port;
                try {
                    File gwFile = new File(dataDir, "public_gateway.json");
                    if (gwFile.exists()) {
                        try (FileInputStream fis = new FileInputStream(gwFile)) {
                            String u = new JSONObject(new String(readAll(fis), StandardCharsets.UTF_8)).optString("url", "").trim().replaceAll("/+$", "");
                            if (!u.isEmpty()) gwUrl = u;
                        }
                    }
                } catch (Exception ignored) {}
                sendJson(out, 200, new JSONObject().put("ok", true).put("url", gwUrl).toString());
            } else if (path.equals("/api/config/public-gateway") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr.isEmpty() ? "{}" : bodyStr);
                String u = req.optString("url", "").trim().replaceAll("/+$", "");
                if (!u.startsWith("http://") && !u.startsWith("https://")) {
                    sendJson(out, 400, "{\"detail\":\"Public gateway URL must start with http:// or https://\"}");
                } else {
                    try (FileOutputStream fos = new FileOutputStream(new File(dataDir, "public_gateway.json"))) {
                        fos.write(new JSONObject().put("url", u).toString(2).getBytes(StandardCharsets.UTF_8));
                    }
                    sendJson(out, 200, new JSONObject().put("ok", true).put("url", u).toString());
                }
            } else if (path.startsWith("/site/")) {
                String rest = path.substring("/site/".length());
                int slashIdx = rest.indexOf('/');
                String rawDom = URLDecoder.decode(slashIdx >= 0 ? rest.substring(0, slashIdx) : rest, "UTF-8");
                String assetRel = slashIdx >= 0 ? rest.substring(slashIdx + 1) : "index.html";
                if (assetRel.isEmpty()) assetRel = "index.html";
                String cleanDom = normalizeXndDomain(rawDom);
                if (!docs.containsKey(cleanDom)) lookupDocNostr(cleanDom);
                JSONObject doc = docs.get(cleanDom);
                if (doc == null) {
                    sendJson(out, 404, "{\"detail\":\"Domain not found\"}");
                } else if ("capsule".equals(doc.optString("kind"))) {
                    out.write(("HTTP/1.1 307 Temporary Redirect\r\nLocation: /xnd-app/" + URLEncoder.encode(cleanDom, "UTF-8") + "/" + assetRel + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.UTF_8));
                    out.flush();
                } else {
                    String rawContent = doc.optString("raw_content", "");
                    JSONArray segs = TransclusionEngine.buildSegments(rawContent, docs);
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < segs.length(); i++) {
                        JSONObject seg = segs.optJSONObject(i);
                        if (seg == null) continue;
                        String st = seg.optString("type", "");
                        if ("text".equals(st)) {
                            sb.append(escapeHtmlSimple(seg.optString("text", "")));
                        } else if ("transclusion".equals(st)) {
                            sb.append("<blockquote style=\"margin:10px 0;padding:10px 14px;border-left:3px solid #2563eb;background:#f8fafc;border-radius:6px;\"><div style=\"font-size:11px;color:#64748b;margin-bottom:4px;\">xnd://")
                                    .append(escapeHtmlSimple(seg.optString("target_domain", ""))).append("</div>")
                                    .append(escapeHtmlSimple(seg.optString("quoted_text", ""))).append("</blockquote>");
                        } else if ("broken_transclusion".equals(st)) {
                            sb.append("<code>").append(escapeHtmlSimple(seg.optString("raw", ""))).append("</code>");
                        }
                    }
                    String title = escapeHtmlSimple(doc.optString("title", cleanDom));
                    int ver = doc.optInt("version_num", doc.optInt("version", 1));
                    String page = "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>"
                            + title + " — xnd://" + escapeHtmlSimple(cleanDom) + "</title>"
                            + "<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:760px;margin:48px auto;padding:0 20px;line-height:1.7;color:#0f172a;background:#fff;}"
                            + ".meta{font-family:ui-monospace,monospace;font-size:12px;color:#64748b;margin-bottom:8px;}h1{margin:0 0 18px;font-size:28px;}article{white-space:pre-wrap;font-size:16px;}</style></head>"
                            + "<body><div class='meta'>xnd://" + escapeHtmlSimple(cleanDom) + " · v" + ver + "</div><h1>" + title + "</h1><article>" + sb + "</article></body></html>";
                    sendBytes(out, 200, "text/html; charset=utf-8", page.getBytes(StandardCharsets.UTF_8));
                }
            } else if (path.equals("/api/gateway/status")) {
                boolean hw = checkHasWan();
                JSONObject gw = hw ? null : findLanGateway();
                JSONObject res = new JSONObject().put("ok", true).put("has_wan", hw).put("share_gateway", shareGateway);
                res.put("active_gateway", gw != null ? gw : JSONObject.NULL);
                sendJson(out, 200, res.toString());
            } else if (path.equals("/api/gateway/toggle") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr.isEmpty() ? "{}" : bodyStr);
                shareGateway = req.optBoolean("share_gateway", true);
                sendJson(out, 200, new JSONObject().put("ok", true).put("share_gateway", shareGateway).toString());
            } else if (path.equals("/api/gateway/lookup")) {
                if (!shareGateway) {
                    sendJson(out, 403, "{\"detail\":\"Mesh gateway sharing disabled\"}");
                } else {
                    String domQ = normalizeXndDomain(qp.getOrDefault("domain", ""));
                    if (!domQ.isEmpty() && !docs.containsKey(domQ)) lookupDocNostr(domQ);
                    JSONObject bundle = exportDomainBundle(domQ);
                    if (bundle.optJSONArray("versions") == null || bundle.optJSONArray("versions").length() == 0) {
                        sendJson(out, 404, "{\"detail\":\"Domain not found\"}");
                    } else {
                        sendJson(out, 200, bundle.toString());
                    }
                }
            } else if (path.equals("/api/gateway/search")) {
                if (!shareGateway) {
                    sendJson(out, 403, "{\"detail\":\"Mesh gateway sharing disabled\"}");
                } else {
                    String q = qp.getOrDefault("q", "");
                    sendJson(out, 200, searchAll(q, false).toString());
                }
            } else if (path.equals("/api/gateway/nostr_publish") && method.equals("POST")) {
                if (!shareGateway) {
                    sendJson(out, 403, "{\"detail\":\"Mesh gateway sharing disabled\"}");
                } else {
                    JSONObject req = new JSONObject(bodyStr.isEmpty() ? "{}" : bodyStr);
                    JSONObject ev = req.optJSONObject("event");
                    if (ev == null || ev.optString("id", "").isEmpty() || ev.optString("sig", "").isEmpty()) {
                        sendJson(out, 400, "{\"detail\":\"Invalid Nostr event\"}");
                    } else {
                        String evMsg = "[\"EVENT\"," + ev.toString() + "]";
                        int acc = relayRawNostrEvent(evMsg);
                        sendJson(out, 200, new JSONObject().put("ok", acc > 0).put("accepted", acc).toString());
                    }
                }
            } else if (path.equals("/api/dht/find")) {
                String clean = normalizeXndDomain(qp.getOrDefault("domain", ""));
                if (clean.isEmpty()) {
                    sendJson(out, 400, "{\"detail\":\"Missing domain\"}");
                } else if (docs.containsKey(clean)) {
                    sendJson(out, 200, new JSONObject().put("ok", true).put("found", true).put("domain", clean).put("bundle", exportDomainBundle(clean)).toString());
                } else {
                    List<String> cands = collectActivePeerUrls();
                    cands.sort((a, b) -> dhtDistanceHex(a, clean).compareTo(dhtDistanceHex(b, clean)));
                    JSONArray closest = new JSONArray();
                    for (int i = 0; i < Math.min(6, cands.size()); i++) {
                        closest.put(new JSONObject().put("url", cands.get(i)).put("label", "Peer"));
                    }
                    sendJson(out, 200, new JSONObject().put("ok", true).put("found", false).put("domain", clean).put("closest_peers", closest).toString());
                }
            } else if (path.startsWith("/api/consensus/")) {
                String clean = normalizeXndDomain(URLDecoder.decode(path.substring("/api/consensus/".length()), "UTF-8"));
                JSONObject doc = docs.get(clean);
                String pub = doc != null ? doc.optString("pubkey_hex", doc.optString("pubkey", "")) : getPinnedPubkey(clean);
                JSONObject pinRec = trustPins.get(clean);
                String pinSrc = pinRec != null ? pinRec.optString("source", "") : (domainKeys.containsKey(clean) ? "self" : "first_seen");
                JSONArray confArr = new JSONArray();
                Map<String, String> cBucket = trustConflicts.get(clean);
                if (cBucket != null) {
                    for (Map.Entry<String, String> ce : cBucket.entrySet()) {
                        confArr.put(new JSONObject().put("alias_domain", ce.getKey()).put("pubkey_hex", ce.getValue()));
                    }
                }
                sendJson(out, 200, new JSONObject()
                        .put("ok", true)
                        .put("domain", clean)
                        .put("pubkey_hex", pub)
                        .put("canonical_domain", pub.isEmpty() ? clean : canonicalDomainFor(clean, pub))
                        .put("pin_source", pinSrc)
                        .put("created_at", doc != null ? doc.optDouble("created_at", 0.0) : 0.0)
                        .put("policy", "earliest_claim_with_petname")
                        .put("conflicts", confArr)
                        .toString());
            } else if (path.equals("/api/seeds") && method.equals("GET")) {
                sendJson(out, 200, new JSONObject()
                        .put("ok", true)
                        .put("self_seed_active", shareGateway && checkHasWan())
                        .put("seeds", loadSeeds())
                        .toString());
            } else if (path.equals("/api/seeds") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr.isEmpty() ? "{}" : bodyStr);
                String u = req.optString("url", "").trim().replaceAll("/+$", "");
                String lbl = req.optString("label", "Community Seed").trim();
                if (!u.startsWith("http://") && !u.startsWith("https://")) {
                    sendJson(out, 400, "{\"detail\":\"Seed URL must start with http:// or https://\"}");
                } else {
                    rememberSeed(u, lbl);
                    sendJson(out, 200, new JSONObject().put("ok", true).put("seeds", loadSeeds()).toString());
                }
            } else if (path.equals("/api/p2p/wifidirect/status")) {
                if (wifiDirectMesh != null) wifiDirectMesh.discoverPeers();
                sendJson(out, 200, (wifiDirectMesh != null ? wifiDirectMesh.status() : new JSONObject().put("started", false)).toString());
            } else if (path.equals("/api/p2p/wifidirect/connect") && method.equals("POST")) {
                JSONObject req = new JSONObject(bodyStr.isEmpty() ? "{}" : bodyStr);
                boolean ok = wifiDirectMesh != null && wifiDirectMesh.connectToPeer(req.optString("address", ""));
                sendJson(out, 200, new JSONObject().put("ok", ok).toString());
            } else if (path.equals("/api/gateway/fetch")) {
                if (!shareGateway) {
                    sendJson(out, 403, "{\"detail\":\"Mesh gateway sharing disabled\"}");
                } else {
                    proxyFetchUrl(qp.getOrDefault("url", ""), "/api/web/browse?url=", method, bodyStr, out);
                }
            } else if (path.equals("/api/web/browse")) {
                String u = qp.getOrDefault("url", "").trim();
                if (!u.startsWith("http://") && !u.startsWith("https://")) u = "https://" + u;
                if (checkHasWan()) {
                    proxyFetchUrl(u, "/api/web/browse?url=", method, bodyStr, out);
                } else {
                    JSONObject gw = findLanGateway();
                    if (gw == null) {
                        sendJson(out, 503, "{\"detail\":\"Offline and no LAN Mesh Gateway peer found\"}");
                    } else {
                        try {
                            String gwUrl = gw.optString("url") + "/api/gateway/fetch?url=" + URLEncoder.encode(u, "UTF-8");
                            HttpURLConnection c = openBoundConnection(new URL(gwUrl));
                            c.setConnectTimeout(5000);
                            c.setReadTimeout(12000);
                            if ("POST".equalsIgnoreCase(method)) {
                                c.setRequestMethod("POST");
                                c.setDoOutput(true);
                                c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                                try (OutputStream os = c.getOutputStream()) {
                                    os.write((bodyStr != null ? bodyStr : "").getBytes(StandardCharsets.UTF_8));
                                }
                            }
                            int code = c.getResponseCode();
                            String ctype = c.getContentType();
                            if (ctype == null || ctype.isEmpty()) ctype = "text/html";
                            InputStream is = code >= 400 ? c.getErrorStream() : c.getInputStream();
                            byte[] data = is != null ? readAllBytesLimited(is, 4 * 1024 * 1024) : new byte[0];
                            sendBytes(out, code, ctype.split(";")[0].trim(), data);
                        } catch (Exception e) {
                            sendJson(out, 502, "{\"detail\":\"Mesh gateway fetch failed\"}");
                        }
                    }
                }
            } else if (path.equals("/api/sync/export")) {
                String domQ = parseQuery(query).getOrDefault("domain", "");
                sendJson(out, 200, (domQ.isEmpty() ? exportSyncBundle() : exportDomainBundle(domQ)).toString());
            } else if (path.equals("/api/sync/import") && method.equals("POST")) {
                int[] st = importBundle(new JSONObject(bodyStr));
                sendJson(out, 200, new JSONObject()
                        .put("ok", true)
                        .put("imported_versions", st[0])
                        .put("rejected", st[1])
                        .put("imported_forum_posts", st.length > 2 ? st[2] : 0)
                        .put("imported_wiki_shards", st.length > 3 ? st[3] : 0)
                        .toString());
            } else if (path.equals("/api/lan/peers")) {
                long nowMs = System.currentTimeMillis();
                JSONArray arr = new JSONArray();
                for (JSONObject lp : lanPeers.values()) {
                    if (nowMs - lp.optLong("last_seen_ms", 0L) < 90_000L) {
                        arr.put(new JSONObject()
                                .put("url", lp.optString("url"))
                                .put("label", lp.optString("label"))
                                .put("last_seen", lp.optLong("last_seen_ms", 0L) / 1000.0)
                                .put("last_synced", lp.optLong("last_synced_ms", 0L) / 1000.0));
                    }
                }
                sendJson(out, 200, new JSONObject().put("peers", arr).put("port", port).toString());
            } else if (path.equals("/api/lan/sync") && method.equals("POST")) {
                long nowMs = System.currentTimeMillis();
                int syncedPeers = 0, impVer = 0, impForum = 0, impWiki = 0, rej = 0;
                for (JSONObject lp : new ArrayList<>(lanPeers.values())) {
                    if (nowMs - lp.optLong("last_seen_ms", 0L) < 90_000L) {
                        try {
                            int[] st = syncOneLanPeer(lp.optString("url"), lp.optString("label", "LAN Peer"));
                            syncedPeers++;
                            impVer += st[0];
                            rej += st[1];
                            if (st.length > 2) impForum += st[2];
                            if (st.length > 3) impWiki += st[3];
                        } catch (Exception ignored) {}
                    }
                }
                sendJson(out, 200, new JSONObject()
                        .put("ok", true)
                        .put("synced_peers", syncedPeers)
                        .put("imported_versions", impVer)
                        .put("imported_forum_posts", impForum)
                        .put("imported_wiki_shards", impWiki)
                        .put("rejected", rej)
                        .toString());
            } else if (path.equals("/api/p2p/discover")) {
                int[] nStats = discoverFromNostr();
                sendJson(out, 200, new JSONObject()
                        .put("ok", true)
                        .put("discovered", new JSONArray(peers))
                        .put("added", nStats[0])
                        .put("total_peers", peers.size())
                        .put("relay_docs_imported", nStats[1])
                        .toString());
            } else if (path.equals("/api/p2p/join") && method.equals("POST")) {
                int[] nStats = discoverFromNostr();
                int synced = 0;
                for (JSONObject p : new ArrayList<>(peers)) {
                    try {
                        pullFromPeer(p.optString("url", ""), p.optString("label", "Peer Node"));
                        synced++;
                    } catch (Exception ignored) {
                    }
                }
                sendJson(out, 200, new JSONObject()
                        .put("ok", true)
                        .put("announced_relays", 0)
                        .put("discovered", nStats[0] + peers.size())
                        .put("synced_peers", synced)
                        .put("relay_docs_imported", nStats[1])
                        .toString());
            } else {
                sendJson(out, 404, "{\"detail\":\"Not found\"}");
            }
        } catch (Exception e) {
            Log.e("LocalNodeServer", "handleClient error", e);
            if (out != null) {
                try {
                    sendJson(out, 500, new JSONObject().put("detail", e.getMessage() != null ? e.getMessage() : "Internal server error").toString());
                } catch (Exception ignored) {
                }
            }
        }
    }

    private synchronized void upsertPeer(String url, String label, double lastSync, Boolean subscribed) {
        try {
            for (JSONObject p : peers) {
                if (url.equals(p.optString("url", ""))) {
                    if (lastSync > 0) p.put("last_sync", lastSync);
                    if (subscribed != null) p.put("subscribed", subscribed);
                    savePeers();
                    return;
                }
            }
            if (peers.size() < 50) {
                peers.add(new JSONObject().put("url", url).put("label", label).put("last_sync", lastSync)
                        .put("subscribed", subscribed != null ? subscribed : false));
                savePeers();
            }
        } catch (Exception ignored) {
        }
    }

    private void upsertPeer(String url, String label, double lastSync) {
        upsertPeer(url, label, lastSync, null);
    }

    private synchronized JSONObject getOrCreateDomainKeys(String dom) throws Exception {
        JSONObject k = domainKeys.get(dom);
        if (k == null) {
            byte[] sk = Ed25519.generatePrivateKey();
            byte[] pk = Ed25519.publicKey(sk);
            k = new JSONObject();
            k.put("pubkey_hex", Ed25519.toHex(pk));
            k.put("privkey_hex", Ed25519.toHex(sk));
            domainKeys.put(dom, k);
            saveKeys();
        }
        return k;
    }

    private JSONObject publishLocalDoc(String dom, String title, String content, String sourceUrl) throws Exception {
        return publishLocalDoc(dom, title, content, sourceUrl, "", false);
    }

    private JSONObject publishLocalDoc(String dom, String title, String content, String sourceUrl, String privkeyHex, boolean requireOwnerKey) throws Exception {
        JSONObject existing = docs.get(dom);
        if (existing == null && dom.endsWith(".xnd")) {
            lookupDocNostr(dom);
            existing = docs.get(dom);
        }
        String providedPriv = privkeyHex != null ? privkeyHex.trim() : "";
        if (existing != null && requireOwnerKey) {
            if (providedPriv.isEmpty()) {
                throw new IllegalStateException("Domain '" + dom + "' already exists. Enter its Domain Private Key to edit or republish.");
            }
            String derivedPub;
            try {
                byte[] sk = Ed25519.fromHex(providedPriv);
                derivedPub = Ed25519.toHex(Ed25519.publicKey(sk));
            } catch (Exception e) {
                throw new IllegalStateException("Invalid Ed25519 private key hex.");
            }
            String existingPub = existing.optString("pubkey_hex", existing.optString("pubkey", ""));
            if (existingPub.isEmpty() || !existingPub.equals(derivedPub)) {
                throw new IllegalStateException("Private key does not match the registered public key for '" + dom + "'.");
            }
            JSONObject kd = new JSONObject().put("pubkey_hex", derivedPub).put("privkey_hex", providedPriv);
            domainKeys.put(dom, kd);
            saveKeys();
        } else if (existing == null && !domainKeys.containsKey(dom)) {
            String label = dom.endsWith(".xnd") ? dom.substring(0, dom.length() - 4) : dom;
            if (label.length() <= 4) {
                throw new IllegalStateException("'" + dom + "' is a reserved ultra-short (1-4 char) .xnd name. Use 5+ chars.");
            }
            if (!providedPriv.isEmpty()) {
                String derivedPub;
                try {
                    byte[] sk = Ed25519.fromHex(providedPriv);
                    derivedPub = Ed25519.toHex(Ed25519.publicKey(sk));
                } catch (Exception e) {
                    throw new IllegalStateException("Invalid Ed25519 private key hex.");
                }
                JSONObject kd = new JSONObject().put("pubkey_hex", derivedPub).put("privkey_hex", providedPriv);
                domainKeys.put(dom, kd);
                saveKeys();
            }
        }
        int ver = existing != null ? existing.optInt("version_num", existing.optInt("version", 0)) + 1 : 1;
        String prevSha = existing != null ? existing.optString("sha256", "") : "";
        String sha = sha256Hex(content);
        JSONObject kp = getOrCreateDomainKeys(dom);
        String pubHex = kp.getString("pubkey_hex");
        String privHex = kp.getString("privkey_hex");
        String signStr = prevSha.isEmpty() ? (dom + "|v" + ver + "|" + sha) : (dom + "|v" + ver + "|" + sha + "|" + prevSha);
        byte[] payload = signStr.getBytes(StandardCharsets.UTF_8);
        String sigHex = Ed25519.toHex(Ed25519.sign(payload, Ed25519.fromHex(privHex), Ed25519.fromHex(pubHex)));
        double now = System.currentTimeMillis() / 1000.0;

        JSONObject d = new JSONObject();
        d.put("domain", dom);
        d.put("title", title);
        d.put("kind", "document");
        d.put("version", ver);
        d.put("version_num", ver);
        d.put("sha256", sha);
        d.put("prev_sha256", prevSha);
        d.put("pubkey", pubHex);
        d.put("pubkey_hex", pubHex);
        d.put("signature", sigHex);
        d.put("signature_hex", sigHex);
        d.put("verified", true);
        d.put("owned_locally", true);
        d.put("created_at", now);
        if (!sourceUrl.isEmpty()) d.put("source_url", sourceUrl);
        d.put("raw_content", content);
        d.put("segments", new JSONArray().put(new JSONObject().put("type", "text").put("text", content).put("start", 0)));
        JSONArray vers = existing != null && existing.has("versions") ? existing.getJSONArray("versions") : new JSONArray();
        vers.put(new JSONObject().put("version_num", ver).put("sha256", sha).put("title", title).put("signature_hex", sigHex));
        d.put("versions", vers);
        d.put("backlinks", new JSONArray());
        d.put("rust_core_active", false);
        docs.put(dom, d);
        saveDocs();

        final int fVer = ver;
        final String fPrevSha = prevSha;
        pool.submit(() -> {
            announceDocNostr(dom, fVer, title, sha, pubHex, sigHex, content, false, fPrevSha);
            pushDomainToQuorum(dom, 3);
        });

        JSONObject outRes = new JSONObject()
                .put("ok", true)
                .put("domain", dom)
                .put("version", ver)
                .put("version_num", ver)
                .put("sha256", sha)
                .put("signature_hex", sigHex);
        if (ver == 1) {
            outRes.put("privkey_hex", privHex);
            outRes.put("is_new_domain", true);
        }
        return outRes;
    }

    private JSONObject publishLocalCapsule(String dom, String title, JSONObject filesObj, String backendPy, String privkeyHex) throws Exception {
        JSONObject existing = docs.get(dom);
        if (existing == null && dom.endsWith(".xnd")) {
            lookupDocNostr(dom);
            existing = docs.get(dom);
        }
        String providedPriv = privkeyHex != null ? privkeyHex.trim() : "";
        if (existing != null) {
            if (providedPriv.isEmpty()) {
                throw new IllegalStateException("Domain '" + dom + "' already exists. Enter its Domain Private Key to edit or deploy.");
            }
            String derivedPub;
            try {
                derivedPub = Ed25519.toHex(Ed25519.publicKey(Ed25519.fromHex(providedPriv)));
            } catch (Exception e) {
                throw new IllegalStateException("Invalid Ed25519 private key hex.");
            }
            String existingPub = existing.optString("pubkey_hex", existing.optString("pubkey", ""));
            if (existingPub.isEmpty() || !existingPub.equals(derivedPub)) {
                throw new IllegalStateException("Private key does not match the registered public key for '" + dom + "'.");
            }
            domainKeys.put(dom, new JSONObject().put("pubkey_hex", derivedPub).put("privkey_hex", providedPriv));
            saveKeys();
        } else if (!domainKeys.containsKey(dom)) {
            String label = dom.endsWith(".xnd") ? dom.substring(0, dom.length() - 4) : dom;
            if (label.length() <= 4) {
                throw new IllegalStateException("'" + dom + "' is a reserved ultra-short (1-4 char) .xnd name. Use 5+ chars.");
            }
            if (!providedPriv.isEmpty()) {
                String derivedPub;
                try {
                    derivedPub = Ed25519.toHex(Ed25519.publicKey(Ed25519.fromHex(providedPriv)));
                } catch (Exception e) {
                    throw new IllegalStateException("Invalid Ed25519 private key hex.");
                }
                domainKeys.put(dom, new JSONObject().put("pubkey_hex", derivedPub).put("privkey_hex", providedPriv));
                saveKeys();
            }
        }
        int ver = existing != null ? existing.optInt("version_num", existing.optInt("version", 0)) + 1 : 1;
        String prevSha = existing != null ? existing.optString("sha256", "") : "";
        String bundlePayload = new JSONObject().put("files", filesObj).put("backend_py", backendPy != null ? backendPy : "").toString();
        String sha = sha256Hex(bundlePayload);
        JSONObject kp = getOrCreateDomainKeys(dom);
        String pubHex = kp.getString("pubkey_hex");
        String privHex = kp.getString("privkey_hex");
        String signStr = prevSha.isEmpty() ? (dom + "|v" + ver + "|" + sha) : (dom + "|v" + ver + "|" + sha + "|" + prevSha);
        byte[] payload = signStr.getBytes(StandardCharsets.UTF_8);
        String sigHex = Ed25519.toHex(Ed25519.sign(payload, Ed25519.fromHex(privHex), Ed25519.fromHex(pubHex)));
        double now = System.currentTimeMillis() / 1000.0;

        JSONObject d = new JSONObject();
        d.put("domain", dom);
        d.put("title", title);
        d.put("kind", "capsule");
        d.put("is_app", true);
        d.put("version", ver);
        d.put("version_num", ver);
        d.put("sha256", sha);
        d.put("prev_sha256", prevSha);
        d.put("pubkey", pubHex);
        d.put("pubkey_hex", pubHex);
        d.put("signature", sigHex);
        d.put("signature_hex", sigHex);
        d.put("verified", true);
        d.put("owned_locally", true);
        d.put("created_at", now);
        d.put("raw_content", bundlePayload);
        d.put("segments", new JSONArray());
        JSONArray vers = existing != null && existing.has("versions") ? existing.getJSONArray("versions") : new JSONArray();
        vers.put(new JSONObject().put("version_num", ver).put("sha256", sha).put("title", title).put("kind", "capsule").put("signature_hex", sigHex));
        d.put("versions", vers);
        d.put("backlinks", new JSONArray());
        d.put("rust_core_active", false);
        docs.put(dom, d);
        saveDocs();

        final int fVer = ver;
        final String fPrevSha = prevSha;
        pool.submit(() -> {
            announceDocNostr(dom, fVer, title, sha, pubHex, sigHex, bundlePayload, true, fPrevSha);
            pushDomainToQuorum(dom, 3);
        });

        JSONObject outRes = new JSONObject()
                .put("ok", true)
                .put("domain", dom)
                .put("kind", "capsule")
                .put("version", ver)
                .put("version_num", ver)
                .put("sha256", sha)
                .put("signature_hex", sigHex);
        if (ver == 1) {
            outRes.put("privkey_hex", privHex);
            outRes.put("is_new_domain", true);
        }
        return outRes;
    }

    private void startGithubAutoSync() {
        Thread t = new Thread(() -> {
            while (running) {
                try {
                    Thread.sleep(60000);
                    if (!running) break;
                    JSONObject st = ghHosting.getStatus();
                    if (!st.optBoolean("connected", false)) continue;
                    JSONObject links = ghHosting.loadLinks();
                    java.util.Iterator<String> keys = links.keys();
                    while (keys.hasNext()) {
                        String dom = keys.next();
                        JSONObject info = links.optJSONObject(dom);
                        if (info == null) continue;
                        String repo = info.optString("repo", "");
                        String branch = info.optString("branch", "");
                        String subdir = info.optString("subdir", "");
                        String lastSha = info.optString("last_sha", "");
                        if (repo.isEmpty()) continue;
                        JSONObject kd = domainKeys.get(dom);
                        String priv = kd != null ? kd.optString("privkey_hex", "") : "";
                        if (priv.isEmpty()) continue;
                        String latestSha = ghHosting.getLatestCommitSha(repo, branch);
                        if (latestSha.isEmpty() || latestSha.equals(lastSha)) continue;
                        GitHubHosting.RepoBundle bundle = ghHosting.fetchRepoBundle(repo, branch, subdir);
                        publishLocalCapsule(dom, dom, bundle.files, bundle.backendPy, priv);
                        if (vaultUnlocked) saveVault();
                        ghHosting.saveLink(dom, repo, bundle.branch, subdir, latestSha);
                    }
                } catch (Exception ignored) {
                }
            }
        }, "xnd-gh-autosync");
        t.setDaemon(true);
        t.start();
    }

    private volatile boolean vaultUnlocked = false;
    private volatile byte[] vaultKey = null;
    private volatile String vaultUsername = "";
    private volatile String vaultUsernameHash = "";
    private volatile String vaultAccountPrivkey = "";

    private File accountFile() {
        return new File(dataDir, "xnd_account.json");
    }

    private JSONObject loadCapsuleState(String dom) {
        try {
            File dir = new File(dataDir, "capsule_state");
            if (!dir.exists()) dir.mkdirs();
            File f = new File(dir, dom.replaceAll("[^a-z0-9._-]", "_") + ".json");
            if (f.exists()) return new JSONObject(readFileStr(f));
        } catch (Exception ignored) {}
        return new JSONObject();
    }

    private void saveCapsuleState(String dom, JSONObject state) {
        try {
            File dir = new File(dataDir, "capsule_state");
            if (!dir.exists()) dir.mkdirs();
            File f = new File(dir, dom.replaceAll("[^a-z0-9._-]", "_") + ".json");
            writeFileStr(f, state.toString());
        } catch (Exception ignored) {}
    }

    private static byte[][] deriveAccountKeys(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 512);
        byte[] dk = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        byte[] authHash = new byte[32];
        byte[] vKey = new byte[32];
        System.arraycopy(dk, 0, authHash, 0, 32);
        System.arraycopy(dk, 32, vKey, 0, 32);
        return new byte[][]{authHash, vKey};
    }

    private void saveVault() {
        try {
            File af = accountFile();
            if (!af.exists() || vaultKey == null) return;
            JSONObject acct = new JSONObject(readFileStr(af));
            JSONObject keyring = new JSONObject();
            for (Map.Entry<String, JSONObject> e : domainKeys.entrySet()) {
                if (!e.getValue().optString("privkey_hex", "").isEmpty()) {
                    keyring.put(e.getKey(), e.getValue());
                }
            }
            JSONObject vaultObj = new JSONObject()
                    .put("keyring", keyring)
                    .put("account_privkey_hex", vaultAccountPrivkey);
            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(vaultKey, "AES"), new GCMParameterSpec(128, nonce));
            byte[] ct = cipher.doFinal(vaultObj.toString().getBytes(StandardCharsets.UTF_8));
            acct.put("vault_nonce_hex", Ed25519.toHex(nonce));
            acct.put("vault_ct_hex", Ed25519.toHex(ct));
            writeFileStr(af, acct.toString(2));
        } catch (Exception e) {
            Log.e("XanaduNode", "saveVault error", e);
        }
    }

    private static String readFileStr(File f) throws Exception {
        try (FileInputStream fis = new FileInputStream(f)) {
            return new String(readAll(fis), StandardCharsets.UTF_8);
        }
    }

    private static void writeFileStr(File f, String s) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(s.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String guessMimeType(String path) {
        String p = path.toLowerCase(Locale.US);
        if (p.endsWith(".html") || p.endsWith(".htm")) return "text/html; charset=utf-8";
        if (p.endsWith(".css")) return "text/css; charset=utf-8";
        if (p.endsWith(".js") || p.endsWith(".mjs")) return "application/javascript; charset=utf-8";
        if (p.endsWith(".json")) return "application/json; charset=utf-8";
        if (p.endsWith(".svg")) return "image/svg+xml";
        if (p.endsWith(".png")) return "image/png";
        if (p.endsWith(".jpg") || p.endsWith(".jpeg")) return "image/jpeg";
        if (p.endsWith(".webp")) return "image/webp";
        if (p.endsWith(".gif")) return "image/gif";
        return "text/plain; charset=utf-8";
    }

    private int[] importBundle(JSONObject bundle) {
        return importBundle(bundle, false);
    }

    private int[] importBundle(JSONObject bundle, boolean ignoreFollowFilter) {
        Map<String, String> blobMap = new HashMap<>();
        JSONArray blobs = bundle.optJSONArray("blobs");
        if (blobs != null) {
            for (int i = 0; i < blobs.length(); i++) {
                JSONObject b = blobs.optJSONObject(i);
                if (b != null) blobMap.put(b.optString("sha256", ""), b.optString("content", ""));
            }
        }
        Map<String, String> pubMap = new HashMap<>();
        Map<String, String> aliasMap = new HashMap<>();
        JSONArray domains = bundle.optJSONArray("domains");
        if (domains != null) {
            for (int i = 0; i < domains.length(); i++) {
                JSONObject dm = domains.optJSONObject(i);
                if (dm == null) continue;
                String rawName = dm.optString("name", "").toLowerCase(Locale.US);
                String inPub = dm.optString("pubkey_hex", "").trim().toLowerCase(Locale.US);
                if (rawName.isEmpty()) continue;
                pubMap.put(rawName, inPub);
                String pinnedPub = getPinnedPubkey(rawName);
                JSONObject pinRec = trustPins.get(rawName);
                String pinSource = pinRec != null ? pinRec.optString("source", "") : "";
                JSONObject existing = docs.get(rawName);
                String existingPub = !pinnedPub.isEmpty() ? pinnedPub : (existing != null ? existing.optString("pubkey_hex", existing.optString("pubkey", "")).trim().toLowerCase(Locale.US) : "");
                double inTs = dm.optDouble("created_at", 0.0);
                double exTs = existing != null ? existing.optDouble("created_at", 0.0) : 0.0;
                boolean locallyOwned = domainKeys.containsKey(rawName) && !domainKeys.get(rawName).optString("privkey_hex", "").isEmpty();
                if (!existingPub.isEmpty() && !inPub.isEmpty() && !existingPub.equals(inPub)) {
                    if (!locallyOwned && !"manual".equals(pinSource) && inTs > 0 && exTs > 0 && (inTs + 60.0) < exTs) {
                        String displacedAlias = canonicalDomainFor(rawName, existingPub);
                        if (existing != null && !docs.containsKey(displacedAlias)) {
                            try {
                                JSONObject moved = new JSONObject(existing.toString());
                                moved.put("domain", displacedAlias);
                                docs.put(displacedAlias, moved);
                                saveDocs();
                            } catch (Exception ignored) {}
                        }
                        recordTrustConflict(rawName, displacedAlias, existingPub);
                        docs.remove(rawName);
                        try {
                            trustPins.put(rawName, new JSONObject().put("pubkey_hex", inPub).put("pinned_at", System.currentTimeMillis() / 1000.0).put("source", "consensus_earliest"));
                            saveTrustPins();
                        } catch (Exception ignored) {}
                        aliasMap.put(rawName, rawName);
                    } else {
                        String alias = canonicalDomainFor(rawName, inPub);
                        aliasMap.put(rawName, alias);
                        recordTrustConflict(rawName, alias, inPub);
                    }
                } else {
                    if (!inPub.isEmpty()) ensureFirstSeenPin(rawName, inPub, "first_seen");
                    aliasMap.put(rawName, rawName);
                }
            }
        }

        int imported = 0;
        int rejected = 0;
        JSONArray versions = bundle.optJSONArray("versions");
        if (versions != null) {
            for (int i = 0; i < versions.length(); i++) {
                JSONObject v = versions.optJSONObject(i);
                if (v == null) continue;
                String origDom = v.optString("domain", "").toLowerCase(Locale.US);
                String targetDom = aliasMap.containsKey(origDom) ? aliasMap.get(origDom) : origDom;
                String sha = v.optString("sha256", "");
                int ver = v.optInt("version_num", v.optInt("version", 1));
                String sigHex = v.optString("signature_hex", "");
                String content = blobMap.get(sha);
                String pubHex = pubMap.containsKey(origDom) ? pubMap.get(origDom) : "";
                if (blockedDomains.contains(origDom) || blockedDomains.contains(targetDom)
                        || (!pubHex.isEmpty() && blockedPubkeys.contains(pubHex.toLowerCase(Locale.US)))) {
                    rejected++;
                    continue;
                }
                if (!ignoreFollowFilter && !followedPubkeys.isEmpty() && !pubHex.isEmpty()
                        && !followedPubkeys.contains(pubHex.toLowerCase(Locale.US))
                        && !docs.containsKey(targetDom)) {
                    continue;
                }
                if (origDom.isEmpty() || content == null) {
                    rejected++;
                    continue;
                }
                try {
                    if (!sha256Hex(content).equals(sha)) {
                        rejected++;
                        continue;
                    }
                } catch (Exception e) {
                    rejected++;
                    continue;
                }
                String prevSha = v.optString("prev_sha256", "");
                if (!pubHex.isEmpty() && !sigHex.isEmpty()) {
                    String verifyStr = prevSha.isEmpty() ? (origDom + "|v" + ver + "|" + sha) : (origDom + "|v" + ver + "|" + sha + "|" + prevSha);
                    byte[] msg = verifyStr.getBytes(StandardCharsets.UTF_8);
                    if (!Ed25519.verify(msg, Ed25519.fromHex(sigHex), Ed25519.fromHex(pubHex))) {
                        rejected++;
                        continue;
                    }
                }
                JSONObject existing = docs.get(targetDom);
                int exVer = existing != null ? existing.optInt("version_num", existing.optInt("version", 0)) : 0;
                if (!prevSha.isEmpty() && existing != null && exVer == ver - 1 && !prevSha.equals(existing.optString("sha256", ""))) {
                    rejected++;
                    continue;
                }
                if (existing != null && (exVer > ver || (exVer == ver && sha.equals(existing.optString("sha256", ""))))) {
                    continue;
                }
                JSONObject d = new JSONObject();
                try {
                    String impKind = v.optString("kind", "");
                    if (impKind.isEmpty()) {
                        if (v.optBoolean("is_app", false) || (content.trim().startsWith("{") && content.contains("\"files\""))) {
                            impKind = "capsule";
                        } else {
                            impKind = "document";
                        }
                    }
                    d.put("domain", targetDom);
                    d.put("kind", impKind);
                    d.put("version", ver);
                    d.put("version_num", ver);
                    d.put("title", v.optString("title", targetDom));
                    d.put("raw_content", content);
                    d.put("sha256", sha);
                    d.put("prev_sha256", prevSha);
                    d.put("pubkey", pubHex);
                    d.put("pubkey_hex", pubHex);
                    d.put("signature", sigHex);
                    d.put("signature_hex", sigHex);
                    d.put("verified", !pubHex.isEmpty() && !sigHex.isEmpty());
                    d.put("created_at", v.optDouble("created_at", System.currentTimeMillis() / 1000.0));
                    d.put("is_app", v.optBoolean("is_app", false));
                    d.put("segments", new JSONArray().put(new JSONObject().put("type", "text").put("text", content).put("start", 0)));
                    JSONArray vers = existing != null && existing.has("versions") ? existing.getJSONArray("versions") : new JSONArray();
                    boolean hasVer = false;
                    for (int vi = 0; vi < vers.length(); vi++) {
                        if (vers.getJSONObject(vi).optInt("version_num", -1) == ver) {
                            hasVer = true;
                            break;
                        }
                    }
                    if (!hasVer) {
                        vers.put(new JSONObject().put("version_num", ver).put("sha256", sha).put("title", v.optString("title", targetDom)).put("signature_hex", sigHex));
                    }
                    d.put("versions", vers);
                    d.put("backlinks", new JSONArray());
                    d.put("rust_core_active", false);
                    docs.put(targetDom, d);
                    domainLastAccess.put(targetDom, System.currentTimeMillis());
                    imported++;
                } catch (Exception ignored) {
                }
            }
        }
        if (imported > 0) {
            pruneUnpinnedDomainsIfNeeded();
            gossipImported += imported;
            saveDocs();
        }
        int impForum = 0;
        try {
            JSONArray inPosts = bundle.optJSONArray("forum_posts");
            if (inPosts != null && inPosts.length() > 0) {
                JSONObject fState = loadCapsuleState("forum.xnd");
                JSONArray curPosts = fState.optJSONArray("posts");
                if (curPosts == null) curPosts = new JSONArray();
                Set<String> seenFp = new HashSet<>();
                for (int i = 0; i < curPosts.length(); i++) {
                    JSONObject cp = curPosts.optJSONObject(i);
                    if (cp != null) seenFp.add(cp.optString("author") + "|" + cp.optString("text") + "|" + cp.optString("created_at"));
                }
                for (int i = 0; i < inPosts.length(); i++) {
                    JSONObject ip = inPosts.optJSONObject(i);
                    if (ip == null || ip.optString("text", "").trim().isEmpty()) continue;
                    String k = ip.optString("author") + "|" + ip.optString("text") + "|" + ip.optString("created_at");
                    if (seenFp.add(k)) {
                        curPosts.put(ip);
                        impForum++;
                    }
                }
                if (impForum > 0) {
                    fState.put("posts", curPosts);
                    saveCapsuleState("forum.xnd", fState);
                }
            }
        } catch (Exception ignored) {}
        int impWiki = 0;
        try {
            JSONArray shards = bundle.optJSONArray("wiki_shards");
            if (shards != null) {
                for (int i = 0; i < shards.length(); i++) {
                    JSONObject sh = shards.optJSONObject(i);
                    if (sh == null) continue;
                    String title = sh.optString("title", "").trim();
                    String summary = sh.optString("summary", "").trim();
                    String key = sh.optString("key", title).trim().toLowerCase(Locale.US);
                    if (!key.isEmpty() && !title.isEmpty() && !summary.isEmpty() && !wikiShards.containsKey(key)) {
                        wikiShards.put(key, sh);
                        impWiki++;
                    }
                }
            }
        } catch (Exception ignored) {}
        return new int[]{imported, rejected, impForum, impWiki};
    }

    private int[] pullFromPeer(String peerUrl, String label) throws Exception {
        String raw = httpGet(peerUrl + "/api/sync/export", 6000);
        int[] stats = importBundle(new JSONObject(raw));
        upsertPeer(peerUrl, label, System.currentTimeMillis() / 1000.0, true);
        try {
            JSONObject pdata = new JSONObject(httpGet(peerUrl + "/api/peers", 3000));
            JSONArray pArr = pdata.optJSONArray("peers");
            if (pArr != null) {
                for (int i = 0; i < pArr.length(); i++) {
                    JSONObject p = pArr.getJSONObject(i);
                    String u = p.optString("url", "").trim().replaceAll("/+$", "");
                    if ((u.startsWith("http://") || u.startsWith("https://"))
                            && !u.contains("127.0.0.1") && !u.contains("localhost")) {
                        upsertPeer(u, p.optString("label", "PEX Peer"), 0.0);
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return stats;
    }

    private JSONObject exportSyncBundle() {
        JSONObject out = new JSONObject();
        JSONArray domains = new JSONArray();
        JSONArray versions = new JSONArray();
        JSONArray blobs = new JSONArray();
        Map<String, byte[]> chunkMap = new HashMap<>();
        List<JSONObject> manifests = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        try {
            synchronized (docs) {
                for (JSONObject d : docs.values()) {
                    String dom = d.optString("domain", "");
                    String sha = d.optString("sha256", "");
                    String pubHex = d.optString("pubkey_hex", d.optString("pubkey", ""));
                    String sigHex = d.optString("signature_hex", d.optString("signature", ""));
                    int ver = d.optInt("version_num", d.optInt("version", 1));
                    double ts = d.optDouble("created_at", System.currentTimeMillis() / 1000.0);
                    domains.put(new JSONObject().put("name", dom).put("pubkey_hex", pubHex).put("created_at", ts));
                    boolean isApp = d.optBoolean("is_app", false) || "capsule".equals(d.optString("kind", ""));
                    versions.put(new JSONObject()
                            .put("domain", dom)
                            .put("version", ver)
                            .put("version_num", ver)
                            .put("sha256", sha)
                            .put("prev_sha256", d.optString("prev_sha256", ""))
                            .put("signature_hex", sigHex)
                            .put("title", d.optString("title", dom))
                            .put("created_at", ts)
                            .put("kind", isApp ? "capsule" : "document")
                            .put("is_app", isApp));
                    if (!sha.isEmpty() && !seen.contains(sha)) {
                        seen.add(sha);
                        blobs.put(new JSONObject()
                                .put("sha256", sha)
                                .put("content", d.optString("raw_content", ""))
                                .put("created_at", ts));
                    }
                }
            }
            out.put("domains", domains);
            out.put("versions", versions);
            out.put("blobs", blobs);
            JSONArray forumPosts = new JSONArray();
            try {
                JSONArray fp = loadCapsuleState("forum.xnd").optJSONArray("posts");
                if (fp != null) {
                    int start = Math.max(0, fp.length() - 150);
                    for (int i = start; i < fp.length(); i++) forumPosts.put(fp.get(i));
                }
            } catch (Exception ignored) {}
            out.put("forum_posts", forumPosts);
            JSONArray wArr = new JSONArray();
            int wc = 0;
            for (JSONObject sh : wikiShards.values()) {
                wArr.put(sh);
                if (++wc >= 120) break;
            }
            out.put("wiki_shards", wArr);
        } catch (Exception ignored) {
        }
        return out;
    }

    private int[] syncOneLanPeer(String peerUrl, String label) throws Exception {
        int[] stats = pullFromPeer(peerUrl, label);
        try {
            httpPostJson(peerUrl + "/api/sync/import", exportSyncBundle().toString(), 5000);
        } catch (Exception ignored) {}
        JSONObject lp = lanPeers.get(peerUrl);
        if (lp != null) lp.put("last_synced_ms", System.currentTimeMillis());
        return stats;
    }

    private void startLanDiscovery() {
        new Thread(() -> {
            try {
                byte[] beacon = new JSONObject()
                        .put("type", "xanadu-lan-peer")
                        .put("node_id", lanNodeId)
                        .put("port", port)
                        .put("label", "Xanadu Android")
                        .toString().getBytes(StandardCharsets.UTF_8);
                while (running) {
                    try (DatagramSocket ds = new DatagramSocket()) {
                        ds.setBroadcast(true);
                        java.util.Set<String> targets = new java.util.LinkedHashSet<>();
                        targets.add("255.255.255.255");
                        try {
                            java.util.Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
                            while (ifaces != null && ifaces.hasMoreElements()) {
                                NetworkInterface nif = ifaces.nextElement();
                                if (!nif.isUp() || nif.isLoopback()) continue;
                                for (InterfaceAddress ia : nif.getInterfaceAddresses()) {
                                    InetAddress addr = ia.getAddress();
                                    if (!(addr instanceof Inet4Address) || addr.isLoopbackAddress()) continue;
                                    InetAddress bcast = ia.getBroadcast();
                                    if (bcast != null) targets.add(bcast.getHostAddress());
                                    String ip = addr.getHostAddress();
                                    String[] parts = ip.split("\\.");
                                    if (parts.length == 4) {
                                        targets.add(parts[0] + "." + parts[1] + "." + parts[2] + ".255");
                                        if (!"1".equals(parts[3])) {
                                            targets.add(parts[0] + "." + parts[1] + "." + parts[2] + ".1");
                                        }
                                    }
                                }
                            }
                        } catch (Exception ignored) {
                        }
                        try (BufferedReader arp = new BufferedReader(new InputStreamReader(new FileInputStream("/proc/net/arp"), StandardCharsets.UTF_8))) {
                            String line;
                            while ((line = arp.readLine()) != null) {
                                String[] cols = line.trim().split("\\s+");
                                if (cols.length >= 4 && cols[0].contains(".") && !"00:00:00:00:00:00".equals(cols[3])) {
                                    targets.add(cols[0]);
                                }
                            }
                        } catch (Exception ignored) {
                        }
                        for (String dst : targets) {
                            try {
                                ds.send(new DatagramPacket(beacon, beacon.length, InetAddress.getByName(dst), 8766));
                            } catch (Exception ignored) {
                            }
                        }
                    } catch (Exception ignored) {
                    }
                    Thread.sleep(5000);
                }
            } catch (Exception ignored) {
            }
        }, "xnd-lan-tx").start();

        new Thread(() -> {
            try (DatagramSocket ds = new DatagramSocket(null)) {
                ds.setReuseAddress(true);
                ds.bind(new InetSocketAddress(8766));
                byte[] buf = new byte[2048];
                while (running) {
                    try {
                        DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                        ds.receive(pkt);
                        JSONObject msg = new JSONObject(new String(pkt.getData(), 0, pkt.getLength(), StandardCharsets.UTF_8));
                        if (!"xanadu-lan-peer".equals(msg.optString("type")) || lanNodeId.equals(msg.optString("node_id"))) {
                            continue;
                        }
                        int pPort = msg.optInt("port", 8765);
                        String pLabel = msg.optString("label", "LAN Peer");
                        String peerUrl = "http://" + pkt.getAddress().getHostAddress() + ":" + pPort;
                        upsertPeer(peerUrl, pLabel, 0.0, true);
                        long nowMs = System.currentTimeMillis();
                        JSONObject prev = lanPeers.get(peerUrl);
                        long lastSynced = prev != null ? prev.optLong("last_synced_ms", 0L) : 0L;
                        JSONObject rec = new JSONObject()
                                .put("url", peerUrl)
                                .put("label", pLabel)
                                .put("last_seen_ms", nowMs)
                                .put("last_synced_ms", lastSynced);
                        boolean shouldSync = (nowMs - lastSynced) > 30_000L;
                        if (shouldSync) rec.put("last_synced_ms", nowMs);
                        lanPeers.put(peerUrl, rec);
                        if (shouldSync) {
                            pool.submit(() -> {
                                try {
                                    if (!checkHasWan() && meshGatewayPeer == null) {
                                        try {
                                            JSONObject m = new JSONObject(peerGet(peerUrl, "/api/sync/manifest", 2000));
                                            if (m.optBoolean("has_wan", false) && m.optBoolean("share_gateway", true)) {
                                                meshGatewayPeer = new JSONObject()
                                                        .put("url", peerUrl)
                                                        .put("label", m.optString("label", pLabel))
                                                        .put("updated_at", System.currentTimeMillis() / 1000.0);
                                            }
                                        } catch (Exception ignored) {}
                                    }
                                    syncOneLanPeer(peerUrl, pLabel);
                                } catch (Exception ignored) {}
                            });
                        }
                    } catch (Exception ignored) {
                    }
                }
            } catch (Exception ignored) {
            }
        }, "xnd-lan-rx").start();
    }

    private int[] discoverFromNostr() {
        String[] relays = {"wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"};
        int addedPeers = 0;
        int importedDocs = 0;
        JSONArray domains = new JSONArray();
        JSONArray versions = new JSONArray();
        JSONArray blobs = new JSONArray();
        Map<String, byte[]> chunkMap = new HashMap<>();
        List<JSONObject> manifests = new ArrayList<>();
        for (String rUrl : relays) {
            try {
                String host = rUrl.replace("wss://", "").split("/")[0];
                try (SSLSocket sock = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, 443)) {
                    sock.setSoTimeout(3500);
                    byte[] nonce = new byte[16];
                    new SecureRandom().nextBytes(nonce);
                    String key = Base64.getEncoder().encodeToString(nonce);
                    String req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                            + "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
                    OutputStream wOut = sock.getOutputStream();
                    InputStream wIn = sock.getInputStream();
                    wOut.write(req.getBytes(StandardCharsets.US_ASCII));
                    wOut.flush();
                    StringBuilder hdr = new StringBuilder();
                    int prev = 0;
                    while (true) {
                        int b = wIn.read();
                        if (b < 0) break;
                        hdr.append((char) b);
                        int len = hdr.length();
                        if (len >= 4 && hdr.substring(len - 4).equals("\r\n\r\n")) break;
                    }
                    if (!hdr.toString().contains("101")) continue;
                    String sub = new JSONArray().put("REQ").put("xnd-" + (System.currentTimeMillis() % 10000))
                            .put(new JSONObject().put("kinds", new JSONArray().put(30078))
                                    .put("#t", new JSONArray().put("xanadu-doc-v1"))
                                    .put("limit", 100))
                            .put(new JSONObject().put("kinds", new JSONArray().put(30078).put(1))
                                    .put("#t", new JSONArray().put("xanadu-p2p-v1").put("xanadu-chunk-v1"))
                                    .put("limit", 40))
                            .toString();
                    wsSendText(wOut, sub);
                    long deadline = System.currentTimeMillis() + 2500;
                    while (System.currentTimeMillis() < deadline) {
                        String msg = wsRecvText(wIn);
                        if (msg == null) break;
                        if (msg.isEmpty()) continue;
                        JSONArray arr = new JSONArray(msg);
                        String kind = arr.optString(0, "");
                        if ("EOSE".equals(kind)) break;
                        if ("EVENT".equals(kind) && arr.length() >= 3) {
                            JSONObject ev = arr.optJSONObject(2);
                            if (ev == null) continue;
                            try {
                                JSONObject data = new JSONObject(ev.optString("content", "{}"));
                                String t = data.optString("type", "");
                                if ("xanadu-peer".equals(t)) {
                                    String u = data.optString("url", "").trim().replaceAll("/+$", "");
                                    if (u.startsWith("http://") || u.startsWith("https://")) {
                                        upsertPeer(u, data.optString("label", "Nostr Peer"), 0.0);
                                        addedPeers++;
                                    }
                                } else if ("xanadu-chunk".equals(t)) {
                                    String cSha = data.optString("sha256", "");
                                    byte[] rawC = Base64.getDecoder().decode(data.optString("data_b64", ""));
                                    if (!cSha.isEmpty() && Ed25519.toHex(Bip340.sha256(rawC)).equals(cSha)) {
                                        chunkMap.put(cSha, rawC);
                                    }
                                } else if ("xanadu-doc".equals(t)) {
                                    if (data.optBoolean("chunked", false)) {
                                        manifests.add(data);
                                        continue;
                                    }
                                    String dom = data.optString("domain", "").trim().toLowerCase(Locale.US);
                                    String sha = data.optString("sha256", "");
                                    String pub = data.optString("pubkey_hex", "");
                                    String sig = data.optString("signature_hex", "");
                                    String txt = data.optString("content", "");
                                    int ver = data.optInt("version_num", 1);
                                    double ts = data.optDouble("created_at", System.currentTimeMillis() / 1000.0);
                                    if (!dom.isEmpty() && !sha.isEmpty() && !pub.isEmpty() && !sig.isEmpty() && !txt.isEmpty()) {
                                        domains.put(new JSONObject().put("name", dom).put("pubkey_hex", pub).put("created_at", ts));
                                        versions.put(new JSONObject().put("domain", dom).put("version_num", ver)
                                                .put("sha256", sha).put("prev_sha256", data.optString("prev_sha256", ""))
                                                .put("signature_hex", sig)
                                                .put("title", data.optString("title", dom)).put("created_at", ts)
                                                .put("is_app", data.optBoolean("is_app", false)));
                                        blobs.put(new JSONObject().put("sha256", sha).put("content", txt).put("created_at", ts));
                                    }
                                }
                            } catch (Exception ignored) {
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }
        try {
            for (JSONObject m : manifests) {
                JSONArray cArr = m.optJSONArray("chunks");
                if (cArr == null || cArr.length() == 0) continue;
                boolean ok = true;
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                for (int i = 0; i < cArr.length(); i++) {
                    byte[] c = chunkMap.get(cArr.optString(i, ""));
                    if (c == null) { ok = false; break; }
                    bos.write(c);
                }
                if (!ok) continue;
                String dom = m.optString("domain", "").trim().toLowerCase(Locale.US);
                String sha = m.optString("sha256", "");
                String pub = m.optString("pubkey_hex", "");
                String sig = m.optString("signature_hex", "");
                String txt = new String(bos.toByteArray(), StandardCharsets.UTF_8);
                int ver = m.optInt("version_num", 1);
                double ts = m.optDouble("created_at", System.currentTimeMillis() / 1000.0);
                if (!dom.isEmpty() && !sha.isEmpty() && !pub.isEmpty() && !sig.isEmpty()) {
                    domains.put(new JSONObject().put("name", dom).put("pubkey_hex", pub).put("created_at", ts));
                    versions.put(new JSONObject().put("domain", dom).put("version_num", ver)
                            .put("sha256", sha).put("prev_sha256", m.optString("prev_sha256", ""))
                            .put("signature_hex", sig)
                            .put("title", m.optString("title", dom)).put("created_at", ts)
                            .put("is_app", m.optBoolean("is_app", false)));
                    blobs.put(new JSONObject().put("sha256", sha).put("content", txt).put("created_at", ts));
                }
            }
            if (versions.length() > 0) {
                int[] res = importBundle(new JSONObject().put("domains", domains).put("versions", versions).put("blobs", blobs), true);
                importedDocs = res[0];
            }
        } catch (Exception ignored) {
        }
        return new int[]{addedPeers, importedDocs};
    }

    private final Map<String, Long> negLookupCache = new java.util.concurrent.ConcurrentHashMap<>();

    private void pruneUnpinnedDomainsIfNeeded() {
        List<Map.Entry<String, Long>> evictable = new ArrayList<>();
        synchronized (docs) {
            for (Map.Entry<String, JSONObject> e : docs.entrySet()) {
                String dom = e.getKey();
                JSONObject d = e.getValue();
                if (d.optBoolean("owned_locally", false) || !d.optString("privkey_hex", "").isEmpty() || domainKeys.containsKey(dom)) {
                    continue;
                }
                String pub = d.optString("pubkey_hex", d.optString("pubkey", "")).toLowerCase(Locale.US);
                if (!pub.isEmpty() && followedPubkeys.contains(pub)) {
                    continue;
                }
                long ts = domainLastAccess.getOrDefault(dom, (long) (d.optDouble("created_at", 0.0) * 1000.0));
                evictable.add(new java.util.AbstractMap.SimpleEntry<>(dom, ts));
            }
            if (evictable.size() <= MAX_CACHED_DOMAINS) return;
            evictable.sort((a, b) -> Long.compare(a.getValue(), b.getValue()));
            int toRemove = evictable.size() - (int) (MAX_CACHED_DOMAINS * 0.9);
            for (int i = 0; i < toRemove && i < evictable.size(); i++) {
                String victim = evictable.get(i).getKey();
                docs.remove(victim);
                domainLastAccess.remove(victim);
            }
        }
    }

    private boolean tryResolveFromPeers(String targetDomain) {
        String clean = targetDomain == null ? "" : targetDomain.trim().toLowerCase(Locale.US);
        if (clean.isEmpty() || blockedDomains.contains(clean)) return false;
        try {
            String qDom = URLEncoder.encode(clean, "UTF-8");
            List<String> candidates = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            for (String u : lanPeers.keySet()) {
                String bu = u.replaceAll("/+$", "");
                if (!bu.isEmpty() && seen.add(bu)) candidates.add(bu);
            }
            synchronized (peers) {
                for (JSONObject p : peers) {
                    String bu = p.optString("url", "").replaceAll("/+$", "");
                    if (!bu.isEmpty() && seen.add(bu)) candidates.add(bu);
                }
            }
            int tried = 0;
            for (String peerUrl : candidates) {
                if (tried++ >= 6) break;
                try {
                    String raw = peerGet(peerUrl, "/api/sync/export?domain=" + qDom, 2500);
                    JSONObject bundle = new JSONObject(raw);
                    if (bundle.has("versions") && bundle.getJSONArray("versions").length() > 0) {
                        int[] st = importBundle(bundle);
                        if (st[0] > 0 || docs.containsKey(clean)) return true;
                    }
                } catch (Exception ignored) {}
            }
        } catch (Exception ignored) {}
        return false;
    }

    private boolean lookupDocNostr(String targetDomain) {
        String clean = targetDomain == null ? "" : targetDomain.trim().toLowerCase(Locale.US);
        if (clean.isEmpty() || blockedDomains.contains(clean)) return false;
        Long negTs = negLookupCache.get(clean);
        if (negTs != null && (System.currentTimeMillis() - negTs) < 30_000L) return false;
        if (checkHasWan()) {
        String[] relays = {"wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"};
        JSONArray domains = new JSONArray();
        JSONArray versions = new JSONArray();
        JSONArray blobs = new JSONArray();
        Map<String, byte[]> chunkMap = Collections.synchronizedMap(new HashMap<>());
        List<JSONObject> manifests = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch latch = new CountDownLatch(relays.length);
        for (String rUrl : relays) {
            pool.submit(() -> {
                try {
                    String host = rUrl.replace("wss://", "").split("/")[0];
                    try (SSLSocket sock = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, 443)) {
                        sock.setSoTimeout(2500);
                        byte[] nonce = new byte[16];
                        new SecureRandom().nextBytes(nonce);
                        String key = Base64.getEncoder().encodeToString(nonce);
                        String req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                + "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
                        OutputStream wOut = sock.getOutputStream();
                        InputStream wIn = sock.getInputStream();
                        wOut.write(req.getBytes(StandardCharsets.US_ASCII));
                        wOut.flush();
                        StringBuilder hdr = new StringBuilder();
                        while (true) {
                            int b = wIn.read();
                            if (b < 0) break;
                            hdr.append((char) b);
                            int len = hdr.length();
                            if (len >= 4 && hdr.substring(len - 4).equals("\r\n\r\n")) break;
                        }
                        if (!hdr.toString().contains("101")) return;
                        String nostrAuthor = "";
                        try {
                            nostrAuthor = Ed25519.toHex(Bip340.pubkeyX(Bip340.privFromSeed("xanadu-doc-nostr-" + clean)));
                        } catch (Exception ignored) {}
                        JSONArray reqArr = new JSONArray().put("REQ").put("xlk-" + (System.currentTimeMillis() % 10000));
                        if (!nostrAuthor.isEmpty()) {
                            reqArr.put(new JSONObject().put("kinds", new JSONArray().put(30078).put(1))
                                    .put("authors", new JSONArray().put(nostrAuthor))
                                    .put("limit", 25));
                        }
                        reqArr.put(new JSONObject().put("kinds", new JSONArray().put(30078).put(1))
                                .put("#t", new JSONArray().put("xanadu-doc-v1"))
                                .put("#d", new JSONArray().put(clean))
                                .put("limit", 10));
                        String sub = reqArr.toString();
                        wsSendText(wOut, sub);
                        long deadline = System.currentTimeMillis() + 2400;
                        while (System.currentTimeMillis() < deadline) {
                            String msg = wsRecvText(wIn);
                            if (msg == null) break;
                            if (msg.isEmpty()) continue;
                            JSONArray arr = new JSONArray(msg);
                            String kind = arr.optString(0, "");
                            if ("EOSE".equals(kind)) break;
                            if ("EVENT".equals(kind) && arr.length() >= 3) {
                                JSONObject ev = arr.optJSONObject(2);
                                if (ev == null) continue;
                                try {
                                    JSONObject data = new JSONObject(ev.optString("content", "{}"));
                                    String t = data.optString("type", "");
                                    if ("xanadu-chunk".equals(t)) {
                                        String cSha = data.optString("sha256", "");
                                        byte[] rawC = Base64.getDecoder().decode(data.optString("data_b64", ""));
                                        if (!cSha.isEmpty() && Ed25519.toHex(Bip340.sha256(rawC)).equals(cSha)) {
                                            chunkMap.put(cSha, rawC);
                                        }
                                        continue;
                                    }
                                    if (!"xanadu-doc".equals(t)) continue;
                                    if (data.optBoolean("chunked", false)) {
                                        manifests.add(data);
                                        continue;
                                    }
                                    String dom = data.optString("domain", "").trim().toLowerCase(Locale.US);
                                    String sha = data.optString("sha256", "");
                                    String pub = data.optString("pubkey_hex", "");
                                    String sig = data.optString("signature_hex", "");
                                    String txt = data.optString("content", "");
                                    int ver = data.optInt("version_num", 1);
                                    double ts = data.optDouble("created_at", System.currentTimeMillis() / 1000.0);
                                    if (!dom.isEmpty() && !sha.isEmpty() && !pub.isEmpty() && !sig.isEmpty() && !txt.isEmpty()) {
                                        synchronized (domains) {
                                            domains.put(new JSONObject().put("name", dom).put("pubkey_hex", pub).put("created_at", ts));
                                            versions.put(new JSONObject().put("domain", dom).put("version_num", ver)
                                                    .put("sha256", sha).put("prev_sha256", data.optString("prev_sha256", ""))
                                                    .put("signature_hex", sig)
                                                    .put("title", data.optString("title", dom)).put("created_at", ts)
                                                    .put("is_app", data.optBoolean("is_app", false)));
                                            blobs.put(new JSONObject().put("sha256", sha).put("content", txt).put("created_at", ts));
                                        }
                                    }
                                } catch (Exception ignored) {
                                }
                            }
                        }
                    }
                } catch (Exception ignored) {
                } finally {
                    latch.countDown();
                }
            });
        }
        try {
            latch.await(3000, TimeUnit.MILLISECONDS);
            for (JSONObject m : new ArrayList<>(manifests)) {
                JSONArray cArr = m.optJSONArray("chunks");
                if (cArr == null || cArr.length() == 0) continue;
                boolean ok = true;
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                for (int i = 0; i < cArr.length(); i++) {
                    byte[] c = chunkMap.get(cArr.optString(i, ""));
                    if (c == null) { ok = false; break; }
                    bos.write(c);
                }
                if (!ok) continue;
                String dom = m.optString("domain", "").trim().toLowerCase(Locale.US);
                String sha = m.optString("sha256", "");
                String pub = m.optString("pubkey_hex", "");
                String sig = m.optString("signature_hex", "");
                String txt = new String(bos.toByteArray(), StandardCharsets.UTF_8);
                int ver = m.optInt("version_num", 1);
                double ts = m.optDouble("created_at", System.currentTimeMillis() / 1000.0);
                if (!dom.isEmpty() && !sha.isEmpty() && !pub.isEmpty() && !sig.isEmpty()) {
                    domains.put(new JSONObject().put("name", dom).put("pubkey_hex", pub).put("created_at", ts));
                    versions.put(new JSONObject().put("domain", dom).put("version_num", ver)
                            .put("sha256", sha).put("prev_sha256", m.optString("prev_sha256", ""))
                            .put("signature_hex", sig)
                            .put("title", m.optString("title", dom)).put("created_at", ts)
                            .put("is_app", m.optBoolean("is_app", false)));
                    blobs.put(new JSONObject().put("sha256", sha).put("content", txt).put("created_at", ts));
                }
            }
            if (versions.length() > 0) {
                importBundle(new JSONObject().put("domains", domains).put("versions", versions).put("blobs", blobs), true);
            }
        } catch (Exception ignored) {
        }
        }
        if (!docs.containsKey(clean)) {
            List<String> frontier = new ArrayList<>(collectActivePeerUrls());
            JSONArray seeds = loadSeeds();
            for (int si = 0; si < seeds.length(); si++) {
                String su = seeds.optJSONObject(si) != null ? seeds.optJSONObject(si).optString("url", "") : "";
                if (!su.isEmpty() && !frontier.contains(su)) frontier.add(su);
            }
            int limit = Math.min(4, frontier.size());
            if (limit > 0) {
                java.util.List<java.util.concurrent.Future<?>> futs = new ArrayList<>();
                for (int i = 0; i < limit; i++) {
                    final String base = frontier.get(i);
                    futs.add(pool.submit(() -> {
                        try {
                            String raw = peerGet(base, "/api/dht/find?domain=" + URLEncoder.encode(clean, "UTF-8"), 1200);
                            JSONObject dj = new JSONObject(raw);
                            if (dj.optBoolean("found", false) && dj.has("bundle")) {
                                importBundle(dj.getJSONObject("bundle"), true);
                            }
                        } catch (Exception ignored) {}
                    }));
                }
                long waitEnd = System.currentTimeMillis() + 1500L;
                for (java.util.concurrent.Future<?> f : futs) {
                    try {
                        long rem = Math.max(50L, waitEnd - System.currentTimeMillis());
                        f.get(rem, java.util.concurrent.TimeUnit.MILLISECONDS);
                    } catch (Exception ignored) {}
                }
            }
        }
        if (!docs.containsKey(clean) && !checkHasWan()) {
            JSONObject gw = findLanGateway();
            if (gw != null) {
                try {
                    String raw = httpGet(gw.optString("url") + "/api/gateway/lookup?domain=" + URLEncoder.encode(clean, "UTF-8"), 2500);
                    if (raw != null && !raw.isEmpty()) {
                        importBundle(new JSONObject(raw), true);
                    }
                } catch (Exception ignored) {
                }
            }
        }
        boolean found = docs.containsKey(clean);
        if (!found) negLookupCache.put(clean, System.currentTimeMillis());
        return found;
    }

    private String dhtDistanceHex(String nodeId, String key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] a = md.digest((nodeId != null ? nodeId : "").getBytes(StandardCharsets.UTF_8));
            md.reset();
            byte[] b = md.digest((key != null ? key.trim().toLowerCase(Locale.US) : "").getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (int i = 0; i < 32; i++) {
                sb.append(String.format(Locale.US, "%02x", (a[i] ^ b[i]) & 0xFF));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private JSONArray loadSeeds() {
        try {
            File f = new File(dataDir, "seeds.json");
            if (f.exists()) {
                try (FileInputStream fis = new FileInputStream(f)) {
                    return new JSONArray(new String(readAll(fis), StandardCharsets.UTF_8));
                }
            }
        } catch (Exception ignored) {}
        return new JSONArray();
    }

    private void rememberSeed(String url, String label) {
        try {
            String clean = url != null ? url.trim().replaceAll("/+$", "") : "";
            if (!clean.startsWith("http://") && !clean.startsWith("https://")) return;
            JSONArray cur = loadSeeds();
            JSONArray next = new JSONArray();
            boolean updated = false;
            long nowSec = System.currentTimeMillis() / 1000L;
            for (int i = 0; i < cur.length(); i++) {
                JSONObject o = cur.optJSONObject(i);
                if (o == null) continue;
                if (clean.equals(o.optString("url", ""))) {
                    o.put("last_seen", nowSec);
                    if (label != null && !label.isEmpty()) o.put("label", label);
                    updated = true;
                }
                next.put(o);
            }
            if (!updated) {
                next.put(new JSONObject().put("url", clean).put("label", label != null && !label.isEmpty() ? label : "Community Seed").put("last_seen", nowSec));
            }
            try (FileOutputStream fos = new FileOutputStream(new File(dataDir, "seeds.json"))) {
                fos.write(next.toString(2).getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception ignored) {}
    }

    private static final long MAX_MESH_QUOTA_BYTES = 100L * 1024L * 1024L;
    private volatile String cachedNodeId = "";
    private volatile NatTunnel natTunnel;

    private void startNatTunnel() {
        try {
            if (natTunnel == null) {
                natTunnel = new NatTunnel(getNodeId(), this::natRpcDispatch, 8767);
                natTunnel.start();
            }
        } catch (Exception ignored) {
        }
    }

    private String natRpcDispatch(String method, String path, String body) {
        try {
            int qIdx = path.indexOf('?');
            String cleanPath = qIdx >= 0 ? path.substring(0, qIdx) : path;
            String q = qIdx >= 0 ? path.substring(qIdx + 1) : "";
            if ("GET".equals(method) && "/api/sync/manifest".equals(cleanPath)) {
                return exportManifest().toString();
            }
            if ("GET".equals(method) && "/api/sync/export".equals(cleanPath)) {
                String domQ = parseQuery(q).getOrDefault("domain", "");
                return (domQ.isEmpty() ? exportSyncBundle() : exportDomainBundle(domQ)).toString();
            }
            if ("POST".equals(method) && "/api/sync/import".equals(cleanPath)) {
                int[] st = importBundle(new JSONObject(body == null || body.isEmpty() ? "{}" : body));
                return new JSONObject().put("ok", true).put("imported_versions", st[0]).put("rejected", st[1]).toString();
            }
            return "{\"ok\":false,\"detail\":\"Unsupported NAT RPC\"}";
        } catch (Exception e) {
            return "{\"ok\":false}";
        }
    }

    private String peerGet(String peerUrl, String path, int timeoutMs) throws Exception {
        if (peerUrl.startsWith("stun://") && natTunnel != null) {
            return natTunnel.rpc(peerUrl, "GET", path, "", timeoutMs);
        }
        return httpGet(peerUrl + path, timeoutMs);
    }

    private boolean peerPostJson(String peerUrl, String path, String payload, int timeoutMs) throws Exception {
        if (peerUrl.startsWith("stun://") && natTunnel != null) {
            String res = natTunnel.rpc(peerUrl, "POST", path, payload, timeoutMs);
            return res != null && !res.isEmpty();
        }
        httpPostJson(peerUrl + path, payload, timeoutMs);
        return true;
    }

    private void announceStunNostr() {
        try {
            if (natTunnel == null || !natTunnel.stunOk || natTunnel.publicIp.isEmpty() || natTunnel.publicPort <= 0) return;
            String nid = getNodeId();
            BigInteger priv = Bip340.privFromSeed("xanadu-stun-" + nid);
            String nostrPub = Ed25519.toHex(Bip340.pubkeyX(priv));
            long createdAt = System.currentTimeMillis() / 1000L;
            String payload = new JSONObject()
                    .put("type", "xanadu-stun")
                    .put("node_id", nid)
                    .put("public_ip", natTunnel.publicIp)
                    .put("public_port", natTunnel.publicPort)
                    .put("local_port", natTunnel.localPort)
                    .put("ts", createdAt)
                    .toString();
            JSONArray tags = new JSONArray()
                    .put(new JSONArray().put("t").put("xanadu-stun-v1"))
                    .put(new JSONArray().put("d").put(nid));
            publishNostrEvent(priv, nostrPub, createdAt, tags, payload, 21078);
        } catch (Exception ignored) {
        }
    }

    private List<String> discoverStunPeersNostr() {
        List<String> out = new ArrayList<>();
        String selfId = getNodeId();
        String[] relays = {"wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"};
        for (String rUrl : relays) {
            try {
                String host = rUrl.replace("wss://", "").split("/")[0];
                try (SSLSocket sock = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, 443)) {
                    sock.setSoTimeout(2000);
                    byte[] nonce = new byte[16];
                    new SecureRandom().nextBytes(nonce);
                    String key = Base64.getEncoder().encodeToString(nonce);
                    String req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                            + "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
                    OutputStream wOut = sock.getOutputStream();
                    InputStream wIn = sock.getInputStream();
                    wOut.write(req.getBytes(StandardCharsets.US_ASCII));
                    wOut.flush();
                    StringBuilder hdr = new StringBuilder();
                    while (true) {
                        int b = wIn.read();
                        if (b < 0) break;
                        hdr.append((char) b);
                        int len = hdr.length();
                        if (len >= 4 && hdr.substring(len - 4).equals("\r\n\r\n")) break;
                    }
                    if (!hdr.toString().contains("101")) continue;
                    String sub = new JSONArray().put("REQ").put("xst-" + (System.currentTimeMillis() % 10000))
                            .put(new JSONObject().put("kinds", new JSONArray().put(21078).put(1))
                                    .put("#t", new JSONArray().put("xanadu-stun-v1"))
                                    .put("limit", 20))
                            .toString();
                    wsSendText(wOut, sub);
                    long deadline = System.currentTimeMillis() + 2000;
                    while (System.currentTimeMillis() < deadline) {
                        String msg = wsRecvText(wIn);
                        if (msg == null) break;
                        if (msg.isEmpty()) continue;
                        JSONArray arr = new JSONArray(msg);
                        String k = arr.optString(0, "");
                        if ("EOSE".equals(k)) break;
                        if ("EVENT".equals(k) && arr.length() >= 3) {
                            JSONObject ev = arr.optJSONObject(2);
                            if (ev == null) continue;
                            JSONObject data = new JSONObject(ev.optString("content", "{}"));
                            if (!"xanadu-stun".equals(data.optString("type", ""))) continue;
                            String nid = data.optString("node_id", "").trim();
                            String pip = data.optString("public_ip", "").trim();
                            int pport = data.optInt("public_port", 0);
                            if (!nid.isEmpty() && !nid.equals(selfId) && !pip.isEmpty() && pport > 0) {
                                out.add("stun://" + nid + "@" + pip + ":" + pport);
                            }
                        }
                    }
                    break;
                }
            } catch (Exception ignored) {
            }
        }
        return out;
    }

    private String getNodeId() {
        if (!cachedNodeId.isEmpty()) return cachedNodeId;
        try {
            File f = new File(dataDir, "node_id.txt");
            if (f.exists()) {
                String s = readFileText(f).trim();
                if (!s.isEmpty()) {
                    cachedNodeId = s;
                    return s;
                }
            }
            byte[] rnd = new byte[8];
            new SecureRandom().nextBytes(rnd);
            String id = Ed25519.toHex(rnd);
            writeFileText(f, id);
            cachedNodeId = id;
            return id;
        } catch (Exception e) {
            return "and-" + Math.abs(System.identityHashCode(this));
        }
    }

    private long computeMeshBytes() {
        long total = 0L;
        synchronized (docs) {
            for (JSONObject d : docs.values()) {
                total += d.optString("raw_content", "").getBytes(StandardCharsets.UTF_8).length;
            }
        }
        return total;
    }

    private JSONObject exportHomeCommons(String mode, int limit) {
        String cleanMode = (mode == null ? "all" : mode.trim().toLowerCase(Locale.US));
        int cap = Math.max(1, Math.min(60, limit));
        long nowSec = System.currentTimeMillis() / 1000L;
        long bucket = nowSec / 900L;
        int lanCount = lanPeers.size();
        JSONArray citationsOut = new JSONArray();
        List<JSONObject> candidates = new ArrayList<>();
        try {
            Map<String, String> firstQuoterByTarget = new HashMap<>();
            Map<String, Integer> blCountByTarget = new HashMap<>();
            synchronized (docs) {
                for (Map.Entry<String, JSONObject> e : docs.entrySet()) {
                    String srcDom = e.getKey();
                    if (blockedDomains.contains(srcDom)) continue;
                    JSONObject d = e.getValue();
                    String raw = d.optString("raw_content", "");
                    if (raw.isEmpty()) continue;
                    JSONArray segs = TransclusionEngine.buildSegments(raw, docs);
                    for (int i = 0; i < segs.length(); i++) {
                        JSONObject seg = segs.optJSONObject(i);
                        if (seg == null || !"transclusion".equals(seg.optString("type"))) continue;
                        String tgtDom = seg.optString("target_domain", "");
                        if (tgtDom.isEmpty() || blockedDomains.contains(tgtDom)) continue;
                        blCountByTarget.put(tgtDom, blCountByTarget.getOrDefault(tgtDom, 0) + 1);
                        if (!firstQuoterByTarget.containsKey(tgtDom)) firstQuoterByTarget.put(tgtDom, srcDom);
                        if (citationsOut.length() < 10) {
                            String qTxt = seg.optString("quoted_text", "");
                            if (qTxt.length() > 180) qTxt = qTxt.substring(0, 180);
                            citationsOut.put(new JSONObject()
                                    .put("source_domain", srcDom)
                                    .put("target_domain", tgtDom)
                                    .put("start", seg.optInt("target_start", 0))
                                    .put("end", seg.optInt("target_end", 0))
                                    .put("quote", qTxt)
                                    .put("age", "recent")
                                    .put("reason", "Quoted by " + srcDom));
                        }
                    }
                }
                for (Map.Entry<String, JSONObject> e : docs.entrySet()) {
                    String dom = e.getKey();
                    JSONObject d = e.getValue();
                    String pub = d.optString("pubkey_hex", d.optString("pubkey", "")).toLowerCase(Locale.US);
                    if (blockedDomains.contains(dom) || (!pub.isEmpty() && blockedPubkeys.contains(pub))) continue;
                    String kind = d.optString("kind", d.optBoolean("is_app", false) ? "capsule" : "document");
                    int bl = blCountByTarget.getOrDefault(dom, 0);
                    boolean followed = !pub.isEmpty() && followedPubkeys.contains(pub);
                    if ("cited".equals(cleanMode) && bl == 0) continue;
                    if ("followed".equals(cleanMode) && !followed) continue;
                    if ("capsules".equals(cleanMode) && !"capsule".equals(kind)) continue;
                    long ageSec = Math.max(0L, nowSec - (long) d.optDouble("created_at", nowSec));
                    String ageStr = ageSec < 60 ? (ageSec + "s") : (ageSec < 3600 ? ((ageSec / 60) + "m") : (ageSec < 86400 ? ((ageSec / 3600) + "h") : ((ageSec / 86400) + "d")));
                    String reason;
                    if (bl > 0) {
                        String q = firstQuoterByTarget.getOrDefault(dom, "peer.xnd");
                        reason = bl == 1 ? ("Quoted by " + q) : ("Quoted by " + q + " (+" + (bl - 1) + ")");
                    } else if (followed) {
                        reason = "Updated " + ageStr + " ago by a key you follow";
                    } else if (lanCount > 0) {
                        reason = "Available across " + lanCount + " Wi-Fi peer(s) • " + ageStr;
                    } else {
                        reason = "Rotation window • updated " + ageStr + " ago";
                    }
                    String rot = TransclusionEngine.sha256Hex(bucket + ":" + dom);
                    String snip = d.optString("raw_content", "").replaceAll("\\s+", " ").trim();
                    if (snip.length() > 180) snip = snip.substring(0, 180);
                    candidates.add(new JSONObject()
                            .put("domain", dom)
                            .put("title", d.optString("title", dom))
                            .put("kind", kind)
                            .put("version", d.optInt("version_num", d.optInt("version", 1)))
                            .put("pubkey_hex", pub)
                            .put("fingerprint", formatFingerprint(pub))
                            .put("snippet", snip)
                            .put("backlinks", bl)
                            .put("followed", followed)
                            .put("age", ageStr)
                            .put("reason", reason)
                            .put("_rot", rot));
                }
            }
            candidates.sort((a, b) -> {
                if ("cited".equals(cleanMode)) {
                    int cmp = Integer.compare(b.optInt("backlinks", 0), a.optInt("backlinks", 0));
                    if (cmp != 0) return cmp;
                }
                return a.optString("_rot").compareTo(b.optString("_rot"));
            });
            JSONArray itemsOut = new JSONArray();
            Set<String> seenPubs = new HashSet<>();
            List<JSONObject> overflow = new ArrayList<>();
            for (JSONObject c : candidates) {
                String p = c.optString("pubkey_hex", "");
                if (!p.isEmpty() && !seenPubs.add(p)) {
                    overflow.add(c);
                    continue;
                }
                c.remove("_rot");
                itemsOut.put(c);
                if (itemsOut.length() >= cap) break;
            }
            if (itemsOut.length() < cap) {
                for (JSONObject c : overflow) {
                    c.remove("_rot");
                    itemsOut.put(c);
                    if (itemsOut.length() >= cap) break;
                }
            }
            return new JSONObject()
                    .put("ok", true)
                    .put("mode", cleanMode)
                    .put("rotation_bucket", bucket)
                    .put("rotation_interval_sec", 900)
                    .put("lan_peers", lanCount)
                    .put("latest_citations", citationsOut)
                    .put("items", itemsOut);
        } catch (Exception e) {
            return new JSONObject();
        }
    }

    private JSONObject exportManifest() {
        return exportManifest(0.0, 500);
    }

    private JSONObject exportManifest(double since, int limit) {
        int cap = Math.max(1, Math.min(2000, limit));
        JSONObject domMap = new JSONObject();
        double nextCursor = since;
        boolean hasMore = false;
        try {
            List<Map.Entry<String, JSONObject>> entries = new ArrayList<>();
            synchronized (docs) {
                for (Map.Entry<String, JSONObject> e : docs.entrySet()) {
                    double upd = e.getValue().optDouble("created_at", 0.0);
                    if (since <= 0.0 || upd > since) {
                        entries.add(e);
                    }
                }
            }
            entries.sort((a, b) -> Double.compare(a.getValue().optDouble("created_at", 0.0), b.getValue().optDouble("created_at", 0.0)));
            if (entries.size() > cap) {
                hasMore = true;
                entries = entries.subList(0, cap);
            }
            for (Map.Entry<String, JSONObject> e : entries) {
                JSONObject d = e.getValue();
                double upd = d.optDouble("created_at", 0.0);
                if (upd > nextCursor) nextCursor = upd;
                domMap.put(e.getKey(), new JSONObject()
                        .put("latest_version", d.optInt("version_num", d.optInt("version", 1)))
                        .put("sha256", d.optString("sha256", ""))
                        .put("pubkey_hex", d.optString("pubkey_hex", d.optString("pubkey", "")))
                        .put("updated_at", upd));
            }
            return new JSONObject()
                    .put("ok", true)
                    .put("node_id", getNodeId())
                    .put("label", "Xanadu Android")
                    .put("has_wan", checkHasWan())
                    .put("share_gateway", shareGateway)
                    .put("seed_node", shareGateway && checkHasWan())
                    .put("dht_k", 3)
                    .put("domains", domMap)
                    .put("next_cursor", nextCursor)
                    .put("has_more", hasMore)
                    .put("mesh_bytes", computeMeshBytes())
                    .put("mesh_quota_bytes", MAX_MESH_QUOTA_BYTES);
        } catch (Exception e) {
            return new JSONObject();
        }
    }

    private JSONObject exportDomainBundle(String domain) {
        JSONObject out = new JSONObject();
        JSONArray domains = new JSONArray();
        JSONArray versions = new JSONArray();
        JSONArray blobs = new JSONArray();
        try {
            String clean = normalizeXndDomain(domain);
            JSONObject d;
            synchronized (docs) {
                d = docs.get(clean);
            }
            if (d != null) {
                String sha = d.optString("sha256", "");
                String pubHex = d.optString("pubkey_hex", d.optString("pubkey", ""));
                String sigHex = d.optString("signature_hex", d.optString("signature", ""));
                int ver = d.optInt("version_num", d.optInt("version", 1));
                double ts = d.optDouble("created_at", System.currentTimeMillis() / 1000.0);
                domains.put(new JSONObject().put("name", clean).put("pubkey_hex", pubHex).put("created_at", ts));
                boolean isApp = d.optBoolean("is_app", false) || "capsule".equals(d.optString("kind", ""));
                versions.put(new JSONObject()
                        .put("domain", clean)
                        .put("version", ver)
                        .put("version_num", ver)
                        .put("sha256", sha)
                        .put("prev_sha256", d.optString("prev_sha256", ""))
                        .put("signature_hex", sigHex)
                        .put("title", d.optString("title", clean))
                        .put("created_at", ts)
                        .put("kind", isApp ? "capsule" : "document")
                        .put("is_app", isApp));
                if (!sha.isEmpty()) {
                    blobs.put(new JSONObject()
                            .put("sha256", sha)
                            .put("content", d.optString("raw_content", ""))
                            .put("created_at", ts));
                }
            }
            out.put("domains", domains).put("versions", versions).put("blobs", blobs)
                    .put("assets", new JSONArray()).put("links", new JSONArray());
        } catch (Exception ignored) {
        }
        return out;
    }

    private List<String> collectActivePeerUrls() {
        List<String> urls = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        List<JSONObject> sortedLan = new ArrayList<>(lanPeers.values());
        sortedLan.sort((a, b) -> Long.compare(b.optLong("last_seen_ms", 0L), a.optLong("last_seen_ms", 0L)));
        for (JSONObject lp : sortedLan) {
            String u = lp.optString("url", "").trim().replaceAll("/+$", "");
            if ((u.startsWith("http://") || u.startsWith("https://"))
                    && !u.contains("127.0.0.1") && !u.contains("localhost") && seen.add(u)) {
                urls.add(u);
            }
        }
        for (JSONObject p : new ArrayList<>(peers)) {
            String u = p.optString("url", "").trim().replaceAll("/+$", "");
            if ((u.startsWith("http://") || u.startsWith("https://"))
                    && !u.contains("127.0.0.1") && !u.contains("localhost") && seen.add(u)) {
                urls.add(u);
            }
        }
        for (String su : discoverStunPeersNostr()) {
            if (seen.add(su)) urls.add(su);
        }
        return urls;
    }

    private void pushDomainToQuorum(String domain, int quorum) {
        try {
            JSONObject bundle = exportDomainBundle(domain);
            if (bundle.optJSONArray("versions") == null || bundle.optJSONArray("versions").length() == 0) return;
            String payload = bundle.toString();
            List<String> candidates = collectActivePeerUrls();
            int limit = Math.min(candidates.size(), Math.max(quorum * 2, 6));
            for (int i = 0; i < limit; i++) {
                final String pUrl = candidates.get(i);
                pool.submit(() -> {
                    try {
                        peerPostJson(pUrl, "/api/sync/import", payload, 3000);
                    } catch (Exception ignored) {
                    }
                });
            }
        } catch (Exception ignored) {
        }
    }

    private String rendezvousRank(String nodeId, String domain) {
        return Ed25519.toHex(Bip340.sha256((nodeId + ":" + domain).getBytes(StandardCharsets.UTF_8)));
    }

    private boolean isTopRendezvousSeeder(List<String> allNodeIds, String selfId, String domain) {
        List<String> sorted = new ArrayList<>(allNodeIds);
        Collections.sort(sorted, (a, b) -> rendezvousRank(b, domain).compareTo(rendezvousRank(a, domain)));
        for (int i = 0; i < Math.min(3, sorted.size()); i++) {
            if (selfId.equals(sorted.get(i))) return true;
        }
        return false;
    }

    private void runMeshAntiEntropy() {
        try {
            String selfId = getNodeId();
            List<String> candidates = collectActivePeerUrls();
            List<String> peerUrls = new ArrayList<>();
            List<String> peerIds = new ArrayList<>();
            List<JSONObject> peerManifests = new ArrayList<>();
            for (int i = 0; i < Math.min(candidates.size(), 6); i++) {
                String pUrl = candidates.get(i);
                try {
                    String raw = peerGet(pUrl, "/api/sync/manifest", 2500);
                    JSONObject m = new JSONObject(raw);
                    if (m.has("domains")) {
                        if (!checkHasWan() && m.optBoolean("has_wan", false) && m.optBoolean("share_gateway", true)) {
                            meshGatewayPeer = new JSONObject()
                                    .put("url", pUrl)
                                    .put("label", m.optString("label", "LAN Peer"))
                                    .put("updated_at", System.currentTimeMillis() / 1000.0);
                        }
                        peerUrls.add(pUrl);
                        peerIds.add(m.optString("node_id", pUrl));
                        peerManifests.add(m.getJSONObject("domains"));
                    }
                } catch (Exception ignored) {
                }
            }
            List<String> allNodeIds = new ArrayList<>();
            allNodeIds.add(selfId);
            allNodeIds.addAll(peerIds);

            boolean underQuota = computeMeshBytes() < (long) (MAX_MESH_QUOTA_BYTES * 0.90);
            for (int i = 0; i < peerManifests.size(); i++) {
                String pUrl = peerUrls.get(i);
                JSONObject pDoms = peerManifests.get(i);
                JSONArray names = pDoms.names();
                if (names == null) continue;
                for (int j = 0; j < names.length(); j++) {
                    String dom = names.getString(j);
                    if (blockedDomains.contains(dom)) continue;
                    int pVer = pDoms.getJSONObject(dom).optInt("latest_version", 0);
                    JSONObject localDoc;
                    synchronized (docs) { localDoc = docs.get(dom); }
                    int localVer = localDoc != null ? localDoc.optInt("version_num", localDoc.optInt("version", 0)) : 0;
                    if (pVer > localVer && (underQuota || isTopRendezvousSeeder(allNodeIds, selfId, dom))) {
                        try {
                            String rawB = peerGet(pUrl, "/api/sync/export?domain=" + URLEncoder.encode(dom, "UTF-8"), 4000);
                            importBundle(new JSONObject(rawB));
                        } catch (Exception ignored) {
                        }
                    }
                }
            }

            if (!peerManifests.isEmpty()) {
                List<String> localKeys;
                synchronized (docs) { localKeys = new ArrayList<>(docs.keySet()); }
                for (String dom : localKeys) {
                    if (blockedDomains.contains(dom)) continue;
                    JSONObject localDoc;
                    synchronized (docs) { localDoc = docs.get(dom); }
                    if (localDoc == null) continue;
                    int localVer = localDoc.optInt("version_num", localDoc.optInt("version", 1));
                    int replicas = 1;
                    List<String> missing = new ArrayList<>();
                    for (int i = 0; i < peerManifests.size(); i++) {
                        JSONObject pInfo = peerManifests.get(i).optJSONObject(dom);
                        int pVer = pInfo != null ? pInfo.optInt("latest_version", 0) : 0;
                        if (pVer >= localVer) replicas++;
                        else missing.add(peerUrls.get(i));
                    }
                    if (replicas < 3 && !missing.isEmpty()) {
                        String payload = exportDomainBundle(dom).toString();
                        int need = Math.min(3 - replicas, missing.size());
                        for (int k = 0; k < need; k++) {
                            try {
                                peerPostJson(missing.get(k), "/api/sync/import", payload, 3000);
                            } catch (Exception ignored) {
                            }
                        }
                    }
                }
            }
            enforceMeshQuota(allNodeIds, selfId);
        } catch (Exception ignored) {
        }
    }

    private void enforceMeshQuota(List<String> allNodeIds, String selfId) {
        long total = computeMeshBytes();
        if (total <= MAX_MESH_QUOTA_BYTES) return;
        synchronized (docs) {
            List<String> evictable = new ArrayList<>();
            for (String dom : docs.keySet()) {
                if (domainKeys.containsKey(dom)) continue; // never evict user-owned domains
                if (!isTopRendezvousSeeder(allNodeIds, selfId, dom)) {
                    evictable.add(dom);
                }
            }
            for (String dom : evictable) {
                if (total <= (long) (MAX_MESH_QUOTA_BYTES * 0.85)) break;
                JSONObject removed = docs.remove(dom);
                if (removed != null) {
                    total -= removed.optString("raw_content", "").getBytes(StandardCharsets.UTF_8).length;
                }
            }
            saveDocs();
        }
    }

    public void runHeadlessMeshSync() {
        try {
            discoverFromNostr();
        } catch (Exception ignored) {
        }
        runMeshAntiEntropy();
    }

    private void startAutoGossip() {
        ScheduledExecutorService sched = Executors.newSingleThreadScheduledExecutor();
        sched.scheduleWithFixedDelay(() -> {
            if (!running) { sched.shutdown(); return; }
            try {
                syncUnconfirmedLocalDomainsToNostr();
            } catch (Exception ignored) {
            }
            try {
                discoverFromNostr();
            } catch (Exception ignored) {
            }
            for (JSONObject p : new ArrayList<>(peers)) {
                if (!p.optBoolean("subscribed", false)) continue;
                try {
                    pullFromPeer(p.optString("url", ""), p.optString("label", "Peer Node"));
                } catch (Exception ignored) {
                }
            }
            announceStunNostr();
            runMeshAntiEntropy();
            if (wifiDirectMesh != null) {
                if (checkHasWan()) {
                    wifiDirectMesh.disconnectIfClient();
                    if (shareGateway) wifiDirectMesh.ensureGroupOwner();
                } else if (findLanGateway() == null) {
                    wifiDirectMesh.discoverAndAutoConnect();
                }
            }
        }, 2, 20, TimeUnit.SECONDS);
    }

    private void syncUnconfirmedLocalDomainsToNostr() {
        List<String> ownedDoms;
        synchronized (domainKeys) {
            ownedDoms = new ArrayList<>(domainKeys.keySet());
        }
        for (String dom : ownedDoms) {
            if (blockedDomains.contains(dom)) continue;
            JSONObject d = docs.get(dom);
            if (d == null) continue;
            int ver = d.optInt("version_num", d.optInt("version", 1));
            Integer synced = nostrSyncedVersions.get(dom);
            if (synced != null && synced >= ver) continue;
            String sha = d.optString("sha256", "");
            String prevSha = d.optString("prev_sha256", "");
            String pubHex = d.optString("pubkey_hex", d.optString("pubkey", ""));
            String sigHex = d.optString("signature_hex", d.optString("signature", ""));
            String title = d.optString("title", dom);
            String raw = d.optString("raw_content", "");
            boolean isApp = "capsule".equals(d.optString("kind", ""));
            if (!sha.isEmpty() && !pubHex.isEmpty() && !sigHex.isEmpty() && !raw.isEmpty()) {
                announceDocNostr(dom, ver, title, sha, pubHex, sigHex, raw, isApp, prevSha);
            }
        }
    }

    private boolean announceDocNostr(String domain, int ver, String title, String sha, String pubHex, String sigHex, String content, boolean isApp, String prevSha) {
        try {
            BigInteger priv = Bip340.privFromSeed("xanadu-doc-nostr-" + domain);
            String nostrPub = Ed25519.toHex(Bip340.pubkeyX(priv));
            long createdAt = System.currentTimeMillis() / 1000L;
            byte[] rawBytes = content.getBytes(StandardCharsets.UTF_8);
            String safePrev = prevSha != null ? prevSha : "";
            int accepted = 0;
            if (rawBytes.length <= 36000) {
                String payload = "{"
                        + "\"type\":\"xanadu-doc\","
                        + "\"domain\":" + nostrJsonString(domain) + ","
                        + "\"version_num\":" + ver + ","
                        + "\"title\":" + nostrJsonString(title) + ","
                        + "\"sha256\":" + nostrJsonString(sha) + ","
                        + "\"prev_sha256\":" + nostrJsonString(safePrev) + ","
                        + "\"pubkey_hex\":" + nostrJsonString(pubHex) + ","
                        + "\"signature_hex\":" + nostrJsonString(sigHex) + ","
                        + "\"content\":" + nostrJsonString(content) + ","
                        + "\"is_app\":" + isApp + ","
                        + "\"created_at\":" + createdAt
                        + "}";
                JSONArray tags = new JSONArray().put(new JSONArray().put("t").put("xanadu-doc-v1"))
                        .put(new JSONArray().put("t").put("xnd-" + domain))
                        .put(new JSONArray().put("d").put(domain));
                accepted = publishNostrEvent(priv, nostrPub, createdAt, tags, payload, 30078);
            } else {
                int chunkSize = 24000;
                JSONArray chunkHashes = new JSONArray();
                for (int i = 0; i < rawBytes.length; i += chunkSize) {
                    int end = Math.min(rawBytes.length, i + chunkSize);
                    byte[] slice = java.util.Arrays.copyOfRange(rawBytes, i, end);
                    String cSha = Ed25519.toHex(Bip340.sha256(slice));
                    chunkHashes.put(cSha);
                    String cPayload = "{"
                            + "\"type\":\"xanadu-chunk\","
                            + "\"sha256\":" + nostrJsonString(cSha) + ","
                            + "\"data_b64\":" + nostrJsonString(Base64.getEncoder().encodeToString(slice))
                            + "}";
                    JSONArray cTags = new JSONArray().put(new JSONArray().put("t").put("xanadu-chunk-v1"))
                            .put(new JSONArray().put("x").put(cSha));
                    publishNostrEvent(priv, nostrPub, createdAt, cTags, cPayload, 1);
                }
                StringBuilder chJson = new StringBuilder("[");
                for (int i = 0; i < chunkHashes.length(); i++) {
                    if (i > 0) chJson.append(',');
                    chJson.append(nostrJsonString(chunkHashes.optString(i, "")));
                }
                chJson.append(']');
                String manifest = "{"
                        + "\"type\":\"xanadu-doc\","
                        + "\"chunked\":true,"
                        + "\"chunks\":" + chJson + ","
                        + "\"domain\":" + nostrJsonString(domain) + ","
                        + "\"version_num\":" + ver + ","
                        + "\"title\":" + nostrJsonString(title) + ","
                        + "\"sha256\":" + nostrJsonString(sha) + ","
                        + "\"prev_sha256\":" + nostrJsonString(safePrev) + ","
                        + "\"pubkey_hex\":" + nostrJsonString(pubHex) + ","
                        + "\"signature_hex\":" + nostrJsonString(sigHex) + ","
                        + "\"is_app\":" + isApp + ","
                        + "\"created_at\":" + createdAt
                        + "}";
                JSONArray tags = new JSONArray().put(new JSONArray().put("t").put("xanadu-doc-v1"))
                        .put(new JSONArray().put("t").put("xnd-" + domain))
                        .put(new JSONArray().put("d").put(domain));
                accepted = publishNostrEvent(priv, nostrPub, createdAt, tags, manifest, 30078);
            }
            if (accepted > 0) {
                nostrSyncedVersions.put(domain, ver);
                return true;
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private static String nostrJsonString(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format(Locale.US, "\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private static String nostrTagsJson(JSONArray tags) {
        StringBuilder sb = new StringBuilder("[");
        if (tags != null) {
            for (int i = 0; i < tags.length(); i++) {
                if (i > 0) sb.append(',');
                JSONArray row = tags.optJSONArray(i);
                sb.append('[');
                if (row != null) {
                    for (int j = 0; j < row.length(); j++) {
                        if (j > 0) sb.append(',');
                        sb.append(nostrJsonString(row.optString(j, "")));
                    }
                }
                sb.append(']');
            }
        }
        sb.append(']');
        return sb.toString();
    }

    private int publishNostrEvent(BigInteger priv, String nostrPub, long createdAt, JSONArray tags, String payload, int evKind) {
        final java.util.concurrent.atomic.AtomicInteger accepted = new java.util.concurrent.atomic.AtomicInteger(0);
        try {
            String tagsJson = nostrTagsJson(tags);
            String payloadJson = nostrJsonString(payload);
            String ser = "[0," + nostrJsonString(nostrPub) + "," + createdAt + "," + evKind + "," + tagsJson + "," + payloadJson + "]";
            byte[] idBytes = Bip340.sha256(ser.getBytes(StandardCharsets.UTF_8));
            String evId = Ed25519.toHex(idBytes);
            String sig = Ed25519.toHex(Bip340.sign(priv, idBytes));
            String msg = "[\"EVENT\",{"
                    + "\"id\":" + nostrJsonString(evId) + ","
                    + "\"pubkey\":" + nostrJsonString(nostrPub) + ","
                    + "\"created_at\":" + createdAt + ","
                    + "\"kind\":" + evKind + ","
                    + "\"tags\":" + tagsJson + ","
                    + "\"content\":" + payloadJson + ","
                    + "\"sig\":" + nostrJsonString(sig)
                    + "}]";
            String[] relays = {"wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"};
            CountDownLatch latch = new CountDownLatch(relays.length);
            for (String rUrl : relays) {
                pool.submit(() -> {
                    try {
                        String host = rUrl.replace("wss://", "").split("/")[0];
                        try (SSLSocket sock = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, 443)) {
                            sock.setSoTimeout(3000);
                            byte[] nonce = new byte[16];
                            new SecureRandom().nextBytes(nonce);
                            String key = Base64.getEncoder().encodeToString(nonce);
                            String req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                    + "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
                            OutputStream wOut = sock.getOutputStream();
                            InputStream wIn = sock.getInputStream();
                            wOut.write(req.getBytes(StandardCharsets.US_ASCII));
                            wOut.flush();
                            StringBuilder hdr = new StringBuilder();
                            while (true) {
                                int b = wIn.read();
                                if (b < 0) break;
                                hdr.append((char) b);
                                int l = hdr.length();
                                if (l >= 4 && hdr.substring(l - 4).equals("\r\n\r\n")) break;
                            }
                            if (hdr.toString().contains("101")) {
                                wsSendText(wOut, msg);
                                String ack = wsRecvText(wIn);
                                if (ack != null && !ack.isEmpty()) {
                                    try {
                                        JSONArray ackArr = new JSONArray(ack);
                                        if ("OK".equals(ackArr.optString(0)) && ackArr.optBoolean(2, false)) {
                                            accepted.incrementAndGet();
                                        }
                                    } catch (Exception ignored) {
                                    }
                                }
                            }
                        }
                    } catch (Exception ignored) {
                    } finally {
                        latch.countDown();
                    }
                });
            }
            latch.await(3200, TimeUnit.MILLISECONDS);
            if (accepted.get() == 0 && !checkHasWan()) {
                JSONObject gw = findLanGateway();
                if (gw != null) {
                    try {
                        String evBody = "{\"event\":{"
                                + "\"id\":" + nostrJsonString(evId) + ","
                                + "\"pubkey\":" + nostrJsonString(nostrPub) + ","
                                + "\"created_at\":" + createdAt + ","
                                + "\"kind\":" + evKind + ","
                                + "\"tags\":" + tagsJson + ","
                                + "\"content\":" + payloadJson + ","
                                + "\"sig\":" + nostrJsonString(sig)
                                + "}}";
                        httpPostJson(gw.optString("url") + "/api/gateway/nostr_publish", evBody, 4000);
                        accepted.incrementAndGet();
                    } catch (Exception ignored) {
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return accepted.get();
    }

    private boolean checkHasWan() {
        long now = System.currentTimeMillis();
        if (now - wanCheckedMs < 15_000L) return wanOk;
        boolean ok = false;
        for (String probe : new String[]{"https://clients3.google.com/generate_204", "https://cp.cloudflare.com/generate_204"}) {
            try {
                HttpURLConnection c = (HttpURLConnection) new URL(probe).openConnection();
                c.setInstanceFollowRedirects(false);
                c.setConnectTimeout(1800);
                c.setReadTimeout(1800);
                if (c.getResponseCode() == 204) {
                    ok = true;
                    break;
                }
            } catch (Exception ignored) {
            }
        }
        wanOk = ok;
        wanCheckedMs = now;
        return ok;
    }

    private JSONObject findLanGateway() {
        if (checkHasWan()) {
            meshGatewayPeer = null;
            return null;
        }
        long now = System.currentTimeMillis();
        JSONObject cur = meshGatewayPeer;
        if (cur != null && (now / 1000.0 - cur.optDouble("updated_at", 0.0)) < 90.0) {
            return cur;
        }
        meshGatewayPeer = null;
        for (String pUrl : collectActivePeerUrls()) {
            try {
                String raw = peerGet(pUrl, "/api/sync/manifest", 1500);
                JSONObject m = new JSONObject(raw);
                if (m.optBoolean("has_wan", false) && m.optBoolean("share_gateway", true)) {
                    JSONObject gw = new JSONObject()
                            .put("url", pUrl)
                            .put("label", m.optString("label", "LAN Peer"))
                            .put("updated_at", now / 1000.0);
                    meshGatewayPeer = gw;
                    return gw;
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private static boolean isSafePublicUrl(String url) {
        try {
            URL u = new URL(url);
            String sch = u.getProtocol().toLowerCase(Locale.US);
            if (!"http".equals(sch) && !"https".equals(sch)) return false;
            String host = u.getHost().toLowerCase(Locale.US);
            if (host.isEmpty() || "localhost".equals(host) || "127.0.0.1".equals(host) || "0.0.0.0".equals(host) || host.endsWith(".local")) {
                return false;
            }
            if (host.startsWith("10.") || host.startsWith("192.168.") || host.startsWith("169.254.")) return false;
            if (host.matches("^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*")) return false;
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] readAllBytesLimited(InputStream is, int maxBytes) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) {
            int allow = Math.min(n, maxBytes - bos.size());
            if (allow > 0) bos.write(buf, 0, allow);
            if (bos.size() >= maxBytes) break;
        }
        return bos.toByteArray();
    }

    private void startWifiDirectMesh() {
        try {
            wifiDirectMesh = new WifiDirectMesh(context, (peerUrl, label) -> {
                try {
                    lanPeers.put(peerUrl, new JSONObject()
                            .put("url", peerUrl)
                            .put("label", label)
                            .put("last_seen_ms", System.currentTimeMillis())
                            .put("last_synced_ms", 0L));
                    upsertPeer(peerUrl, label, 0.0, true);
                    pool.submit(() -> {
                        try { syncOneLanPeer(peerUrl, label); } catch (Exception ignored) {}
                    });
                } catch (Exception ignored) {
                }
            });
            wifiDirectMesh.start();
        } catch (Throwable ignored) {
        }
    }

    private void proxyFetchUrl(String targetUrl, String browsePrefix, String method, String bodyStr, OutputStream out) throws Exception {
        if (!isSafePublicUrl(targetUrl)) {
            sendJson(out, 400, "{\"detail\":\"Invalid or restricted URL\"}");
            return;
        }
        HttpURLConnection c = (HttpURLConnection) new URL(targetUrl).openConnection();
        c.setInstanceFollowRedirects(true);
        c.setConnectTimeout(7000);
        c.setReadTimeout(15000);
        c.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36");
        if ("POST".equalsIgnoreCase(method)) {
            c.setRequestMethod("POST");
            c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            try (OutputStream os = c.getOutputStream()) {
                os.write((bodyStr != null ? bodyStr : "").getBytes(StandardCharsets.UTF_8));
            }
        }
        int code = c.getResponseCode();
        String finalUrl = c.getURL().toString();
        String ctype = c.getContentType();
        if (ctype == null || ctype.isEmpty()) ctype = "application/octet-stream";
        ctype = ctype.split(";")[0].trim().toLowerCase(Locale.US);
        InputStream is = code >= 400 ? c.getErrorStream() : c.getInputStream();
        byte[] raw = is != null ? readAllBytesLimited(is, 4 * 1024 * 1024) : new byte[0];
        if ("text/html".equals(ctype)) {
            String txt = new String(raw, StandardCharsets.UTF_8);
            Matcher m = Pattern.compile("(?i)\\b(href|src|action|poster|data-src)\\s*=\\s*([\"'])([^\"']*)\\2").matcher(txt);
            StringBuffer sb = new StringBuffer();
            URL base = new URL(finalUrl);
            while (m.find()) {
                String attr = m.group(1), q = m.group(2), u = m.group(3);
                if (u.isEmpty() || u.startsWith("#") || u.startsWith("javascript:") || u.startsWith("data:") || u.startsWith("mailto:") || u.startsWith("tel:")) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(m.group(0)));
                    continue;
                }
                try {
                    String abs = new URL(base, u).toString();
                    if (abs.startsWith("http://") || abs.startsWith("https://")) {
                        m.appendReplacement(sb, Matcher.quoteReplacement(attr + "=" + q + browsePrefix + URLEncoder.encode(abs, "UTF-8") + q));
                    } else {
                        m.appendReplacement(sb, Matcher.quoteReplacement(m.group(0)));
                    }
                } catch (Exception e) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(m.group(0)));
                }
            }
            m.appendTail(sb);
            txt = sb.toString();
            txt = txt.replaceAll("(?i)\\s+integrity\\s*=\\s*([\"'])[^\"']*\\1", "");
            txt = txt.replaceAll("(?i)<meta[^>]+http-equiv\\s*=\\s*([\"'])Content-Security-Policy\\1[^>]*>", "");
            String baseTag = !txt.toLowerCase(Locale.US).contains("<base ") ? "<base href=\"" + finalUrl.replace("\"", "&quot;") + "\">" : "";
            String webShim = "<script>(function(){var bp=" + nostrJsonString(browsePrefix) + ",bu=" + nostrJsonString(finalUrl) + ";"
                    + "function rw(u){try{if(!u||typeof u!=='string')return u;if(u.startsWith(bp)||u.startsWith('data:')||u.startsWith('javascript:')||u.startsWith('#'))return u;var a=new URL(u,bu).href;if(a.startsWith('http://')||a.startsWith('https://'))return bp+encodeURIComponent(a);}catch(e){}return u;}"
                    + "var _f=window.fetch;if(_f){window.fetch=function(i,o){if(typeof i==='string')i=rw(i);return _f.call(this,i,o);};}"
                    + "var _o=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=rw(u);return _o.apply(this,arguments);};"
                    + "})();</script>";
            String injectHead = baseTag + webShim;
            Matcher hm = Pattern.compile("(?i)<head\\b[^>]*>").matcher(txt);
            if (hm.find()) {
                txt = txt.substring(0, hm.end()) + injectHead + txt.substring(hm.end());
            } else {
                txt = injectHead + txt;
            }
            sendBytes(out, code, "text/html", txt.getBytes(StandardCharsets.UTF_8));
        } else if ("text/css".equals(ctype)) {
            String css = new String(raw, StandardCharsets.UTF_8);
            URL base = new URL(finalUrl);
            Matcher cm = Pattern.compile("url\\(\\s*([\"']?)([^\"')]+)\\1\\s*\\)").matcher(css);
            StringBuffer csb = new StringBuffer();
            while (cm.find()) {
                String q = cm.group(1), u = cm.group(2).trim();
                if (u.isEmpty() || u.startsWith("data:") || u.startsWith("#")) {
                    cm.appendReplacement(csb, Matcher.quoteReplacement(cm.group(0)));
                    continue;
                }
                try {
                    String abs = new URL(base, u).toString();
                    if (abs.startsWith("http://") || abs.startsWith("https://")) {
                        cm.appendReplacement(csb, Matcher.quoteReplacement("url(" + q + browsePrefix + URLEncoder.encode(abs, "UTF-8") + q + ")"));
                    } else {
                        cm.appendReplacement(csb, Matcher.quoteReplacement(cm.group(0)));
                    }
                } catch (Exception e) {
                    cm.appendReplacement(csb, Matcher.quoteReplacement(cm.group(0)));
                }
            }
            cm.appendTail(csb);
            sendBytes(out, code, "text/css", csb.toString().getBytes(StandardCharsets.UTF_8));
        } else {
            sendBytes(out, code, ctype, raw);
        }
    }

    private int relayRawNostrEvent(String msg) {
        final java.util.concurrent.atomic.AtomicInteger accepted = new java.util.concurrent.atomic.AtomicInteger(0);
        String[] relays = {"wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"};
        CountDownLatch latch = new CountDownLatch(relays.length);
        for (String rUrl : relays) {
            pool.submit(() -> {
                try {
                    String host = rUrl.replace("wss://", "").split("/")[0];
                    try (SSLSocket sock = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, 443)) {
                        sock.setSoTimeout(3000);
                        byte[] nonce = new byte[16];
                        new SecureRandom().nextBytes(nonce);
                        String key = Base64.getEncoder().encodeToString(nonce);
                        String req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                + "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
                        OutputStream wOut = sock.getOutputStream();
                        InputStream wIn = sock.getInputStream();
                        wOut.write(req.getBytes(StandardCharsets.US_ASCII));
                        wOut.flush();
                        StringBuilder hdr = new StringBuilder();
                        while (true) {
                            int b = wIn.read();
                            if (b < 0) break;
                            hdr.append((char) b);
                            int l = hdr.length();
                            if (l >= 4 && hdr.substring(l - 4).equals("\r\n\r\n")) break;
                        }
                        if (hdr.toString().contains("101")) {
                            wsSendText(wOut, msg);
                            String ack = wsRecvText(wIn);
                            if (ack != null && ack.contains("\"OK\"") && ack.contains("true")) {
                                accepted.incrementAndGet();
                            }
                        }
                    }
                } catch (Exception ignored) {
                } finally {
                    latch.countDown();
                }
            });
        }
        try {
            latch.await(3200, TimeUnit.MILLISECONDS);
        } catch (Exception ignored) {
        }
        return accepted.get();
    }

    private static void wsSendText(OutputStream out, String text) throws Exception {
        byte[] payload = text.getBytes(StandardCharsets.UTF_8);
        byte[] mask = new byte[4];
        new SecureRandom().nextBytes(mask);
        ByteArrayOutputStream frame = new ByteArrayOutputStream();
        frame.write(0x81);
        if (payload.length < 126) {
            frame.write(0x80 | payload.length);
        } else {
            frame.write(0x80 | 126);
            frame.write((payload.length >> 8) & 0xff);
            frame.write(payload.length & 0xff);
        }
        frame.write(mask);
        for (int i = 0; i < payload.length; i++) frame.write(payload[i] ^ mask[i % 4]);
        out.write(frame.toByteArray());
        out.flush();
    }

    private static String wsRecvText(InputStream in) throws Exception {
        int b1 = in.read();
        int b2 = in.read();
        if (b1 < 0 || b2 < 0) return null;
        int opcode = b1 & 0x0f;
        boolean masked = (b2 & 0x80) != 0;
        int len = b2 & 0x7f;
        if (len == 126) {
            len = ((in.read() & 0xff) << 8) | (in.read() & 0xff);
        } else if (len == 127) {
            for (int i = 0; i < 4; i++) in.read();
            len = ((in.read() & 0xff) << 24) | ((in.read() & 0xff) << 16) | ((in.read() & 0xff) << 8) | (in.read() & 0xff);
        }
        byte[] mask = new byte[4];
        if (masked) {
            for (int i = 0; i < 4; i++) mask[i] = (byte) in.read();
        }
        byte[] data = new byte[len];
        int off = 0;
        while (off < len) {
            int r = in.read(data, off, len - off);
            if (r < 0) break;
            off += r;
        }
        if (masked) {
            for (int i = 0; i < len; i++) data[i] ^= mask[i % 4];
        }
        if (opcode == 0x8) return null;
        if (opcode == 0x9) return "";
        return new String(data, 0, off, StandardCharsets.UTF_8);
    }

    private final java.util.concurrent.ConcurrentHashMap<String, JSONObject> newsCache = new java.util.concurrent.ConcurrentHashMap<>();

    private JSONObject fetchNewsJson(String cat) {
        long nowMs = System.currentTimeMillis();
        JSONObject cachedNews = newsCache.get(cat);
        if (cachedNews != null && (nowMs - cachedNews.optLong("_ts", 0L)) < 90_000L) {
            return cachedNews;
        }
        if (!checkHasWan()) {
            JSONObject gw = findLanGateway();
            if (gw != null) {
                try {
                    String raw = httpGet(gw.optString("url") + "/api/news?category=" + URLEncoder.encode(cat, "UTF-8"), 12000);
                    JSONObject gd = new JSONObject(raw);
                    if (gd.has("stories") && gd.optJSONArray("stories") != null && gd.optJSONArray("stories").length() > 0) {
                        gd.put("_ts", nowMs);
                        newsCache.put(cat, gd);
                        return gd;
                    }
                } catch (Exception ignored) {
                }
            }
        }
        String[][] feeds;
        switch (cat) {
            case "trending":
                feeds = new String[][]{
                        {"Trending · 1h", "https://news.google.com/rss/search?q=when:1h&hl=en-US&gl=US&ceid=US:en"},
                        {"Al Jazeera", "https://www.aljazeera.com/xml/rss/all.xml"},
                        {"BBC News", "https://feeds.bbci.co.uk/news/rss.xml"},
                        {"ESPN", "https://www.espn.com/espn/rss/news"},
                        {"TechCrunch", "https://techcrunch.com/feed/"}
                };
                break;
            case "world":
                feeds = new String[][]{{"World · 1h", "https://news.google.com/rss/search?q=world+when:1h&hl=en-US&gl=US&ceid=US:en"}, {"Al Jazeera", "https://www.aljazeera.com/xml/rss/all.xml"}, {"BBC World", "https://feeds.bbci.co.uk/news/world/rss.xml"}};
                break;
            case "tech":
                feeds = new String[][]{{"Tech · 1h", "https://news.google.com/rss/search?q=technology+when:1h&hl=en-US&gl=US&ceid=US:en"}, {"TechCrunch", "https://techcrunch.com/feed/"}, {"Ars Technica", "https://feeds.arstechnica.com/arstechnica/index"}, {"BBC Tech", "https://feeds.bbci.co.uk/news/technology/rss.xml"}};
                break;
            case "sports":
                feeds = new String[][]{{"Sports · 1h", "https://news.google.com/rss/search?q=sports+when:1h&hl=en-US&gl=US&ceid=US:en"}, {"ESPN", "https://www.espn.com/espn/rss/news"}, {"BBC Sport", "https://feeds.bbci.co.uk/sport/rss.xml"}};
                break;
            case "business":
                feeds = new String[][]{{"Business · 1h", "https://news.google.com/rss/search?q=business+when:1h&hl=en-US&gl=US&ceid=US:en"}, {"BBC Business", "https://feeds.bbci.co.uk/news/business/rss.xml"}};
                break;
            case "science":
                feeds = new String[][]{{"Science · 1h", "https://news.google.com/rss/search?q=science+when:1h&hl=en-US&gl=US&ceid=US:en"}, {"ScienceDaily", "https://www.sciencedaily.com/rss/all.xml"}, {"BBC Science", "https://feeds.bbci.co.uk/news/science_and_environment/rss.xml"}};
                break;
            default:
                feeds = new String[][]{{"Breaking · 1h", "https://news.google.com/rss/search?q=when:1h&hl=en-US&gl=US&ceid=US:en"}, {"Al Jazeera", "https://www.aljazeera.com/xml/rss/all.xml"}, {"BBC News", "https://feeds.bbci.co.uk/news/rss.xml"}, {"NPR News", "https://feeds.npr.org/1001/rss.xml"}};
                break;
        }
        List<List<JSONObject>> feedBatches = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (String[] f : feeds) {
            JSONArray batch = new JSONArray();
            try {
                String xml = httpGet(f[1], 3500);
                parseRssItems(xml, f[0], batch, seen, 6);
            } catch (Exception ignored) {
            }
            List<JSONObject> list = new ArrayList<>();
            for (int i = 0; i < batch.length(); i++) {
                JSONObject obj = batch.optJSONObject(i);
                if (obj != null) list.add(obj);
            }
            feedBatches.add(list);
        }
        JSONArray stories = new JSONArray();
        int maxLen = 0;
        for (List<JSONObject> b : feedBatches) if (b.size() > maxLen) maxLen = b.size();
        java.util.Random rng = new java.util.Random();
        for (int i = 0; i < maxLen && stories.length() < 28; i++) {
            List<JSONObject> round = new ArrayList<>();
            for (List<JSONObject> b : feedBatches) {
                if (i < b.size()) round.add(b.get(i));
            }
            Collections.shuffle(round, rng);
            for (JSONObject st : round) {
                if (stories.length() < 28) stories.put(st);
            }
        }
        if (stories.length() == 0) {
            JSONObject gw = findLanGateway();
            if (gw != null) {
                try {
                    String raw = httpGet(gw.optString("url") + "/api/news?category=" + URLEncoder.encode(cat, "UTF-8"), 5000);
                    JSONObject gd = new JSONObject(raw);
                    if (gd.has("stories") && gd.optJSONArray("stories") != null && gd.optJSONArray("stories").length() > 0) {
                        return gd;
                    }
                } catch (Exception ignored) {
                }
            }
        }
        try {
            return new JSONObject().put("category", cat).put("stories", stories);
        } catch (Exception e) {
            return new JSONObject();
        }
    }

    private void parseRssItems(String xml, String defaultSrc, JSONArray out, Set<String> seen, int maxItems) throws Exception {
        XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
        factory.setNamespaceAware(true);
        XmlPullParser p = factory.newPullParser();
        p.setInput(new StringReader(xml));
        boolean inItem = false;
        String title = "", link = "", pub = "", desc = "", img = "", src = defaultSrc;
        int ev = p.getEventType();
        long now = System.currentTimeMillis();
        while (ev != XmlPullParser.END_DOCUMENT && out.length() < maxItems) {
            if (ev == XmlPullParser.START_TAG) {
                String name = p.getName().toLowerCase(Locale.US);
                if (name.equals("item")) {
                    inItem = true;
                    title = ""; link = ""; pub = ""; desc = ""; img = ""; src = defaultSrc;
                } else if (inItem) {
                    if (name.equals("title")) title = p.nextText().trim();
                    else if (name.equals("link")) link = p.nextText().trim();
                    else if (name.equals("pubdate")) pub = p.nextText().trim();
                    else if (name.equals("description")) desc = p.nextText().trim();
                    else if (name.equals("source")) src = p.nextText().trim();
                    else if (name.equals("thumbnail") || name.equals("content") || name.equals("enclosure")) {
                        String u = p.getAttributeValue(null, "url");
                        if (u != null && u.startsWith("http")) img = upgrade4k(u);
                    }
                }
            } else if (ev == XmlPullParser.END_TAG && p.getName().equalsIgnoreCase("item") && inItem) {
                inItem = false;
                if (!title.isEmpty() && !link.isEmpty() && seen.add(link)) {
                    if (img.isEmpty()) {
                        try {
                            String host = new URL(link).getHost();
                            img = "https://www.google.com/s2/favicons?domain=" + URLEncoder.encode(host, "UTF-8") + "&sz=256";
                        } catch (Exception ignored) {}
                    }
                    String cleanDesc = desc.replaceAll("<[^>]+>", " ").replaceAll("\\s+", " ").trim();
                    if (cleanDesc.length() > 180) cleanDesc = cleanDesc.substring(0, 180);
                    JSONObject item = new JSONObject();
                    item.put("title", title);
                    item.put("url", link);
                    item.put("source", src.isEmpty() ? defaultSrc : src);
                    item.put("published", formatAge(pub, now));
                    item.put("is_fresh", isFresh(pub, now));
                    item.put("summary", cleanDesc);
                    item.put("image", img);
                    out.put(item);
                }
            }
            ev = p.next();
        }
    }

    private static String extractCrawlText(JSONObject d) {
        String raw = d.optString("raw_content", "");
        String kind = d.optString("kind", "document");
        if ("capsule".equals(kind) || (raw.trim().startsWith("{") && raw.contains("\"files\""))) {
            StringBuilder sb = new StringBuilder();
            try {
                JSONObject b = new JSONObject(raw);
                JSONObject files = b.optJSONObject("files");
                if (files != null) {
                    java.util.Iterator<String> it = files.keys();
                    while (it.hasNext()) {
                        String fn = it.next();
                        String fv = files.optString(fn, "");
                        if (fv.startsWith("data:") && fv.contains(";base64,")) {
                            sb.append(' ').append(fn);
                            continue;
                        }
                        String low = fn.toLowerCase(Locale.US);
                        if (low.endsWith(".html") || low.endsWith(".htm")) {
                            String stripped = fv.replaceAll("(?is)<(script|style)[^>]*>.*?</\\1>", " ").replaceAll("(?s)<[^>]+>", " ");
                            sb.append(' ').append(stripped);
                        } else if (low.endsWith(".md") || low.endsWith(".txt") || low.endsWith(".js") || low.endsWith(".css") || low.endsWith(".json")) {
                            sb.append(' ').append(fv.length() > 4000 ? fv.substring(0, 4000) : fv);
                        }
                    }
                }
                String bpy = b.optString("backend_py", "");
                if (!bpy.isEmpty()) sb.append(' ').append(bpy.length() > 2000 ? bpy.substring(0, 2000) : bpy);
                return sb.toString().replaceAll("\\s+", " ").trim();
            } catch (Exception ignored) {}
        }
        return raw.replaceAll("\\{\\{xnd://[^}]+\\}\\}", " ").replaceAll("\\s+", " ").trim();
    }

    private static int justinAge() {
        java.util.Calendar cal = java.util.Calendar.getInstance();
        int y = cal.get(java.util.Calendar.YEAR);
        int m = cal.get(java.util.Calendar.MONTH) + 1;
        int d = cal.get(java.util.Calendar.DAY_OF_MONTH);
        return y - 2000 - ((m < 9 || (m == 9 && d < 7)) ? 1 : 0);
    }

    private static boolean isXanaduFounderQuery(String query) {
        String ql = query == null ? "" : query.trim().toLowerCase(Locale.US);
        if (ql.isEmpty()) return false;
        if (ql.contains("justin ndambiri") || ql.contains("ndambiri")) return true;
        String[] intents = {"own", "owner", "founder", "found", "creat", "made", "built", "develop", "architect", "who", "when", "where", "age", "what is", "about", "browser", "app"};
        if (ql.contains("xanadu")) {
            for (String iw : intents) { if (ql.contains(iw)) return true; }
        }
        String[] selfRefs = {"this browser", "this app", "this platform", "this web", "this search engine", "this site", ".xnd"};
        boolean hasRef = false;
        for (String sr : selfRefs) { if (ql.contains(sr)) { hasRef = true; break; } }
        if (!hasRef) return false;
        for (String iw : intents) { if (ql.contains(iw)) return true; }
        return false;
    }

    private static JSONObject buildFounderKnowledgeCard(String query) throws Exception {
        int age = justinAge();
        String ql = query == null ? "" : query.trim().toLowerCase(Locale.US);
        boolean isWhen = ql.contains("when") || ql.contains("created") || ql.contains("founded") || ql.contains("date") || ql.contains("year") || ql.contains("started");
        boolean isOwner = ql.contains("owner") || ql.contains("own") || ql.contains("owns") || ql.contains("founder") || ql.contains("who made") || ql.contains("who created") || ql.contains("who built") || ql.contains("who developed");
        boolean isJustin = ql.contains("justin") || ql.contains("ndambiri");
        boolean isHowXnd = ql.contains("what is .xnd") || ql.contains("what is xanadu") || ql.contains("how does xanadu") || ql.contains("how does this browser");
        java.util.Random rng = new java.util.Random();

        String[] titles;
        String[] summaries;
        String subtitle;
        if (isWhen && (ql.contains("xanadu") || ql.contains("this browser") || ql.contains("this app"))) {
            titles = new String[] {
                "Xanadu Was Created in June 2026",
                "Xanadu (.xnd) — Founded June 2026 in Kenya",
                "Origin of Xanadu Browser: Created June 2026"
            };
            summaries = new String[] {
                "Xanadu was created in June 2026 in Kenya by founder Justin Ndambiri (age " + age + "). It was built as a sovereign, zero-DB peer-to-peer web and browser powered by Ed25519 cryptographic ownership.",
                "Founded in June 2026, Xanadu (.xnd) was created by Justin Ndambiri in Kenya (currently age " + age + "). The platform replaces centralized domain registrars with cryptographic .xnd domains and millisecond local indexing.",
                "This browser (Xanadu .xnd) was founded in June 2026 by Kenya-based engineer Justin Ndambiri (age " + age + ") to establish a two-way, peer-owned web with live transclusion."
            };
            subtitle = "Founded June 2026 · Kenya · Founder: Justin Ndambiri";
        } else if (isOwner) {
            titles = new String[] {
                "Justin Ndambiri — Owner & Founder of Xanadu Browser",
                "Justin Ndambiri Owns Xanadu (.xnd)",
                "Browser Owner & Founder: Justin Ndambiri (Kenya)"
            };
            summaries = new String[] {
                "Justin Ndambiri owns and founded this browser (Xanadu .xnd). Based in Kenya and currently age " + age + ", he created Xanadu in June 2026 as a decentralized, cryptographically verified web.",
                "This browser — Xanadu (.xnd) — is owned and engineered by Justin Ndambiri (age " + age + "), based in Kenya. Founded in June 2026, Xanadu gives domain holders direct Ed25519 cryptographic ownership instead of registrar leases.",
                "The owner and founder of Xanadu Browser is Justin Ndambiri (age " + age + ", Kenya), who launched it in June 2026 to power a fast, peer-to-peer two-way web."
            };
            subtitle = "Justin Ndambiri · Age " + age + " · Kenya · Founded June 2026";
        } else if (isJustin) {
            titles = new String[] {
                "Justin Ndambiri — Founder of Xanadu (.xnd)",
                "Justin Ndambiri (Kenya) · Creator of Xanadu Browser"
            };
            summaries = new String[] {
                "Justin Ndambiri (age " + age + ") is a Kenya-based software architect and the founder of Xanadu (.xnd), the sovereign peer-to-peer web browser and network he created in June 2026.",
                "Based in Kenya, Justin Ndambiri (age " + age + ") founded Xanadu in June 2026—engineering a zero-DB cryptographic browser ecosystem where domains, apps, and live transclusions belong directly to keyholders."
            };
            subtitle = "Founder of Xanadu · Kenya · Age " + age;
        } else if (isHowXnd) {
            titles = new String[] {
                "Xanadu (.xnd) — Two-Way Sovereign Browser",
                "Inside Xanadu Browser — Ed25519 Web & Live Index"
            };
            summaries = new String[] {
                "Xanadu (.xnd) is a two-way sovereign web browser created in June 2026 by Justin Ndambiri (age " + age + ") in Kenya. It pairs an instant local RAM index of .xnd domains and app capsules with live WWW search and character-level transclusion.",
                "Built in Kenya in June 2026 by Justin Ndambiri (age " + age + "), Xanadu runs as a zero-DB peer node where .xnd domains are owned by Ed25519 keys and indexed in milliseconds."
            };
            subtitle = "Xanadu (.xnd) · Founded June 2026 · Justin Ndambiri";
        } else {
            titles = new String[] {
                "Xanadu (.xnd) — Sovereign Peer-to-Peer Web",
                "About Xanadu — Founded June 2026 by Justin Ndambiri"
            };
            summaries = new String[] {
                "Xanadu (.xnd) is a sovereign, zero-DB peer-to-peer web and browser created in June 2026 by Justin Ndambiri (age " + age + ") in Kenya. It combines live WWW discovery with an instant local .xnd index and Ed25519 domain ownership.",
                "Created in June 2026 in Kenya by Justin Ndambiri (age " + age + "), Xanadu (.xnd) is a two-way web browser featuring millisecond local RAM indexing, live character transclusion, and cryptographic app capsules."
            };
            subtitle = "Founded June 2026 · Justin Ndambiri · Kenya";
        }

        return new JSONObject()
                .put("domain", "founder.xnd")
                .put("title", titles[rng.nextInt(titles.length)])
                .put("subtitle", subtitle)
                .put("summary", summaries[rng.nextInt(summaries.length)]);
    }

    private void ensureFounderDoc() {
        try {
            int age = justinAge();
            String body = "Xanadu (.xnd) — Official Founder & Origin Summary\n\n"
                    + "Founder & Owner: Justin Ndambiri\n"
                    + "Location: Kenya\n"
                    + "Founded: June 2026\n"
                    + "Age: " + age + "\n\n"
                    + "Executive Overview:\n"
                    + "Xanadu was created and founded in June 2026 by Justin Ndambiri in Kenya as a sovereign, "
                    + "peer-to-peer web architecture and browser. Designed around a zero-DB cryptographic node model, "
                    + "Xanadu replaces centralized domain registrars with Ed25519 keypair ownership, millisecond local "
                    + "RAM indexing, and live character-level transclusion across .xnd documents and app capsules.\n\n"
                    + "Core Pillars:\n"
                    + "• Sovereign Identity: Domains (.xnd) are owned directly by Ed25519 cryptographic keys.\n"
                    + "• Two-Way Web: Live web discovery paired with an instant local .xnd knowledge index.\n"
                    + "• Built in Kenya: Engineered from the ground up starting June 2026 by Justin Ndambiri.";
            JSONObject doc = new JSONObject()
                    .put("domain", "founder.xnd")
                    .put("title", "Justin Ndambiri — Founder & Owner of Xanadu (.xnd)")
                    .put("kind", "document")
                    .put("content", body)
                    .put("version", 1)
                    .put("updated_at", System.currentTimeMillis() / 1000L);
            synchronized (docs) {
                docs.put("founder.xnd", doc);
                if (!docs.containsKey("documentation.xnd")) {
                    String docBody = "Xanadu Browser (.xnd) — Official Documentation & Architecture\n\n"
                            + "Founder & Inspiration:\n"
                            + "Founded in June 2026 in Kenya by Justin Ndambiri, Xanadu Browser is directly inspired by Ted Nelson's original Project Xanadu — the first hypertext project conceived in 1960.\n"
                            + "Where the modern World Wide Web settled for fragile one-way links, centralized servers, and rented domain names, Xanadu Browser brings Ted Nelson's 1960 vision to life: a two-way, attribution-preserving, cryptographic web that belongs to its users.\n\n"
                            + "What Xanadu Browser Does:\n"
                            + "Xanadu Browser is a sovereign, zero-database peer-to-peer browser and local node that runs natively on Android phones and Linux desktops. Every device acts as its own independent node, storing, verifying, indexing, and syncing .xnd documents and full web applications without any central server.\n\n"
                            + "Core Functions:\n"
                            + "1. Sovereign .xnd Domains (Ed25519 + Hash-Chained History): Domains belong directly to Ed25519 keypairs — zero ICANN registrars, zero yearly fees, and tamper-evident prev_sha256 version chains.\n"
                            + "2. Two-Way Transclusion & Origin Bridges: Exact character-span citations stay permanently tethered to their source side-by-side.\n"
                            + "3. Cryptographic App Capsules & GitHub Hosting: Multi-file HTML/CSS/JS websites and sandboxed backends synced across peers and Nostr relays.\n"
                            + "4. Instant Local RAM Search & Deterministic Featured Snippets: Sub-millisecond local indexing + extractive Q&A with zero paid AI or central servers.\n"
                            + "5. LAN Mesh, Wi-Fi Direct & Offline Internet Sharing: Automatic peer sync and offline gateway sharing when a device has no internet.\n\n"
                            + "Why Choose Xanadu Over Centralized Modern WWW:\n"
                            + "• No Link Rot or Silent Rewrites: Content hashes and version chains preserve truth.\n"
                            + "• True Ownership: Your domain and keys live on your device, not a corporate database.\n"
                            + "• Zero Central Gatekeepers: No single server to censor, track, or shut down.\n"
                            + "• Works Offline & Peer-to-Peer: Browse locally or share connectivity with nearby peers.";
                    docs.put("documentation.xnd", new JSONObject()
                            .put("domain", "documentation.xnd")
                            .put("title", "documentation.xnd — Xanadu Browser Official Documentation")
                            .put("kind", "document")
                            .put("content", docBody)
                            .put("version", 1)
                            .put("updated_at", System.currentTimeMillis() / 1000L));
                }
            }
        } catch (Exception ignored) {}
    }

    private static JSONObject solveInstantCalc(String query) {
        try {
            String q = query == null ? "" : query.trim();
            String ql = q.toLowerCase(Locale.US);
            java.util.regex.Matcher mPct = java.util.regex.Pattern.compile("^(\\d+(?:\\.\\d+)?)\\s*%\\s+of\\s+(\\d+(?:\\.\\d+)?)\\s*\\??$").matcher(ql);
            if (mPct.matches()) {
                double ans = (Double.parseDouble(mPct.group(1)) / 100.0) * Double.parseDouble(mPct.group(2));
                String fmt = ans == (long) ans ? String.valueOf((long) ans) : String.valueOf(ans);
                return new JSONObject().put("domain", "home.xnd")
                        .put("title", mPct.group(1) + "% of " + mPct.group(2) + " = " + fmt)
                        .put("subtitle", "Instant Calculator · Deterministic")
                        .put("summary", mPct.group(1) + "% of " + mPct.group(2) + " equals " + fmt + ".");
            }
            java.util.regex.Matcher mUnit = java.util.regex.Pattern.compile("^(?:convert\\s+)?(-?\\d+(?:\\.\\d+)?)\\s*([a-z]+)\\s+(?:to|in)\\s+([a-z]+)\\s*\\??$").matcher(ql);
            if (mUnit.matches()) {
                double val = Double.parseDouble(mUnit.group(1));
                String u1 = mUnit.group(2), u2 = mUnit.group(3);
                if (u1.startsWith("mile")) u1 = "mi"; if (u2.startsWith("mile")) u2 = "mi";
                if (u1.startsWith("kilometer")) u1 = "km"; if (u2.startsWith("kilometer")) u2 = "km";
                if (u1.equals("lbs") || u1.startsWith("pound")) u1 = "lb"; if (u2.equals("lbs") || u2.startsWith("pound")) u2 = "lb";
                if (u1.startsWith("kilogram")) u1 = "kg"; if (u2.startsWith("kilogram")) u2 = "kg";
                Double conv = null;
                if (u1.equals("km") && u2.equals("mi")) conv = val * 0.621371;
                else if (u1.equals("mi") && u2.equals("km")) conv = val * 1.60934;
                else if (u1.equals("kg") && u2.equals("lb")) conv = val * 2.20462;
                else if (u1.equals("lb") && u2.equals("kg")) conv = val * 0.453592;
                else if (u1.equals("c") && u2.equals("f")) conv = (val * 9.0 / 5.0) + 32.0;
                else if (u1.equals("f") && u2.equals("c")) conv = (val - 32.0) * 5.0 / 9.0;
                if (conv != null) {
                    String outS = String.format(Locale.US, "%.4f", conv).replaceAll("0+$", "").replaceAll("\\.$", "");
                    return new JSONObject().put("domain", "home.xnd")
                            .put("title", val + " " + u1 + " = " + outS + " " + u2)
                            .put("subtitle", "Instant Unit Converter · Deterministic")
                            .put("summary", val + " " + u1 + " converts to " + outS + " " + u2 + ".");
                }
            }
            java.util.regex.Matcher mOp = java.util.regex.Pattern.compile("^(?:calculate|compute|what\\s+is)?\\s*(-?\\d+(?:\\.\\d+)?)\\s*([+\\-*/])\\s*(-?\\d+(?:\\.\\d+)?)\\s*\\??$").matcher(ql);
            if (mOp.matches()) {
                double a = Double.parseDouble(mOp.group(1)), b = Double.parseDouble(mOp.group(3));
                String op = mOp.group(2);
                double ans = op.equals("+") ? a + b : op.equals("-") ? a - b : op.equals("*") ? a * b : (b != 0 ? a / b : Double.NaN);
                if (!Double.isNaN(ans)) {
                    String fmt = ans == (long) ans ? String.valueOf((long) ans) : String.valueOf(ans);
                    return new JSONObject().put("domain", "home.xnd")
                            .put("title", mOp.group(1) + " " + op + " " + mOp.group(3) + " = " + fmt)
                            .put("subtitle", "Instant Calculator · Deterministic")
                            .put("summary", mOp.group(1) + " " + op + " " + mOp.group(3) + " evaluates to " + fmt + ".");
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private final Map<String, JSONObject> crawlCache = Collections.synchronizedMap(new java.util.LinkedHashMap<String, JSONObject>(64, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, JSONObject> eldest) {
            return size() > 128;
        }
    });

    private static String stemToken(String tok) {
        if (tok == null || tok.length() <= 3) return tok == null ? "" : tok;
        if (tok.endsWith("ies") && tok.length() > 4) return tok.substring(0, tok.length() - 3) + "y";
        String[] sufs = {"ation", "ment", "ness", "ing", "ers", "ed", "es", "er", "or", "ly"};
        for (String suf : sufs) {
            if (tok.endsWith(suf) && tok.length() - suf.length() >= 3) {
                return tok.substring(0, tok.length() - suf.length());
            }
        }
        if (tok.endsWith("s") && !tok.endsWith("ss") && tok.length() > 3) return tok.substring(0, tok.length() - 1);
        return tok;
    }

    private static List<String> expandSynonyms(String tok) {
        String[][] groups = {
            {"owner", "founder", "creator", "author", "architect", "maker"},
            {"made", "built", "created", "founded", "launched", "started"},
            {"site", "app", "website", "page", "capsule", "web"},
            {"browser", "node", "client"},
            {"kenya", "nairobi"},
            {"code", "repo", "repository", "source"},
            {"forum", "discussion", "thread", "post"}
        };
        List<String> out = new ArrayList<>();
        out.add(tok);
        String st = stemToken(tok);
        if (!st.equals(tok)) out.add(st);
        for (String[] g : groups) {
            for (String w : g) {
                if (w.equals(tok)) {
                    for (String alt : g) {
                        if (!alt.equals(tok)) {
                            out.add(alt);
                            String ast = stemToken(alt);
                            if (!ast.equals(alt)) out.add(ast);
                        }
                    }
                }
            }
        }
        return out;
    }

    private JSONObject searchAll(String query, boolean fast) {
        JSONObject out = new JSONObject();
        try {
            ensureFounderDoc();
            long t0 = System.nanoTime();
            String qLow = query.trim().toLowerCase(Locale.US);
            String core = query.replaceAll("^(?i)(what\\s+is\\s+(?:the\\s+)?|what's\\s+(?:the\\s+)?|what\\s+are\\s+|who\\s+(?:is|was|are|owns|created|made|founded|built|invented)\\s+(?:the\\s+)?|when\\s+(?:was|did|is)\\s+(?:the\\s+)?|where\\s+(?:is|was|are)\\s+(?:the\\s+)?|why\\s+(?:is|does|do|did)\\s+|how\\s+(?:does|do|to|can\\s+i|do\\s+i)\\s+|difference\\s+between\\s+|steps\\s+to\\s+|guide\\s+to\\s+|define\\s+|explain\\s+)", "").replaceAll("[?.!\"']+$", "").trim();
            if (core.isEmpty()) core = query;

            String intent = "WHAT_IS";
            String scope = "external";
            JSONObject knowledgeCard = solveInstantCalc(query);
            if (knowledgeCard != null) {
                intent = "CALCULATE";
                scope = "internal";
            } else if (isXanaduFounderQuery(query)) {
                intent = "SELF";
                boolean pureSelf = qLow.contains("this browser") || qLow.contains("this app") || qLow.contains("this platform") || qLow.contains("this web") || qLow.contains("this search engine");
                scope = pureSelf ? "internal" : "hybrid";
                knowledgeCard = buildFounderKnowledgeCard(query);
            } else if (qLow.endsWith(".xnd")) {
                intent = "SELF";
                scope = "internal";
            } else if (qLow.matches(".*\\b(vs\\.?|versus)\\b.*") || qLow.startsWith("difference between ")) {
                intent = "COMPARE";
            } else if (qLow.matches("^(who\\s|who's\\s|whose\\s).*")) {
                intent = "WHO";
            } else if (qLow.matches("^(when\\s|what\\s+year\\s|what\\s+date\\s).*")) {
                intent = "WHEN";
            } else if (qLow.matches("^(where\\s|which\\s+country\\s|which\\s+city\\s).*")) {
                intent = "WHERE";
            } else if (qLow.matches("^(how\\s+to\\s|how\\s+do\\s+i\\s|how\\s+can\\s+i\\s|steps\\s+to\\s|guide\\s+to\\s).*")) {
                intent = "HOW_TO";
            }

            out.put("query", query);
            out.put("core_term", core);
            out.put("intent", intent);
            out.put("scope", scope);
            if (knowledgeCard != null) {
                out.put("knowledge_card", knowledgeCard);
            }

            JSONArray local = new JSONArray();
            String ql = core.toLowerCase(Locale.US);
            if (!fast && ql.endsWith(".xnd") && !docs.containsKey(ql)) {
                lookupDocNostr(ql);
            }
            String[] terms = ql.split("\\s+");
            List<JSONObject> scored = new ArrayList<>();
            synchronized (docs) {
                for (JSONObject d : docs.values()) {
                    String dom = d.optString("domain", "");
                    String title = d.optString("title", "");
                    String kind = d.optString("kind", "document");
                    String raw = extractCrawlText(d);
                    String hay = (dom + " " + title + " " + raw).toLowerCase(Locale.US);
                    int score = 0;
                    for (String t : terms) {
                        if (t.isEmpty()) continue;
                        if (dom.toLowerCase(Locale.US).contains(t)) score += 10;
                        if (title.toLowerCase(Locale.US).contains(t)) score += 5;
                        if (raw.toLowerCase(Locale.US).contains(t)) score += 2;
                        for (String exp : expandSynonyms(t)) {
                            if (!exp.equals(t) && hay.contains(exp)) score += 1;
                        }
                    }
                    if (score > 0 || hay.contains(ql)) {
                        String snippet = "";
                        int idx = raw.toLowerCase(Locale.US).indexOf(ql);
                        if (idx < 0 && terms.length > 0 && !terms[0].isEmpty()) idx = raw.toLowerCase(Locale.US).indexOf(terms[0]);
                        if (idx >= 0) {
                            int s = Math.max(0, idx - 40);
                            int e = Math.min(raw.length(), idx + 140);
                            snippet = raw.substring(s, e).trim();
                        } else if (!raw.isEmpty()) {
                            snippet = raw.substring(0, Math.min(140, raw.length())).trim();
                        }
                        JSONObject hit = new JSONObject().put("domain", dom).put("title", title).put("kind", kind)
                                .put("snippet", snippet).put("source_url", d.optString("source_url"))
                                .put("backlinks_count", 0).put("_score", score);
                        scored.add(hit);
                    }
                }
            }
            scored.sort((a, b) -> Integer.compare(b.optInt("_score", 0), a.optInt("_score", 0)));
            for (JSONObject hit : scored) {
                hit.remove("_score");
                local.put(hit);
            }
            double indexMs = Math.round(((System.nanoTime() - t0) / 1_000_000.0) * 100.0) / 100.0;
            out.put("results", local);
            out.put("index_ms", indexMs);

            if (!"internal".equals(scope)) {
                JSONObject cached = crawlCache.get(ql);
                if (cached != null && (System.currentTimeMillis() - cached.optLong("_ts", 0L)) < 600_000L) {
                    out.put("fast", false);
                    out.put("disambiguation", cached.optJSONArray("disambiguation"));
                    out.put("images", cached.optJSONArray("images"));
                    out.put("forums", cached.optJSONArray("forums"));
                    if (knowledgeCard == null && cached.has("knowledge_card")) {
                        out.put("knowledge_card", cached.optJSONObject("knowledge_card"));
                    }
                    out.put("index_ms", Math.round(((System.nanoTime() - t0) / 1_000_000.0) * 100.0) / 100.0);
                    return out;
                }
            }

            if (fast || "internal".equals(scope)) {
                JSONArray fastImgs = new JSONArray();
                boolean fFounder = ql.contains("justin") || ql.contains("ndambiri") || ql.contains("founder")
                        || ql.contains("owner") || ql.contains("ownership") || ql.contains("creator")
                        || ql.contains("who made") || ql.contains("who created") || ql.contains("who built")
                        || ql.contains("who founded") || ql.contains("author")
                        || ql.contains("xanadu browser") || ql.contains("about xanadu") || ql.contains("what is xanadu");
                if (fFounder) {
                    String[] fFiles = new String[]{"image2.png"};
                    for (int fi = 0; fi < fFiles.length; fi++) {
                        fastImgs.put(new JSONObject().put("title", "Justin Ndambiri — Founder & Owner of Xanadu (.xnd) #" + (fi + 1))
                                .put("image", "/static/founder/" + fFiles[fi])
                                .put("source", "founder.xnd"));
                    }
                    if (knowledgeCard != null && !knowledgeCard.has("image")) {
                        knowledgeCard.put("image", "/static/founder/image2.png");
                    }
                }
                if (ql.contains("xanadu") || ql.contains("xnd")) {
                    fastImgs.put(new JSONObject().put("title", "Xanadu (.xnd) Official Logo")
                            .put("image", "/static/logo.png")
                            .put("source", "xanadu.xnd"));
                    fastImgs.put(new JSONObject().put("title", "Xanadu (.xnd) Mathematical Logo")
                            .put("image", "/static/mathematical.png")
                            .put("source", "xanadu.xnd"));
                    if (knowledgeCard != null && !knowledgeCard.has("image")) {
                        knowledgeCard.put("image", "/static/logo.png");
                    }
                }
                out.put("fast", fast && !"internal".equals(scope));
                out.put("disambiguation", new JSONArray());
                out.put("images", fastImgs);
                out.put("forums", new JSONArray());
                return out;
            }

            JSONArray dis = new JSONArray();
            if (core.matches("(?i)^(https?://)?[a-z0-9.-]+\\.[a-z]{2,}(/.*)?$") && !core.toLowerCase(Locale.US).endsWith(".xnd")) {
                String live = core.toLowerCase(Locale.US).startsWith("http") ? core : "https://" + core;
                dis.put(new JSONObject().put("title", "Open " + core + " — Live Website").put("category", "Live WWW Website")
                        .put("summary", "Navigate directly to " + live).put("url", live));
            }
            Set<String> seenDisUrls = new HashSet<>();
            for (int i = 0; i < dis.length(); i++) seenDisUrls.add(dis.optJSONObject(i).optString("url"));
            JSONArray webHits = new JSONArray();
            if (!checkHasWan() && findLanGateway() != null) {
                // Fast-path: offline phone skips dead WAN calls and goes straight to LAN Mesh Gateway
            } else {
                webHits = searchInternetWeb(query);
            }
            for (int i = 0; i < webHits.length(); i++) {
                JSONObject wh = webHits.optJSONObject(i);
                if (wh != null && seenDisUrls.add(wh.optString("url"))) dis.put(wh);
            }
            JSONArray imgs = new JSONArray();
            boolean isFounderQ = ql.contains("justin") || ql.contains("ndambiri") || ql.contains("founder")
                    || ql.contains("owner") || ql.contains("ownership") || ql.contains("creator")
                    || ql.contains("who made") || ql.contains("who created") || ql.contains("who built")
                    || ql.contains("who founded") || ql.contains("author")
                    || ql.contains("xanadu browser") || ql.contains("about xanadu") || ql.contains("what is xanadu");
            if (isFounderQ) {
                String[] fFiles = new String[]{"image2.png"};
                for (int fi = 0; fi < fFiles.length; fi++) {
                    imgs.put(new JSONObject().put("title", "Justin Ndambiri — Founder & Owner of Xanadu (.xnd) #" + (fi + 1))
                            .put("image", "/static/founder/" + fFiles[fi])
                            .put("source", "founder.xnd"));
                }
                if (knowledgeCard != null && !knowledgeCard.has("image")) {
                    knowledgeCard.put("image", "/static/founder/image2.png");
                }
            }
            if (ql.contains("xanadu") || ql.contains("xnd")) {
                imgs.put(new JSONObject().put("title", "Xanadu (.xnd) Official Logo")
                        .put("image", "/static/logo.png")
                        .put("source", "xanadu.xnd"));
                imgs.put(new JSONObject().put("title", "Xanadu (.xnd) Mathematical Logo")
                        .put("image", "/static/mathematical.png")
                        .put("source", "xanadu.xnd"));
                if (knowledgeCard != null && !knowledgeCard.has("image")) {
                    knowledgeCard.put("image", "/static/logo.png");
                }
            }
            JSONArray forums = new JSONArray();
            if (checkHasWan() || findLanGateway() == null) {
                try {
                    String w = httpGet("https://en.wikipedia.org/w/api.php?action=opensearch&limit=4&namespace=0&format=json&search=" + URLEncoder.encode(core, "UTF-8"), 2500);
                    JSONArray wa = new JSONArray(w);
                JSONArray ts = wa.optJSONArray(1), ds = wa.optJSONArray(2), us = wa.optJSONArray(3);
                if (ts != null && us != null) {
                    for (int i = 0; i < ts.length(); i++) {
                        String wu = us.optString(i);
                        if (seenDisUrls.add(wu)) {
                            dis.put(new JSONObject().put("title", ts.optString(i)).put("category", "Knowledge Graph · Wikipedia")
                                    .put("summary", ds != null ? ds.optString(i) : "").put("url", wu));
                        }
                    }
                }
            } catch (Exception ignored) {}
            try {
                String dj = httpGet("https://api.duckduckgo.com/?format=json&no_html=1&skip_disambig=1&q=" + URLEncoder.encode(core, "UTF-8"), 2000);
                JSONObject ddg = new JSONObject(dj);
                String abs = ddg.optString("AbstractText", "").trim();
                String absUrl = ddg.optString("AbstractURL", "").trim();
                if (!abs.isEmpty() && !absUrl.isEmpty() && seenDisUrls.add(absUrl)) {
                    dis.put(new JSONObject().put("title", ddg.optString("Heading", core))
                            .put("category", "Live Web · " + ddg.optString("AbstractSource", "DuckDuckGo"))
                            .put("summary", abs).put("url", absUrl));
                }
            } catch (Exception ignored) {}
            out.put("disambiguation", dis);

            try {
                String cj = httpGet("https://commons.wikimedia.org/w/api.php?action=query&generator=search&gsrnamespace=6&gsrlimit=6&prop=imageinfo&iiprop=url&iiurlwidth=2160&format=json&gsrsearch=" + URLEncoder.encode(core, "UTF-8"), 3500);
                JSONObject pages = new JSONObject(cj).optJSONObject("query").optJSONObject("pages");
                if (pages != null) {
                    JSONArray keys = pages.names();
                    for (int i = 0; keys != null && i < keys.length(); i++) {
                        JSONObject pg = pages.getJSONObject(keys.getString(i));
                        JSONArray ii = pg.optJSONArray("imageinfo");
                        if (ii != null && ii.length() > 0) {
                            String iu = ii.getJSONObject(0).optString("thumburl", ii.getJSONObject(0).optString("url"));
                            if (!iu.endsWith(".svg")) {
                                imgs.put(new JSONObject().put("title", pg.optString("title").replace("File:", ""))
                                        .put("image", iu).put("source", "Wikimedia Commons"));
                            }
                        }
                    }
                }
            } catch (Exception ignored) {}
            out.put("images", imgs);

            Set<String> indexedTerms = new java.util.LinkedHashSet<>();
            indexedTerms.add(core.toLowerCase(Locale.US));
            for (int i = 0; i < Math.min(10, local.length()); i++) {
                JSONObject r = local.optJSONObject(i);
                if (r == null) continue;
                String dom = r.optString("domain", "").toLowerCase(Locale.US);
                if (!dom.isEmpty()) {
                    indexedTerms.add(dom);
                    if (dom.endsWith(".xnd")) indexedTerms.add(dom.substring(0, dom.length() - 4));
                }
                for (String w : r.optString("title", "").toLowerCase(Locale.US).split("[^a-z0-9]+")) {
                    if (w.length() >= 3) indexedTerms.add(w);
                }
            }

            boolean wantForums = ql.contains("forum") || ql.contains("discussion") || ql.contains("reddit") || ql.contains("hacker news") || ql.contains("forum.xnd");
            if (wantForums) {
            try {
                String hj = httpGet("https://hn.algolia.com/api/v1/search?hitsPerPage=3&tags=story&query=" + URLEncoder.encode(core, "UTF-8"), 2500);
                JSONArray hits = new JSONObject(hj).optJSONArray("hits");
                if (hits != null) {
                    List<JSONObject> extForums = new ArrayList<>();
                    for (int i = 0; i < hits.length(); i++) {
                        JSONObject h = hits.getJSONObject(i);
                        String fTitle = h.optString("title");
                        int boost = 0;
                        String fl = fTitle.toLowerCase(Locale.US);
                        for (String t : indexedTerms) {
                            if (t.length() >= 3 && fl.contains(t)) boost++;
                        }
                        extForums.add(new JSONObject().put("title", fTitle)
                                .put("url", "https://news.ycombinator.com/item?id=" + h.optString("objectID"))
                                .put("forum", "Hacker News").put("points", h.optInt("points")).put("comments", h.optInt("num_comments")).put("_boost", boost));
                    }
                    extForums.sort((a, b) -> Integer.compare(b.optInt("_boost", 0), a.optInt("_boost", 0)));
                    for (JSONObject ef : extForums) {
                        ef.remove("_boost");
                        forums.put(ef);
                    }
                }
            } catch (Exception ignored) {}
            }
            }
            out.put("forums", forums);
            if (knowledgeCard == null) {
                JSONObject xndQa = answerFromXndCorpus(query, local);
                if (xndQa != null) {
                    knowledgeCard = xndQa;
                    out.put("knowledge_card", xndQa);
                }
            }
            if (webHits.length() == 0 && !checkHasWan()) {
                JSONObject gw = findLanGateway();
                if (gw != null) {
                    try {
                        String raw = httpGet(gw.optString("url") + "/api/gateway/search?q=" + URLEncoder.encode(query, "UTF-8") + "&scope=" + URLEncoder.encode(scope, "UTF-8"), 16000);
                        JSONObject gd = new JSONObject(raw);
                        if (knowledgeCard == null && gd.has("knowledge_card") && !gd.isNull("knowledge_card")) {
                            knowledgeCard = gd.optJSONObject("knowledge_card");
                            out.put("knowledge_card", knowledgeCard);
                        }
                        if (gd.has("deep_passages") && !out.has("deep_passages")) {
                            out.put("deep_passages", gd.optJSONArray("deep_passages"));
                        }
                        if (gd.has("alternatives") && !out.has("alternatives")) {
                            out.put("alternatives", gd.optJSONArray("alternatives"));
                        }
                        if (gd.has("disambiguation")) {
                            JSONArray gDis = gd.optJSONArray("disambiguation");
                            if (gDis != null) {
                                for (int i = 0; i < gDis.length(); i++) {
                                    JSONObject item = gDis.optJSONObject(i);
                                    if (item != null && seenDisUrls.add(item.optString("url"))) dis.put(item);
                                }
                            }
                        }
                        if (imgs.length() == 0 && gd.has("images")) {
                            JSONArray gImgs = gd.optJSONArray("images");
                            if (gImgs != null) {
                                for (int i = 0; i < gImgs.length(); i++) imgs.put(gImgs.get(i));
                            }
                        }
                        if (forums.length() == 0 && gd.has("forums")) {
                            JSONArray gFor = gd.optJSONArray("forums");
                            if (gFor != null) {
                                for (int i = 0; i < gFor.length(); i++) forums.put(gFor.get(i));
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
            if (knowledgeCard == null && !"internal".equals(scope)) {
                JSONObject qa = extractiveQaAnswer(query, core, intent, dis, forums);
                if (qa != null) {
                    out.put("knowledge_card", qa);
                } else {
                    JSONObject ws = wikiShards.get(ql);
                    if (ws == null) {
                        for (Map.Entry<String, JSONObject> e : wikiShards.entrySet()) {
                            if (e.getKey().contains(ql) || ql.contains(e.getKey())) { ws = e.getValue(); break; }
                        }
                    }
                    if (ws != null) {
                        out.put("knowledge_card", new JSONObject()
                                .put("title", ws.optString("title"))
                                .put("subtitle", "wikipedia.xnd · Synced Offline Shard")
                                .put("summary", ws.optString("summary"))
                                .put("url", ws.optString("url"))
                                .put("facts", new JSONArray()));
                    }
                }
            }
            if (!"internal".equals(scope) && (dis.length() > 0 || imgs.length() > 0 || forums.length() > 0 || out.has("knowledge_card"))) {
                JSONObject toCache = new JSONObject()
                        .put("_ts", System.currentTimeMillis())
                        .put("disambiguation", dis)
                        .put("images", imgs)
                        .put("forums", forums);
                if (out.has("knowledge_card")) toCache.put("knowledge_card", out.optJSONObject("knowledge_card"));
                crawlCache.put(ql, toCache);
            }
        } catch (Exception ignored) {}
        return out;
    }

    private final Map<String, Map<String, Double>> qaPatterns = Collections.synchronizedMap(new HashMap<>());
    private volatile boolean qaPatternsLoaded = false;

    private void ensureQaPatternsLoaded() {
        if (qaPatternsLoaded) return;
        qaPatternsLoaded = true;
        try {
            File f = new File(dataDir, "qa_patterns.json");
            if (!f.exists()) return;
            JSONObject obj = new JSONObject(readFileText(f));
            JSONArray keys = obj.names();
            if (keys == null) return;
            for (int i = 0; i < keys.length(); i++) {
                String pk = keys.getString(i);
                JSONObject dm = obj.optJSONObject(pk);
                if (dm == null) continue;
                Map<String, Double> m = new HashMap<>();
                JSONArray dKeys = dm.names();
                if (dKeys != null) {
                    for (int j = 0; j < dKeys.length(); j++) {
                        String d = dKeys.getString(j);
                        m.put(d, dm.optDouble(d, 0.0));
                    }
                }
                qaPatterns.put(pk, m);
            }
        } catch (Exception ignored) {
        }
    }

    private static String classifyQuestionIr(String query) {
        String q = query == null ? "" : query.trim().toLowerCase(Locale.US);
        if (q.matches("^(how|steps|guide|tutorial|way to)\\b.*") || q.contains(" how to ")) return "HOW";
        if (q.matches("^(who|founder|creator|author)\\b.*") || q.contains(" who ")) return "WHO";
        if (q.matches("^(what|define|explain|meaning)\\b.*") || q.contains(" what is ")) return "DEFINE";
        if (q.contains(" vs ") || q.contains(" versus ") || q.startsWith("difference between ")) return "COMPARE";
        if (q.matches("^(where|when)\\b.*")) return "WHEN_WHERE";
        return "FACT";
    }

    private static String normalizePatternKey(String query) {
        Set<String> stop = new HashSet<>(Arrays.asList(
                "the", "is", "are", "was", "were", "a", "an", "of", "in", "on", "to", "for",
                "and", "or", "what", "who", "when", "where", "why", "how", "did", "do", "does",
                "this", "that", "with", "from", "by", "as", "at", "about", "can", "i", "you", "my"
        ));
        Set<String> toks = new java.util.TreeSet<>();
        Matcher m = Pattern.compile("[a-z0-9]+").matcher((query == null ? "" : query).toLowerCase(Locale.US));
        while (m.find()) {
            String t = m.group();
            if (t.length() >= 2 && !stop.contains(t)) toks.add(t);
        }
        if (toks.isEmpty()) return "";
        List<String> list = new ArrayList<>(toks);
        if (list.size() > 6) list = list.subList(0, 6);
        return classifyQuestionIr(query) + ":" + String.join(" ", list);
    }

    private JSONObject recordPatternFeedback(String query, String domain, double delta) {
        ensureQaPatternsLoaded();
        JSONObject out = new JSONObject();
        try {
            String pk = normalizePatternKey(query);
            String dom = domain == null ? "" : domain.trim().toLowerCase(Locale.US);
            if (pk.isEmpty() || dom.isEmpty()) return out.put("ok", false);
            double next;
            synchronized (qaPatterns) {
                Map<String, Double> entry = qaPatterns.get(pk);
                if (entry == null) {
                    entry = new HashMap<>();
                    qaPatterns.put(pk, entry);
                }
                double cur = entry.containsKey(dom) ? entry.get(dom) : 0.0;
                next = Math.max(-5.0, Math.min(25.0, cur + delta));
                entry.put(dom, next);
                JSONObject root = new JSONObject();
                for (Map.Entry<String, Map<String, Double>> e : qaPatterns.entrySet()) {
                    root.put(e.getKey(), new JSONObject(e.getValue()));
                }
                writeFileText(new File(dataDir, "qa_patterns.json"), root.toString());
            }
            out.put("ok", true).put("pattern_key", pk).put("domain", dom).put("score", next);
        } catch (Exception ignored) {
        }
        return out;
    }

    private double getPatternBoost(String query, String domain) {
        ensureQaPatternsLoaded();
        String pk = normalizePatternKey(query);
        if (pk.isEmpty() || domain == null) return 0.0;
        synchronized (qaPatterns) {
            Map<String, Double> entry = qaPatterns.get(pk);
            if (entry == null) return 0.0;
            Double v = entry.get(domain.toLowerCase(Locale.US));
            return v != null ? v : 0.0;
        }
    }

    private JSONObject answerFromXndCorpus(String query, JSONArray results) {
        try {
            String q = query == null ? "" : query.trim();
            if (q.length() < 2) return null;
            String qtype = classifyQuestionIr(q);
            Set<String> stop = new HashSet<>(Arrays.asList(
                    "the", "is", "are", "was", "were", "a", "an", "of", "in", "on", "to", "for",
                    "and", "or", "what", "who", "when", "where", "why", "how", "did", "do", "does",
                    "this", "that", "with", "from", "by", "as", "at", "about", "can", "i", "you", "my"
            ));
            List<String> qTokens = new ArrayList<>();
            Matcher m = Pattern.compile("[a-z0-9]+").matcher(q.toLowerCase(Locale.US));
            while (m.find()) {
                String t = m.group();
                if (t.length() >= 2 && !stop.contains(t) && !qTokens.contains(t)) qTokens.add(t);
            }
            if (qTokens.isEmpty()) return null;

            List<String> coreDoms = Arrays.asList("founder.xnd", "home.xnd", "justin.xnd", "heart.xnd", "manifesto.xnd", "forum.xnd", "xanadu.xnd");
            List<String> cands = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            for (int i = 0; i < Math.min(8, results.length()); i++) {
                String d = results.getJSONObject(i).optString("domain", "").toLowerCase(Locale.US);
                if (!d.isEmpty() && seen.add(d)) cands.add(d);
            }
            for (String cd : coreDoms) {
                if (docs.containsKey(cd) && seen.add(cd)) cands.add(cd);
            }

            double bestScore = 0.0;
            String bestDom = "";
            String bestTitle = "";
            String bestSummary = "";
            JSONArray bestFacts = new JSONArray();

            for (String dom : cands) {
                JSONObject docObj;
                synchronized (docs) { docObj = docs.get(dom); }
                if (docObj == null) continue;
                String raw = docObj.optString("raw_content", "");
                if (raw.isEmpty()) continue;
                if ("capsule".equals(docObj.optString("kind", "")) && raw.trim().startsWith("{")) {
                    try {
                        JSONObject b = new JSONObject(raw);
                        raw = b.getJSONObject("files").optString("index.html", "");
                    } catch (Exception ignored) {}
                }
                String title = docObj.optString("title", dom);
                String stripped = raw.replaceAll("(?is)<(script|style|noscript)[^>]*>.*?</\\1>", " ")
                        .replaceAll("(?i)<(h[1-3]|p|div|li|br|tr)[^>]*>", "\n")
                        .replaceAll("<[^>]+>", " ")
                        .replaceAll("[ \\t]+", " ");
                String[] blocks = stripped.split("\\n+");
                JSONArray facts = new JSONArray();
                double coreBoost = coreDoms.contains(dom) ? 1.6 : 0.0;
                double ltrBoost = getPatternBoost(q, dom);
                String titleLow = title.toLowerCase(Locale.US);
                int titleHits = 0;
                for (String qt : qTokens) if (titleLow.contains(qt)) titleHits++;

                for (int idx = 0; idx < blocks.length; idx++) {
                    String blk = blocks[idx].trim();
                    if (blk.length() < 25) continue;
                    Matcher fm = Pattern.compile("^([A-Z][A-Za-z0-9 _/-]{2,28}):\\s+(.{4,120})$").matcher(blk);
                    if (fm.matches() && facts.length() < 3) {
                        facts.put(new JSONObject().put("label", fm.group(1).trim()).put("value", fm.group(2).trim()));
                    }
                    String pLow = blk.toLowerCase(Locale.US);
                    int hits = 0;
                    for (String qt : qTokens) if (pLow.contains(qt)) hits++;
                    if (hits == 0 && titleHits == 0) continue;

                    double score = ((double) hits / Math.max(1, qTokens.size())) * 6.0 + (titleHits * 1.4) + coreBoost + (ltrBoost * 0.6);
                    if ("HOW".equals(qtype) && pLow.matches(".*\\b(step|click|run|install|deploy|publish|open|enter)\\b.*")) score += 2.0;
                    else if ("DEFINE".equals(qtype) && pLow.matches(".*\\b(is a|is an|is the|are |refers to|means)\\b.*")) score += 2.0;
                    else if ("WHO".equals(qtype) && pLow.matches(".*\\b(founded|created|built|author|by|made)\\b.*")) score += 2.0;
                    if (idx <= 2) score += 0.6;
                    if (score > bestScore) {
                        bestScore = score;
                        bestDom = dom;
                        bestTitle = title;
                        bestSummary = blk.length() > 380 ? blk.substring(0, 380) + "…" : blk;
                        bestFacts = facts;
                    }
                }
            }
            if (bestDom.isEmpty() || bestScore < 2.2) return null;
            return new JSONObject()
                    .put("title", bestTitle)
                    .put("subtitle", "xnd://" + bestDom + " · Featured Snippet (" + qtype + ")")
                    .put("summary", bestSummary)
                    .put("url", "xnd://" + bestDom)
                    .put("domain", bestDom)
                    .put("pattern_key", normalizePatternKey(q))
                    .put("facts", bestFacts);
        } catch (Exception e) {
            return null;
        }
    }

    private static JSONObject extractiveQaAnswer(String query, String core, String intent, JSONArray dis, JSONArray forums) {
        try {
            String[] rawTokens = (query + " " + core).toLowerCase(Locale.US).split("[^a-z0-9]+");
            Set<String> stop = new HashSet<>(java.util.Arrays.asList(
                "the", "is", "are", "was", "were", "a", "an", "of", "in", "on", "to", "for",
                "and", "or", "what", "who", "when", "where", "why", "how", "did", "do", "does",
                "this", "that", "with", "from", "by", "as", "at", "about"
            ));
            List<String> qTokens = new ArrayList<>();
            for (String t : rawTokens) {
                if (t.length() >= 2 && !stop.contains(t) && !qTokens.contains(t)) qTokens.add(t);
            }
            if (qTokens.isEmpty()) return null;

            String attrTargetPid = null;
            String attrEntity = null;
            java.util.regex.Matcher mAttr = java.util.regex.Pattern.compile("^(?:what\\s+is\\s+(?:the\\s+)?|what's\\s+(?:the\\s+)?|who\\s+is\\s+(?:the\\s+)?)?(population|capital|president|head of state|ceo|chief executive|founder|currency|area|boiling point|melting point|country)\\s+of\\s+(.+?)\\s*[?.!\"']*$").matcher(query.trim().toLowerCase(Locale.US));
            if (mAttr.matches()) {
                String ak = mAttr.group(1);
                attrEntity = mAttr.group(2).trim();
                if (ak.equals("population")) attrTargetPid = "P1082";
                else if (ak.equals("capital")) attrTargetPid = "P36";
                else if (ak.equals("president") || ak.equals("head of state")) attrTargetPid = "P35";
                else if (ak.equals("ceo") || ak.equals("chief executive")) attrTargetPid = "P169";
                else if (ak.equals("founder")) attrTargetPid = "P112";
                else if (ak.equals("currency")) attrTargetPid = "P38";
                else if (ak.equals("area")) attrTargetPid = "P2046";
                else if (ak.equals("boiling point")) attrTargetPid = "P2102";
                else if (ak.equals("melting point")) attrTargetPid = "P2101";
                else if (ak.equals("country")) attrTargetPid = "P17";
            }

            String wikiTitle = attrEntity != null ? attrEntity : core;
            if (attrEntity == null) {
                for (int i = 0; i < dis.length(); i++) {
                    JSONObject d = dis.optJSONObject(i);
                    if (d != null && d.optString("url", "").contains("wikipedia.org")) {
                        wikiTitle = d.optString("title", core);
                        break;
                    }
                }
            }
            String slug = URLEncoder.encode(wikiTitle.replace(" ", "_"), "UTF-8").replace("+", "%20");
            String ext = "";
            String wikibaseId = "";
            String wikiSrc = wikiTitle;
            String wikiUrl = "https://en.wikipedia.org/wiki/" + slug;
            try {
                String summaryJson = httpGet("https://en.wikipedia.org/api/rest_v1/page/summary/" + slug, 1800);
                if (summaryJson != null && !summaryJson.isEmpty()) {
                    JSONObject w = new JSONObject(summaryJson);
                    ext = w.optString("extract", "").trim();
                    wikibaseId = w.optString("wikibase_item", "").trim();
                    wikiSrc = w.optString("title", wikiTitle);
                    JSONObject cu = w.optJSONObject("content_urls");
                    if (cu != null && cu.optJSONObject("desktop") != null) {
                        wikiUrl = cu.optJSONObject("desktop").optString("page", wikiUrl);
                    }
                }
            } catch (Exception ignored) {}

            List<String[]> passages = new ArrayList<>();
            if (!ext.isEmpty()) passages.add(new String[]{wikiSrc, wikiUrl, ext, "1"});
            for (int i = 0; i < dis.length(); i++) {
                JSONObject d = dis.optJSONObject(i);
                if (d == null) continue;
                String sn = d.optString("summary", "").trim();
                String du = d.optString("url", "");
                if (sn.length() >= 40 && du.startsWith("http") && !du.contains("news.google.com")) {
                    passages.add(new String[]{d.optString("title", wikiTitle), du, sn, du.contains("wikipedia.org") ? "1" : "0"});
                }
            }
            if (passages.isEmpty()) return null;

            double bestScore = -1.0;
            String bestSent = "";
            String bestSrc = wikiSrc;
            String bestUrl = wikiUrl;
            String secondSent = "";
            double secondScore = -1.0;

            for (String[] p : passages) {
                String pSrc = p[0], pUrl = p[1], pText = p[2];
                boolean isWiki = "1".equals(p[3]);
                String[] sents = pText.split("(?<=[.!?])\\s+");
                for (int i = 0; i < Math.min(20, sents.length); i++) {
                    String s = sents[i].trim();
                    if (s.length() < 35 || s.length() > 320) continue;
                    String sl = s.toLowerCase(Locale.US);
                    double overlap = 0.0;
                    for (String tok : qTokens) {
                        if (sl.contains(tok)) overlap += (tok.length() >= 5 ? 1.5 : 1.0);
                    }
                    if (overlap == 0.0 && !isWiki) continue;
                    double score = overlap + ((isWiki && i < 2) ? 1.5 : 0.0);
                    if ("WHEN".equals(intent)) {
                        if (s.matches(".*\\b(1\\d{3}|20\\d{2})\\b.*")) score += 3.5;
                        if (sl.contains("founded") || sl.contains("created") || sl.contains("born") || sl.contains("established") || sl.contains("launched")) score += 2.5;
                    } else if ("WHO".equals(intent)) {
                        if (s.matches(".*\\b[A-Z][a-z]{2,}\\s+[A-Z][a-z]{2,}\\b.*")) score += 2.5;
                        if (sl.contains("founder") || sl.contains("ceo") || sl.contains("owner") || sl.contains("invented") || sl.contains("president") || sl.contains("author")) score += 3.0;
                    } else if ("WHERE".equals(intent)) {
                        if (sl.contains("located in") || sl.contains("based in") || sl.contains("capital") || sl.contains("country") || sl.contains("city")) score += 3.5;
                    } else if ("HOW_TO".equals(intent)) {
                        if (sl.contains("first") || sl.contains("step") || sl.contains("install") || sl.contains("run") || sl.contains("use")) score += 2.5;
                    } else if ("WHAT_IS".equals(intent)) {
                        if (sl.contains(" is a ") || sl.contains(" is an ") || sl.contains(" refers to ") || sl.contains(" is the ")) score += 2.0;
                    }
                    if (score > bestScore) {
                        if (bestUrl.equals(pUrl)) {
                            secondScore = bestScore;
                            secondSent = bestSent;
                        }
                        bestScore = score;
                        bestSent = s;
                        bestSrc = pSrc;
                        bestUrl = pUrl;
                    } else if (score > secondScore && bestUrl.equals(pUrl) && !s.equals(bestSent)) {
                        secondScore = score;
                        secondSent = s;
                    }
                }
            }
            if (bestSent.isEmpty()) return null;
            String[] leadIns = {
                "According to " + bestSrc + ":",
                "From " + bestSrc + ":",
                "Summarized from " + bestSrc + ":",
                bestSrc + " notes:"
            };
            String lead = leadIns[new java.util.Random().nextInt(leadIns.length)];
            String combined = lead + " " + bestSent + ((!secondSent.isEmpty() && secondScore >= bestScore * 0.65) ? " " + secondSent : "");
            JSONArray facts = fetchWikidataFacts(wikibaseId, attrTargetPid);
            String titleOut = bestSrc;
            if (attrTargetPid != null && facts.length() > 0) {
                for (int i = 0; i < facts.length(); i++) {
                    JSONObject f = facts.optJSONObject(i);
                    if (f != null && attrTargetPid.equals(f.optString("_pid"))) {
                        titleOut = bestSrc + " — " + f.optString("label") + ": " + f.optString("value");
                        combined = f.optString("label") + " of " + bestSrc + ": " + f.optString("value") + ". " + bestSent;
                        break;
                    }
                }
            }
            JSONArray cleanFacts = new JSONArray();
            for (int i = 0; i < facts.length(); i++) {
                JSONObject f = facts.optJSONObject(i);
                if (f != null) cleanFacts.put(new JSONObject().put("label", f.optString("label")).put("value", f.optString("value")));
            }
            return new JSONObject()
                    .put("title", titleOut)
                    .put("subtitle", "Structured Fact & QA (" + intent + ") · en.wikipedia.org")
                    .put("summary", combined)
                    .put("url", bestUrl)
                    .put("facts", cleanFacts);
        } catch (Exception ignored) {}
        return null;
    }

    private static JSONArray fetchWikidataFacts(String qid, String targetPid) {
        JSONArray facts = new JSONArray();
        if (qid == null || !qid.matches("^Q\\d+$")) return facts;
        try {
            String wdJson = httpGet("https://www.wikidata.org/w/api.php?action=wbgetentities&ids=" + qid + "&props=claims&format=json", 1600);
            if (wdJson == null || wdJson.isEmpty()) return facts;
            JSONObject claims = new JSONObject(wdJson).optJSONObject("entities").optJSONObject(qid).optJSONObject("claims");
            if (claims == null) return facts;
            String[][] props = {
                {"P1082", "Population"}, {"P36", "Capital"}, {"P169", "CEO"}, {"P35", "Head of State"},
                {"P112", "Founder"}, {"P38", "Currency"}, {"P2102", "Boiling Point"}, {"P2101", "Melting Point"},
                {"P2046", "Area"}, {"P571", "Founded"}
            };
            List<String[]> ordered = new ArrayList<>(java.util.Arrays.asList(props));
            if (targetPid != null) {
                ordered.sort((a, b) -> Integer.compare(a[0].equals(targetPid) ? 0 : 1, b[0].equals(targetPid) ? 0 : 1));
            }
            List<String[]> raw = new ArrayList<>();
            List<String> refIds = new ArrayList<>();
            for (String[] p : ordered) {
                JSONArray arr = claims.optJSONArray(p[0]);
                if (arr == null || arr.length() == 0) continue;
                JSONObject best = arr.optJSONObject(0);
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject c = arr.optJSONObject(i);
                    if (c != null && "preferred".equals(c.optString("rank"))) { best = c; break; }
                }
                JSONObject dv = best != null && best.optJSONObject("mainsnak") != null ? best.optJSONObject("mainsnak").optJSONObject("datavalue") : null;
                if (dv == null) continue;
                String vt = dv.optString("type");
                if ("wikibase-entityid".equals(vt) && dv.optJSONObject("value") != null) {
                    String rid = dv.optJSONObject("value").optString("id");
                    if (!rid.isEmpty()) { raw.add(new String[]{p[0], p[1], "QREF:" + rid}); refIds.add(rid); }
                } else if ("quantity".equals(vt) && dv.optJSONObject("value") != null) {
                    String amt = dv.optJSONObject("value").optString("amount", "").replaceFirst("^\\+", "");
                    try {
                        double num = Double.parseDouble(amt);
                        amt = (num == Math.floor(num) && Math.abs(num) >= 1000) ? String.format(Locale.US, "%,d", (long) num) : amt;
                    } catch (Exception ignored) {}
                    String unit = dv.optJSONObject("value").optString("unit", "");
                    if (unit.endsWith("/Q11579")) amt += " K";
                    else if (unit.endsWith("/Q25267")) amt += " °C";
                    else if (unit.endsWith("/Q712226")) amt += " km²";
                    raw.add(new String[]{p[0], p[1], amt});
                } else if ("time".equals(vt) && dv.optJSONObject("value") != null) {
                    String ts = dv.optJSONObject("value").optString("time", "").replaceFirst("^\\+", "");
                    if (ts.length() >= 4) raw.add(new String[]{p[0], p[1], ts.substring(0, 4)});
                }
                if (raw.size() >= 4) break;
            }
            Map<String, String> lblMap = new HashMap<>();
            if (!refIds.isEmpty()) {
                String ids = String.join("|", refIds);
                String lj = httpGet("https://www.wikidata.org/w/api.php?action=wbgetentities&ids=" + URLEncoder.encode(ids, "UTF-8") + "&props=labels&languages=en&format=json", 1400);
                if (lj != null && !lj.isEmpty()) {
                    JSONObject ents = new JSONObject(lj).optJSONObject("entities");
                    if (ents != null) {
                        for (String rid : refIds) {
                            JSONObject e = ents.optJSONObject(rid);
                            if (e != null && e.optJSONObject("labels") != null && e.optJSONObject("labels").optJSONObject("en") != null) {
                                lblMap.put(rid, e.optJSONObject("labels").optJSONObject("en").optString("value"));
                            }
                        }
                    }
                }
            }
            for (String[] r : raw) {
                String v = r[2].startsWith("QREF:") ? lblMap.get(r[2].substring(5)) : r[2];
                if (v != null && !v.isEmpty()) {
                    facts.put(new JSONObject().put("_pid", r[0]).put("label", r[1]).put("value", v));
                }
            }
        } catch (Exception ignored) {}
        return facts;
    }

    private static String upgrade4k(String u) {
        return u.replaceAll("(https?://ichef\\.bbci\\.co\\.uk/(?:ace/standard|news)/)\\d+(/.*)", "$12048$2");
    }

    private static long parsePubMs(String pub) {
        if (pub == null || pub.isEmpty()) return 0;
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
            sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
            Date d = sdf.parse(pub);
            return d != null ? d.getTime() : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    private static boolean isFresh(String pub, long nowMs) {
        long ts = parsePubMs(pub);
        return ts > 0 && (nowMs - ts) <= 3900_000L;
    }

    private static String formatAge(String pub, long nowMs) {
        long ts = parsePubMs(pub);
        if (ts <= 0) return pub;
        long sec = Math.max(0, (nowMs - ts) / 1000L);
        if (sec < 60) return "Just now";
        if (sec < 3600) return (sec / 60) + "m ago";
        if (sec < 86400) return (sec / 3600) + "h ago";
        return (sec / 86400) + "d ago";
    }

    private static JSONArray searchInternetWeb(String query) {
        JSONArray out = new JSONArray();
        try {
            if (query == null || query.trim().isEmpty()) return out;
            HttpURLConnection conn = (HttpURLConnection) new URL("https://html.duckduckgo.com/html/").openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(2200);
            conn.setReadTimeout(2200);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36");
            conn.setRequestProperty("Accept-Language", "en-US,en;q=0.9");
            conn.setRequestProperty("Referer", "https://html.duckduckgo.com/");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            byte[] postBytes = ("q=" + URLEncoder.encode(query.trim(), "UTF-8")).getBytes(StandardCharsets.UTF_8);
            try (OutputStream os = conn.getOutputStream()) { os.write(postBytes); }
            String body;
            try (InputStream is = conn.getInputStream()) { body = new String(readAll(is), StandardCharsets.UTF_8); }
            java.util.regex.Matcher mLink = java.util.regex.Pattern.compile("class=\"result__a\"[^>]*href=\"([^\"]+)\"[^>]*>(.*?)</a>", java.util.regex.Pattern.DOTALL).matcher(body);
            java.util.regex.Matcher mSnip = java.util.regex.Pattern.compile("class=\"result__snippet\"[^>]*>(.*?)</(?:a|div|span)>", java.util.regex.Pattern.DOTALL).matcher(body);
            List<String[]> links = new ArrayList<>();
            while (mLink.find() && links.size() < 10) links.add(new String[]{mLink.group(1), mLink.group(2)});
            List<String> snips = new ArrayList<>();
            while (mSnip.find() && snips.size() < 10) snips.add(mSnip.group(1));
            Set<String> seen = new HashSet<>();
            for (int i = 0; i < links.size() && out.length() < 8; i++) {
                String u = links.get(i)[0].replace("&amp;", "&").trim();
                int ui = u.indexOf("uddg=");
                if (ui >= 0) {
                    String sub = u.substring(ui + 5);
                    int amp = sub.indexOf('&');
                    if (amp >= 0) sub = sub.substring(0, amp);
                    u = java.net.URLDecoder.decode(sub, "UTF-8");
                }
                if (u.startsWith("//")) u = "https:" + u;
                if (!u.startsWith("http") || !seen.add(u)) continue;
                String title = links.get(i)[1].replaceAll("<[^>]+>", " ").replace("&amp;", "&").replace("&#x27;", "'").replace("&quot;", "\"").replaceAll("\\s+", " ").trim();
                String snip = i < snips.size() ? snips.get(i).replaceAll("<[^>]+>", " ").replace("&amp;", "&").replace("&#x27;", "'").replace("&quot;", "\"").replaceAll("\\s+", " ").trim() : "";
                if (!title.isEmpty()) {
                    String host = "";
                    try { host = new URL(u).getHost().replaceFirst("^www\\.", ""); } catch (Exception ignored) {}
                    out.put(new JSONObject()
                            .put("title", title)
                            .put("category", host.isEmpty() ? "Internet Web" : "Internet Web · " + host)
                            .put("summary", snip.isEmpty() ? "Live web result from " + host : snip)
                            .put("url", u));
                }
            }
        } catch (Exception ignored) {}
        return out;
    }

    private String[] getOrCreateSdkSigningKey(String dom) {
        JSONObject d = docs.get(dom);
        String priv = d != null ? d.optString("privkey_hex", "") : "";
        String pub = d != null ? d.optString("pubkey_hex", "") : "";
        if (!priv.isEmpty()) {
            if (pub.isEmpty()) pub = Ed25519.toHex(Ed25519.publicKey(Ed25519.fromHex(priv)));
            return new String[]{pub, priv};
        }
        JSONObject st = loadCapsuleState(dom);
        String nPub = st.optString("_sdk_node_pub", "");
        String nPriv = st.optString("_sdk_node_priv", "");
        if (nPriv.isEmpty()) {
            byte[] sk = Ed25519.generatePrivateKey();
            byte[] pk = Ed25519.publicKey(sk);
            nPub = Ed25519.toHex(pk);
            nPriv = Ed25519.toHex(sk);
            try {
                st.put("_sdk_node_pub", nPub);
                st.put("_sdk_node_priv", nPriv);
                saveCapsuleState(dom, st);
            } catch (Exception ignored) {}
        }
        return new String[]{nPub, nPriv};
    }

    private static String escapeHtmlSimple(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static HttpURLConnection openBoundConnection(URL url) throws Exception {
        String host = url.getHost() != null ? url.getHost() : "";
        boolean isLanIp = host.startsWith("192.168.") || host.startsWith("10.")
                || host.matches("^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*");
        if (isLanIp && staticContext != null) {
            try {
                android.net.ConnectivityManager cm = (android.net.ConnectivityManager) staticContext.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    for (android.net.Network net : cm.getAllNetworks()) {
                        android.net.NetworkCapabilities nc = cm.getNetworkCapabilities(net);
                        if (nc != null && nc.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)) {
                            return (HttpURLConnection) net.openConnection(url);
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
        }
        return (HttpURLConnection) url.openConnection();
    }

    private static void httpPostJson(String urlStr, String jsonBody, int timeoutMs) throws Exception {
        HttpURLConnection conn = openBoundConnection(new URL(urlStr));
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(timeoutMs);
        conn.setReadTimeout(timeoutMs);
        conn.setRequestProperty("Content-Type", "application/json");
        byte[] bytes = jsonBody.getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = conn.getOutputStream()) { os.write(bytes); }
        try (InputStream is = conn.getInputStream()) { readAll(is); }
    }

    private static String httpGet(String urlStr, int timeoutMs) throws Exception {
        HttpURLConnection conn = openBoundConnection(new URL(urlStr));
        conn.setConnectTimeout(timeoutMs);
        conn.setReadTimeout(timeoutMs);
        conn.setRequestProperty("User-Agent", "XanaduAndroid/1.0");
        try (InputStream is = conn.getInputStream()) {
            return new String(readAll(is), StandardCharsets.UTF_8);
        }
    }

    private byte[] readAsset(String name) throws Exception {
        try (InputStream is = assets.open(name)) {
            return readAll(is);
        }
    }

    private static byte[] readAll(InputStream is) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int r;
        while ((r = is.read(buf)) != -1) bos.write(buf, 0, r);
        return bos.toByteArray();
    }

    private static void sendBytes(OutputStream out, int code, String ctype, byte[] body) throws Exception {
        sendBytesWithHeaders(out, code, ctype, body, null);
    }

    private static void sendBytesWithHeaders(OutputStream out, int code, String ctype, byte[] body, Map<String, String> extra) throws Exception {
        StringBuilder hdr = new StringBuilder();
        hdr.append("HTTP/1.1 ").append(code).append(" OK\r\n");
        hdr.append("Content-Type: ").append(ctype).append("\r\n");
        hdr.append("Cache-Control: no-store, no-cache, must-revalidate\r\n");
        hdr.append("Content-Length: ").append(body.length).append("\r\n");
        if (extra != null) {
            for (Map.Entry<String, String> e : extra.entrySet()) {
                hdr.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
            }
        }
        hdr.append("Connection: close\r\n\r\n");
        out.write(hdr.toString().getBytes(StandardCharsets.US_ASCII));
        out.write(body);
        out.flush();
    }

    private static void sendDownload(OutputStream out, int code, String ctype, String filename, byte[] body) throws Exception {
        String hdr = "HTTP/1.1 " + code + " OK\r\nContent-Type: " + ctype + "\r\nContent-Disposition: attachment; filename=\"" + filename + "\"\r\nContent-Length: " + body.length + "\r\nConnection: close\r\n\r\n";
        out.write(hdr.getBytes(StandardCharsets.US_ASCII));
        out.write(body);
        out.flush();
    }

    private static void sendJson(OutputStream out, int code, String json) throws Exception {
        sendBytes(out, code, "application/json; charset=utf-8", json.getBytes(StandardCharsets.UTF_8));
    }

    private static String normalizeXndDomain(String raw) {
        if (raw == null) return "";
        String dom = raw.trim().toLowerCase(Locale.US);
        dom = dom.replaceFirst("^(?:xnd|https?)://", "");
        int slash = dom.indexOf('/');
        if (slash >= 0) dom = dom.substring(0, slash);
        int q = dom.indexOf('?');
        if (q >= 0) dom = dom.substring(0, q);
        int h = dom.indexOf('#');
        if (h >= 0) dom = dom.substring(0, h);
        dom = dom.trim();
        if (!dom.isEmpty() && !dom.endsWith(".xnd")) dom = dom + ".xnd";
        return dom;
    }

    private String[] parseCanonicalDomain(String domain) {
        if (domain == null) return null;
        Matcher m = CANONICAL_DOMAIN_RE.matcher(domain.trim().toLowerCase(Locale.US));
        if (!m.matches()) return null;
        return new String[]{m.group(1) + ".xnd", m.group(2)};
    }

    private String canonicalDomainFor(String domain, String pubHex) {
        String clean = domain == null ? "" : domain.trim().toLowerCase(Locale.US);
        String[] p = parseCanonicalDomain(clean);
        String base = p != null ? p[0] : clean;
        String stem = base.endsWith(".xnd") ? base.substring(0, base.length() - 4) : base;
        String tag = (pubHex != null && pubHex.length() >= 8) ? pubHex.substring(0, 8).toLowerCase(Locale.US) : "00000000";
        return stem + "." + tag + ".xnd";
    }

    private String formatFingerprint(String pubHex) {
        String h = pubHex == null ? "" : pubHex.trim().toLowerCase(Locale.US);
        if (h.length() < 8) return h.isEmpty() ? "unknown" : h;
        return h.substring(0, 4) + "-" + h.substring(4, 8);
    }

    private synchronized void loadTrustPins() {
        try {
            File tf = new File(dataDir, "trust_pins.json");
            if (!tf.exists()) return;
            JSONObject root = new JSONObject(readFileText(tf));
            JSONObject pins = root.optJSONObject("pins");
            if (pins != null) {
                for (java.util.Iterator<String> it = pins.keys(); it.hasNext(); ) {
                    String k = it.next();
                    trustPins.put(k, pins.getJSONObject(k));
                }
            }
            JSONObject pets = root.optJSONObject("petnames");
            if (pets != null) {
                for (java.util.Iterator<String> it = pets.keys(); it.hasNext(); ) {
                    String k = it.next();
                    trustPetnames.put(k, pets.getString(k));
                }
            }
            JSONObject confs = root.optJSONObject("conflicts");
            if (confs != null) {
                for (java.util.Iterator<String> it = confs.keys(); it.hasNext(); ) {
                    String base = it.next();
                    JSONObject bObj = confs.getJSONObject(base);
                    Map<String, String> m = new HashMap<>();
                    for (java.util.Iterator<String> it2 = bObj.keys(); it2.hasNext(); ) {
                        String ak = it2.next();
                        m.put(ak, bObj.getString(ak));
                    }
                    trustConflicts.put(base, m);
                }
            }
        } catch (Exception ignored) {}
    }

    private synchronized void saveTrustPins() {
        try {
            JSONObject root = new JSONObject();
            JSONObject pins = new JSONObject();
            for (Map.Entry<String, JSONObject> e : trustPins.entrySet()) pins.put(e.getKey(), e.getValue());
            JSONObject pets = new JSONObject();
            for (Map.Entry<String, String> e : trustPetnames.entrySet()) pets.put(e.getKey(), e.getValue());
            JSONObject confs = new JSONObject();
            for (Map.Entry<String, Map<String, String>> e : trustConflicts.entrySet()) {
                JSONObject mObj = new JSONObject();
                for (Map.Entry<String, String> e2 : e.getValue().entrySet()) mObj.put(e2.getKey(), e2.getValue());
                confs.put(e.getKey(), mObj);
            }
            root.put("pins", pins).put("petnames", pets).put("conflicts", confs);
            writeFileText(new File(dataDir, "trust_pins.json"), root.toString());
        } catch (Exception ignored) {}
    }

    private String getPinnedPubkey(String domain) {
        JSONObject rec = trustPins.get(domain.trim().toLowerCase(Locale.US));
        return rec != null ? rec.optString("pubkey_hex", "") : "";
    }

    private String ensureFirstSeenPin(String domain, String pubHex, String source) {
        String dom = domain.trim().toLowerCase(Locale.US);
        String pub = pubHex == null ? "" : pubHex.trim().toLowerCase(Locale.US);
        if (dom.isEmpty() || pub.isEmpty()) return pub;
        JSONObject existing = trustPins.get(dom);
        if (existing == null || existing.optString("pubkey_hex", "").isEmpty()) {
            try {
                trustPins.put(dom, new JSONObject().put("pubkey_hex", pub).put("pinned_at", System.currentTimeMillis() / 1000.0).put("source", source));
                saveTrustPins();
            } catch (Exception ignored) {}
            return pub;
        }
        return existing.optString("pubkey_hex", "");
    }

    private void recordTrustConflict(String baseDom, String aliasDom, String pubHex) {
        String base = baseDom.trim().toLowerCase(Locale.US);
        String alias = aliasDom.trim().toLowerCase(Locale.US);
        String pub = pubHex == null ? "" : pubHex.trim().toLowerCase(Locale.US);
        if (base.isEmpty() || alias.isEmpty() || pub.isEmpty()) return;
        Map<String, String> bucket = trustConflicts.get(base);
        if (bucket == null) {
            bucket = Collections.synchronizedMap(new HashMap<>());
            trustConflicts.put(base, bucket);
        }
        if (!pub.equals(bucket.get(alias))) {
            bucket.put(alias, pub);
            saveTrustPins();
        }
    }

    private JSONArray getTrustConflictsArray(String baseDom) {
        JSONArray arr = new JSONArray();
        Map<String, String> bucket = trustConflicts.get(baseDom.trim().toLowerCase(Locale.US));
        if (bucket != null) {
            for (Map.Entry<String, String> e : bucket.entrySet()) {
                try {
                    arr.put(new JSONObject()
                        .put("domain", e.getKey())
                        .put("pubkey_hex", e.getValue())
                        .put("fingerprint", formatFingerprint(e.getValue())));
                } catch (Exception ignored) {}
            }
        }
        return arr;
    }

    private String hmacSha256Hex(byte[] key, String msg) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
        return Ed25519.toHex(mac.doFinal(msg.getBytes(StandardCharsets.UTF_8)));
    }

    private String mintCapsuleToken(String domain) {
        try {
            String dom = domain.trim().toLowerCase(Locale.US);
            long exp = (System.currentTimeMillis() / 1000L) + 86400L;
            String sig = hmacSha256Hex(capTokenSecret, dom + "|" + exp);
            return exp + "." + sig;
        } catch (Exception e) {
            return "";
        }
    }

    private boolean verifyCapsuleToken(String domain, String token) {
        try {
            if (token == null || !token.contains(".")) return false;
            int dot = token.indexOf('.');
            long exp = Long.parseLong(token.substring(0, dot));
            if (exp < (System.currentTimeMillis() / 1000L)) return false;
            String sig = token.substring(dot + 1).trim();
            String expected = hmacSha256Hex(capTokenSecret, domain.trim().toLowerCase(Locale.US) + "|" + exp);
            return sig.equals(expected);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isCapsuleTokenAllowed(String domain, String capToken, String reqOrigin, String reqReferer) {
        if (capToken != null && !capToken.isEmpty()) {
            return verifyCapsuleToken(domain, capToken);
        }
        String o = reqOrigin == null ? "" : reqOrigin.trim().toLowerCase(Locale.US);
        String r = reqReferer == null ? "" : reqReferer.trim().toLowerCase(Locale.US);
        return !o.equals("null") && !r.contains("/xnd-app/");
    }

    private static boolean isValidXndDomain(String dom) {
        return dom != null && !dom.isEmpty() && dom.length() <= 253
                && dom.matches("^(?:[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,62}\\.)+xnd$");
    }

    private static Map<String, String> parseQuery(String q) {
        Map<String, String> map = new HashMap<>();
        if (q == null || q.isEmpty()) return map;
        for (String pair : q.split("&")) {
            int idx = pair.indexOf('=');
            try {
                if (idx > 0) map.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
            } catch (Exception ignored) {}
        }
        return map;
    }

    private static String sha256Hex(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] b = md.digest(s.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static String readFileText(File f) throws Exception {
        try (FileInputStream fis = new FileInputStream(f)) {
            return new String(readAll(fis), StandardCharsets.UTF_8);
        }
    }

    private static void writeFileText(File f, String s) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(s.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static long dirSize(File f) {
        if (!f.exists()) return 0;
        if (f.isFile()) return f.length();
        long sum = 0;
        File[] list = f.listFiles();
        if (list != null) for (File c : list) sum += dirSize(c);
        return sum;
    }
}
