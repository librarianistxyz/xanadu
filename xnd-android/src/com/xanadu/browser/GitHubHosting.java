package com.xanadu.browser;

import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class GitHubHosting {
    private static final String GITHUB_API = "https://api.github.com";
    private static final String GITHUB_CLIENT_ID = "Ov23lizdQd2tWjV4GOlm";
    private static final Set<String> TEXT_EXTS = new HashSet<>(Arrays.asList(
            ".html", ".htm", ".css", ".js", ".mjs", ".cjs", ".json", ".svg",
            ".txt", ".md", ".xml", ".yaml", ".yml", ".py", ".wasm"
    ));

    private final File authFile;
    private final File linksFile;
    private volatile String activeDeviceCode = "";
    private final Object pollLock = new Object();

    public GitHubHosting(File dataDir) {
        this.authFile = new File(dataDir, "github_auth.json");
        this.linksFile = new File(dataDir, "github_links.json");
    }

    public synchronized JSONObject loadLinks() {
        try {
            if (!linksFile.exists()) return new JSONObject();
            byte[] b = Files.readAllBytes(linksFile.toPath());
            return new JSONObject(new String(b, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return new JSONObject();
        }
    }

    public synchronized void saveLink(String domain, String repo, String branch, String subdir, String sha) {
        try {
            JSONObject links = loadLinks();
            JSONObject item = new JSONObject();
            item.put("domain", domain);
            item.put("repo", repo);
            item.put("branch", branch);
            item.put("subdir", subdir != null ? subdir : "");
            item.put("last_sha", sha != null ? sha : "");
            item.put("locked", true);
            item.put("updated_at", System.currentTimeMillis() / 1000.0);
            links.put(domain, item);
            try (OutputStream os = new java.io.FileOutputStream(linksFile)) {
                os.write(links.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception ignored) {}
    }

    public synchronized boolean removeLink(String domain) {
        try {
            JSONObject links = loadLinks();
            if (!links.has(domain)) return false;
            links.remove(domain);
            try (OutputStream os = new java.io.FileOutputStream(linksFile)) {
                os.write(links.toString().getBytes(StandardCharsets.UTF_8));
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String getLatestCommitSha(String repo, String branch) {
        try {
            String tok = requireToken();
            String cleanRepo = repo == null ? "" : repo.trim();
            String cleanBranch = branch == null || branch.trim().isEmpty() ? "main" : branch.trim();
            if (!cleanRepo.matches("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")) return "";
            HttpRes r = request("GET", GITHUB_API + "/repos/" + cleanRepo + "/commits/" + URLEncoder.encode(cleanBranch, "UTF-8"), tok, null);
            if (r.code == 200) {
                return new JSONObject(r.body).optString("sha", "");
            }
        } catch (Exception ignored) {}
        return "";
    }

    private JSONObject loadAuth() {
        try {
            if (!authFile.exists()) return new JSONObject();
            byte[] b = Files.readAllBytes(authFile.toPath());
            return new JSONObject(new String(b, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return new JSONObject();
        }
    }

    private String requireToken() {
        String tok = loadAuth().optString("token", "").trim();
        if (tok.isEmpty()) throw new IllegalStateException("GitHub account is not connected.");
        return tok;
    }

    public JSONObject getStatus() {
        JSONObject a = loadAuth();
        JSONObject out = new JSONObject();
        try {
            if (a.optString("token", "").trim().isEmpty()) {
                out.put("connected", false).put("username", "").put("name", "").put("avatar_url", "");
            } else {
                out.put("connected", true)
                        .put("username", a.optString("username", ""))
                        .put("name", a.optString("name", ""))
                        .put("avatar_url", a.optString("avatar_url", ""));
            }
        } catch (Exception ignored) {}
        return out;
    }

    public JSONObject connect(String token) throws Exception {
        String tok = token == null ? "" : token.trim();
        if (tok.isEmpty()) throw new IllegalArgumentException("GitHub Personal Access Token is required.");
        HttpRes res = request("GET", GITHUB_API + "/user", tok, null);
        if (res.code != 200) {
            throw new IllegalArgumentException("GitHub authentication failed (" + res.code + "). Check your token and scopes.");
        }
        JSONObject u = new JSONObject(res.body);
        String login = u.optString("login", "");
        String name = u.optString("name", "").isEmpty() ? login : u.optString("name", login);
        JSONObject saved = new JSONObject()
                .put("token", tok)
                .put("username", login)
                .put("name", name)
                .put("avatar_url", u.optString("avatar_url", ""));
        if (authFile.getParentFile() != null) authFile.getParentFile().mkdirs();
        Files.write(authFile.toPath(), saved.toString(2).getBytes(StandardCharsets.UTF_8));
        return getStatus();
    }

    public JSONObject disconnect() {
        if (authFile.exists()) authFile.delete();
        JSONObject out = new JSONObject();
        try {
            out.put("ok", true).put("connected", false);
        } catch (Exception ignored) {}
        return out;
    }

    public JSONObject startDeviceFlow() throws Exception {
        String form = "client_id=" + URLEncoder.encode(GITHUB_CLIENT_ID, "UTF-8")
                + "&scope=" + URLEncoder.encode("repo", "UTF-8");
        HttpRes res = postForm("https://github.com/login/device/code", form);
        if (res.code != 200) {
            throw new IllegalArgumentException("Failed to start GitHub Device Login (" + res.code + ").");
        }
        JSONObject d = new JSONObject(res.body);
        if (d.has("error")) {
            throw new IllegalArgumentException(d.optString("error_description", d.optString("error", "Device login error")));
        }
        final String devCode = d.optString("device_code", "");
        final int interval = Math.max(5, d.optInt("interval", 5));
        final int expiresIn = Math.min(900, d.optInt("expires_in", 900));
        this.activeDeviceCode = devCode;

        Thread bg = new Thread(() -> {
            long deadline = System.currentTimeMillis() + expiresIn * 1000L;
            int waitMs = interval * 1000;
            while (System.currentTimeMillis() < deadline && devCode.equals(activeDeviceCode)) {
                try {
                    Thread.sleep(waitMs);
                    if (!devCode.equals(activeDeviceCode)) break;
                    JSONObject pr = pollDeviceFlow(devCode);
                    String st = pr.optString("status", "");
                    if ("authorized".equals(st)) {
                        activeDeviceCode = "";
                        break;
                    }
                    if ("slow_down".equals(st)) {
                        waitMs = Math.max(10, pr.optInt("interval", 10)) * 1000;
                    }
                } catch (IllegalArgumentException iae) {
                    break;
                } catch (Exception ignored) {
                }
            }
        });
        bg.setDaemon(true);
        bg.start();

        return new JSONObject()
                .put("ok", true)
                .put("device_code", devCode)
                .put("user_code", d.optString("user_code", ""))
                .put("verification_uri", d.optString("verification_uri", "https://github.com/login/device"))
                .put("expires_in", expiresIn)
                .put("interval", interval);
    }

    public JSONObject pollDeviceFlow(String deviceCode) throws Exception {
        String code = deviceCode == null ? "" : deviceCode.trim();
        if (code.isEmpty()) throw new IllegalArgumentException("device_code is required.");
        synchronized (pollLock) {
            JSONObject cur = getStatus();
            if (cur.optBoolean("connected", false) && !code.equals(activeDeviceCode)) {
                cur.put("ok", true).put("status", "authorized");
                return cur;
            }
            String form = "client_id=" + URLEncoder.encode(GITHUB_CLIENT_ID, "UTF-8")
                    + "&device_code=" + URLEncoder.encode(code, "UTF-8")
                    + "&grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:device_code", "UTF-8");
            HttpRes res = postForm("https://github.com/login/oauth/access_token", form);
            if (res.code != 200) {
                throw new IllegalArgumentException("GitHub token poll failed (" + res.code + ").");
            }
            JSONObject d = new JSONObject(res.body);
            String accessToken = d.optString("access_token", "");
            if (!accessToken.isEmpty()) {
                JSONObject st = connect(accessToken);
                activeDeviceCode = "";
                st.put("ok", true).put("status", "authorized");
                return st;
            }
            String err = d.optString("error", "");
            if ("authorization_pending".equals(err)) {
                return new JSONObject().put("ok", true).put("status", "pending");
            }
            if ("slow_down".equals(err)) {
                return new JSONObject().put("ok", true).put("status", "slow_down").put("interval", d.optInt("interval", 10));
            }
            throw new IllegalArgumentException(d.optString("error_description", err.isEmpty() ? "GitHub authorization denied" : err));
        }
    }

    private static HttpRes postForm(String urlStr, String formBody) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setRequestMethod("POST");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(15000);
        conn.setDoOutput(true);
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("User-Agent", "Xanadu-Browser/0.1");
        try (OutputStream os = conn.getOutputStream()) {
            os.write(formBody.getBytes(StandardCharsets.UTF_8));
        }
        HttpRes out = new HttpRes();
        out.code = conn.getResponseCode();
        InputStream is = out.code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        if (is != null) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] tmp = new byte[4096];
            int n;
            while ((n = is.read(tmp)) != -1) buf.write(tmp, 0, n);
            out.body = new String(buf.toByteArray(), StandardCharsets.UTF_8);
            is.close();
        } else {
            out.body = "{}";
        }
        conn.disconnect();
        return out;
    }

    public JSONArray listRepos() throws Exception {
        String tok = requireToken();
        HttpRes res = request("GET", GITHUB_API + "/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member", tok, null);
        if (res.code != 200) throw new IllegalArgumentException("Failed to list GitHub repositories (" + res.code + ").");
        JSONArray src = new JSONArray(res.body);
        JSONArray out = new JSONArray();
        for (int i = 0; i < src.length(); i++) {
            JSONObject it = src.getJSONObject(i);
            JSONObject owner = it.optJSONObject("owner");
            out.put(new JSONObject()
                    .put("full_name", it.optString("full_name", ""))
                    .put("owner", owner != null ? owner.optString("login", "") : "")
                    .put("name", it.optString("name", ""))
                    .put("private", it.optBoolean("private", false))
                    .put("default_branch", it.optString("default_branch", "main"))
                    .put("description", it.optString("description", ""))
                    .put("html_url", it.optString("html_url", "")));
        }
        return out;
    }

    public static class RepoBundle {
        public JSONObject files = new JSONObject();
        public String backendPy = "";
        public String branch = "main";
    }

    public RepoBundle fetchRepoBundle(String repo, String branch, String subdir) throws Exception {
        String cleanRepo = repo == null ? "" : repo.trim();
        if (!cleanRepo.matches("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")) {
            throw new IllegalArgumentException("Invalid repository format. Expected owner/repo.");
        }
        String tok = requireToken();
        String cleanBranch = branch == null ? "" : branch.trim();
        String cleanSub = subdir == null ? "" : subdir.trim().replaceAll("^/+|/+$", "");

        if (cleanBranch.isEmpty()) {
            HttpRes rr = request("GET", GITHUB_API + "/repos/" + cleanRepo, tok, null);
            if (rr.code != 200) throw new IllegalArgumentException("Repository '" + cleanRepo + "' not accessible (" + rr.code + ").");
            cleanBranch = new JSONObject(rr.body).optString("default_branch", "main");
        }

        String zipUrl = GITHUB_API + "/repos/" + cleanRepo + "/zipball/" + URLEncoder.encode(cleanBranch, "UTF-8");
        HttpURLConnection conn = (HttpURLConnection) new URL(zipUrl).openConnection();
        conn.setInstanceFollowRedirects(true);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(30000);
        conn.setRequestProperty("Authorization", "Bearer " + tok);
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("X-GitHub-Api-Version", "2022-11-28");
        conn.setRequestProperty("User-Agent", "Xanadu-Browser/0.1");
        int code = conn.getResponseCode();
        if (code != 200) {
            conn.disconnect();
            throw new IllegalArgumentException("Could not download branch '" + cleanBranch + "' archive (" + code + ").");
        }

        RepoBundle bundle = new RepoBundle();
        bundle.branch = cleanBranch;
        Map<String, byte[]> rawMap = new LinkedHashMap<>();
        Map<String, String> lowerKeys = new HashMap<>();

        try (ZipInputStream zis = new ZipInputStream(conn.getInputStream())) {
            ZipEntry entry;
            byte[] buf = new byte[8192];
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.isDirectory()) continue;
                String fullName = entry.getName().replaceFirst("^/+", "");
                int slash = fullName.indexOf('/');
                String path = slash >= 0 ? fullName.substring(slash + 1) : fullName;
                if (path.isEmpty() || path.startsWith(".git/") || path.contains("/.git/") || path.contains("node_modules/") || path.contains("..")) continue;

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                int n;
                while ((n = zis.read(buf)) != -1) {
                    if (baos.size() + n > 1000000) break;
                    baos.write(buf, 0, n);
                }
                rawMap.put(path, baos.toByteArray());
                lowerKeys.put(path.toLowerCase(Locale.US), path);
            }
        } finally {
            conn.disconnect();
        }

        String chosenDir = cleanSub;
        if (chosenDir.isEmpty()) {
            String rootIdx = lowerKeys.containsKey("index.html") ? lowerKeys.get("index.html") : lowerKeys.get("index.htm");
            boolean rootIsDev = false;
            if (rootIdx != null) {
                String rootHtml = new String(rawMap.get(rootIdx), StandardCharsets.UTF_8).toLowerCase(Locale.US);
                rootIsDev = rootHtml.contains("/src/") || rootHtml.contains(".tsx") || rootHtml.contains(".jsx");
            }
            String[] outDirs = new String[]{"dist", "build", "out", ".output/public", "public", "docs", "_site", "www", "site"};
            String autoDir = null;
            for (String d : outDirs) {
                if (lowerKeys.containsKey(d + "/index.html") || lowerKeys.containsKey(d + "/index.htm")) {
                    if (rootIdx == null || rootIsDev) {
                        autoDir = d;
                        break;
                    }
                }
            }
            if (autoDir == null && rootIdx != null) {
                autoDir = "";
            } else if (autoDir == null) {
                for (String k : rawMap.keySet()) {
                    String lk = k.toLowerCase(Locale.US);
                    if (lk.endsWith("/index.html") || lk.endsWith("/index.htm")) {
                        autoDir = k.substring(0, k.lastIndexOf('/'));
                        break;
                    }
                }
            }
            if (autoDir == null) {
                if (lowerKeys.containsKey("package.json")) {
                    throw new IllegalArgumentException("NEEDS_BUILD_ACTION: This repo needs a build step (Vite/Next/React). Tap 'Enable Auto-Build Action' below to compile it on GitHub automatically.");
                }
                throw new IllegalArgumentException("Repository must contain an index.html or a built output folder (dist/build/out).");
            }
            if (autoDir.isEmpty() && rootIsDev && lowerKeys.containsKey("package.json")) {
                throw new IllegalArgumentException("NEEDS_BUILD_ACTION: Source-only framework repo detected. Tap 'Enable Auto-Build Action' below to build dist/ on GitHub automatically.");
            }
            chosenDir = autoDir;
        }

        String prefix = chosenDir.isEmpty() ? "" : chosenDir + "/";
        int totalBytes = 0;
        int count = 0;
        for (Map.Entry<String, byte[]> e : rawMap.entrySet()) {
            String path = e.getKey();
            String relPath = path;
            if (!prefix.isEmpty()) {
                if (!path.startsWith(prefix)) continue;
                relPath = path.substring(prefix.length());
            }
            if (relPath.isEmpty() || count >= 120 || totalBytes > 5000000) continue;
            byte[] rawBytes = e.getValue();
            totalBytes += rawBytes.length;
            count++;

            String lower = relPath.toLowerCase(Locale.US);
            if (lower.equals("index.html") || lower.equals("index.htm")) relPath = "index.html";
            int dot = lower.lastIndexOf('.');
            String ext = dot >= 0 ? lower.substring(dot) : "";
            if (TEXT_EXTS.contains(ext)) {
                bundle.files.put(relPath, new String(rawBytes, StandardCharsets.UTF_8));
            } else {
                String mime = guessMime(ext);
                bundle.files.put(relPath, "data:" + mime + ";base64," + Base64.encodeToString(rawBytes, Base64.NO_WRAP));
            }
        }

        if (!bundle.files.has("index.html")) {
            throw new IllegalArgumentException("Repository must contain an index.html file.");
        }
        if (bundle.files.has("backend.py")) {
            bundle.backendPy = bundle.files.optString("backend.py", "");
            bundle.files.remove("backend.py");
        }
        return bundle;
    }

    public JSONObject pushFilesToRepo(String repo, String branch, String subdir, JSONObject files, String backendPy, String message) throws Exception {
        String cleanRepo = repo == null ? "" : repo.trim();
        if (!cleanRepo.matches("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")) {
            throw new IllegalArgumentException("Invalid repository format. Expected owner/repo.");
        }
        String tok = requireToken();
        String cleanBranch = branch == null ? "" : branch.trim();
        String cleanSub = subdir == null ? "" : subdir.trim().replaceAll("^/+|/+$", "");
        if (cleanBranch.isEmpty()) {
            HttpRes rr = request("GET", GITHUB_API + "/repos/" + cleanRepo, tok, null);
            if (rr.code != 200) throw new IllegalArgumentException("Repository '" + cleanRepo + "' not accessible (" + rr.code + ").");
            cleanBranch = new JSONObject(rr.body).optString("default_branch", "main");
        }

        JSONObject allFiles = new JSONObject(files.toString());
        if (backendPy != null && !backendPy.trim().isEmpty()) {
            allFiles.put("backend.py", backendPy);
        }

        int pushed = 0;
        String commitUrl = "";
        String msg = (message == null || message.trim().isEmpty()) ? "Update site from Xanadu" : message.trim();

        Iterator<String> keys = allFiles.keys();
        while (keys.hasNext()) {
            String rel = keys.next().replace("\\", "/").replaceFirst("^\\./", "").replaceFirst("^/+", "");
            if (rel.isEmpty() || rel.contains("..")) continue;
            String target = cleanSub.isEmpty() ? rel : (cleanSub + "/" + rel);
            String val = allFiles.optString(rel, "");

            String existingSha = "";
            HttpRes gr = request("GET", GITHUB_API + "/repos/" + cleanRepo + "/contents/" + encodePath(target) + "?ref=" + URLEncoder.encode(cleanBranch, "UTF-8"), tok, null);
            if (gr.code == 200) {
                existingSha = new JSONObject(gr.body).optString("sha", "");
            }

            String b64;
            if (val.startsWith("data:") && val.contains(";base64,")) {
                b64 = val.substring(val.indexOf(";base64,") + 8);
            } else {
                b64 = Base64.encodeToString(val.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
            }

            JSONObject body = new JSONObject()
                    .put("message", msg)
                    .put("content", b64)
                    .put("branch", cleanBranch);
            if (!existingSha.isEmpty()) body.put("sha", existingSha);

            HttpRes pr = request("PUT", GITHUB_API + "/repos/" + cleanRepo + "/contents/" + encodePath(target), tok, body.toString());
            if (pr.code != 200 && pr.code != 201) {
                throw new IllegalArgumentException("Failed pushing '" + target + "' (" + pr.code + ")");
            }
            pushed++;
            JSONObject cObj = new JSONObject(pr.body).optJSONObject("commit");
            if (cObj != null && !cObj.optString("html_url", "").isEmpty()) {
                commitUrl = cObj.optString("html_url", "");
            }
        }

        return new JSONObject()
                .put("ok", true)
                .put("repo", cleanRepo)
                .put("branch", cleanBranch)
                .put("pushed_count", pushed)
                .put("commit_url", commitUrl);
    }

    public JSONObject installBuildWorkflow(String repo, String branch) throws Exception {
        String cleanRepo = repo == null ? "" : repo.trim();
        if (!cleanRepo.matches("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")) {
            throw new IllegalArgumentException("Invalid repository format. Expected owner/repo.");
        }
        String tok = requireToken();
        String cleanBranch = branch == null ? "" : branch.trim();
        if (cleanBranch.isEmpty()) {
            HttpRes rr = request("GET", GITHUB_API + "/repos/" + cleanRepo, tok, null);
            if (rr.code != 200) throw new IllegalArgumentException("Repository '" + cleanRepo + "' not accessible (" + rr.code + ").");
            cleanBranch = new JSONObject(rr.body).optString("default_branch", "main");
        }

        String wfPath = ".github/workflows/xanadu-build.yml";
        String wfYaml = "name: Xanadu Build\n"
                + "on:\n"
                + "  push:\n    branches: [" + cleanBranch + "]\n"
                + "  workflow_dispatch:\n"
                + "permissions:\n  contents: write\n"
                + "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
                + "      - uses: actions/checkout@v4\n"
                + "      - uses: actions/setup-node@v4\n        with:\n          node-version: 20\n"
                + "      - run: npm ci || npm install\n"
                + "      - run: npm run build\n"
                + "      - name: Commit build output\n"
                + "        run: |\n"
                + "          git config user.name \"xanadu-bot\"\n"
                + "          git config user.email \"bot@xanadu.xnd\"\n"
                + "          git add -f dist build out .output/public 2>/dev/null || true\n"
                + "          git diff --cached --quiet || (git commit -m \"chore(xanadu): build static output [skip ci]\" && git push)\n";

        String url = GITHUB_API + "/repos/" + cleanRepo + "/contents/" + encodePath(wfPath);
        String existingSha = "";
        HttpRes gr = request("GET", url + "?ref=" + URLEncoder.encode(cleanBranch, "UTF-8"), tok, null);
        if (gr.code == 200) existingSha = new JSONObject(gr.body).optString("sha", "");

        JSONObject payload = new JSONObject()
                .put("message", "chore(xanadu): enable auto-build workflow [skip ci]")
                .put("content", Base64.encodeToString(wfYaml.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP))
                .put("branch", cleanBranch);
        if (!existingSha.isEmpty()) payload.put("sha", existingSha);

        HttpRes pr = request("PUT", url, tok, payload.toString());
        if (pr.code < 200 || pr.code >= 300) {
            throw new IllegalArgumentException("Failed to install workflow (" + pr.code + "). Ensure repo write permission.");
        }
        try {
            request("POST", GITHUB_API + "/repos/" + cleanRepo + "/actions/workflows/xanadu-build.yml/dispatches", tok, new JSONObject().put("ref", cleanBranch).toString());
        } catch (Exception ignored) {}

        return new JSONObject()
                .put("ok", true)
                .put("repo", cleanRepo)
                .put("branch", cleanBranch)
                .put("workflow", wfPath);
    }

    private static String encodePath(String p) throws Exception {
        String[] parts = p.split("/");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) sb.append("/");
            sb.append(URLEncoder.encode(parts[i], "UTF-8").replace("+", "%20"));
        }
        return sb.toString();
    }

    private static String guessMime(String ext) {
        switch (ext) {
            case ".png": return "image/png";
            case ".jpg":
            case ".jpeg": return "image/jpeg";
            case ".gif": return "image/gif";
            case ".webp": return "image/webp";
            case ".ico": return "image/x-icon";
            case ".woff2": return "font/woff2";
            case ".woff": return "font/woff";
            case ".ttf": return "font/ttf";
            default: return "application/octet-stream";
        }
    }

    private static class HttpRes {
        int code;
        String body;
    }

    private static HttpRes request(String method, String urlStr, String token, String jsonBody) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(15000);
        conn.setRequestProperty("Authorization", "Bearer " + token);
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("X-GitHub-Api-Version", "2022-11-28");
        conn.setRequestProperty("User-Agent", "Xanadu-Browser/0.1");
        if (jsonBody != null) {
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
            }
        }
        HttpRes out = new HttpRes();
        out.code = conn.getResponseCode();
        InputStream is = out.code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        if (is != null) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] tmp = new byte[4096];
            int n;
            while ((n = is.read(tmp)) != -1) buf.write(tmp, 0, n);
            out.body = new String(buf.toByteArray(), StandardCharsets.UTF_8);
            is.close();
        } else {
            out.body = "{}";
        }
        conn.disconnect();
        return out;
    }
}
