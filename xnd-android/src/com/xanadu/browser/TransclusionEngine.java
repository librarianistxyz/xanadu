package com.xanadu.browser;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Independent Two-Way Xanadu Transclusion & Cryptographic Provenance Engine.
 * Kept strictly decoupled from search, scrapers, and LAN sync.
 */
public final class TransclusionEngine {
    public static final Pattern TRANSCLUSION_RE = Pattern.compile(
            "\\{\\{\\s*xnd://([a-z0-9.-]+\\.xnd)(?:@v(\\d+))?(?:#([0-9a-fA-F]{6,64}))?(?::(\\d+)-(\\d+))?\\s*\\}\\}",
            Pattern.CASE_INSENSITIVE
    );

    private TransclusionEngine() {}

    public static String sha256Hex(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest((text != null ? text : "").getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(dig.length * 2);
            for (byte b : dig) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    public static JSONArray buildSegments(String content, Map<String, JSONObject> docs) {
        JSONArray segments = new JSONArray();
        String src = content != null ? content : "";
        Matcher m = TRANSCLUSION_RE.matcher(src);
        int pos = 0;
        int idx = 0;
        while (m.find()) {
            if (m.start() > pos) {
                try {
                    segments.put(new JSONObject()
                            .put("type", "text")
                            .put("text", src.substring(pos, m.start()))
                            .put("start", pos)
                            .put("end", m.start()));
                } catch (Exception ignored) {}
            }
            String tDomain = m.group(1).toLowerCase(Locale.US);
            String expectedHash = m.group(3) != null ? m.group(3).toLowerCase(Locale.US) : "";
            JSONObject targetDoc = docs != null ? docs.get(tDomain) : null;
            String tText = targetDoc != null ? targetDoc.optString("raw_content", "") : null;
            if (targetDoc != null && tText != null) {
                int reqStart = m.group(4) != null ? Integer.parseInt(m.group(4)) : 0;
                int reqEnd = m.group(5) != null ? Integer.parseInt(m.group(5)) : tText.length();
                int s = Math.max(0, Math.min(reqStart, tText.length()));
                int e = Math.max(s, Math.min(reqEnd, tText.length()));
                String actualHash = targetDoc.optString("sha256", "").toLowerCase(Locale.US);
                boolean hashVerified = expectedHash.isEmpty() || actualHash.startsWith(expectedHash);
                String quoted = tText.substring(s, e);
                int tVer = targetDoc.optInt("version_num", targetDoc.optInt("version", 1));
                try {
                    segments.put(new JSONObject()
                            .put("type", "transclusion")
                            .put("bridge_id", "bridge-" + idx)
                            .put("target_domain", tDomain)
                            .put("target_version", tVer)
                            .put("target_hash", actualHash)
                            .put("expected_hash", expectedHash)
                            .put("hash_verified", hashVerified)
                            .put("span_sha256", sha256Hex(quoted))
                            .put("target_start", s)
                            .put("target_end", e)
                            .put("quoted_text", quoted)
                            .put("source_start", m.start())
                            .put("source_end", m.end()));
                } catch (Exception ignored) {}
            } else {
                try {
                    segments.put(new JSONObject()
                            .put("type", "broken_transclusion")
                            .put("raw", m.group(0))
                            .put("target_domain", tDomain));
                } catch (Exception ignored) {}
            }
            pos = m.end();
            idx++;
        }
        if (pos < src.length()) {
            try {
                segments.put(new JSONObject()
                        .put("type", "text")
                        .put("text", src.substring(pos))
                        .put("start", pos)
                        .put("end", src.length()));
            } catch (Exception ignored) {}
        }
        return segments;
    }

    public static JSONArray computeBacklinks(String targetDomain, Map<String, JSONObject> docs) {
        JSONArray backlinks = new JSONArray();
        if (targetDomain == null || docs == null) return backlinks;
        String td = targetDomain.toLowerCase(Locale.US);
        for (JSONObject d : docs.values()) {
            String srcDom = d.optString("domain", "");
            int srcVer = d.optInt("version_num", d.optInt("version", 1));
            String raw = d.optString("raw_content", "");
            Matcher m = TRANSCLUSION_RE.matcher(raw);
            while (m.find()) {
                if (td.equals(m.group(1).toLowerCase(Locale.US))) {
                    try {
                        backlinks.put(new JSONObject()
                                .put("source_domain", srcDom)
                                .put("source_version", srcVer)
                                .put("target_domain", td)
                                .put("target_version", m.group(2) != null ? Integer.parseInt(m.group(2)) : 1)
                                .put("target_hash", m.group(3) != null ? m.group(3).toLowerCase(Locale.US) : "")
                                .put("source_start", m.start())
                                .put("source_end", m.end())
                                .put("target_start", m.group(4) != null ? Integer.parseInt(m.group(4)) : 0)
                                .put("target_end", m.group(5) != null ? Integer.parseInt(m.group(5)) : 0)
                                .put("link_type", "transclusion"));
                    } catch (Exception ignored) {}
                }
            }
        }
        return backlinks;
    }
}
