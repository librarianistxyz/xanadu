package com.xanadu.browser;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Real JVM conformance test runner for xnd-android cryptography & transclusion against spec/test_vectors.json. */
public final class ConformanceTest {
    private static void check(boolean cond, String msg) {
        if (!cond) {
            throw new AssertionError("Conformance failure: " + msg);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            throw new IllegalArgumentException("Usage: ConformanceTest <path/to/test_vectors.json>");
        }
        String raw = Files.readString(Path.of(args[0]), StandardCharsets.UTF_8);
        JSONObject tv = new JSONObject(raw);

        String authorPrivHex = tv.getString("author_privkey_hex");
        String authorPubHex = tv.getString("author_pubkey_hex");
        String peerPrivHex = tv.getString("peer_privkey_hex");
        String peerPubHex = tv.getString("peer_pubkey_hex");
        String domain = tv.getString("domain");

        byte[] authorSk = Ed25519.fromHex(authorPrivHex);
        byte[] authorPk = Ed25519.publicKey(authorSk);
        check(Ed25519.toHex(authorPk).equals(authorPubHex), "Ed25519 publicKey derivation mismatch");

        // v1 hash + signature verification + deterministic signing
        JSONObject v1 = tv.getJSONObject("v1");
        String v1Content = v1.getString("content");
        String v1Sha = v1.getString("sha256");
        check(TransclusionEngine.sha256Hex(v1Content).equals(v1Sha), "v1 sha256 mismatch");
        byte[] v1Msg = v1.getString("signing_string").getBytes(StandardCharsets.UTF_8);
        byte[] v1Sig = Ed25519.fromHex(v1.getString("signature_hex"));
        check(Ed25519.verify(v1Msg, v1Sig, authorPk), "v1 Ed25519.verify failed");
        check(Ed25519.toHex(Ed25519.sign(v1Msg, authorSk, authorPk)).equals(v1.getString("signature_hex")),
                "v1 Ed25519.sign deterministic mismatch");

        // v2 hash + signature verification + transclusion slice
        JSONObject v2 = tv.getJSONObject("v2");
        String v2Content = v2.getString("content");
        String v2Sha = v2.getString("sha256");
        check(TransclusionEngine.sha256Hex(v2Content).equals(v2Sha), "v2 sha256 mismatch");
        byte[] v2Msg = v2.getString("signing_string").getBytes(StandardCharsets.UTF_8);
        byte[] v2Sig = Ed25519.fromHex(v2.getString("signature_hex"));
        check(Ed25519.verify(v2Msg, v2Sig, authorPk), "v2 Ed25519.verify failed");

        JSONObject tr = v2.getJSONObject("transclusion");
        Map<String, JSONObject> docs = new HashMap<>();
        docs.put(domain, new JSONObject()
                .put("raw_content", v1Content)
                .put("sha256", v1Sha)
                .put("version_num", 1));
        JSONArray segs = TransclusionEngine.buildSegments(v2Content, docs);
        boolean foundTr = false;
        for (int i = 0; i < segs.length(); i++) {
            JSONObject seg = segs.getJSONObject(i);
            if ("transclusion".equals(seg.optString("type"))) {
                foundTr = true;
                check(tr.getString("target_domain").equals(seg.getString("target_domain")), "transclusion domain");
                check(tr.getInt("start") == seg.getInt("target_start"), "transclusion start");
                check(tr.getInt("end") == seg.getInt("target_end"), "transclusion end");
                check(tr.getString("expected_slice").equals(seg.getString("quoted_text")), "transclusion slice");
            }
        }
        check(foundTr, "transclusion segment not found");

        // E2EE decrypt vector (both author and peer) + round-trip encrypt/decrypt
        JSONObject e2ee = tv.getJSONObject("e2ee");
        String expectedPlain = e2ee.getString("plaintext");
        String envelope = e2ee.getString("envelope");

        for (String priv : Arrays.asList(authorPrivHex, peerPrivHex)) {
            E2eeSpaces.DecryptResult res = E2eeSpaces.decryptWithPrivkeys(envelope, List.of(priv));
            check(res.decrypted && expectedPlain.equals(res.plaintext), "E2eeSpaces.decryptWithPrivkeys failed");
            check(res.recipients.contains(authorPubHex) && res.recipients.contains(peerPubHex),
                    "E2eeSpaces recipients missing");
        }

        String rtEnv = E2eeSpaces.encryptForPeers("Roundtrip Java->Java E2EE", authorPrivHex, List.of(peerPubHex));
        E2eeSpaces.DecryptResult rtPeer = E2eeSpaces.decryptWithPrivkeys(rtEnv, List.of(peerPrivHex));
        check(rtPeer.decrypted && "Roundtrip Java->Java E2EE".equals(rtPeer.plaintext), "E2EE round-trip failed");

        System.out.println("JAVA_CONFORMANCE_PASSED");
    }
}
