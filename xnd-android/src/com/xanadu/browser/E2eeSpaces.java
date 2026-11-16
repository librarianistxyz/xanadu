package com.xanadu.browser;

import org.json.JSONObject;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Independent End-to-End Encrypted Private .xnd Spaces (Ed25519 -> X25519 + AES-256-GCM).
 * Compatible byte-for-byte with Python e2ee_spaces.py.
 */
public final class E2eeSpaces {
    public static final String E2EE_PREFIX = "XND-E2EE-v1:";
    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger A24 = BigInteger.valueOf(121665);
    private static final byte[] X25519_BASE = new byte[]{
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    private E2eeSpaces() {}

    public static boolean isEncryptedBlob(String content) {
        return content != null && content.startsWith(E2EE_PREFIX);
    }

    public static List<String> parseAllowedPubkeys(String raw) {
        List<String> out = new ArrayList<>();
        if (raw == null || raw.trim().isEmpty()) return out;
        for (String part : raw.split("[\\s,;]+")) {
            String h = part.trim().toLowerCase(Locale.US);
            if (h.matches("^[0-9a-f]{64}$") && !out.contains(h)) out.add(h);
        }
        return out;
    }

    public static String encryptForPeers(String plaintext, String authorPrivHex, List<String> allowedPubkeys) throws Exception {
        byte[] seed = hexToBytes(authorPrivHex.trim());
        String authorPubHex = Ed25519.toHex(Ed25519.publicKey(seed)).toLowerCase(Locale.US);
        Set<String> recips = new LinkedHashSet<>();
        recips.add(authorPubHex);
        if (allowedPubkeys != null) {
            for (String p : allowedPubkeys) {
                String h = p != null ? p.trim().toLowerCase(Locale.US) : "";
                if (h.matches("^[0-9a-f]{64}$")) recips.add(h);
            }
        }

        SecureRandom rng = new SecureRandom();
        byte[] docKey = new byte[32];
        byte[] docNonce = new byte[12];
        rng.nextBytes(docKey);
        rng.nextBytes(docNonce);
        byte[] ct = aesGcmEncrypt(docKey, docNonce, plaintext.getBytes(StandardCharsets.UTF_8));

        JSONObject wrapped = new JSONObject();
        for (String pubHex : recips) {
            byte[] ephSk = new byte[32];
            rng.nextBytes(ephSk);
            clampX25519(ephSk);
            byte[] ephPub = x25519(ephSk, X25519_BASE);
            byte[] recipXPub = edPubToX25519(hexToBytes(pubHex));
            byte[] shared = x25519(ephSk, recipXPub);
            byte[] wrapKey = MessageDigest.getInstance("SHA-256").digest(shared);
            byte[] wNonce = new byte[12];
            rng.nextBytes(wNonce);
            byte[] wk = aesGcmEncrypt(wrapKey, wNonce, docKey);
            wrapped.put(pubHex, new JSONObject()
                    .put("eph", bytesToHex(ephPub))
                    .put("nonce", Base64.getEncoder().encodeToString(wNonce))
                    .put("wk", Base64.getEncoder().encodeToString(wk)));
        }

        JSONObject env = new JSONObject()
                .put("v", 1)
                .put("nonce", Base64.getEncoder().encodeToString(docNonce))
                .put("ct", Base64.getEncoder().encodeToString(ct))
                .put("recipients", wrapped);
        return E2EE_PREFIX + env.toString();
    }

    public static DecryptResult decryptWithPrivkeys(String envelopeStr, List<String> candidatePrivkeys) {
        if (!isEncryptedBlob(envelopeStr)) {
            return new DecryptResult(true, envelopeStr != null ? envelopeStr : "", new ArrayList<>());
        }
        List<String> recipList = new ArrayList<>();
        try {
            JSONObject env = new JSONObject(envelopeStr.substring(E2EE_PREFIX.length()));
            JSONObject recipients = env.optJSONObject("recipients");
            if (recipients == null) return new DecryptResult(false, "", recipList);
            Iterator<String> keys = recipients.keys();
            while (keys.hasNext()) recipList.add(keys.next());

            byte[] docNonce = Base64.getDecoder().decode(env.getString("nonce"));
            byte[] ct = Base64.getDecoder().decode(env.getString("ct"));

            for (String privHex : candidatePrivkeys) {
                String ph = privHex != null ? privHex.trim() : "";
                if (!ph.matches("^[0-9a-fA-F]{64}$")) continue;
                try {
                    byte[] seed = hexToBytes(ph);
                    String pubHex = Ed25519.toHex(Ed25519.publicKey(seed)).toLowerCase(Locale.US);
                    JSONObject entry = recipients.optJSONObject(pubHex);
                    if (entry == null) continue;
                    byte[] xSk = edPrivToX25519(seed);
                    byte[] ephPub = hexToBytes(entry.getString("eph"));
                    byte[] shared = x25519(xSk, ephPub);
                    byte[] wrapKey = MessageDigest.getInstance("SHA-256").digest(shared);
                    byte[] docKey = aesGcmDecrypt(
                            wrapKey,
                            Base64.getDecoder().decode(entry.getString("nonce")),
                            Base64.getDecoder().decode(entry.getString("wk")));
                    byte[] plain = aesGcmDecrypt(docKey, docNonce, ct);
                    return new DecryptResult(true, new String(plain, StandardCharsets.UTF_8), recipList);
                } catch (Exception ignored) {}
            }
        } catch (Exception ignored) {}
        return new DecryptResult(false, "", recipList);
    }

    public static final class DecryptResult {
        public final boolean decrypted;
        public final String plaintext;
        public final List<String> recipients;
        public DecryptResult(boolean decrypted, String plaintext, List<String> recipients) {
            this.decrypted = decrypted;
            this.plaintext = plaintext;
            this.recipients = recipients;
        }
    }

    private static byte[] aesGcmEncrypt(byte[] key, byte[] nonce, byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return c.doFinal(plain);
    }

    private static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] ct) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return c.doFinal(ct);
    }

    private static byte[] edPrivToX25519(byte[] seed) throws Exception {
        byte[] h = MessageDigest.getInstance("SHA-512").digest(seed);
        byte[] k = new byte[32];
        System.arraycopy(h, 0, k, 0, 32);
        clampX25519(k);
        return k;
    }

    private static void clampX25519(byte[] k) {
        k[0] &= (byte) 248;
        k[31] &= (byte) 127;
        k[31] |= (byte) 64;
    }

    private static byte[] edPubToX25519(byte[] edPub) {
        byte[] copy = edPub.clone();
        copy[31] &= (byte) 127;
        BigInteger y = fromLittleEndian(copy);
        BigInteger onePlusY = BigInteger.ONE.add(y).mod(P);
        BigInteger oneMinusY = BigInteger.ONE.subtract(y).mod(P);
        BigInteger u = onePlusY.multiply(oneMinusY.modInverse(P)).mod(P);
        return toLittleEndian32(u);
    }

    private static byte[] x25519(byte[] scalarBytes, byte[] uBytes) {
        byte[] k = scalarBytes.clone();
        clampX25519(k);
        byte[] uCopy = uBytes.clone();
        uCopy[31] &= (byte) 127;
        BigInteger x1 = fromLittleEndian(uCopy).mod(P);
        BigInteger x2 = BigInteger.ONE, z2 = BigInteger.ZERO;
        BigInteger x3 = x1, z3 = BigInteger.ONE;
        int swap = 0;
        for (int t = 254; t >= 0; t--) {
            int kt = (k[t / 8] >> (t & 7)) & 1;
            swap ^= kt;
            if (swap != 0) {
                BigInteger tmp = x2; x2 = x3; x3 = tmp;
                tmp = z2; z2 = z3; z3 = tmp;
            }
            swap = kt;
            BigInteger A = x2.add(z2).mod(P);
            BigInteger AA = A.multiply(A).mod(P);
            BigInteger B = x2.subtract(z2).mod(P);
            BigInteger BB = B.multiply(B).mod(P);
            BigInteger E = AA.subtract(BB).mod(P);
            BigInteger C = x3.add(z3).mod(P);
            BigInteger D = x3.subtract(z3).mod(P);
            BigInteger DA = D.multiply(A).mod(P);
            BigInteger CB = C.multiply(B).mod(P);
            BigInteger x3n = DA.add(CB).mod(P);
            x3 = x3n.multiply(x3n).mod(P);
            BigInteger z3n = DA.subtract(CB).mod(P);
            z3 = x1.multiply(z3n.multiply(z3n).mod(P)).mod(P);
            x2 = AA.multiply(BB).mod(P);
            z2 = E.multiply(AA.add(A24.multiply(E)).mod(P)).mod(P);
        }
        if (swap != 0) {
            x2 = x3;
            z2 = z3;
        }
        BigInteger res = x2.multiply(z2.modInverse(P)).mod(P);
        return toLittleEndian32(res);
    }

    private static BigInteger fromLittleEndian(byte[] b) {
        byte[] be = new byte[b.length + 1];
        for (int i = 0; i < b.length; i++) be[b.length - i] = b[i];
        return new BigInteger(be);
    }

    private static byte[] toLittleEndian32(BigInteger v) {
        byte[] be = v.toByteArray();
        byte[] out = new byte[32];
        for (int i = 0; i < 32 && i < be.length; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
