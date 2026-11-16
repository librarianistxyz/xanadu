package com.xanadu.browser;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Pure-Java BIP-340 Schnorr signing for Nostr NIP-01 events (Android API 26+).
 */
public final class Bip340 {
    private static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    private static final BigInteger N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger GX = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    private static final BigInteger GY = new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    private static final BigInteger[] G = {GX, GY};

    private Bip340() {}

    public static byte[] pubkeyX(BigInteger priv) {
        BigInteger[] pt = pointMul(G, priv);
        return toBytes32(pt[0]);
    }

    public static byte[] sign(BigInteger priv, byte[] msg32) {
        BigInteger[] Ppt = pointMul(G, priv);
        BigInteger d = Ppt[1].testBit(0) ? N.subtract(priv) : priv;
        byte[] aux = new byte[32];
        new SecureRandom().nextBytes(aux);
        byte[] t = xor32(toBytes32(d), taggedHash("BIP0340/aux", aux));
        byte[] pBytes = toBytes32(Ppt[0]);
        byte[] kInput = concat(t, pBytes, msg32);
        BigInteger k0 = new BigInteger(1, taggedHash("BIP0340/nonce", kInput)).mod(N);
        if (k0.equals(BigInteger.ZERO)) throw new IllegalStateException("k0 == 0");
        BigInteger[] R = pointMul(G, k0);
        BigInteger k = R[1].testBit(0) ? N.subtract(k0) : k0;
        byte[] rBytes = toBytes32(R[0]);
        BigInteger e = new BigInteger(1, taggedHash("BIP0340/challenge", concat(rBytes, pBytes, msg32))).mod(N);
        BigInteger s = k.add(e.multiply(d)).mod(N);
        return concat(rBytes, toBytes32(s));
    }

    public static BigInteger privFromSeed(String seed) {
        byte[] h = sha256(seed.getBytes(StandardCharsets.UTF_8));
        return new BigInteger(1, h).mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] taggedHash(String tag, byte[] msg) {
        byte[] th = sha256(tag.getBytes(StandardCharsets.UTF_8));
        return sha256(concat(th, th, msg));
    }

    private static BigInteger[] pointAdd(BigInteger[] p1, BigInteger[] p2) {
        if (p1 == null) return p2;
        if (p2 == null) return p1;
        BigInteger x1 = p1[0], y1 = p1[1], x2 = p2[0], y2 = p2[1];
        if (x1.equals(x2) && !y1.equals(y2)) return null;
        BigInteger lam;
        if (x1.equals(x2)) {
            lam = BigInteger.valueOf(3).multiply(x1).mod(P).multiply(x1).mod(P)
                    .multiply(BigInteger.valueOf(2).multiply(y1).modInverse(P)).mod(P);
        } else {
            lam = y2.subtract(y1).mod(P).multiply(x2.subtract(x1).mod(P).modInverse(P)).mod(P);
        }
        BigInteger x3 = lam.multiply(lam).subtract(x1).subtract(x2).mod(P);
        BigInteger y3 = lam.multiply(x1.subtract(x3)).subtract(y1).mod(P);
        return new BigInteger[]{x3, y3};
    }

    private static BigInteger[] pointMul(BigInteger[] pt, BigInteger n) {
        BigInteger[] r = null;
        BigInteger[] cur = pt;
        for (int i = 0; i < 256; i++) {
            if (n.testBit(i)) r = pointAdd(r, cur);
            cur = pointAdd(cur, cur);
        }
        return r;
    }

    private static byte[] toBytes32(BigInteger v) {
        byte[] src = v.toByteArray();
        byte[] out = new byte[32];
        if (src.length <= 32) {
            System.arraycopy(src, 0, out, 32 - src.length, src.length);
        } else {
            System.arraycopy(src, src.length - 32, out, 0, 32);
        }
        return out;
    }

    private static byte[] xor32(byte[] a, byte[] b) {
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
