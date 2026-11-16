package com.xanadu.browser;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Pure-Java RFC 8032 Ed25519 (Works on Android API 26+ without external deps).
 */
public final class Ed25519 {
    private static final BigInteger Q = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger L = BigInteger.ONE.shiftLeft(252)
            .add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger D = new BigInteger("-121665")
            .multiply(new BigInteger("121666").modInverse(Q)).mod(Q);
    private static final BigInteger I = BigInteger.valueOf(2)
            .modPow(Q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), Q);

    private static final BigInteger BY = BigInteger.valueOf(4)
            .multiply(BigInteger.valueOf(5).modInverse(Q)).mod(Q);
    private static final BigInteger BX = recoverX(BY);
    private static final BigInteger[] B = {BX, BY};

    private Ed25519() {}

    public static byte[] generatePrivateKey() {
        byte[] sk = new byte[32];
        new SecureRandom().nextBytes(sk);
        return sk;
    }

    public static byte[] publicKey(byte[] sk) {
        byte[] h = sha512(sk);
        byte[] aBytes = Arrays.copyOfRange(h, 0, 32);
        aBytes[0] &= (byte) 248;
        aBytes[31] &= (byte) 127;
        aBytes[31] |= (byte) 64;
        BigInteger a = fromLittleEndian(aBytes);
        BigInteger[] A = scalarMult(B, a);
        return encodePoint(A);
    }

    public static byte[] sign(byte[] msg, byte[] sk, byte[] pk) {
        byte[] h = sha512(sk);
        byte[] aBytes = Arrays.copyOfRange(h, 0, 32);
        aBytes[0] &= (byte) 248;
        aBytes[31] &= (byte) 127;
        aBytes[31] |= (byte) 64;
        BigInteger a = fromLittleEndian(aBytes);

        byte[] rInput = new byte[32 + msg.length];
        System.arraycopy(h, 32, rInput, 0, 32);
        System.arraycopy(msg, 0, rInput, 32, msg.length);
        BigInteger r = fromLittleEndian(sha512(rInput)).mod(L);

        BigInteger[] R = scalarMult(B, r);
        byte[] rEnc = encodePoint(R);

        byte[] kInput = new byte[32 + 32 + msg.length];
        System.arraycopy(rEnc, 0, kInput, 0, 32);
        System.arraycopy(pk, 0, kInput, 32, 32);
        System.arraycopy(msg, 0, kInput, 64, msg.length);
        BigInteger k = fromLittleEndian(sha512(kInput)).mod(L);

        BigInteger S = r.add(k.multiply(a)).mod(L);
        byte[] sEnc = toLittleEndian32(S);

        byte[] sig = new byte[64];
        System.arraycopy(rEnc, 0, sig, 0, 32);
        System.arraycopy(sEnc, 0, sig, 32, 32);
        return sig;
    }

    public static boolean verify(byte[] msg, byte[] sig, byte[] pk) {
        if (sig == null || sig.length != 64 || pk == null || pk.length != 32) return false;
        try {
            BigInteger[] A = decodePoint(pk);
            byte[] rEnc = Arrays.copyOfRange(sig, 0, 32);
            BigInteger[] R = decodePoint(rEnc);
            BigInteger S = fromLittleEndian(Arrays.copyOfRange(sig, 32, 64));
            if (S.compareTo(L) >= 0) return false;

            byte[] kInput = new byte[32 + 32 + msg.length];
            System.arraycopy(rEnc, 0, kInput, 0, 32);
            System.arraycopy(pk, 0, kInput, 32, 32);
            System.arraycopy(msg, 0, kInput, 64, msg.length);
            BigInteger k = fromLittleEndian(sha512(kInput)).mod(L);

            BigInteger[] lhs = scalarMult(B, S);
            BigInteger[] rhs = edAdd(R, scalarMult(A, k));
            return lhs[0].equals(rhs[0]) && lhs[1].equals(rhs[1]);
        } catch (Exception e) {
            return false;
        }
    }

    public static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v & 0xff));
        return sb.toString();
    }

    public static byte[] fromHex(String s) {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        }
        return out;
    }

    private static byte[] sha512(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static BigInteger recoverX(BigInteger y) {
        BigInteger y2 = y.multiply(y).mod(Q);
        BigInteger xx = y2.subtract(BigInteger.ONE)
                .multiply(D.multiply(y2).add(BigInteger.ONE).modInverse(Q)).mod(Q);
        BigInteger x = xx.modPow(Q.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), Q);
        if (!x.multiply(x).subtract(xx).mod(Q).equals(BigInteger.ZERO)) {
            x = x.multiply(I).mod(Q);
        }
        if (x.testBit(0)) x = Q.subtract(x);
        return x;
    }

    private static BigInteger[] edAdd(BigInteger[] P, BigInteger[] R) {
        BigInteger x1 = P[0], y1 = P[1], x2 = R[0], y2 = R[1];
        BigInteger t = D.multiply(x1).mod(Q).multiply(x2).mod(Q).multiply(y1).mod(Q).multiply(y2).mod(Q);
        BigInteger x3 = x1.multiply(y2).add(x2.multiply(y1))
                .multiply(BigInteger.ONE.add(t).modInverse(Q)).mod(Q);
        BigInteger y3 = y1.multiply(y2).add(x1.multiply(x2))
                .multiply(BigInteger.ONE.subtract(t).modInverse(Q)).mod(Q);
        return new BigInteger[]{x3, y3};
    }

    private static BigInteger[] scalarMult(BigInteger[] P, BigInteger e) {
        BigInteger[] acc = {BigInteger.ZERO, BigInteger.ONE};
        BigInteger[] cur = {P[0], P[1]};
        for (int i = 0; i < 256; i++) {
            if (e.testBit(i)) acc = edAdd(acc, cur);
            cur = edAdd(cur, cur);
        }
        return acc;
    }

    private static byte[] encodePoint(BigInteger[] P) {
        byte[] out = toLittleEndian32(P[1]);
        if (P[0].testBit(0)) out[31] |= (byte) 0x80;
        return out;
    }

    private static BigInteger[] decodePoint(byte[] enc) {
        byte[] yBytes = Arrays.copyOf(enc, 32);
        boolean sign = (yBytes[31] & 0x80) != 0;
        yBytes[31] &= 0x7f;
        BigInteger y = fromLittleEndian(yBytes);
        if (y.compareTo(Q) >= 0) throw new IllegalArgumentException("Invalid point");
        BigInteger y2 = y.multiply(y).mod(Q);
        BigInteger xx = y2.subtract(BigInteger.ONE)
                .multiply(D.multiply(y2).add(BigInteger.ONE).modInverse(Q)).mod(Q);
        BigInteger x = xx.modPow(Q.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), Q);
        if (!x.multiply(x).subtract(xx).mod(Q).equals(BigInteger.ZERO)) {
            x = x.multiply(I).mod(Q);
        }
        if (!x.multiply(x).subtract(xx).mod(Q).equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Not on curve");
        }
        if (x.testBit(0) != sign) x = Q.subtract(x);
        return new BigInteger[]{x, y};
    }

    private static BigInteger fromLittleEndian(byte[] b) {
        byte[] be = new byte[b.length + 1];
        for (int i = 0; i < b.length; i++) be[b.length - i] = b[i];
        return new BigInteger(1, be);
    }

    private static byte[] toLittleEndian32(BigInteger v) {
        byte[] be = v.toByteArray();
        byte[] out = new byte[32];
        for (int i = 0; i < 32 && i < be.length; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }
}
