package com.xanadu.browser;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class NatTunnel {
    public interface RpcHandler {
        String handle(String method, String path, String body);
    }

    private static final int STUN_MAGIC_COOKIE = 0x2112A442;
    private static final int CHUNK_RAW_SIZE = 750;
    private static final String[][] STUN_SERVERS = {
            {"stun.l.google.com", "19302"},
            {"stun1.l.google.com", "19302"},
            {"stun.cloudflare.com", "3478"}
    };

    private final String nodeId;
    private final RpcHandler rpcHandler;
    private final DatagramSocket sock;
    public final int localPort;
    public volatile String publicIp = "";
    public volatile int publicPort = 0;
    public volatile boolean stunOk = false;
    private volatile boolean running = false;

    private final ExecutorService pool = Executors.newCachedThreadPool();
    private final Map<String, CountDownLatch> stunWaiters = new ConcurrentHashMap<>();
    private final Map<String, String[]> stunResults = new ConcurrentHashMap<>();
    private final Map<String, Map<Integer, String>> incomingReqs = new ConcurrentHashMap<>();
    private final Map<String, Map<Integer, String>> incomingRes = new ConcurrentHashMap<>();
    private final Map<String, CountDownLatch> resWaiters = new ConcurrentHashMap<>();
    private final Map<String, String> resPayloads = new ConcurrentHashMap<>();
    private final Map<String, String> punchedPeers = new ConcurrentHashMap<>();

    public NatTunnel(String nodeId, RpcHandler rpcHandler, int udpPort) throws Exception {
        this.nodeId = nodeId;
        this.rpcHandler = rpcHandler;
        DatagramSocket s;
        try {
            s = new DatagramSocket(udpPort);
        } catch (Exception e) {
            s = new DatagramSocket(0);
        }
        s.setSoTimeout(1000);
        this.sock = s;
        this.localPort = s.getLocalPort();
    }

    public void start() {
        if (running) return;
        running = true;
        new Thread(this::recvLoop, "xnd-nat-recv").start();
        new Thread(this::keepaliveLoop, "xnd-nat-stun").start();
    }

    public void stop() {
        running = false;
        try { sock.close(); } catch (Exception ignored) {}
        pool.shutdownNow();
    }

    private void recvLoop() {
        byte[] buf = new byte[4096];
        while (running) {
            try {
                DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                sock.receive(pkt);
                int len = pkt.getLength();
                byte[] data = Arrays.copyOf(pkt.getData(), len);
                if (len >= 20 && data[0] == 0x01 && data[1] == 0x01) {
                    int cookie = ByteBuffer.wrap(data, 4, 4).getInt();
                    if (cookie == STUN_MAGIC_COOKIE) {
                        String txHex = Ed25519.toHex(Arrays.copyOfRange(data, 8, 20));
                        CountDownLatch latch = stunWaiters.get(txHex);
                        if (latch != null) {
                            String[] parsed = parseStunResponse(data);
                            if (parsed != null) {
                                stunResults.put(txHex, parsed);
                                latch.countDown();
                            }
                        }
                        continue;
                    }
                }
                String text = new String(data, StandardCharsets.UTF_8);
                if (text.startsWith("XND_PUNCH|")) {
                    String pid = text.substring("XND_PUNCH|".length()).trim();
                    punchedPeers.put(pid, pkt.getAddress().getHostAddress() + ":" + pkt.getPort());
                    byte[] ack = ("XND_PUNCH_ACK|" + nodeId).getBytes(StandardCharsets.UTF_8);
                    sock.send(new DatagramPacket(ack, ack.length, pkt.getAddress(), pkt.getPort()));
                } else if (text.startsWith("XND_PUNCH_ACK|")) {
                    String pid = text.substring("XND_PUNCH_ACK|".length()).trim();
                    punchedPeers.put(pid, pkt.getAddress().getHostAddress() + ":" + pkt.getPort());
                } else if (text.startsWith("XND_REQ|") || text.startsWith("XND_RES|")) {
                    handleChunkFrame(text, pkt.getAddress(), pkt.getPort());
                }
            } catch (SocketTimeoutException ignored) {
            } catch (Exception e) {
                if (!running) break;
            }
        }
    }

    private void handleChunkFrame(String text, InetAddress addr, int port) {
        String[] parts = text.split("\\|", 4);
        if (parts.length != 4) return;
        String kind = parts[0];
        String msgId = parts[1];
        String[] seq = parts[2].split("/", 2);
        if (seq.length != 2) return;
        int idx, total;
        try {
            idx = Integer.parseInt(seq[0]);
            total = Integer.parseInt(seq[1]);
        } catch (NumberFormatException e) {
            return;
        }
        if (total <= 0 || total > 512 || idx < 0 || idx >= total) return;

        Map<String, Map<Integer, String>> store = "XND_REQ".equals(kind) ? incomingReqs : incomingRes;
        String assembled = null;
        synchronized (store) {
            Map<Integer, String> entry = store.get(msgId);
            if (entry == null) {
                entry = new HashMap<>();
                store.put(msgId, entry);
            }
            entry.put(idx, parts[3]);
            if (entry.size() == total) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < total; i++) {
                    String p = entry.get(i);
                    if (p == null) return;
                    sb.append(p);
                }
                store.remove(msgId);
                try {
                    assembled = new String(Base64.getDecoder().decode(sb.toString()), StandardCharsets.UTF_8);
                } catch (Exception ignored) {
                    return;
                }
            }
        }
        if (assembled == null) return;
        final String payload = assembled;
        if ("XND_REQ".equals(kind)) {
            pool.submit(() -> {
                String resp;
                try {
                    JSONObject req = new JSONObject(payload);
                    resp = rpcHandler.handle(
                            req.optString("method", "GET"),
                            req.optString("path", "/api/sync/manifest"),
                            req.optString("body", ""));
                } catch (Exception e) {
                    resp = "{\"ok\":false}";
                }
                sendChunked("XND_RES", msgId, resp, addr, port);
            });
        } else {
            resPayloads.put(msgId, payload);
            CountDownLatch l = resWaiters.get(msgId);
            if (l != null) l.countDown();
        }
    }

    private void sendChunked(String prefix, String msgId, String text, InetAddress addr, int port) {
        String b64 = Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
        List<String> chunks = new ArrayList<>();
        for (int i = 0; i < b64.length(); i += CHUNK_RAW_SIZE) {
            chunks.add(b64.substring(i, Math.min(b64.length(), i + CHUNK_RAW_SIZE)));
        }
        if (chunks.isEmpty()) chunks.add("");
        int total = chunks.size();
        for (int i = 0; i < total; i++) {
            byte[] frame = (prefix + "|" + msgId + "|" + i + "/" + total + "|" + chunks.get(i)).getBytes(StandardCharsets.UTF_8);
            try {
                sock.send(new DatagramPacket(frame, frame.length, addr, port));
            } catch (Exception ignored) {
                break;
            }
        }
    }

    private String[] parseStunResponse(byte[] data) {
        int msgLen = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
        int pos = 20;
        int end = Math.min(data.length, 20 + msgLen);
        while (pos + 4 <= end) {
            int attrType = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            int attrLen = ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF);
            int valStart = pos + 4;
            pos += 4 + ((attrLen + 3) & ~3);
            if (valStart + attrLen > end) break;
            if (attrType == 0x0020 && attrLen >= 8 && data[valStart + 1] == 0x01) {
                int xPort = (((data[valStart + 2] & 0xFF) << 8) | (data[valStart + 3] & 0xFF)) ^ (STUN_MAGIC_COOKIE >>> 16);
                int xIp = ByteBuffer.wrap(data, valStart + 4, 4).getInt() ^ STUN_MAGIC_COOKIE;
                String ip = ((xIp >>> 24) & 0xFF) + "." + ((xIp >>> 16) & 0xFF) + "." + ((xIp >>> 8) & 0xFF) + "." + (xIp & 0xFF);
                return new String[]{ip, String.valueOf(xPort)};
            }
            if (attrType == 0x0001 && attrLen >= 8 && data[valStart + 1] == 0x01) {
                int port = ((data[valStart + 2] & 0xFF) << 8) | (data[valStart + 3] & 0xFF);
                String ip = (data[valStart + 4] & 0xFF) + "." + (data[valStart + 5] & 0xFF) + "." + (data[valStart + 6] & 0xFF) + "." + (data[valStart + 7] & 0xFF);
                return new String[]{ip, String.valueOf(port)};
            }
        }
        return null;
    }

    public boolean discoverStun() {
        SecureRandom rng = new SecureRandom();
        for (String[] srv : STUN_SERVERS) {
            byte[] tx = new byte[12];
            rng.nextBytes(tx);
            String txHex = Ed25519.toHex(tx);
            byte[] req = new byte[20];
            ByteBuffer bb = ByteBuffer.wrap(req);
            bb.putShort((short) 0x0001);
            bb.putShort((short) 0);
            bb.putInt(STUN_MAGIC_COOKIE);
            bb.put(tx);
            CountDownLatch latch = new CountDownLatch(1);
            stunWaiters.put(txHex, latch);
            try {
                InetAddress addr = InetAddress.getByName(srv[0]);
                sock.send(new DatagramPacket(req, req.length, addr, Integer.parseInt(srv[1])));
                if (latch.await(2000, TimeUnit.MILLISECONDS)) {
                    String[] res = stunResults.get(txHex);
                    if (res != null) {
                        publicIp = res[0];
                        publicPort = Integer.parseInt(res[1]);
                        stunOk = true;
                        return true;
                    }
                }
            } catch (Exception ignored) {
            } finally {
                stunWaiters.remove(txHex);
                stunResults.remove(txHex);
            }
        }
        return false;
    }

    private void keepaliveLoop() {
        try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
        while (running) {
            discoverStun();
            try { Thread.sleep(25000); } catch (InterruptedException ignored) { break; }
        }
    }

    public void punch(InetAddress addr, int port) {
        byte[] pkt = ("XND_PUNCH|" + nodeId).getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < 3; i++) {
            try {
                sock.send(new DatagramPacket(pkt, pkt.length, addr, port));
                Thread.sleep(50);
            } catch (Exception ignored) {
            }
        }
    }

    public String rpc(String stunUrl, String method, String path, String body, int timeoutMs) throws Exception {
        String raw = stunUrl.substring("stun://".length());
        String hostPort = raw.contains("@") ? raw.split("@", 2)[1] : raw;
        int idx = hostPort.lastIndexOf(':');
        String ip = hostPort.substring(0, idx);
        int port = Integer.parseInt(hostPort.substring(idx + 1));
        InetAddress addr = InetAddress.getByName(ip);
        punch(addr, port);

        byte[] idBytes = new byte[6];
        new SecureRandom().nextBytes(idBytes);
        String msgId = Ed25519.toHex(idBytes);
        CountDownLatch latch = new CountDownLatch(1);
        resWaiters.put(msgId, latch);
        try {
            String reqJson = new JSONObject().put("method", method).put("path", path).put("body", body == null ? "" : body).toString();
            sendChunked("XND_REQ", msgId, reqJson, addr, port);
            if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                throw new Exception("STUN UDP RPC timeout");
            }
            return resPayloads.getOrDefault(msgId, "");
        } finally {
            resWaiters.remove(msgId);
            resPayloads.remove(msgId);
        }
    }

    public JSONObject status() {
        JSONObject out = new JSONObject();
        try {
            JSONObject pObj = new JSONObject();
            for (Map.Entry<String, String> e : punchedPeers.entrySet()) {
                pObj.put(e.getKey(), e.getValue());
            }
            out.put("ok", true)
                    .put("node_id", nodeId)
                    .put("local_port", localPort)
                    .put("public_ip", publicIp)
                    .put("public_port", publicPort)
                    .put("stun_ok", stunOk)
                    .put("punched_peers", pObj);
        } catch (Exception ignored) {
        }
        return out;
    }
}
