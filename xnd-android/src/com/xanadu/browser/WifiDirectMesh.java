package com.xanadu.browser;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.NetworkInfo;
import android.net.wifi.p2p.WifiP2pConfig;
import android.net.wifi.p2p.WifiP2pDevice;
import android.net.wifi.p2p.WifiP2pDeviceList;
import android.net.wifi.p2p.WifiP2pInfo;
import android.net.wifi.p2p.WifiP2pManager;
import android.os.Looper;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Wi-Fi Direct (P2P) transport for bypassing Wi-Fi router Client/AP Isolation.
 * Discovers nearby Xanadu devices directly and links their port 8765 into LocalNodeServer.
 */
public final class WifiDirectMesh {
    public interface PeerCallback {
        void onP2pPeerReady(String peerUrl, String label);
    }

    private final Context ctx;
    private final PeerCallback callback;
    private WifiP2pManager manager;
    private WifiP2pManager.Channel channel;
    private BroadcastReceiver receiver;
    private volatile boolean started = false;
    private volatile boolean groupFormed = false;
    private volatile boolean isGroupOwner = false;
    private volatile String groupOwnerIp = "";
    private volatile long lastAutoAttemptMs = 0L;
    private volatile long lastGroupCreateMs = 0L;
    private final List<WifiP2pDevice> discoveredPeers = Collections.synchronizedList(new ArrayList<>());

    public WifiDirectMesh(Context ctx, PeerCallback callback) {
        this.ctx = ctx.getApplicationContext();
        this.callback = callback;
    }

    public synchronized void start() {
        if (started) return;
        try {
            manager = (WifiP2pManager) ctx.getSystemService(Context.WIFI_P2P_SERVICE);
            if (manager == null) return;
            channel = manager.initialize(ctx, Looper.getMainLooper(), null);
            IntentFilter filter = new IntentFilter();
            filter.addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION);
            filter.addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION);
            filter.addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION);
            filter.addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION);
            receiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    String action = intent.getAction();
                    if (WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION.equals(action)) {
                        requestPeers();
                    } else if (WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION.equals(action)) {
                        NetworkInfo ni = intent.getParcelableExtra(WifiP2pManager.EXTRA_NETWORK_INFO);
                        if (ni != null && ni.isConnected()) {
                            requestConnectionInfo();
                        } else {
                            groupFormed = false;
                            groupOwnerIp = "";
                        }
                    }
                }
            };
            ctx.registerReceiver(receiver, filter);
            started = true;
            discoverPeers();
        } catch (Throwable ignored) {
        }
    }

    public synchronized void stop() {
        if (!started) return;
        started = false;
        try {
            if (receiver != null) ctx.unregisterReceiver(receiver);
        } catch (Throwable ignored) {
        }
    }

    public void discoverPeers() {
        if (manager == null || channel == null) return;
        try {
            manager.discoverPeers(channel, new WifiP2pManager.ActionListener() {
                @Override public void onSuccess() {}
                @Override public void onFailure(int reason) {}
            });
        } catch (Throwable ignored) {
        }
    }

    private void requestPeers() {
        if (manager == null || channel == null) return;
        try {
            manager.requestPeers(channel, (WifiP2pDeviceList peers) -> {
                synchronized (discoveredPeers) {
                    discoveredPeers.clear();
                    if (peers != null && peers.getDeviceList() != null) {
                        discoveredPeers.addAll(peers.getDeviceList());
                    }
                }
            });
        } catch (Throwable ignored) {
        }
    }

    private void requestConnectionInfo() {
        if (manager == null || channel == null) return;
        try {
            manager.requestConnectionInfo(channel, (WifiP2pInfo info) -> {
                if (info != null && info.groupFormed) {
                    groupFormed = true;
                    isGroupOwner = info.isGroupOwner;
                    if (!info.isGroupOwner && info.groupOwnerAddress != null) {
                        groupOwnerIp = info.groupOwnerAddress.getHostAddress();
                        if (callback != null && groupOwnerIp != null && !groupOwnerIp.isEmpty()) {
                            callback.onP2pPeerReady("http://" + groupOwnerIp + ":8765", "Wi-Fi Direct Gateway");
                        }
                    }
                }
            });
        } catch (Throwable ignored) {
        }
    }

    public void ensureGroupOwner() {
        if (manager == null || channel == null || groupFormed) return;
        long now = System.currentTimeMillis();
        if (now - lastGroupCreateMs < 60_000L) return;
        lastGroupCreateMs = now;
        try {
            manager.createGroup(channel, new WifiP2pManager.ActionListener() {
                @Override public void onSuccess() {}
                @Override public void onFailure(int reason) {}
            });
        } catch (Throwable ignored) {
        }
    }

    public void discoverAndAutoConnect() {
        if (manager == null || channel == null || groupFormed) return;
        long now = System.currentTimeMillis();
        if (now - lastAutoAttemptMs < 30_000L) return;
        lastAutoAttemptMs = now;
        discoverPeers();
        WifiP2pDevice target = null;
        synchronized (discoveredPeers) {
            for (WifiP2pDevice d : discoveredPeers) {
                if (d.status == WifiP2pDevice.AVAILABLE) {
                    target = d;
                    break;
                }
            }
        }
        if (target != null) {
            connectToPeer(target.deviceAddress);
        }
    }

    public void disconnectIfClient() {
        if (manager == null || channel == null || !groupFormed || isGroupOwner) return;
        try {
            manager.removeGroup(channel, new WifiP2pManager.ActionListener() {
                @Override public void onSuccess() { groupFormed = false; groupOwnerIp = ""; }
                @Override public void onFailure(int reason) {}
            });
        } catch (Throwable ignored) {
        }
    }

    public boolean connectToPeer(String deviceAddress) {
        if (manager == null || channel == null) return false;
        WifiP2pDevice target = null;
        synchronized (discoveredPeers) {
            for (WifiP2pDevice d : discoveredPeers) {
                if (deviceAddress == null || deviceAddress.isEmpty() || deviceAddress.equalsIgnoreCase(d.deviceAddress)) {
                    target = d;
                    break;
                }
            }
        }
        if (target == null) {
            discoverPeers();
            return false;
        }
        try {
            WifiP2pConfig cfg = new WifiP2pConfig();
            cfg.deviceAddress = target.deviceAddress;
            manager.connect(channel, cfg, new WifiP2pManager.ActionListener() {
                @Override public void onSuccess() {}
                @Override public void onFailure(int reason) {}
            });
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    public JSONObject status() {
        JSONObject out = new JSONObject();
        try {
            out.put("started", started);
            out.put("group_formed", groupFormed);
            out.put("is_group_owner", isGroupOwner);
            out.put("group_owner_ip", groupOwnerIp);
            JSONArray arr = new JSONArray();
            synchronized (discoveredPeers) {
                for (WifiP2pDevice d : discoveredPeers) {
                    arr.put(new JSONObject()
                            .put("name", d.deviceName != null ? d.deviceName : "Peer")
                            .put("address", d.deviceAddress != null ? d.deviceAddress : "")
                            .put("status", d.status));
                }
            }
            out.put("peers", arr);
        } catch (Exception ignored) {
        }
        return out;
    }
}
