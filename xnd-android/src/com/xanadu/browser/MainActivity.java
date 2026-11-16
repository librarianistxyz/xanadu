package com.xanadu.browser;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.ContentValues;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.text.InputType;
import android.view.Gravity;
import android.view.ViewGroup;
import android.webkit.ConsoleMessage;
import android.webkit.CookieManager;
import android.webkit.URLUtil;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class MainActivity extends Activity {
    private static final String PREFS = "xanadu_prefs";
    private static final String KEY_HUB = "hub_url";
    private static final String KEY_NODE_MIGRATED = "local_node_migrated_v1";
    private static final String DEFAULT_HUB = "http://127.0.0.1:8765/";

    private WebView webView;
    private SharedPreferences prefs;
    private LocalNodeServer localNode;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        if (!prefs.getBoolean(KEY_NODE_MIGRATED, false)) {
            prefs.edit()
                    .putString(KEY_HUB, DEFAULT_HUB)
                    .putBoolean(KEY_NODE_MIGRATED, true)
                    .apply();
        }

        localNode = new LocalNodeServer(this, 8765);
        localNode.startAndWait(3000);
        scheduleMeshSyncJob();
        if (Build.VERSION.SDK_INT >= 33) {
            if (checkSelfPermission("android.permission.NEARBY_WIFI_DEVICES") != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{"android.permission.NEARBY_WIFI_DEVICES"}, 101);
            }
        } else if (Build.VERSION.SDK_INT >= 23) {
            if (checkSelfPermission(android.Manifest.permission.ACCESS_FINE_LOCATION) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{android.Manifest.permission.ACCESS_FINE_LOCATION}, 101);
            }
        }

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#1a1d24"));

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(14, 8, 14, 8);
        bar.setBackgroundColor(Color.parseColor("#1a1d24"));

        Button homeBtn = new Button(this);
        homeBtn.setText("Xanadu");
        homeBtn.setTextSize(11f);
        homeBtn.setTextColor(Color.parseColor("#ffffff"));
        homeBtn.setBackgroundColor(Color.parseColor("#1a73e8"));
        homeBtn.setOnClickListener(v -> webView.loadUrl(prefs.getString(KEY_HUB, DEFAULT_HUB)));

        Button hubBtn = new Button(this);
        hubBtn.setText("Node");
        hubBtn.setTextSize(11f);
        hubBtn.setTextColor(Color.parseColor("#e8eaed"));
        hubBtn.setBackgroundColor(Color.parseColor("#2d313c"));
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        hp.setMargins(10, 0, 0, 0);
        hubBtn.setLayoutParams(hp);
        hubBtn.setOnClickListener(v -> promptHubUrl());

        Button reloadBtn = new Button(this);
        reloadBtn.setText("Reload");
        reloadBtn.setTextSize(11f);
        reloadBtn.setTextColor(Color.parseColor("#e8eaed"));
        reloadBtn.setBackgroundColor(Color.parseColor("#2d313c"));
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rp.setMargins(10, 0, 0, 0);
        reloadBtn.setLayoutParams(rp);
        reloadBtn.setOnClickListener(v -> webView.reload());

        bar.addView(homeBtn);
        bar.addView(hubBtn);
        bar.addView(reloadBtn);

        webView = new WebView(this);
        webView.setBackgroundColor(Color.parseColor("#111318"));
        WebSettings ws = webView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setDatabaseEnabled(true);
        ws.setUserAgentString(ws.getUserAgentString() + " XanaduAndroid/1.0");
        CookieManager.getInstance().setAcceptCookie(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, true);
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onConsoleMessage(ConsoleMessage cm) {
                android.util.Log.d("XanaduWebView", cm.message() + " (" + cm.sourceId() + ":" + cm.lineNumber() + ")");
                return super.onConsoleMessage(cm);
            }
        });
        webView.setDownloadListener((url, userAgent, contentDisposition, mimetype, contentLength) -> {
            final String fileName = URLUtil.guessFileName(url, contentDisposition, mimetype != null ? mimetype : "application/json");
            new Thread(() -> {
                try {
                    HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                    conn.setConnectTimeout(10000);
                    conn.setReadTimeout(10000);
                    int code = conn.getResponseCode();
                    if (code < 200 || code >= 300) {
                        throw new RuntimeException("HTTP " + code);
                    }
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    try (InputStream is = conn.getInputStream()) {
                        byte[] buf = new byte[4096];
                        int r;
                        while ((r = is.read(buf)) != -1) bos.write(buf, 0, r);
                    }
                    byte[] data = bos.toByteArray();
                    String savedLocation;
                    if (Build.VERSION.SDK_INT >= 29) {
                        ContentValues cv = new ContentValues();
                        cv.put(MediaStore.Downloads.DISPLAY_NAME, fileName);
                        cv.put(MediaStore.Downloads.MIME_TYPE, mimetype != null && !mimetype.isEmpty() ? mimetype : "application/json");
                        cv.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
                        Uri uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                        if (uri == null) throw new RuntimeException("Failed to create download entry");
                        try (OutputStream os = getContentResolver().openOutputStream(uri)) {
                            if (os == null) throw new RuntimeException("Failed to open download stream");
                            os.write(data);
                        }
                        savedLocation = "Downloads/" + fileName;
                    } else {
                        File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                        if (dir == null || (!dir.exists() && !dir.mkdirs())) {
                            dir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                        }
                        File outFile = new File(dir, fileName);
                        try (FileOutputStream fos = new FileOutputStream(outFile)) {
                            fos.write(data);
                        }
                        savedLocation = outFile.getAbsolutePath();
                    }
                    runOnUiThread(() -> Toast.makeText(MainActivity.this, "Saved to " + savedLocation, Toast.LENGTH_LONG).show());
                } catch (Exception e) {
                    runOnUiThread(() -> Toast.makeText(MainActivity.this, "Download failed: " + e.getMessage(), Toast.LENGTH_LONG).show());
                }
            }).start();
        });
        webView.setWebViewClient(new WebViewClient() {
            private boolean retried = false;
            @Override
            public void onPageStarted(WebView view, String url, android.graphics.Bitmap favicon) {
                android.util.Log.d("XanaduMain", "onPageStarted: " + url);
            }
            @Override
            public void onPageFinished(WebView view, String url) {
                android.util.Log.d("XanaduMain", "onPageFinished: " + url + " title=" + view.getTitle());
            }
            @Override
            public void onReceivedError(WebView view, WebResourceRequest req, WebResourceError err) {
                android.util.Log.e("XanaduMain", "onReceivedError: " + (req != null ? req.getUrl() : "") + " code=" + (err != null ? err.getErrorCode() : 0) + " desc=" + (err != null ? err.getDescription() : ""));
                if (req != null && req.isForMainFrame() && !retried) {
                    retried = true;
                    view.postDelayed(() -> view.reload(), 400);
                }
            }
        });

        root.addView(bar, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(webView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);

        String hubUrl = prefs.getString(KEY_HUB, DEFAULT_HUB);
        webView.loadUrl(hubUrl);
    }

    private void promptHubUrl() {
        EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_TEXT_VARIATION_URI);
        input.setText(prefs.getString(KEY_HUB, DEFAULT_HUB));

        new AlertDialog.Builder(this)
                .setTitle("Xanadu Node URL")
                .setMessage("Default is your phone's built-in node (http://127.0.0.1:8765/), or enter another peer URL:")
                .setView(input)
                .setPositiveButton("Connect", (d, w) -> {
                    String u = input.getText().toString().trim();
                    if (u.isEmpty()) u = DEFAULT_HUB;
                    if (!u.startsWith("http://") && !u.startsWith("https://")) {
                        u = "http://" + u;
                    }
                    prefs.edit().putString(KEY_HUB, u).apply();
                    webView.loadUrl(u);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    private void scheduleMeshSyncJob() {
        try {
            JobScheduler js = (JobScheduler) getSystemService(JOB_SCHEDULER_SERVICE);
            if (js == null) return;
            ComponentName cn = new ComponentName(this, MeshSyncJobService.class);
            JobInfo info = new JobInfo.Builder(8765, cn)
                    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                    .setPeriodic(15 * 60 * 1000L)
                    .setPersisted(true)
                    .build();
            js.schedule(info);
        } catch (Exception ignored) {
        }
    }

    @Override
    protected void onDestroy() {
        if (localNode != null) localNode.stop();
        super.onDestroy();
    }
}
