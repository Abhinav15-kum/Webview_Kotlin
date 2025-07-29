package com.example.kotlin_codeql;


import android.annotation.SuppressLint;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.appcompat.app.AppCompatActivity;

public class UpdatedWebView extends AppCompatActivity {

    private WebView secureWebView;

    @SuppressLint("SetJavaScriptEnabled") // okay with proper precautions
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        secureWebView = new WebView(this);
        setContentView(secureWebView);

        WebSettings webSettings = secureWebView.getSettings();
        webSettings.setJavaScriptEnabled(true); // Only enable if necessary
        webSettings.setAllowFileAccess(false); // Prevent file access
        webSettings.setAllowContentAccess(false);
        webSettings.setDomStorageEnabled(true);

        secureWebView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                // Prevent redirecting to untrusted URLs
                if (url.startsWith("https://trusted.com")) {
                    return false; // Load within WebView
                }
                return true; // Block or handle differently
            }
        });

        // Load a safe, HTTPS URL
        secureWebView.loadUrl("https://trusted.com");
    }

    @Override
    protected void onDestroy() {
        if (secureWebView != null) {
            secureWebView.destroy();
        }
        super.onDestroy();
    }
}