package com.example.kotlin_codeql

import android.os.Bundle
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.example.kotlin_codeql.ui.theme.Kotlin_CodeqlTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            var pass="XYZ"

            var webView: WebView = WebView(this)
            setContentView(webView)

            val webSettings: WebSettings = webView.getSettings()
            webSettings.setJavaScriptEnabled(true)
            webSettings.setAllowFileAccess(true)
            webSettings.setAllowContentAccess(true)

            webView.setWebViewClient(WebViewClient())


            // Load local HTML file from assets

            webView.loadUrl("file:///android_asset/index.html")
        }
    }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello $name!",
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    Kotlin_CodeqlTheme {
        Greeting("Android")
    }
}