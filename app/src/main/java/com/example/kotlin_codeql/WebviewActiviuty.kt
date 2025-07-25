import android.os.Bundle
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity

class WebviewActiviuty : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val webView = WebView(this)
        setContentView(webView)

        val webSettings: WebSettings = webView.settings
        webSettings.javaScriptEnabled = true
webSettings.allowFileAccess=true

        webSettings.allowFileAccessFromFileURLs = true
        webSettings.allowUniversalAccessFromFileURLs = true


        webView.addJavascriptInterface(InsecureInterface(), "Android")

        webView.webViewClient = WebViewClient()
        webView.webChromeClient = WebChromeClient()


        val url = intent.getStringExtra("url")
        if (url != null) {
            webView.loadUrl(url)
        }
    }

    // Exposes native methods to JS - can be exploited if attacker injects JS
    class InsecureInterface {
        @android.webkit.JavascriptInterface
        fun showToast(message: String) {
            // Some action
            println("Message from JS: $message")
        }
    }
}
