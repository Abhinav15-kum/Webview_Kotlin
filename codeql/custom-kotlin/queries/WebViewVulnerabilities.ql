import java
import android
import android.WebView
import android.Intent
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.controlflow.Guards

/**
 * Detects insecure WebView configurations in Android apps.
 */
class InsecureWebView extends WebViewConfig {
  InsecureWebView() {
    this.hasJavaScriptEnabled() and
    this.hasJavascriptInterface() and
    this.loadsExternalUrl() and
    this.allowsFileAccess()
  }
}

class WebViewConfig {
  WebView webview;

  WebViewConfig() {
    exists(WebView w |
      w.getAnAccess() = this.getWebViewAccess() |
      webview = w
    )
  }

  predicate getWebViewAccess() { result = webview.getAnAccess() }

  predicate hasJavaScriptEnabled() {
    exists(MethodAccess call |
      call.getMethod().getName() = "setJavaScriptEnabled" and
      call.getQualifier() instanceof Expr and
      call.getArgument(0).getValue().toString() = "true"
    )
  }

  predicate hasJavascriptInterface() {
    exists(MethodAccess call |
      call.getMethod().getName() = "addJavascriptInterface"
    )
  }

  predicate allowsFileAccess() {
    exists(MethodAccess call |
      call.getMethod().getName() = "setAllowFileAccess" and
      call.getArgument(0).getValue().toString() = "true"
    )
  }

  predicate loadsExternalUrl() {
    exists(MethodAccess call |
      call.getMethod().getName() = "loadUrl" and
      call.getArgument(0).getAnAccess() instanceof MethodAccess and
      call.getArgument(0).getAnAccess().getMethod().getName() = "getStringExtra"
    )
  }
}
