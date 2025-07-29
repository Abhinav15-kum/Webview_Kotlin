/**
 * @name Insecure WebView usage
 * @description Detects WebView components that enable JavaScript or allow file access, which can be dangerous.
 * @kind problem
 * @problem.severity warning
 * @id kotlin/insecure-webview
 */

import kotlin
import semmle.code.kotlin.dataflow.DataFlow
import semmle.code.kotlin.controlflow.ControlFlow

class WebViewUsage extends Expr {
  WebViewUsage() {
    exists(ConstructorCall cc |
      cc.getType().hasQualifiedName("android.webkit", "WebView") and
      cc = this
    )
  }
}

from MethodAccess ma, WebViewUsage wv
where
  wv = ma.getQualifier() and
  (
    ma.getMethod().getName() = "getSettings" or
    ma.getMethod().getName() = "setJavaScriptEnabled" or
    ma.getMethod().getName() = "setAllowFileAccess"
  )
select ma, "Potentially insecure WebView configuration."
