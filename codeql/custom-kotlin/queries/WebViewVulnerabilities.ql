/**
 * @name WebView JavaScript Enabled
 * @description Detects when JavaScript is explicitly enabled in WebView settings
 * @kind problem
 * @problem.severity warning
 * @id custom-kotlin/webview-javascript-enabled
 * @tags security
 *       android
 *       webview
 */

import java

class WebSettings extends RefType {
  WebSettings() {
    this.hasQualifiedName("android.webkit", "WebSettings")
  }
}

from MethodAccess ma
where
  ma.getMethod().getDeclaringType() instanceof WebSettings and
  ma.getMethod().hasName("setJavaScriptEnabled") and
  (
    ma.getArgument(0).(BooleanLiteral).getBooleanValue() = true or
    ma.getArgument(0).(CompileTimeConstantExpr).getBooleanValue() = true
  )
select ma, "JavaScript is explicitly enabled in WebView, which may introduce security vulnerabilities."
