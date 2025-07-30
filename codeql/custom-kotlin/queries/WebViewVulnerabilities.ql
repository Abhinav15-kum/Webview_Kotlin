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

from MethodAccess call
where
  call.getMethod().hasName("setJavaScriptEnabled") and
  call.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebSettings")
select call, "JavaScript is enabled in WebView. Ensure this is necessary and properly secured."
