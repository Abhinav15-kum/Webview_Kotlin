/**
 * @name Insecure WebView JavaScript Enabled
 * @description Detects WebView configurations where JavaScript is enabled
 * @kind problem
 * @problem.severity warning
 * @id custom-kotlin/webview-javascript-enabled
 * @tags security
 *       webview
 *       android
 */

import java

from MethodAccess call
where
  call.getMethod().hasName("setJavaScriptEnabled") and
  call.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebSettings") and
  call.getArgument(0).(CompileTimeConstantExpr).getBooleanValue() = true
select call, "JavaScript is enabled in WebView, which may pose security risks."
