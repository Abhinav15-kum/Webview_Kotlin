/**
 * @name WebView Security Vulnerabilities (Basic)
 * @description Detects potentially unsafe WebView configurations
 * @kind problem
 * @problem.severity warning
 * @id custom/webview-basic
 * @tags security
 */

import java

from CallableCall call, string message
where
  // JavaScript enabled
  (call.getCallee().getName() = "setJavaScriptEnabled" and
   call.getCallee().getDeclaringType().getName() = "WebSettings" and
   message = "JavaScript enabled in WebView - potential XSS risk") or
  
  // File access from file URLs
  (call.getCallee().getName() = "setAllowFileAccessFromFileURLs" and
   call.getCallee().getDeclaringType().getName() = "WebSettings" and
   message = "File access from file URLs enabled - potential local file access") or
   
  // Universal access from file URLs
  (call.getCallee().getName() = "setAllowUniversalAccessFromFileURLs" and
   call.getCallee().getDeclaringType().getName() = "WebSettings" and
   message = "Universal access from file URLs enabled - serious security risk") or
   
  // JavaScript interface
  (call.getCallee().getName() = "addJavascriptInterface" and
   call.getCallee().getDeclaringType().getName() = "WebView" and
   message = "JavaScript interface added - ensure input validation") or
   
  // Load URL
  (call.getCallee().getName() = "loadUrl" and
   call.getCallee().getDeclaringType().getName() = "WebView" and
   message = "WebView loads URL - verify URL safety")
   
select call, message
