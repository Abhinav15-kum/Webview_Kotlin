/**
 * @name WebView Security Check
 * @description Simple pattern matching for WebView security issues
 * @kind problem
 * @problem.severity warning
 * @id custom/webview-simple
 * @tags security
 */
import java

from Method m, string message
where
  (m.getName() = "setJavaScriptEnabled" and
   message = "JavaScript may be enabled in WebView - ensure this is necessary and safe") or
  
  (m.getName() = "setAllowFileAccessFromFileURLs" and
   message = "File access from file URLs may be enabled - this can be dangerous") or
   
  (m.getName() = "setAllowUniversalAccessFromFileURLs" and
   message = "Universal access from file URLs may be enabled - high security risk") or
   
  (m.getName() = "addJavascriptInterface" and
   message = "JavaScript interface added to WebView - verify interface security") or
   
  (m.getName() = "loadUrl" and 
   m.getDeclaringType().getName() = "WebView" and
   message = "WebView loads URL - verify URL is trusted and sanitized")

select m, message
