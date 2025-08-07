/**
 * @name WebView Security Check
 * @description Detects potentially unsafe WebView method calls
 * @kind problem
 * @problem.severity warning
 * @id custom/webview-simple
 * @tags security
 */
import java

from MethodAccess call, string message
where
  (call.getMethod().getName() = "setJavaScriptEnabled" and
   message = "JavaScript enabled in WebView - ensure this is necessary") or
  
  (call.getMethod().getName() = "setAllowFileAccessFromFileURLs" and
   message = "File access from file URLs enabled - potential security risk") or
   
  (call.getMethod().getName() = "setAllowUniversalAccessFromFileURLs" and
   message = "Universal access from file URLs enabled - high security risk") or
   
  (call.getMethod().getName() = "addJavascriptInterface" and
   message = "JavaScript interface added - verify interface is secure") or
   
  (call.getMethod().getName() = "loadUrl" and 
   call.getMethod().getDeclaringType().getName() = "WebView" and
   message = "WebView loading URL - ensure URL is validated")

select call, message
