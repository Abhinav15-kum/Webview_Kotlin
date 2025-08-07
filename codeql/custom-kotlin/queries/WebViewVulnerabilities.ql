/**
 * @name WebView Security Check
 * @description Simple pattern matching for WebView security issues
 * @kind problem
 * @problem.severity warning
 * @id custom/webview-simple
 * @tags security
 */
import java

from Method m
where
  m.getName() = "setJavaScriptEnabled" or
  m.getName() = "setAllowFileAccessFromFileURLs" or
  m.getName() = "setAllowUniversalAccessFromFileURLs" or
  m.getName() = "addJavascriptInterface" or
  (m.getName() = "loadUrl" and m.getDeclaringType().getName() = "WebView")

select m, 
  "Potentially unsafe WebView method: " + m.getName() + " in class " + m.getDeclaringType().getName()
