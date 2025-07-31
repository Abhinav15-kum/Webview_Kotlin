/**
 * @name WebView Security Vulnerabilities
 * @description Detects potentially unsafe WebView configurations in Android applications
 * @kind problem
 * @problem.severity warning
 * @id custom/webview-vulnerabilities
 * @tags security
 *        android
 *        webview
 */

import java
import semmle.code.java.dataflow.DataFlow

/**
 * A method call that enables JavaScript in a WebView
 */
class JavaScriptEnabledCall extends MethodAccess {
  JavaScriptEnabledCall() {
    this.getMethod().hasName("setJavaScriptEnabled") and
    this.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebSettings") and
    this.getArgument(0).(BooleanLiteral).getBooleanValue() = true
  }
}

/**
 * A method call that allows file access from file URLs
 */
class FileAccessFromFileURLsCall extends MethodAccess {
  FileAccessFromFileURLsCall() {
    this.getMethod().hasName("setAllowFileAccessFromFileURLs") and
    this.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebSettings") and
    this.getArgument(0).(BooleanLiteral).getBooleanValue() = true
  }
}

/**
 * A method call that allows universal access from file URLs
 */
class UniversalAccessFromFileURLsCall extends MethodAccess {
  UniversalAccessFromFileURLsCall() {
    this.getMethod().hasName("setAllowUniversalAccessFromFileURLs") and
    this.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebSettings") and
    this.getArgument(0).(BooleanLiteral).getBooleanValue() = true
  }
}

/**
 * A method call that adds a JavaScript interface
 */
class AddJavaScriptInterfaceCall extends MethodAccess {
  AddJavaScriptInterfaceCall() {
    this.getMethod().hasName("addJavascriptInterface") and
    this.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebView")
  }
}

/**
 * A WebView loadUrl call with potentially unsafe URL
 */
class LoadUrlCall extends MethodAccess {
  LoadUrlCall() {
    this.getMethod().hasName("loadUrl") and
    this.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebView")
  }
  
  predicate hasUnsafeUrl() {
    exists(StringLiteral url | 
      url = this.getArgument(0) and
      (url.getValue().matches("http://%") or 
       url.getValue().matches("file://%") or
       url.getValue().matches("javascript:%"))
    )
  }
}

from MethodAccess call, string message
where
  (call instanceof JavaScriptEnabledCall and 
   message = "JavaScript is enabled in WebView, which may allow XSS attacks") or
  (call instanceof FileAccessFromFileURLsCall and 
   message = "File access from file URLs is enabled, which may allow local file access") or
  (call instanceof UniversalAccessFromFileURLsCall and 
   message = "Universal access from file URLs is enabled, which is a serious security risk") or
  (call instanceof AddJavaScriptInterfaceCall and 
   message = "JavaScript interface added to WebView, ensure proper input validation") or
  (call instanceof LoadUrlCall and call.(LoadUrlCall).hasUnsafeUrl() and
   message = "WebView loads potentially unsafe URL")
select call, message
