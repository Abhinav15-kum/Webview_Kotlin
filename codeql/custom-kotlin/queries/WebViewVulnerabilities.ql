/**
 * @name Unsafe use of addJavascriptInterface in WebView
 * @kind problem
 * @id android/webview/add-javascript-interface
 * @problem.severity warning
 * @description Detects unsafe use of WebView.addJavascriptInterface, which can expose native methods to JavaScript.
 */

import java
import android

from MethodAccess call
where
  call.getMethod().getName() = "addJavascriptInterface" and
  call.getMethod().getDeclaringType().getName() = "WebView"
select call, "This WebView uses addJavascriptInterface, which may expose native methods to JavaScript."
