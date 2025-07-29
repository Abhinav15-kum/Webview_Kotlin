/**
 * @name Use of addJavascriptInterface in Kotlin WebView
 * @description Detects potentially unsafe use of addJavascriptInterface in Kotlin code.
 * @kind problem
 * @problem.severity warning
 * @id kotlin/webview/add-javascript-interface
 */

import kotlin
import kotlin.reflect
import kotlin.qldoc

from MethodCall call
where
  call.getMethod().getQualifiedName().matches("%WebView%addJavascriptInterface%")
select call, "Use of addJavascriptInterface may be dangerous if input is attacker-controlled."
