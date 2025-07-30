/**
 * @name WebView JavaScript Enabled in Kotlin
 * @description Detects when JavaScript is explicitly enabled in Kotlin WebView settings
 * @kind problem
 * @problem.severity warning
 * @id custom-kotlin/webview-javascript-enabled
 * @tags security
 *       android
 *       webview
 */

import kotlin
import kotlin.DataFlow
import kotlin.exprs.PropertyAccess
import kotlin.exprs.BoolLiteral

from PropertyAccess pa, BoolLiteral b
where
  pa.getName() = "javaScriptEnabled" and
  b.getBooleanValue() = true and
  pa.getAnAssignment().getRhs() = b
select pa, "JavaScript is enabled in WebView. Ensure this is necessary and properly secured."
