/**
 * @name WebView JavaScript Enabled
 * @description Finds assignments to javaScriptEnabled field
 * @kind problem
 * @problem.severity warning
 * @id java/webview-js-enabled
 */

import java

from Assignment assign, FieldAccess fa
where 
  fa = assign.getDest() and
  fa.getField().getName() = "javaScriptEnabled"
select assign, "Assignment to javaScriptEnabled field found"
