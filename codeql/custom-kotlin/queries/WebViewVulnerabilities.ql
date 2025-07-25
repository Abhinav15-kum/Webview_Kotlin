import semmle.code.kotlin.PropertyAccess
import semmle.code.kotlin.BooleanLiteral
import semmle.code.kotlin.Property
import semmle.code.kotlin.ClassInstanceExpr

from PropertyAccess access, BooleanLiteral lit
where
  access.getName() = "javaScriptEnabled" and
  access.isWrite() and
  access.getAssignedValue() = lit and
  lit.getBooleanValue() = true
select access,
  "JavaScript is enabled on a WebView, which can expose it to injection vulnerabilities."
