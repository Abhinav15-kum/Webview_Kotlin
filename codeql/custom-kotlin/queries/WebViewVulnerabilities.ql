import semmle.code.kotlin.Assignment
import semmle.code.kotlin.PropertyAccess
import semmle.code.kotlin.BooleanLiteral

from Assignment assign, PropertyAccess prop, BooleanLiteral lit
where
  assign.getLhs() = prop and
  prop.getTarget().hasName("javaScriptEnabled") and
  assign.getRhs() = lit and
  lit.getBooleanValue() = true
select assign, 
  "JavaScript is enabled on a WebView, which can expose it to injection vulnerabilities."
