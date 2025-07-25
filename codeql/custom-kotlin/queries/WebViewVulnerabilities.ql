import kotlin
import semmle.code.kotlin.Expr
import semmle.code.kotlin.Property
import semmle.code.kotlin.BooleanLiteral

from Expr e, BooleanLiteral lit
where
  e.toString().matches("%javaScriptEnabled%") and
  e.getType().getUnspecifiedName() = "boolean" and
  e = lit and
  lit.getBooleanValue() = true
select e,
  "JavaScript is enabled on a WebView, which can expose it to injection vulnerabilities."
