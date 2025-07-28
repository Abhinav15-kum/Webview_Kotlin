import semmle.code.kotlin.Expr
import semmle.code.kotlin.Property
import semmle.code.kotlin.BooleanLiteral

from Property p, BooleanLiteral lit
where
  p.getName() = "javaScriptEnabled" and
  p.getAnAccess() = lit and
  lit.getBooleanValue() = true
select lit, "JavaScript is enabled on a WebView, which can expose it to injection vulnerabilities."
