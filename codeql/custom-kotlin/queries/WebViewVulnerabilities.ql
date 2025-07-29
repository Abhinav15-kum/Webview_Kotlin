import semmle.code.kotlin.Assignment
import semmle.code.kotlin.Property

from Assignment assign, Property p, BooleanLiteral lit
where
  assign.getTarget() = p and
  p.getName() = "javaScriptEnabled" and
  assign.getValue() = lit and
  lit.getBooleanValue() = true
select assign, "JavaScript is enabled on a WebView, exposing injection risks."
