import kotlin

from PropertyWrite pw
where
  pw.getTarget().getName() = "javaScriptEnabled" and
  pw.getValue() instanceof BooleanLiteral and
  ((BooleanLiteral)pw.getValue()).getBooleanValue() = true
select pw, "JavaScript is enabled on a WebView without validation."
