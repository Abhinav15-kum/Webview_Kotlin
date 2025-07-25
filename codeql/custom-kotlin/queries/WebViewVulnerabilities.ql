import semmle.code.kotlin.MethodCallExpr
import semmle.code.kotlin.Expr
import semmle.code.kotlin.BooleanLiteral

from MethodCallExpr call
where
  call.getMethodName() = "setJavaScriptEnabled" and
  exists(BooleanLiteral lit | lit = call.getArgument(0) and lit.getBooleanValue() = true)
select call, "JavaScript is enabled on a WebView, which can expose it to injection vulnerabilities."
