import java
import semmle.code.java.frameworks.kotlin.Kotlin

from MethodAccess call
where 
  call.getMethod().hasName("setJavaScriptEnabled") and
  call.getArgument(0).(CompileTimeConstantExpr).getBooleanValue() = true
select call, "WebView JavaScript is enabled, which may allow XSS attacks."
