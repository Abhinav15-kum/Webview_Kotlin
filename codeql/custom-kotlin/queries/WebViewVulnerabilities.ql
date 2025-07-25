import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.Security

from MethodAccess ma
where
  ma.getMethod().hasName("setJavaScriptEnabled") and
 ma.getMethod().hasName("allowFileAccess") and
  ma.getMethod().getDeclaringType().getName() = "WebSettings" and
  ma.getArgument(0) instanceof BooleanLiteral and
  ((BooleanLiteral)ma.getArgument(0)).getBooleanValue() = true
select ma, "JavaScript is enabled on a WebView, which can expose it to injection vulnerabilities."

