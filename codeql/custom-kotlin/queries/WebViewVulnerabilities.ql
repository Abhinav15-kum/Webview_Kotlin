import java
import android
import semmle.code.java.security.TaintTracking
import DataFlow::PathGraph

class WebViewSink extends MethodAccess {
  WebViewSink() {
    this.getMethod().getDeclaringType().getName() = "WebView" and
    (
      this.getMethod().getName() = "addJavascriptInterface" or
      this.getMethod().getName() = "loadUrl"
    )
  }
}

class UserControlledSource extends DataFlow::SourceNode {
  UserControlledSource() {
    exists(MethodAccess m |
      m.getMethod().getName() = "getStringExtra" and
      m.getQualifier().getType().hasQualifiedName("android.content", "Intent") and
      this.asExpr() = m
    )
  }
}

from UserControlledSource src, WebViewSink sink, PathNode path
where path = DataFlow::localFlowPath(src.asExpr(), sink)
select sink, "WebView receives user-controlled input from here.", path
