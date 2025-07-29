import kotlin

from MethodCall call, string message
where
  call.getMethod().getName().matches("setJavaScriptEnabled") and
  message = "WebView JavaScript is enabled, which may allow XSS attacks if loading untrusted content."
select call, message
