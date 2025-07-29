import java

from MethodInvocation mi, string message
where
  (
    mi.getMethod().getName() = "setJavaScriptEnabled" and
    message = "WebView JavaScript is enabled, which may allow XSS attacks if loading untrusted content."
  ) or
  (
    mi.getMethod().getName() = "setAllowFileAccess" and
    message = "WebView file access is enabled, which may lead to local file disclosure."
  ) or
  (
    mi.getMethod().getName() = "setAllowContentAccess" and
    message = "WebView content access is enabled, which may allow access to content providers."
  ) or
  (
    mi.getMethod().getName() = "setAllowFileAccessFromFileURLs" and
    message = "WebView allows file access from file URLs, which may lead to local file disclosure."
  ) or
  (
    mi.getMethod().getName() = "setAllowUniversalAccessFromFileURLs" and
    message = "WebView allows universal access from file URLs, which is a serious security risk."
  )
select mi, message
