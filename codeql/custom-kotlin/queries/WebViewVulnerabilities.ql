/**
 * @name Insecure WebView Configuration (Java)
 * @description Flags calls to dangerous WebView settings
 * @kind problem
 * @problem.severity warning
 * @id custom-java/insecure-webview-settings
 */

import java

from MethodAccess ma, string message
where
  (
    ma.getMethod().getName() = "setJavaScriptEnabled" and
    message = "WebView JavaScript is enabled, which may allow XSS attacks if loading untrusted content."
  ) or
  (
    ma.getMethod().getName() = "setAllowFileAccess" and
    message = "WebView file access is enabled, which may lead to local file disclosure."
  ) or
  (
    ma.getMethod().getName() = "setAllowContentAccess" and
    message = "WebView content access is enabled, which may allow access to content providers."
  ) or
  (
    ma.getMethod().getName() = "setAllowFileAccessFromFileURLs" and
    message = "WebView allows file access from file URLs, which may lead to local file disclosure."
  ) or
  (
    ma.getMethod().getName() = "setAllowUniversalAccessFromFileURLs" and
    message = "WebView allows universal access from file URLs, which is a serious security risk."
  )
select ma, message
