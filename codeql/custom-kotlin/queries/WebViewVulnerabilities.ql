/**
 * @name Insecure WebView Configuration (Kotlin)
 * @description Flags calls to dangerous WebView settings
 * @kind problem
 * @problem.severity warning
 * @id custom-kotlin/insecure-webview-settings
 */

import kotlin

from MethodCall call, string message
where
  (
    call.getMethod().getName() = "setJavaScriptEnabled" and
    message = "WebView JavaScript is enabled, which may allow XSS attacks if loading untrusted content."
  ) or
  (
    call.getMethod().getName() = "setAllowFileAccess" and
    message = "WebView file access is enabled, which may lead to local file disclosure."
  ) or
  (
    call.getMethod().getName() = "setAllowContentAccess" and
    message = "WebView content access is enabled, which may allow access to content providers."
  ) or
  (
    call.getMethod().getName() = "setAllowFileAccessFromFileURLs" and
    message = "WebView allows file access from file URLs, which may lead to local file disclosure."
  ) or
  (
    call.getMethod().getName() = "setAllowUniversalAccessFromFileURLs" and
    message = "WebView allows universal access from file URLs, which is a serious security risk."
  )
select call, message
