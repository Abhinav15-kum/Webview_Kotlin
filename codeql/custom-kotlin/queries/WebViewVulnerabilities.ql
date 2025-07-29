 *       webview
 */

import java

from FieldWrite fw, Field f, string message
where 
  f = fw.getField() and
  (
    (f.getName() = "javaScriptEnabled" and 
     message = "WebView JavaScript is enabled, which may allow XSS attacks if loading untrusted content.") or
    (f.getName() = "allowFileAccess" and 
     message = "WebView file access is enabled, which may lead to local file disclosure.") or
    (f.getName() = "allowContentAccess" and 
     message = "WebView content access is enabled, which may allow access to content providers.") or
    (f.getName() = "allowFileAccessFromFileURLs" and 
     message = "WebView allows file access from file URLs, which may lead to local file disclosure.") or
    (f.getName() = "allowUniversalAccessFromFileURLs" and 
     message = "WebView allows universal access from file URLs, which is a serious security risk.")
  )
select fw, message
