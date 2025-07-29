/**
 * @name WebView Security Vulnerabilities
 * @description Detects potentially unsafe WebView configurations in Android applications
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id java/webview-security
 * @tags security
 *       android
 *       webview
 */

import java

from Expr expr, string message
where 
  (
    // Look for javaScriptEnabled = true
    exists(Assignment assign |
      assign.getDest().(FieldAccess).getField().getName() = "javaScriptEnabled" and
      assign.getSource().(Literal).getValue() = "true" and
      expr = assign and
      message = "WebView JavaScript is enabled, which may allow XSS attacks if loading untrusted content."
    )
  ) or (
    // Look for allowFileAccess = true  
    exists(Assignment assign |
      assign.getDest().(FieldAccess).getField().getName() = "allowFileAccess" and
      assign.getSource().(Literal).getValue() = "true" and
      expr = assign and
      message = "WebView file access is enabled, which may lead to local file disclosure."
    )
  ) or (
    // Look for addJavascriptInterface calls
    exists(Call call |
      call.getCallable().getName() = "addJavascriptInterface" and
      expr = call and
      message = "WebView JavaScript interface is exposed, which can be exploited if attacker injects JavaScript."
    )
  )
select expr, message
