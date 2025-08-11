/**
 * @name Cleartext Traffic Enabled
 * @description Detects Android applications with usesCleartextTraffic set to true, which allows unencrypted HTTP connections
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @id java/android/cleartext-traffic-enabled
 * @tags security
 *       android
 *       network
 *       cleartext
 */

import java
from XmlFile manifest
where
  manifest.getRelativePath().matches("%AndroidManifest.xml") and
  root = manifest.getAChild() and
  root.getName() = "manifest" and
  application = root.getAChild() and
  application.getName() = "application" and
  attr = application.getAttribute("usesCleartextTraffic") and
  attr.getValue() = "true"
select attr, "usesCleartextTraffic is enabled - allows HTTP connections, creating security vulnerability"
