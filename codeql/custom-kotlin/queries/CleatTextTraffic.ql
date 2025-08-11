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
from XmlFile manifest, XmlElement application
where
  manifest.getRelativePath().matches("%AndroidManifest.xml") and
  application = manifest.getAChild*() and
  application.getName() = "application" and
  application.getAttributeValue("usesCleartextTraffic") = "true"
select application, "usesCleartextTraffic is enabled - allows HTTP connections, creating security vulnerability"
