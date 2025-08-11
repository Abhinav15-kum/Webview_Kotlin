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
  // Focus on main manifest, exclude build variant specific manifests
  not manifest.getRelativePath().matches("%/debug/%") and
  not manifest.getRelativePath().matches("%/release/%") and
  application = manifest.getAChild*() and
  application.getName() = "application" and
  application.getAttributeValue("usesCleartextTraffic") = "true"
select manifest, "usesCleartextTraffic is enabled in " + manifest.getRelativePath() + " - allows HTTP connections, creating security vulnerability"
