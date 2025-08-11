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
from XmlFile manifest, XmlElement application, XmlAttribute attr
where
  manifest.getRelativePath().matches("%AndroidManifest.xml") and
  // Focus on main manifest, exclude build variant specific manifests
  not manifest.getRelativePath().matches("%/debug/%") and
  not manifest.getRelativePath().matches("%/release/%") and
  application = manifest.getAChild*() and
  application.getName() = "application" and
  attr = application.getAttribute("usesCleartextTraffic") and
  attr.getValue() = "true"
select attr, "usesCleartextTraffic is enabled - allows HTTP connections, creating security vulnerability"

// Alternative: Select the application element itself
/*
import java
from XmlFile manifest, XmlElement application
where
  manifest.getRelativePath().matches("%AndroidManifest.xml") and
  not manifest.getRelativePath().matches("%/debug/%") and
  not manifest.getRelativePath().matches("%/release/%") and
  application = manifest.getAChild*() and
  application.getName() = "application" and
  application.getAttributeValue("usesCleartextTraffic") = "true"
select application, "usesCleartextTraffic is enabled on application element - allows HTTP connections, creating security vulnerability"
*/

// Alternative: More specific location reporting
/*
import java
from XmlFile manifest, XmlElement application, XmlAttribute attr
where
  manifest.getRelativePath().matches("%/src/main/%AndroidManifest.xml") and
  application = manifest.getAChild*() and
  application.getName() = "application" and
  attr = application.getAttribute("usesCleartextTraffic") and
  attr.getValue() = "true"
select attr, "usesCleartextTraffic=\"true\" allows unencrypted HTTP connections (security risk)"
*/
