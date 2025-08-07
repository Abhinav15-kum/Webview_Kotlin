/**
 * @name Uses Cleartext Traffic Enabled
 * @description Detects when usesCleartextTraffic is enabled in Android manifest
 * @kind problem
 * @problem.severity warning
 * @id custom/uses-cleartext-traffic-enabled
 * @tags security android manifest
 */

import java

from XmlFile manifest, XmlElement application, XmlAttribute attr
where
  // Match AndroidManifest.xml files
  manifest.getRelativePath().matches("%AndroidManifest.xml") and
  
  // Find application element
  application = manifest.getAChild*() and
  application.getName() = "application" and
  
  // Find usesCleartextTraffic attribute set to true
  attr = application.getAttribute("usesCleartextTraffic") and
  (attr.getValue() = "true" or attr.getValue() = "True" or attr.getValue() = "TRUE")

select attr, "usesCleartextTraffic is enabled in Android manifest - this allows unencrypted HTTP connections and may expose sensitive data to network attacks"
