/**
 * @name Clear Text Traffic Enabled
 * @description Detects when clearTextTraffic is enabled in Android manifest
 * @kind problem
 * @problem.severity warning
 * @id custom/cleartext-traffic-enabled
 * @tags security android manifest
 */

import java

from XmlFile manifest, XmlElement app, XmlAttribute attr
where
  // Match AndroidManifest.xml files
  manifest.getRelativePath().matches("%AndroidManifest.xml") and
  
  // Find application element
  app = manifest.getAChild*() and
  app.getName() = "application" and
  
  // Find clearTextTraffic attribute set to true
  attr = app.getAttribute("clearTextTraffic") and
  (attr.getValue() = "true" or attr.getValue() = "True" or attr.getValue() = "TRUE")

select attr, "Clear text traffic is enabled in Android manifest - this allows HTTP connections and may expose sensitive data"
