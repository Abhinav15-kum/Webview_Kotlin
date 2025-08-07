/**
 * @name Uses Cleartext Traffic Enabled
 * @description Detects usesCleartextTraffic=true with unique results
 * @kind problem
 * @problem.severity warning
 * @id custom/cleartext-unique
 * @tags security android manifest
 */

import java

from XmlFile manifest, XmlElement root, XmlElement application, XmlAttribute attr
where
  manifest.getRelativePath().matches("%AndroidManifest.xml") and
  root = manifest.getAChild() and
  root.getName() = "manifest" and
  application = root.getAChild() and
  application.getName() = "application" and
  attr = application.getAttribute("usesCleartextTraffic") and
  attr.getValue() = "true"

select attr, "usesCleartextTraffic is enabled - allows HTTP connections, creating security vulnerability"
