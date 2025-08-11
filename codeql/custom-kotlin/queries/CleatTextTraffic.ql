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
select manifest, "usesCleartextTraffic is enabled in " + manifest.getRelativePath() + " - allows HTTP connections, creating security vulnerability"

// Alternative approach using exists() to be more explicit:
/*
import java
from XmlFile manifest, XmlElement application
where
  manifest.getRelativePath().matches("%AndroidManifest.xml") and
  exists(XmlElement root |
    root = manifest.getAChild() and
    root.getName() = "manifest" and
    application = root.getAChild() and
    application.getName() = "application"
  ) and
  exists(XmlAttribute attr |
    attr = application.getAttribute("usesCleartextTraffic") and
    attr.getValue() = "true"
  )
select manifest, "usesCleartextTraffic is enabled - allows HTTP connections, creating security vulnerability"
*/

// Most concise approach:
/*
import java
from XmlFile manifest
where
  manifest.getRelativePath().matches("%AndroidManifest.xml") and
  exists(XmlElement application |
    application = manifest.getAChild*() and
    application.getName() = "application" and
    application.getAttributeValue("usesCleartextTraffic") = "true"
  )
select manifest, "usesCleartextTraffic is enabled - allows HTTP connections, creating security vulnerability"
*/
