/**
 * @name Uses Cleartext Traffic Detection
 * @description Detects various forms of usesCleartextTraffic=true
 * @kind problem
 * @problem.severity error
 * @id custom/cleartext-detection
 * @tags security android manifest network
 */

import java

from File f
where
  f.getExtension() = "xml" and
  f.getRelativePath().regexpMatch(".*AndroidManifest\\.xml") and
  (
    f.getContents().matches("%usesCleartextTraffic=\"true\"%") or
    f.getContents().matches("%usesCleartextTraffic='true'%") or
    f.getContents().matches("%usesCleartextTraffic=\"True\"%") or
    f.getContents().matches("%usesCleartextTraffic='True'%")
  )

select f, "SECURITY RISK: usesCleartextTraffic is enabled, allowing unencrypted HTTP connections in " + f.getRelativePath()
