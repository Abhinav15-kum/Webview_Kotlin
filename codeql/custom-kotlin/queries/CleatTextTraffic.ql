/**
 * @name Clear Text Traffic Detection
 * @description Finds clearTextTraffic=true in any form
 * @kind problem
 * @problem.severity warning
 * @id custom/cleartext-comprehensive
 * @tags security android manifest
 */

import java

from File f, int line, string lineContent
where
  f.getExtension() = "xml" and
  lineContent = f.getContents().splitAt("\n", line) and
  (
    lineContent.regexpMatch(".*clearTextTraffic\\s*=\\s*[\"'](?i)true[\"'].*") or
    lineContent.regexpMatch(".*android:clearTextTraffic\\s*=\\s*[\"'](?i)true[\"'].*")
  )

select f, "Clear text traffic enabled at line " + line + ": " + lineContent.trim()
