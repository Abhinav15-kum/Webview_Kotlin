/**
 * @name Custom Kotlin Query
 * @description Your custom query description
 * @kind problem
 * @problem.severity warning
 * @id custom-kotlin/my-query
 */

import kotlin

from Method m
where m.getName() = "onCreate"
select m, "Found onCreate method"
