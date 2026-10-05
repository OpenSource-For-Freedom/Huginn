# Disclosure — ResolveSpec: `sort` parameter reaches `ORDER BY` through a keyword denylist (funcspec)

**Status:** VALIDATED (static), DRAFT NOT SENT. Awaiting owner approval.  
**Report to:** Hein Puth (`bitechdev`), maintainer and main committer. Use GitHub private vulnerability
reporting on `bitechdev/ResolveSpec` if it is enabled (Security tab); otherwise email
`hein@bitechsystems.co.za` (the address on his commits). Do not open a public issue.  
**Package:** `github.com/bitechdev/ResolveSpec` (also served as `github.com/bitechdev/resolvespec`), `pkg/funcspec`  
**Affected:** v0.0.63 (2025-12-01, when `funcspec` was added) through v1.2.6, and `main` at 9c4d916 (2026-09-30).  
**Weakness:** CWE-89 (SQL injection)  
**Suggested CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) where the route is public;
`PR:L` (6.5) where the application puts the route behind authentication.
**Rechecked 2026-10-05:** v1.3.3 is also affected. ValidSQL is byte-identical, and SqlQueryList still appends the sort value to ORDER BY. Affected range is now v0.0.63 through v1.3.3.

---

## Report text (ready to send)

**Subject:** SQL injection through the `sort` parameter in funcspec (ResolveSpec v0.0.63–v1.2.6)

Hi Hein,

While reviewing recent Go module releases, I found that the `sort` value in `funcspec` list endpoints
reaches the SQL `ORDER BY` clause without being limited to column names. I'm reporting it privately
first.

**Details**

- `pkg/funcspec/function_api.go`, `Handler.SqlQueryList`: the sort value comes from the `sort` query
  parameter (`parsePaginationParams`) or the `x-sort` header (`parameters.go`). It is appended as
  `ORDER BY %s` after `ValidSQL(sortcols, "select")`.
- The `"select"` mode of `ValidSQL` removes a short list of keywords and comment markers. It is a
  denylist, so SQL expressions that don't use those keywords still pass through to the `ORDER BY` clause
  of the main list query.
- Because the result order is observable, this allows blind SQL injection against the application's
  database role on any route built with `SqlQueryList`.
- The other request-driven parts of the query (column filters, `IN` lists, field filters) are built with
  the `colname` allow-list and quote escaping. The sort value is the one place a free-form expression gets in.

**Suggested fix**

Parse the sort value into a list of `column [ASC|DESC]` items. Validate each column with the same
`colname` rule (or, better, against the columns of the configured query), allow only `ASC`/`DESC`, and
reject anything else. The `"select"` denylist mode could then be removed.

**Affected versions:** v0.0.63 through v1.2.6 (and current `main`).

I'm following a 90-day coordinated disclosure window, or earlier if a fixed release ships, and I'm happy to
adjust if you need more time. I'd also be glad to help with a GitHub security advisory / CVE if you want one.

Thanks,
Tim Burns

---

## Evidence (internal)

- Scanned artifact: Go module `v1.2.1` (both module path spellings), Huginn hunt 36768072204.
- `ValidSQL` `"select"` mode and the `ORDER BY` append are unchanged on `main` at 9c4d916.
- `funcspec` is not present in v0.0.62 or earlier; first tag with it is v0.0.63.
- `funcspec` is listed as not audited in the repository's own `audit/pkg/_CROSS-CUTTING.audit.md`.
- Related but out of scope: `restheadspec` accepts an `X-Custom-SQL-Where` header as a raw WHERE clause.
  That is a documented feature, so it is not part of this report.
- Static review only; nothing was executed against any deployment.
