# Disclosure — filterbymodel: management API is unauthenticated by default

**Status:** VALIDATED (static), DRAFT NOT SENT. Tim sends the report and submits the MITRE form.  
**Report to:** Salvatore Cervone, maintainer. The repository has no SECURITY.md, so use GitHub private
vulnerability reporting on `SalvatoreCervone/filterbymodel` if the Security tab offers it; otherwise email
`salvatore999@virgilio.it` (Packagist author address and commit address). Do not open a public issue.  
**Package:** `salvatorecervone/filterbymodel` (Packagist), Laravel row-level security package  
**Affected:** v1.0.0 (2026-08-18) through 1.3.1, and `main` at b3d4423 (2026-10-01).
- v1.0.0 and later: filter-definition create/list/delete without authentication.
- v1.2.0 and later: also `/column-values` and `/model-columns` table and column introspection.
- 1.2.8 and later: also the user bypass toggle.

**Weakness:** CWE-306 (Missing Authentication for Critical Function); CWE-200 (Exposure of Sensitive Information)  
**CVSS 4.0:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` — **9.3 Critical**
(default configuration; applications that added `auth` to the package's API middleware are not exposed).

---

## Maintainer report (ready to send)

**Subject:** filterbymodel: the package API is reachable without authentication in the default configuration

Hi Salvatore,

While reviewing recent Packagist releases, I found that filterbymodel's REST API is registered without
authentication by default. Because the package enforces row-level security, this lets anyone who can reach
the application change its security rules. I'm reporting it privately first.

I've also requested a CVE ID from MITRE for this issue and will share it with you when it's assigned.

**Details**

- `config/filterbymodel.php` registers the API routes with `'middleware' => ['api']` and `'enabled' => true`.
  `FilterByModelServiceProvider::loadRoutes()` loads `routes/api.php` with that middleware. The README tells
  users to protect the web dashboard with `auth`, but not the API.
- The controllers (`FilterDefinitionController`, `UserFilterController`) perform no authorization checks.
- As a result, an unauthenticated client can:
  - create, list and delete filter definitions (`/api/filter-definitions`);
  - create, change, copy and delete per-user filters (`/api/user-filters`);
  - turn the global bypass on for any user (`/api/user-bypass-toggle`, 1.2.8+);
  - list the columns of any table (`/api/model-columns`) and read up to the configured number of distinct values
    of any column of any table (`/api/column-values`, v1.2.0+). The `table` parameter is not limited to the
    configured models. The only exclusion is column names containing `password`, `token`, `secret` or `hash`, so
    columns such as e-mail addresses, personal data, or the `id` column of Laravel's `sessions` table (database
    session driver) are returned.
- `model_class` is also instantiated directly (`new $modelClass()`) for any class that exists.

**Suggested fix**

1. Default the API middleware to `['api', 'auth:sanctum']` (or `['web', 'auth']`) and document that both route
   groups must be restricted to administrators.
2. Add an authorization check (a Gate or policy, e.g. `filterbymodel.manage`) in every controller action, so a
   misconfigured route group is not enough to expose the API.
3. For introspection, accept only tables and models that are configured in the package (an allow-list), and
   resolve `model_class` against that list instead of instantiating arbitrary classes.

**Affected versions:** v1.0.0 through 1.3.1 (and current `main`).

I'm following a 90-day coordinated disclosure window, or earlier if a fixed release ships, and I'm happy to
adjust if you need more time. I can help with a GitHub security advisory if you want one.

Thanks,
Tim Burns

---

## MITRE CVE request (cveform.mitre.org) — answers

- **Request type:** Report Vulnerability/Request CVE ID
- **Vulnerability type:** Missing Authentication for Critical Function (CWE-306); Information Exposure (CWE-200)
- **Vendor of the product:** Salvatore Cervone
- **Product:** filterbymodel (Packagist `salvatorecervone/filterbymodel`)
- **Version:** v1.0.0 through 1.3.1
- **Has vendor confirmed or acknowledged the vulnerability:** No (reported to the maintainer on the send date)
- **Attack type:** Remote
- **Impact:** Information Disclosure; Escalation of Privileges (bypass of row-level security rules)
- **Affected component:** `config/filterbymodel.php` (routes.api.middleware default), `routes/api.php`,
  `src/FilterByModelServiceProvider.php` (loadRoutes), `src/Http/Controllers/FilterDefinitionController.php`
  (modelColumns, columnValues, store, destroy), `src/Http/Controllers/UserFilterController.php` (store, update,
  destroy, copy, toggleBypass)
- **Attack vector:** An unauthenticated network attacker sends HTTP requests to the package's API routes, which
  are registered with only the `api` middleware group by default and have no authorization checks.
- **Suggested description:**
  > filterbymodel (salvatorecervone/filterbymodel) v1.0.0 through 1.3.1 for Laravel registers its REST API
  > routes with only the `api` middleware group by default and performs no authorization in its controllers.
  > A remote unauthenticated attacker can create, modify and delete the package's row-level security filter
  > definitions and per-user filters, enable a global filter bypass for any user (1.2.8 and later), and read
  > table column listings and distinct column values from arbitrary database tables through the column-values
  > and model-columns endpoints (v1.2.0 and later).
- **Discoverer:** Tim Burns
- **References:** https://github.com/SalvatoreCervone/filterbymodel ;
  https://packagist.org/packages/salvatorecervone/filterbymodel (add the advisory or fix link once public)
- **CVSS 4.0:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N (9.3 Critical)

---

## Evidence (internal)

- Scanned artifact: Packagist 1.2.8 (sha256 f12b516aaa2d17ebfb331e47ac79260164a8dccd921249dd3b216669f54fa2d0),
  Huginn hunt 36838640922; candidates in `FilterDefinitionController.php` lines 96–97 and 144–147.
- Checked by reading tags: rule CRUD routes with `['api']` middleware present from v1.0.0; `column-values` from
  v1.2.0; `user-bypass-toggle` from 1.2.8; unchanged in 1.3.1 and `main` b3d4423.
- No `Gate::`, `authorize` or `auth()` checks in `src/Http/Controllers`.
- Scan-time OSV and GHSA lookups: no match. No SECURITY.md in the repository.
- Packagist shows low adoption (47 total installs at review time).
- Static review only; nothing was executed against any deployment.
