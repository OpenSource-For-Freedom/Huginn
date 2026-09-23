# Huginn Validation Report — npm + Advisory Enrichment

**Branch:** feature/security-advisory-enrichment  
**Scope:** Static capture/dedup validation only  
**Disclosure state:** No automatic disclosure or CVE submission

## Test status

The implementation was tested in GitHub Actions against the pull-request merge result.

- Unit tests: 12 passed.
- Live advisory smoke checks: passed.
- Package execution: none.
- Package installation: none.
- Automatic disclosure: disabled.
- Automatic CVE submission: disabled.

## Live known-CVE controls

These deliberately vulnerable historical package versions were used as positive controls for the advisory enrichment layer.

| Registry | Package | Version | Required control CVE | OSV | GitHub Advisory API | Result |
|---|---|---:|---|---|---|---|
| npm | lodash | 4.17.23 | CVE-2026-4800 | MATCH | MATCH | PASS |
| PyPI | jinja2 | 3.1.4 | CVE-2024-56326 | MATCH | MATCH | PASS |
| RubyGems | rack | 2.2.3 | CVE-2024-26141 | MATCH | MATCH | PASS |

The controls prove that Huginn can use exact ecosystem + package + version lookups to recover known advisory identifiers across npm, PyPI, and RubyGems.

They do not prove that a future static finding is novel.

## npm control detail

For lodash 4.17.23, the live package/version query returned CVE-2026-4800 through both package-aware sources.

The same package/version also returned additional advisories, which is intentional test coverage for the dedup design: an affected release can have several unrelated advisories.

Huginn must therefore never suppress an unrelated Semgrep finding solely because a package/version has an existing advisory.

## PyPI control detail

For jinja2 3.1.4, both OSV and the GitHub Advisory API returned CVE-2024-56326 for the exact package/version query.

This validates the PyPI-to-OSV ecosystem mapping and PyPI-to-GitHub `pip` ecosystem mapping.

## RubyGems control detail

For rack 2.2.3, both OSV and the GitHub Advisory API returned CVE-2024-26141 for the exact package/version query.

The version has a large advisory history, which validates that Huginn can preserve a many-advisory result set without collapsing it into one arbitrary match.

## Independent CVE-source checks

### NVD

An exact lookup for CVE-2026-4800 returned a MATCH with CVE-2026-4800.

This validates the NVD exact-ID corroboration path independently of package-name matching.

### Red Hat Security Data

An exact lookup for CVE-2026-26017 returned a MATCH with CVE-2026-26017.

This validates the Red Hat exact-ID corroboration path.

## Dedup safety controls

The unit suite validates the following semantics:

- Exact package/version with no OSV/GHSA advisory -> `NO_MATCH`.
- One failed package-aware source -> `LOOKUP_FAILED`, never `NO_MATCH`.
- Existing advisory on the exact package/version -> `POSSIBLE_MATCH` for a static finding unless identity equality is established.
- Direct scanner/advisory identifier equality -> `KNOWN_EXACT`.
- NVD and Red Hat remain `SKIPPED` when there is no CVE identifier to corroborate.

These rules prevent a package-level advisory hit from hiding a separate potential vulnerability.

## npm follower controls

Unit tests validate:

- A first npm follower run initializes at the current replication sequence and does not attempt an unbounded historical scan.
- A later changed package can yield a newly published version from its packument.
- Cursor advancement is separated from package completion.
- Capture code advances a batch checkpoint only when the batch contains no failed package scans.

## What is validated now

The following path has test evidence:

`registry/package identity -> exact package/version advisory lookup -> OSV/GHSA aliases -> CVE-ID corroboration through NVD/Red Hat -> conservative dedup classification -> analyst CSV`

The following path requires the dedicated self-hosted Huginn runner for an end-to-end live package capture:

`new registry event -> artifact download -> isolated unpack -> Trivy/Semgrep scan -> enrichment -> review_findings.csv`

That second path intentionally cannot run in the hosted advisory smoke job because untrusted package parsing/scanning is restricted to the dedicated rootless self-hosted runner.

## Acceptance for the next manual run

A live capture run is acceptable for analyst review when:

1. `scan_manifest.csv` accounts for every attempted package.
2. Failed scans are visible and do not advance the npm checkpoint past the failed batch.
3. Every finding has artifact SHA-256, scanner/rule identity, exact inspection location where applicable, and enrichment status.
4. Known dependency CVEs resolve to `KNOWN_EXACT` when identifiers agree.
5. Static findings with package-level advisory overlap remain `POSSIBLE_MATCH`.
6. Static findings with successful exact package/version advisory lookups and no advisory become `NO_MATCH`.
7. A human still performs reachability, security-boundary, affected-version, and known-advisory verification before `VALIDATED`.

## Conclusion

The npm follower and advisory-enrichment layer has passed unit and live known-CVE positive-control testing.

No result in this report is presented as a newly discovered CVE. The next evidence needed is a real self-hosted capture artifact containing Huginn-generated Trivy/Semgrep findings for newly published packages, followed by manual source validation of the highest-confidence `NO_MATCH` candidates.
