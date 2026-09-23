# Huginn Implementation Report — npm + Advisory Enrichment

## Status

Huginn now has a review-first capture path for npm, PyPI, and RubyGems with package-aware advisory enrichment before findings are written to the analyst CSV.

This remains a private static-analysis system. It does not execute discovered packages and does not automatically disclose or request CVEs.

## Implemented in this pass

### npm follower

The npm adapter follows the official registry replication changes feed.

It maintains two durable values in SQLite:

- `npm.sequence` — the last committed replication sequence.
- `npm.publish_window` — the publication-time anchor used during packument reconciliation.

The first npm run initializes at the current replication position instead of replaying the full registry history.

For subsequent changes Huginn:

1. reads changes after the stored sequence;
2. fetches the changed package packument;
3. reconciles exact package-version publication timestamps;
4. uses a 24-hour overlap window to tolerate replication/CDN timing differences;
5. filters completed package/version identities through SQLite;
6. emits NEW_PACKAGE or NEW_VERSION candidates;
7. advances the cursor only when the batch has no failed scans.

A failed scan therefore keeps the cursor behind the affected page so the next run can replay it.

### PyPI and RubyGems

Existing adapters remain active.

The default capture mode is now `all`, which includes both first publishes and new versions.

### Package scanning

Published artifacts remain opaque until they enter the rootless Podman isolation boundary.

Untrusted scan workers retain:

- no network;
- read-only container root;
- dropped capabilities;
- no-new-privileges;
- CPU, memory, PID, and tmpfs limits;
- no engine socket;
- no package execution or install step.

The persistent trusted Trivy database is copied into a disposable per-scan cache so an untrusted scan cannot modify the database used by later runs.

### Advisory enrichment

After the no-network scanner exits, normalized findings are enriched in the trusted controller.

#### OSV.dev

Exact ecosystem + package + version query.

#### GitHub Global Security Advisories

Exact ecosystem and `package@version` affect query.

#### NVD

Exact CVE-ID corroboration/enrichment only. Huginn intentionally does not use loose package-name NVD search as a suppression mechanism.

An optional `NVD_API_KEY` can be supplied to the workflow. Without it Huginn applies conservative client-side pacing.

#### Red Hat Security Data

Exact CVE-ID lookup for corroboration and additional context when available.

### Dependency ecosystem preservation

Trivy dependency results now retain the dependency ecosystem independently of the registry being scanned.

This prevents a JavaScript lockfile discovered inside a Python package, for example, from being queried against the wrong advisory ecosystem.

### Conservative dedup states

The enrichment layer uses:

- `KNOWN_EXACT` — actual scanner/advisory identifier match.
- `POSSIBLE_MATCH` — advisory affects the exact package/version, but equality with the static finding is not proven.
- `NO_MATCH` — package-aware sources found no advisory for the exact package/version.
- `LOOKUP_FAILED` — package-aware lookup could not be completed.

A Semgrep finding does not become `KNOWN_EXACT` merely because the same release has an unrelated advisory.

### Expanded analyst CSV

`review_findings.csv` now carries per-source fields:

- OSV status and IDs;
- GHSA status and IDs;
- NVD status and IDs;
- Red Hat status and IDs;
- advisory CVEs;
- advisory CWEs;
- dedup match basis;
- enrichment completion/error state.

The existing manual verification columns remain mandatory before a row can pass as VALIDATED.

### Workflow

The manual workflow now supports:

- npm;
- PyPI;
- RubyGems;
- all registries.

The default mode scans both first publishes and new versions.

The workflow passes the GitHub Actions token only to the trusted controller for public GHSA queries. The optional `NVD_API_KEY` secret is also controller-only and is never passed into the untrusted package scan container.

The hourly schedule remains gated behind:

`HUGINN_SCHEDULE_ENABLED=true`

## Tests added

New unit coverage verifies:

- first npm run initializes a current replication cursor without historical backlog;
- subsequent npm changes reconcile a recent version correctly;
- package-aware no-match becomes `NO_MATCH`;
- exact package/version advisory overlap remains `POSSIBLE_MATCH`;
- a direct known dependency CVE identifier becomes `KNOWN_EXACT`.

Existing tests continue to cover archive traversal rejection, normal extraction, scanner normalization, CSV format, and manual review validation gates.

## What a successful test run should prove

A small manual capture should demonstrate all three classes in the resulting CSV where data permits:

1. **KNOWN_EXACT** — known dependency CVEs detected by Trivy and corroborated by advisory sources.
2. **POSSIBLE_MATCH** — static findings on releases with existing advisories requiring human comparison.
3. **NO_MATCH** — static findings with no package/version advisory match, requiring deeper manual validation.

None of these states alone establishes a new CVE.

## Remaining before unattended vulnerability triage

### Rule quality

The initial Semgrep rule set is intentionally small. Real manual runs should be used to measure false-positive rates before adding more language-specific/dataflow rules.

### Full durable work queue

The npm cursor is durable and batch-safe, but the requirements document still calls for a general leased job queue with explicit retry scheduling and backoff for all registries.

### Advisory cache persistence

Enrichment currently caches within a process. A persistent advisory cache would reduce repeated API requests across runs and should be added before high-volume scheduling.

### Review interface

CSV remains the source of truth. A local TUI should come only after the review schema stabilizes.

### Disclosure automation

Still intentionally absent. A validated finding remains a manual disclosure decision.

## Recommended validation sequence

1. Merge this pass.
2. Run the npm workflow once to initialize its cursor.
3. Run npm again after new publications occur.
4. Run PyPI and RubyGems with a small limit.
5. Download the private review artifact.
6. Check `scan_manifest.csv` for failures first.
7. Inspect several `KNOWN_EXACT` rows and confirm the CVE aliases/sources agree.
8. Compare any `POSSIBLE_MATCH` rows with their existing advisories.
9. Deep-review the highest-confidence `NO_MATCH` rows.
10. Complete the analyst columns only after source inspection verifies reachability, affected version, security boundary, and novelty.
11. Keep scheduled capture disabled until the observed false-positive and failure rates are acceptable.
