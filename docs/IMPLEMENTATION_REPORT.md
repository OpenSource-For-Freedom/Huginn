# Huginn Implementation Report — Review-First CVE Capture

## Status

Huginn now has a runnable private capture pipeline for npm, PyPI, and RubyGems with static scanning, advisory enrichment, durable queueing, and CSV-first analyst validation.

It remains intentionally non-disclosing: no vendor contact, CNA request, CVE request, or public disclosure is automated.

## Implemented

### Registry discovery

Active adapters:

- npm replication changes follower with durable sequence cursor, packument reconciliation, release-time overlap protection, and exact version deduplication.
- PyPI latest-updates feed for new versions.
- PyPI newest-packages feed for first publishes.
- RubyGems just-updated activity feed for new versions.
- RubyGems latest activity feed for first publishes.

Release identity is persisted as registry + package name + version.

### Durable queue and retries

Discovered releases are written to a SQLite-backed job queue before scanning.

The queue provides:

- priority classes;
- transactional leases;
- lease expiry and crash recovery;
- attempt counts;
- retry state;
- exponential retry backoff;
- queue-state counts in run_summary.json.

Validation seeds receive the highest priority, first-publish events are prioritized above normal updates, and completed live releases are not re-enqueued.

### Artifact handling and isolation

For each leased release Huginn:

1. resolves the published artifact;
2. downloads it as opaque bytes;
3. calculates SHA-256 during download;
4. verifies a registry SHA-256 when available;
5. enforces compressed and expanded size limits;
6. parses and extracts only inside the isolated scan boundary.

No install scripts, package imports, tests, package CLIs, or other package code are executed.

The rootless Podman scan boundary uses:

- no network;
- read-only container root;
- all Linux capabilities dropped;
- no-new-privileges;
- PID, CPU, memory, and tmpfs limits;
- no container-engine socket;
- short-lived source volume;
- disposable per-scan Trivy DB copy so untrusted scanning cannot modify the trusted persistent DB cache.

Archive validation rejects absolute paths, parent traversal, links that escape the extraction model, device/FIFO entries, oversized expansion, excessive file counts, and unsupported archive forms.

### Static scanners

Pinned initial versions:

- Trivy 0.74.0
- Semgrep 1.177.0
- Python 3.13 slim extraction image

Trivy records known vulnerable dependency and supported static/misconfiguration findings.

Semgrep runs a local versioned ruleset and records exact file/line evidence for review.

### Advisory enrichment

Every scanned package/version is enriched against:

- OSV.dev;
- GitHub Global Security Advisories;
- NVD;
- Red Hat Security Data.

Matching remains conservative:

- KNOWN_EXACT: the finding/advisory identifier is directly corroborated or the advisory source returned an exact affected package/version match.
- POSSIBLE_MATCH: advisory information overlaps the package/version but does not prove the same finding.
- NO_MATCH: all enabled lookups completed with no matching advisory.
- LOOKUP_FAILED: one or more required lookups failed and no stronger status applies.

NVD requests use bounded retries/backoff and bounded per-package corroboration to reduce rate-limit pressure.

Raw advisory evidence is preserved in advisory_evidence.json.

### Review outputs

Every run creates:

- review_findings.csv
- scan_manifest.csv
- advisory_evidence.json
- run_summary.json

review_findings.csv remains the primary analyst worksheet. It contains package identity, artifact integrity, scanner/rule identity, CVE/advisory data, severity/confidence/novelty, exact file and line, dependency/fixed-version context, evidence, dedup details, and manual validation fields on the same row.

scan_manifest.csv records every attempted package, including failures, so an empty findings CSV cannot be mistaken for successful clean coverage.

### Manual validation gate

huginn-review-validate rejects incomplete analyst decisions.

VALIDATED requires:

- reviewer;
- reviewer_decision;
- reviewer_notes;
- verified_at_utc;
- reachability_verified=true;
- security_boundary_verified=true;
- affected_version_verified=true;
- known_advisory_verified=true.

REJECTED requires false_positive_reason.

### Validation controls

The end-to-end integration workflow scans known-vulnerable historical controls labeled VALIDATION_SEED. These are test controls, not new discoveries.

The verified integration run completed all three control packages and recovered exact CVE matches in the review CSV.

### Live recent-release canary

PR CI also scans a small sample of current PyPI/RubyGems updates while bootstrapping the npm follower cursor. It uploads a separate live review packet so current registry behavior and false-positive rates can be inspected independently from seeded controls.

### Legion Runner

Every Huginn GitHub Actions job starts with Wraith Security Legion Runner pinned to commit:

b459e7433723418301974a1f05098607b7e8d027

Current mode:

- egress-policy: audit
- disable-telemetry: true

This gives local CI egress/file-integrity visibility while the baseline is established without unexpectedly blocking required package, GitHub, advisory, or container-registry traffic.

### GitHub Actions capture workflow

The production capture workflow:

- targets a self-hosted Linux runner labeled huginn;
- supports npm, PyPI, RubyGems, or all;
- supports first-publish and update modes;
- supports optional validation controls;
- refreshes the trusted Trivy DB outside the untrusted scan containers;
- uploads each review packet for 30 days.

The hourly schedule remains gated by HUGINN_SCHEDULE_ENABLED until the dedicated self-hosted runner and baseline are confirmed.

No automatic disclosure or CVE submission exists.

## Validation result

A successful end-to-end control run scanned:

- npm lodash 4.17.20
- npm minimist 1.2.5
- PyPI Jinja2 2.10.1

Result:

- 3 package scans completed;
- 0 package scan failures;
- 12 exact CVE review rows recovered;
- advisory evidence came from OSV/GHSA and was corroborated by NVD/Red Hat where available.

The controls prove the package -> artifact -> isolated scan -> enrichment -> CSV path works. They are not claimed as novel Huginn discoveries.

## Remaining operator gates

The code gaps originally called out for npm, advisory enrichment, and durable queue/retry are implemented.

Before unattended disclosure work is considered, the operator should still:

1. run current-release capture for enough cycles to establish Semgrep false-positive rates;
2. review NO_MATCH static candidates manually;
3. tune language-aware Semgrep rules from those review outcomes;
4. confirm the dedicated self-hosted huginn runner is online and stable;
5. enable HUGINN_SCHEDULE_ENABLED only after that baseline.

The CSV remains intentionally primary. A local TUI is optional ergonomics, not a correctness dependency.

Automatic CNA/CVE submission remains out of scope until the manual evidence and disclosure workflow is proven repeatedly.
