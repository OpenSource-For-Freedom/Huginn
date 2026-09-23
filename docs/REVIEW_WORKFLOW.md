# Huginn Manual Review Workflow

Huginn is review-first. Scanner output is evidence to inspect, not an automatically validated vulnerability.

## Run outputs

Every capture run emits a private review packet:

- review_findings.csv — one row per Trivy, Semgrep, or exact advisory finding.
- scan_manifest.csv — one row per package release attempted, including failures.
- advisory_evidence.json — raw normalized OSV, GHSA, NVD, and Red Hat lookup evidence.
- run_summary.json — run counts, queue state, and automation state.

The CSV is UTF-8 with BOM for Excel compatibility.

## Registry coverage

Huginn currently supports:

1. npm — durable replication cursor plus packument/version reconciliation.
2. PyPI — newest-package and latest-update feeds.
3. RubyGems — latest and just-updated activity feeds.

NEW_PACKAGE and NEW_VERSION remain distinct queue events.

VALIDATION_SEED is reserved for deliberately selected historical controls and must never be interpreted as a new discovery.

## Queue behavior

Discovery writes releases to SQLite before scanning.

Jobs use transactional leases. Failed jobs enter retry state with exponential backoff; expired leases can be reclaimed after a worker crash. First-publish events receive higher priority than ordinary update churn.

run_summary.json reports queue state so backlog and retry behavior are visible.

## review_findings.csv inspection fields

Every row includes:

- Run identity: run_id, run_started_at_utc, finding_id, finding_fingerprint, triage_priority.
- Package identity: registry, event_type, package_name, package_version, PURL, publication time, first-seen time.
- Artifact integrity: artifact filename, URL, SHA-256, byte size, registry digest.
- Scanner identity: scanner, scanner_version, rule_id, ruleset_hash.
- Finding classification: finding_class, vulnerability_id, advisory source/URL, severity, confidence, novelty_state, CVSS, CWE.
- Inspection location: file_path, start_line, end_line.
- Dependency context: dependency_name, installed_version, fixed_version.
- Evidence: title, message, evidence, source, sink, known_dependency, suspicious_package.
- Dedup: dedup_status, dedup_sources, dedup_identifiers, dedup_checked_at_utc.
- Analyst fields: review_status, reviewer, reviewer_decision, reviewer_notes, reachability/security-boundary/affected-version/known-advisory verification, false-positive reason, verified timestamp, disclosure state/reference.

## Dedup interpretation

KNOWN_EXACT means the same advisory/CVE is directly corroborated or an advisory source explicitly reports the exact package/version as affected.

POSSIBLE_MATCH means the package/version overlaps known advisory information, but Huginn cannot prove it is the same weakness.

NO_MATCH means enabled advisory sources completed without a matching advisory. It does not by itself prove a new vulnerability.

LOOKUP_FAILED means enrichment was incomplete and manual validation must not treat the finding as novel yet.

## Finding interpretation

### Trivy

Known dependency vulnerabilities are evidence of existing CVEs in the package dependency context. They remain useful inspection rows but are not novel CVE candidates by themselves.

### Semgrep

Semgrep rows are static candidates with exact code location and rule evidence. A Semgrep hit becomes a vulnerability candidate only after source/reachability/security-boundary and affected-version checks.

### Advisory enrichment rows

Exact package/version advisory matches are added to the same CSV as known_package_advisory rows. These are useful controls and context, not new discoveries.

### Suspicious-package indicators

Reverse-shell/malware-like indicators are marked suspicious_package=true and remain separate from CVE novelty decisions.

## Manual validation

After editing a review CSV:

    huginn-review-validate reports/<run-id>/review_findings.csv

VALIDATED rows require all four verification booleans true plus reviewer identity, decision, notes, and timestamp.

REJECTED rows require false_positive_reason.

A NO_MATCH row should not be marked VALIDATED solely because advisory sources found nothing.

## Isolation

Package archives are untrusted from the first byte.

Parsing/extraction and static scanning occur inside rootless Podman with no network, read-only root, dropped capabilities, no-new-privileges, resource limits, and short-lived scan storage.

Trivy receives a disposable copy of the trusted vulnerability database cache for each package scan.

No package code is executed.

## Workflow controls

Every workflow job starts with Wraith Security Legion Runner pinned to a full commit SHA, currently in audit mode with telemetry disabled.

The CVE capture workflow supports manual runs immediately.

The hourly production schedule remains gated by HUGINN_SCHEDULE_ENABLED and targets the dedicated self-hosted runner labeled huginn.

CI separately runs:

- unit tests;
- known-vulnerable validation controls;
- a current-release live canary.

No workflow submits to a CNA, MITRE, NVD, a vendor, or a public disclosure endpoint.

## Analyst sequence

For a potentially novel row:

1. verify the exact artifact SHA-256 and version;
2. inspect the exact file/line and surrounding code;
3. establish attacker-controlled or untrusted input;
4. establish reachability;
5. establish the security-sensitive sink/boundary;
6. confirm concrete confidentiality, integrity, or availability impact;
7. confirm the vulnerable code is shipped and relevant;
8. determine the affected version range;
9. re-run advisory checks and manually inspect possible matches;
10. only then mark the row VALIDATED.

Disclosure remains a separate, deliberate step after validation.
