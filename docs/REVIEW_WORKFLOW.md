# Huginn Manual Review Workflow

Huginn capture is intentionally review-first. A scanner finding is evidence to inspect, not an automatically validated vulnerability.

## Run outputs

Every capture run emits a private review packet:

- review_findings.csv — one row per Trivy or Semgrep finding. This is the primary analyst worksheet.
- scan_manifest.csv — one row per package release attempted, including failures and finding counts. Use this to verify coverage.
- run_summary.json — run counts and automation state.

The CSV is UTF-8 with BOM so it opens cleanly in Excel.

## review_findings.csv inspection fields

Every row includes enough immutable evidence to inspect the published package before making a decision:

- Run identity: run_id, run_started_at_utc, finding_id, finding_fingerprint, triage_priority.
- Package identity: registry, event_type, package_name, package_version, PURL, publication time, first-seen time.
- Artifact integrity: artifact filename, source URL, SHA-256, byte size, and registry digest when available.
- Scanner identity: scanner, scanner_version, rule_id, and ruleset_hash.
- Finding classification: finding_class, vulnerability_id, advisory_source, advisory_url, severity, confidence, novelty_state, CVSS, CWE.
- Exact inspection location: file_path, start_line, end_line.
- Dependency context: dependency_name, installed_version, fixed_version.
- Evidence: title, message, evidence, source, sink, known_dependency, suspicious_package.
- Dedup state: dedup_status, dedup_sources, dedup_identifiers, dedup_checked_at_utc.

The analyst section is on the same row:

- review_status: PENDING, IN_REVIEW, VALIDATED, REJECTED, KNOWN, or DEFERRED.
- reviewer: reviewer identity.
- reviewer_decision: concise result such as confirmed, not_reachable, known_cve, or not_security_relevant.
- reviewer_notes: evidence-based reasoning.
- reachability_verified: true only when the relevant path is reachable or meaningfully exposed.
- security_boundary_verified: true only after a real confidentiality, integrity, or availability boundary is confirmed.
- affected_version_verified: true only after the exact published artifact/version is confirmed affected.
- known_advisory_verified: true only after checking whether the same vulnerability is already known.
- false_positive_reason: required when rejecting a row.
- verified_at_utc: timestamp of final manual review.
- disclosure_status: remains NOT_READY until a separate disclosure process is intentionally started.
- disclosure_reference: private tracking reference.

A row cannot pass the review validator as VALIDATED unless all four verification booleans are true and reviewer identity, decision, notes, and timestamp are present.

## Finding interpretation

### Trivy

Known dependency vulnerabilities are emitted as known_dependency_vulnerability with the CVE/advisory ID, installed version, fixed version, severity, CVSS where available, and the dependency/manifest target. These rows are marked KNOWN_EXACT because Trivy is reporting an existing advisory.

A Trivy dependency CVE is useful package intelligence but is not a novel CVE candidate by itself.

### Semgrep

Semgrep rows are static candidates. They carry exact path, line, evidence, rule ID, ruleset hash, category, CWE where defined, and confidence.

They remain unreviewed and NOT_CHECKED until manual verification and advisory-dedup enrichment are complete.

Reverse-shell indicators are explicitly marked suspicious_package=true and should be handled as suspicious/malicious-package intelligence rather than automatically treated as CVE candidates.

## Review validation

After editing a review CSV, run:

    huginn-review-validate reports/<run-id>/review_findings.csv

The validator rejects incomplete VALIDATED rows and requires a false-positive reason for REJECTED rows.

## Workflow safety gate

The GitHub workflow supports manual workflow_dispatch runs immediately.

An hourly schedule is defined, but scheduled capture runs only when the private repository variable HUGINN_SCHEDULE_ENABLED is exactly true. This permits several manual review cycles before unattended capture is enabled.

The workflow does not submit findings to a CNA, MITRE, NVD, a vendor, or any public endpoint.

## Isolation

Package artifacts are downloaded as opaque bytes. Parsing and extraction occur only inside rootless Podman with:

- no network;
- read-only container root;
- all capabilities dropped;
- no-new-privileges;
- PID, CPU, memory, and tmpfs limits;
- a short-lived named volume for extracted source;
- no container-engine socket inside the scan;
- no package execution or install scripts.

Trivy and Semgrep inspect the extracted tree with network disabled. The short-lived scan volume is deleted after each package.

## Current registry coverage

The first runnable capture slice enables:

1. PyPI newest-package and latest-update RSS feeds.
2. RubyGems latest and just-updated activity feeds.

npm remains the next adapter. Its current replication endpoint needs a durable cursor plus packument reconciliation, so it should be implemented explicitly rather than approximated with scraping or a lossy polling shortcut.

## Next implementation gate

Before scheduled capture is enabled, complete several manual runs and inspect:

- false-positive rate by Semgrep rule;
- package scan failure rate;
- average package size and scan time;
- manifest-to-findings coverage;
- whether the CSV evidence is sufficient to confirm or reject a finding without reopening raw scanner JSON.

After that baseline, add npm cursor-following and OSV/NVD/Red Hat/GHSA enrichment before any disclosure automation is considered.
