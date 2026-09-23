# Huginn Implementation Report — Review-First CVE Capture

## Status

This implementation establishes the first runnable private capture slice for Huginn.

It is intentionally not a CVE-submission system. It captures evidence, normalizes scanner output, and creates analyst-ready CSV files so findings can be manually verified before any later automation is enabled.

## Implemented

### Registry discovery

Active adapters:

- PyPI latest updates feed for new versions.
- PyPI newest packages feed for first publishes.
- RubyGems just-updated activity feed for new versions.
- RubyGems latest activity feed for first publishes.

Release identity is persisted in a local SQLite database using registry + package name + version so completed releases are not rescanned on every poll.

### Artifact handling

For each unseen release Huginn:

1. resolves a published package artifact;
2. downloads the artifact as opaque bytes;
3. calculates SHA-256 during download;
4. verifies PyPI registry SHA-256 when supplied;
5. enforces a default 100 MiB compressed artifact limit;
6. sends the artifact to the isolated unpack/scan boundary.

No package installation or package code execution is performed.

### Archive safety

Archive parsing happens inside the rootless Podman boundary.

The extractor rejects:

- absolute paths;
- parent-directory traversal;
- tar links;
- ZIP symlinks;
- device and FIFO entries;
- excessive file counts;
- excessive expanded size;
- unsupported archive types.

RubyGem payload extraction is handled without invoking gem install.

### Static scanning

Pinned initial scanner versions:

- Trivy 0.74.0
- Semgrep 1.177.0
- Python 3.13 slim image for isolated extraction

The scanner containers have no network access and run with a read-only root filesystem, dropped capabilities, no-new-privileges, PID limits, CPU limits, memory limits, and short-lived scan storage.

Trivy captures known dependency vulnerabilities and supported misconfiguration findings.

Semgrep uses a local versioned ruleset so untrusted scan containers do not need network access to fetch rules.

### Review CSV

Each run produces review_findings.csv.

The CSV includes run identity, package identity, PURL, publication and first-seen timestamps, artifact URL/hash/size, scanner version, rule ID, rule-set hash, finding class, CVE/advisory ID, severity, confidence, novelty state, CVSS, CWE, exact file/line, dependency and fixed-version details, evidence, source/sink description, suspicious-package flag, dedup state, and all manual review fields on the same row.

Every row starts in PENDING review state.

### Scan manifest

Each run also produces scan_manifest.csv with one row per attempted package release.

It records artifact identity, scan start/finish, scanner exit codes, finding count, final scan status, and errors.

This prevents an empty findings CSV from being mistaken for complete clean coverage when packages actually failed to scan.

### Manual validation gate

huginn-review-validate checks an edited review_findings.csv.

VALIDATED rows require:

- reviewer identity;
- reviewer decision;
- reviewer notes;
- verified timestamp;
- reachability_verified=true;
- security_boundary_verified=true;
- affected_version_verified=true;
- known_advisory_verified=true.

REJECTED rows require a false-positive reason.

### GitHub Actions workflow

The private workflow supports manual workflow_dispatch capture runs.

An hourly schedule is present but is disabled by default. Scheduled capture only runs when the repository variable HUGINN_SCHEDULE_ENABLED is true.

The job requires a self-hosted Linux runner carrying the huginn label and rootless Podman.

Each successful run uploads the private review packet as a GitHub Actions artifact with 30-day retention.

No automatic disclosure or CVE submission is implemented.

## CSV review contract

The analyst-facing CSV is the current source of truth for manual validation.

Immutable evidence should not be edited. Review fields may be completed during inspection.

The combination of finding_fingerprint + artifact_sha256 identifies the specific scanner observation against the exact published artifact.

Before a row becomes a confirmed vulnerability candidate, the reviewer should verify:

1. exact artifact/version;
2. exact file and line;
3. finding semantics;
4. input/source reachability;
5. security-sensitive sink or boundary;
6. real confidentiality, integrity, or availability impact;
7. whether the affected path ships in the package;
8. affected-version scope;
9. whether an existing advisory already covers the same vulnerability.

## Remaining before unattended triage

### npm follower

npm remains the highest-priority missing registry adapter.

The current npm replication API no longer supports include_docs on the changes endpoint, so the adapter needs:

- persistent replication sequence cursor;
- current changes pagination;
- packument fetch from registry.npmjs.org;
- release-time reconciliation;
- overlap handling for replication/CDN lag;
- protection against replaying a package's historical versions.

This should be implemented next rather than approximated with scraping.

### Advisory enrichment

Semgrep/static candidates still need explicit cross-reference enrichment against:

- OSV.dev;
- NVD;
- Red Hat Security Data;
- GitHub Global Security Advisories.

The CSV schema already contains the dedup columns needed for this stage.

The enrichment layer must distinguish exact known matches from possible package/version matches. A package-level advisory hit must not automatically suppress a different novel weakness.

### Rule maturity

The initial local Semgrep rules are deliberately small and conservative.

Before scheduled capture is enabled, measure per-rule false-positive rates and replace generic heuristics with language-aware dataflow rules where practical.

### Queue and retry maturity

The SQLite state currently tracks release completion/failure. The requirements document's full leased-job queue, retry scheduling, backoff, registry cursors, and retention service remain the target for the next implementation phase.

### Review interface

CSV is intentionally the first review interface.

The planned local TUI can be added after the CSV schema stabilizes so the TUI does not become a second competing source of truth.

## Recommended activation sequence

1. Merge this capture slice.
2. Configure a dedicated rootless self-hosted runner with the huginn label.
3. Run manual PyPI capture with a small limit.
4. Inspect review_findings.csv and scan_manifest.csv.
5. Tune rules and resource limits from observed false-positive/failure rates.
6. Run manual RubyGems capture.
7. Add npm follower support.
8. Add OSV/NVD/Red Hat/GHSA dedup enrichment.
9. Run several more manual review cycles.
10. Only then set HUGINN_SCHEDULE_ENABLED=true.

Automatic CNA/CVE submission remains outside this activation sequence.
