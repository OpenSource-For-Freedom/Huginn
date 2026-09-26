# Huginn Manual Review Workflow

Huginn capture is intentionally review-first. A scanner finding is evidence to inspect, not an automatically validated vulnerability.

## Run outputs

Every capture run emits a private review packet:

- `review_findings.csv` — one row per Trivy or Semgrep finding. This is the primary analyst worksheet.
- `scan_manifest.csv` — one row per package release attempted, including failures and finding counts.
- `run_summary.json` — run counts, dedup totals, and automation state.

The CSV is UTF-8 with BOM so it opens cleanly in Excel.

## Registry capture

Huginn currently supports:

1. npm replication changes with a durable sequence cursor and packument reconciliation.
2. PyPI newest-package and latest-update feeds.
3. RubyGems latest and just-updated activity feeds.

The default `all` mode captures both first publishes and new versions.

### npm cursor safety

The first npm run initializes the replication sequence at the current registry position instead of attempting a full historical replay.

Later runs:

1. read changes after the stored sequence;
2. fetch the changed package packument;
3. reconcile exact version publication timestamps with a 24-hour overlap window;
4. let SQLite package/version identity remove repeats;
5. scan unseen releases;
6. advance the sequence checkpoint only when the batch has no failed scans.

If a scan fails, the checkpoint remains behind that page so the change can be replayed on the next run.

## review_findings.csv inspection fields

Every row includes immutable evidence needed to inspect the published package:

- Run identity: run ID, run time, finding ID/fingerprint, triage priority.
- Package identity: registry, event type, package name/version, PURL, publication time, first-seen time.
- Artifact integrity: artifact filename, source URL, SHA-256, byte size, and registry digest when available.
- Scanner identity: scanner/version, rule ID, and ruleset hash.
- Finding classification: finding class, vulnerability ID, advisory source/URL, severity, confidence, novelty state, CVSS, CWE.
- Exact location: file path and start/end line.
- Dependency context: dependency ecosystem, package name, installed version, and fixed version.
- Evidence: title, message, evidence snippet, source, sink, known-dependency flag, suspicious-package flag.
- Dedup summary: dedup status, sources, identifiers, check time, and match basis.
- Per-source enrichment:
  - `osv_status`, `osv_ids`
  - `ghsa_status`, `ghsa_ids`
  - `nvd_status`, `nvd_ids`
  - `redhat_status`, `redhat_ids`
  - `advisory_cves`, `advisory_cwes`
  - `enrichment_status`, `enrichment_error`

The analyst fields remain on the same row:

- `review_status`: PENDING, IN_REVIEW, VALIDATED, REJECTED, KNOWN, or DEFERRED.
- `reviewer`
- `reviewer_decision`
- `reviewer_notes`
- `reachability_verified`
- `security_boundary_verified`
- `affected_version_verified`
- `known_advisory_verified`
- `false_positive_reason`
- `verified_at_utc`
- `disclosure_status`
- `disclosure_reference`

A row cannot pass the validator as VALIDATED unless all four verification booleans are true and reviewer identity, decision, notes, and timestamp are present.

## Advisory enrichment and dedup semantics

Advisory lookups occur in the trusted controller only after the no-network scanner exits.

### OSV

Huginn queries the exact ecosystem + package + version.

### GitHub Global Security Advisories

Huginn queries the matching ecosystem using the exact `package@version` affect filter.

### NVD

NVD is used to corroborate/enrich CVE identifiers found by scanners or package-aware sources. Huginn does not use a loose NVD package-name search to suppress static findings.

An optional `NVD_API_KEY` may be configured. Without one, Huginn uses conservative client-side pacing.

### Red Hat Security Data

Red Hat is queried by exact CVE identifier for corroboration and additional CWE/context where available.

### Dedup states

- `KNOWN_EXACT` — an actual scanner/advisory identifier match, including a known dependency CVE.
- `POSSIBLE_MATCH` — an advisory affects the exact package/version, but Huginn cannot prove that the static finding is the same vulnerability.
- `NO_MATCH` — exact package/version queries found no matching advisory in the package-aware sources.
- `LOOKUP_FAILED` — both package-aware sources failed; the row remains unreviewed.

A Semgrep finding is never automatically changed to KNOWN_EXACT merely because the release has another advisory.

`dedup_match_basis` explains the decision, for example:

- `scanner_identifier`
- `package_version+cwe`
- `package_version`
- `exact_package_version_no_advisory`
- `lookup_failed`

## Finding interpretation

### Trivy

Known dependency vulnerabilities carry the vulnerability identifier, dependency ecosystem, installed version, fixed version, severity, CVSS where available, and dependency/manifest target.

A Trivy dependency CVE is useful package intelligence but is not a novel CVE candidate by itself.

### Semgrep

Semgrep findings carry exact path, line, evidence, rule ID, ruleset hash, category, CWE where defined, and confidence.

After enrichment:

- `NO_MATCH` is a stronger manual-review candidate, not proof of a new vulnerability.
- `POSSIBLE_MATCH` means inspect the existing advisory before deciding novelty.
- `KNOWN_EXACT` requires an actual identifier match and is not assigned to ordinary static overlaps.

Reverse-shell indicators remain suspicious-package intelligence and are not automatically CVE candidates.

## Manual verification

For a candidate to become VALIDATED, manually verify:

1. the exact published artifact and SHA-256;
2. the exact source location;
3. that the vulnerable path ships in the package;
4. attacker-controlled/untrusted input reachability where applicable;
5. the security-sensitive sink or trust-boundary crossing;
6. a concrete confidentiality, integrity, or availability impact;
7. the exact affected version;
8. existing advisories and aliases across the enrichment sources.

Then fill the analyst fields and run:

    huginn-review-validate reports/<run-id>/review_findings.csv

The validator rejects incomplete VALIDATED rows and requires a false-positive reason for REJECTED rows.

## Workflow safety gate

Manual `workflow_dispatch` runs are enabled.

The hourly schedule runs only when the private repository variable `HUGINN_SCHEDULE_ENABLED` is exactly `true`.

The workflow does not submit findings to a CNA, the CVE Program, NVD, a vendor, or a public endpoint.

## Isolation

Untrusted package artifacts are parsed and scanned only inside rootless Podman with:

- no network;
- read-only container root;
- all capabilities dropped;
- no-new-privileges;
- PID, CPU, memory, and tmpfs limits;
- short-lived extracted-source storage;
- no container-engine socket;
- no package execution or install scripts.

Trivy receives a disposable copy of the trusted vulnerability database for each scan. An untrusted scan cannot modify the persistent database used by later runs.

## Manual test sequence before enabling the schedule

1. Run npm once to initialize its replication cursor.
2. Run npm again after new registry activity exists.
3. Run PyPI and RubyGems with a small limit.
4. Verify every `scan_manifest.csv` row is either intentionally failed or completed.
5. Sort `review_findings.csv` by dedup status and priority.
6. Manually inspect several KNOWN_EXACT dependency CVEs to validate source enrichment.
7. Inspect POSSIBLE_MATCH rows against the linked advisory data.
8. Manually verify NO_MATCH static candidates before labeling any as a new vulnerability.
9. Tune high-noise rules before setting `HUGINN_SCHEDULE_ENABLED=true`.

No automatic CVE request or disclosure is part of this stage.


## Security weakness and coverage-alert scope

Huginn's static hunt now treats these as separate evidence classes:

- memory safety: unsafe C/C++ buffer operations and allocation arithmetic;
- resource exhaustion / denial of service, including attacker-controlled allocation and regex patterns;
- command execution and dynamic evaluation;
- unsafe deserialization;
- SSRF;
- path traversal / attacker-controlled filesystem access;
- SQL injection;
- XSS;
- hard-coded secret exposure through Trivy secret scanning;
- suspicious-package indicators.

A static match is still only a candidate until reachability, security boundary, affected version, and impact are verified.

Operational failures are not CVEs. They are emitted to `operational_alerts.csv` because they can create a blind spot in the hunt. Alerted conditions include registry discovery failures, package/artifact scan failures, advisory API retrieval failures, and failed adjacent-version comparisons.

A critical ecosystem coverage failure or failed package scan makes that matrix leg fail after its review packet is written. High-severity partial advisory failures remain visible as workflow warnings and in the operational alert CSV.

## Repository CVE ledger

After every hunt on `Primary`, the aggregate job runs `scripts/update_cve_ledger.py` and commits three static CSVs to the `huginn-ledger` branch under `ledger/`:

- `cve_ledger.csv` — true positives only, severity LOW through CRITICAL, with every column filled. A row enters the ledger in one of two ways:
  - `ADVISORY_EXACT_MATCH`: the shipped dependency version is an exact advisory match (`dedup_status=KNOWN_EXACT`) for a CVE or GHSA identifier. These are known, public CVEs present in the package, not novel findings.
  - `ANALYST_VALIDATED`: an analyst set `review_status=VALIDATED` on a row in `candidate_queue.csv` and the row passes `huginn.review_validate`, so all four verification booleans are true and reviewer identity, decision, notes and timestamp are present.
  Facts that no advisory publishes are written as explicit values (`NOT_PUBLISHED`, `NO_FIX_AVAILABLE`, `NOT_APPLICABLE`), never left blank. Repeat sightings update `last_seen_*` and `times_seen`.
- `candidate_queue.csv` — `HIGH_VALUE_MANUAL_CANDIDATE` rows with the full review columns, deduplicated by finding fingerprint. Analyst edits to the review fields survive later hunts.
- `run_log.csv` — one fully populated row per hunt.

Sink-only scanner output never enters the ledger automatically. The job fails, and pushes nothing, if the ledger would contain a blank cell or a validated row that fails review validation.
