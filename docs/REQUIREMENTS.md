# Huginn — Project Requirements

**Repository:** OpenSource-For-Freedom/Huginn  
**Owner:** OpenSource-For-Freedom  
**Classification:** Private  
**Operating model:** Continuous static analysis only. No package execution, detonation, emulation, install-script execution, or behavioral sandboxing.

Huginn is an independent package-registry reconnaissance tool. It continuously scouts newly published public packages and package versions, performs static security analysis, cross-references known vulnerability sources, and presents only novel, high-confidence candidates for manual review. Huginn does not automatically request CVEs or disclose findings.

---

# Phase 1 — Planning

## 1.1 Registry scope and priority

Huginn SHALL implement registry support in this order:

### Priority 1 — npm

**Why first**
- npm has very high publication velocity and a broad JavaScript/TypeScript package ecosystem.
- The registry exposes a replication/follower model suitable for continuous discovery.
- JavaScript packages frequently contain install-time and runtime code paths that static rules can inspect without executing them.
- Semgrep and Trivy provide strong coverage for the JavaScript/TypeScript ecosystem.

**Discovery requirement**
- Use the npm replication/follower feed as the primary discovery source.
- Treat a registry document change as a discovery signal, not automatically as a new release.
- Compare registry version/timestamp metadata against Huginn's local state to determine whether the event represents a previously unseen version.

### Priority 2 — PyPI

**Why second**
- PyPI has high package and release volume, strong relevance to server-side and automation software, and excellent artifact availability.
- PyPI exposes separate feeds for newest projects and latest release updates, which maps directly to Huginn's first-publish vs. new-version distinction.
- Python is well supported by Semgrep and dependency scanners.

**Discovery requirement**
- Use the PyPI newest-packages RSS feed for first-publish events.
- Use the PyPI latest-updates RSS feed for release events.
- Use the PyPI JSON/Index APIs only to enrich a discovered project/release and resolve exact downloadable artifacts.

### Priority 3 — RubyGems

**Why third**
- RubyGems has a clean API distinction between newly added gems and recently updated gems.
- The volume is expected to be materially lower than npm and PyPI, making it a good third ecosystem for validating multi-registry behavior without overwhelming the host.
- Ruby remains relevant to web-facing applications where injection, deserialization, command execution, and XSS findings can be meaningful.

**Discovery requirement**
- Use the RubyGems latest-activity endpoint for first-publish events.
- Use the just-updated endpoint for new-version events.
- Resolve an exact version artifact before enqueueing a scan.

### Later expansion

After npm, PyPI, and RubyGems remain stable under the configured host resource budget, Huginn MAY add adapters in roughly this order:

1. crates.io
2. Packagist
3. Maven Central
4. NuGet
5. Go module sources/proxy feeds

Expansion SHALL be gated by:
- reliable release discovery;
- deterministic artifact retrieval;
- language coverage in Semgrep;
- dependency coverage in Trivy;
- acceptable local scan cost;
- package identity support using Package URLs (PURLs);
- a queue age that remains within the configured service-level target.

Huginn SHALL NOT enable every supported registry merely because an API exists. Registry expansion is a capacity decision.

## 1.2 Precise definition of "new"

Huginn SHALL distinguish two event types.

### NEW_PACKAGE

A package is NEW_PACKAGE when Huginn observes the first published release of a package identity that has never existed in that registry before.

Identity key:

`registry + normalized_package_name`

Examples:
- npm scoped names preserve scope.
- PyPI names are normalized according to Python packaging normalization rules.
- RubyGems names use the registry canonical gem name.

### NEW_VERSION

A release is NEW_VERSION when:
- the package identity is already known; and
- the exact registry version has not previously been recorded by Huginn.

Release identity key:

`registry + normalized_package_name + normalized_version`

A registry metadata update that does not add a previously unseen version SHALL NOT create a NEW_VERSION scan job.

### Expected volume behavior

Huginn SHALL assume NEW_VERSION traffic will substantially exceed NEW_PACKAGE traffic because established packages may publish repeatedly while a package can only be first-published once.

The system SHALL maintain separate queue classes for:
- first-publish scans;
- new-version scans;
- retries.

Default scheduling policy:
- reserve capacity for NEW_PACKAGE so first publishes cannot be starved by release churn;
- process NEW_VERSION continuously with remaining capacity;
- do not drop events when the scanner is saturated; persist them and apply backpressure.

The exact ratio SHALL be configurable because actual registry traffic changes over time.

## 1.3 What constitutes a reportable finding

A scanner match alone SHALL NOT be considered reportable.

A finding becomes a **NOVEL_CANDIDATE** only when all of the following are true:

1. **Published artifact**
   - The affected code is present in an actual published registry artifact.
   - The artifact hash and registry metadata are recorded.

2. **Security impact**
   - The behavior crosses a meaningful security boundary or can cause a concrete confidentiality, integrity, or availability impact.
   - Examples include attacker-influenced command execution, exploitable injection, unsafe deserialization with a plausible attacker-controlled path, authentication/authorization bypass, sensitive data exposure, or exploitable XSS in a shipped web-facing path.

3. **Package-attributable**
   - The weakness is attributable to the package's own shipped code or its insecure default behavior.
   - A known vulnerable transitive dependency is not a new Huginn vulnerability candidate unless the package itself introduces a separate vulnerability.

4. **Static evidence**
   - The finding has a stable file path, line/range, rule identifier, and evidence snippet.
   - Where applicable, the reviewer can identify the input/source, security-sensitive sink, and intervening code path by inspection.

5. **Released-path relevance**
   - The affected code is not solely in tests, examples, benchmarks, fixtures, generated docs, or dead/unreachable sample code unless the package actually ships and exposes that path as product behavior.

6. **Novelty**
   - NVD, OSV, Red Hat Security Data, and GitHub Global Security Advisories do not contain an exact or strongly supported advisory covering the same package/version/weakness.
   - Name-only or fuzzy matches SHALL NOT auto-dismiss a finding.

7. **Manual confirmation**
   - A reviewer explicitly marks the finding as confirmed after inspecting the artifact and the normalized scanner evidence.

### Findings that SHALL NOT enter the CVE candidate queue

The following SHALL be routed elsewhere or closed as noise:
- scanner parse failures;
- formatting/style issues without security impact;
- known dependency CVEs;
- duplicates of an existing advisory;
- test/example-only findings with no shipped exposure;
- hardcoded-secret heuristics without enough context to establish a security issue;
- intentionally malicious package behavior detected by reverse-shell or malware-like indicators;
- suspicious obfuscation by itself;
- generic misconfiguration warnings with no package-specific security boundary;
- a package name similarity match that is not supported by version and vulnerability evidence.

Malicious-package indicators MAY be retained in a separate **SUSPICIOUS_PACKAGE** queue. They SHALL NOT be presented as novel CVE candidates merely because malware-like code was found.

## 1.4 Severity, confidence, and novelty ranking

Each normalized finding SHALL have three independent dimensions:

### Severity
Estimated potential impact:
- critical
- high
- medium
- low
- informational

Severity SHALL describe technical impact only. It SHALL NOT be used as a substitute for exploitability or confidence.

### Confidence
How strongly the static evidence supports a real security issue:
- high: direct source/sink or unmistakable vulnerable construct in a shipped path;
- medium: credible construct requiring manual reachability/context validation;
- low: heuristic indicator, suspicious string, weak pattern, or incomplete data flow.

### Novelty
- novel: no supported known-advisory match;
- possible_match: fuzzy/name-only/advisory ambiguity;
- known: exact known advisory or CVE match.

Default queue behavior SHALL show:
1. novel + high confidence + critical/high severity;
2. novel + high confidence + medium severity;
3. novel + medium confidence;
4. possible_match items;
5. known items only on demand.

A known match SHALL be deprioritized, not deleted, so dedup decisions remain auditable.

## 1.5 Manual review and disclosure workflow

Huginn SHALL have no automatic CVE submission path in the initial release.

Required state machine:

`DISCOVERED -> SCANNED -> CANDIDATE -> REVIEWING -> CONFIRMED | REJECTED | KNOWN -> DISCLOSURE_READY -> DISCLOSED -> CLOSED`

### Step 1 — Candidate review

Reviewer SHALL verify:
- exact registry/package/version;
- artifact cryptographic hash;
- exact file and line/range;
- scanner rule and raw scanner evidence;
- whether the file is shipped product code;
- whether attacker-controlled or untrusted input can plausibly reach the vulnerable behavior;
- whether impact is security relevant.

### Step 2 — Clean-artifact revalidation

Before disclosure, Huginn SHALL:
- re-fetch registry metadata;
- verify the artifact hash against the originally scanned artifact when the registry provides a digest;
- re-run the relevant static rule set in a clean ephemeral scan environment;
- compare adjacent package versions when useful to identify introduction/fix boundaries;
- run the known-vulnerability dedup step again.

No package code SHALL be executed during revalidation.

### Step 3 — Evidence bundle

A confirmed finding SHALL produce a private evidence bundle containing:
- package PURL;
- registry URL/reference;
- affected version or version range;
- artifact SHA-256;
- finding type and CWE when justified;
- exact file and line/range;
- concise code evidence;
- source/sink or security-boundary explanation;
- impact statement;
- known-advisory search results and timestamps;
- reviewer notes;
- disclosure history.

The bundle SHALL avoid generating exploit payloads or proof-of-concept execution instructions by default.

### Step 4 — Supplier/project contact

The reviewer SHALL identify:
- project security policy;
- private reporting channel;
- supplier/vendor CNA, if one exists and is in scope.

The initial report SHALL be private and SHALL contain enough evidence for the maintainer to reproduce by source inspection.

### Step 5 — CNA/CVE Program path

After manual confirmation and private vendor contact:
- prefer the CNA with the most appropriate scope;
- if the supplier/project CNA declines, is out of scope, or no applicable supplier CNA exists, follow the CVE Program's appropriate CNA/Root/CNA-LR request path;
- do not submit a vulnerability to NVD as if NVD were the CVE assignment authority;
- keep disclosure and CVE-request actions manual and separately confirmed.

### Step 6 — Disclosure tracking

Huginn SHALL record:
- contact date;
- response state;
- maintainer acknowledgement;
- fix commit/release if provided;
- CVE reservation/assignment if provided;
- public disclosure date;
- closure reason.

Any disclosure deadline SHALL be a configurable operator policy rather than hard-coded into the scanner.

## 1.6 Resource constraints for continuous single-machine operation

Huginn SHALL favor bounded throughput over lowest possible latency.

Default operating profile:

- **Active package scan workers:** 1
- **Scanner subprocesses per package:** up to 2, allowing Trivy and Semgrep to run in parallel
- **Discovery HTTP concurrency:** small, bounded async pool
- **CPU:** scanner worker limited to a configurable host budget; default target no more than roughly half of logical CPU capacity and no more than 2 cores unless explicitly raised
- **Memory:** per-scan sandbox hard limit; default target 2 GiB, with a global configurable ceiling
- **Priority:** run scanner workers at reduced CPU/I/O scheduling priority when supported
- **Compressed artifact limit:** configurable; reject or defer unusually large artifacts
- **Expanded-size limit:** configurable hard cap to prevent archive bombs
- **File-count and path-depth limits:** configurable hard caps
- **Per-scan timeout:** configurable hard timeout
- **Disk spool quota:** configurable global quota with retention-driven purge
- **Backpressure:** discovery persists events even when scan workers are saturated

Huginn SHALL remain functional when scan throughput is lower than incoming registry traffic. It SHALL expose queue age, queue depth, scan duration, disk use, and resource-limit rejections so the operator can tune capacity instead of silently losing events.

---

# Phase 2 — Architecture

## 2.1 High-level flow

`Registry Pollers -> Discovery Store -> Durable Job Queue -> Artifact Fetch -> Ephemeral Static Scan Sandbox -> Normalization -> Advisory Dedup -> Ranking -> Review Queue`

The controller SHALL be the only long-running process that needs registry/advisory network access. Untrusted package scanning SHALL occur without network access.

## 2.2 Discovery service

Each registry SHALL implement a common adapter interface:

- `poll(cursor) -> discovery_events`
- `resolve_release(package, version) -> release_metadata`
- `fetch_artifact_metadata(package, version) -> artifact descriptors`

Each adapter SHALL persist:
- registry;
- canonical package name;
- observed version;
- event type;
- registry publication time when available;
- Huginn first-seen time;
- source cursor/sequence;
- artifact URL/reference;
- registry-provided digest when available.

### Cursor behavior

- npm adapter SHALL persist its replication sequence/cursor.
- PyPI adapter SHALL deduplicate RSS events against local release state because RSS is not a durable queue.
- RubyGems adapter SHALL deduplicate activity windows against local release state.

A restart SHALL resume from local state without reprocessing already completed release identities.

## 2.3 Local datastore and durable queue

Huginn SHALL use one local transactional datastore for:
- registry cursors;
- package/release identity;
- job queue;
- scan runs;
- findings;
- advisory cross-references;
- review state;
- retention metadata.

The queue SHALL use transactional leasing:
- pending;
- leased;
- complete;
- failed;
- deferred.

A crashed worker SHALL allow an expired lease to return to pending state.

No Redis, RabbitMQ, or external database SHALL be required for the default single-machine deployment.

## 2.4 Fetch/unpack service

Artifact fetch SHALL occur outside the untrusted scan sandbox only to the extent necessary to download opaque bytes and calculate hashes.

Controller responsibilities:
- validate scheme/host against the selected registry adapter;
- stream download with a byte limit;
- compute SHA-256 while streaming;
- compare registry-provided digest when available;
- store artifact as opaque content-addressed bytes;
- never import, install, source, require, or execute package contents.

### Unpacking rule

Unpacking SHALL occur only inside the ephemeral static-scan isolation boundary.

Before extraction, the worker SHALL inspect archive metadata and reject dangerous structures including:
- absolute paths;
- parent-directory traversal;
- device nodes;
- unreasonable nesting;
- configured size/file-count expansion limits;
- link targets that escape the extraction root.

Because archive parsers themselves process untrusted bytes, these checks do not replace isolation. The archive parser SHALL still run inside the sandbox.

## 2.5 Static scan sandbox

Each scan job SHALL create a fresh rootless isolated worker with:
- no network;
- read-only container root filesystem;
- no host home directory;
- no Docker/Podman socket;
- all Linux capabilities dropped;
- `no-new-privileges`;
- user namespace/rootless execution;
- seccomp confinement;
- PID limit;
- memory limit;
- CPU limit;
- ephemeral tmpfs working directory;
- package artifact mounted read-only;
- Semgrep rules mounted read-only;
- Trivy database mounted read-only;
- no writable host bind mount for the extracted tree.

The worker SHALL:
1. validate and unpack into tmpfs;
2. launch Trivy and Semgrep concurrently within the configured limits;
3. emit machine-readable results to stdout/pipe;
4. terminate;
5. destroy the tmpfs/extracted tree.

The extracted package tree SHALL never need to persist on the host filesystem.

## 2.6 Scan orchestration

### Trivy

Trivy SHALL be used for:
- known vulnerable dependencies;
- package dependency inventory;
- applicable static misconfiguration/security checks supported by the artifact type.

Known dependency vulnerabilities SHALL normally be classified as `known_context`, not novel Huginn candidates.

Trivy's vulnerability database SHALL be updated by a separate trusted maintenance task. The untrusted scan sandbox SHALL receive the database read-only and SHALL not download updates itself.

### Semgrep

Semgrep SHALL run:
- a small curated Huginn rule set;
- selected community rules;
- language-appropriate subsets only.

Initial rule categories:
- command/shell execution sinks;
- injection points;
- unsafe deserialization;
- hardcoded credentials/secrets indicators;
- dangerous dynamic evaluation;
- filesystem/path traversal opportunities;
- SSRF-relevant request construction where statically meaningful;
- XSS-relevant unsafe output/sanitization bypass patterns;
- reverse-shell/malware-like indicators for the separate suspicious-package queue.

Rules SHALL be versioned and pinned so a finding can be reproduced later.

### Parallelism

Trivy and Semgrep MAY run concurrently for the same extracted artifact, but the worker SHALL enforce one shared CPU/memory budget. Scanner-internal parallelism SHALL be limited so two scanners do not each assume they own the entire host.

## 2.7 Normalization layer

All scanner output SHALL map to one common finding schema.

Required normalized fields:
- finding_id;
- scan_run_id;
- scanner;
- scanner_version;
- rule_id;
- rule_version/ruleset hash;
- registry;
- package;
- version;
- PURL;
- artifact_sha256;
- category;
- CWE if justified;
- severity;
- confidence;
- file_path;
- start_line/start_column;
- end_line/end_column;
- evidence_snippet;
- source description when available;
- sink description when available;
- message;
- known_dependency flag;
- suspicious_package flag;
- raw_result_reference;
- created_at.

The normalized schema SHALL be stable even if Trivy or Semgrep changes its native JSON format.

## 2.8 CVE/advisory deduplication

Huginn SHALL cross-reference each candidate against:

1. **NVD** — primary CVE enrichment/reference source.
2. **OSV.dev** — package/ecosystem/version-aware advisory matching.
3. **Red Hat Security Data API** — additional CVE and package context.
4. **GitHub Global Security Advisories** — ecosystem/package mappings and GitHub-originated advisories.

### Matching order

Strong matches:
- same CVE/GHSA/OSV identifier already present in scanner output;
- exact PURL/package + affected version match from an ecosystem-aware advisory;
- exact NVD CPE/product/version match when a reliable CPE mapping exists.

Possible matches:
- normalized package name + overlapping version range;
- repository URL + weakness similarity;
- package name keyword match without reliable product mapping.

Weak/name-only matches SHALL never automatically mark a finding known.

### Result states

Each advisory lookup SHALL create an immutable cross-reference record with:
- source;
- advisory identifier;
- lookup timestamp;
- match type;
- match confidence;
- affected-version evidence;
- source URL/reference;
- result hash/cache key.

Dedup state:
- `KNOWN_EXACT`
- `KNOWN_PROBABLE`
- `POSSIBLE_MATCH`
- `NO_MATCH`
- `LOOKUP_FAILED`

Only `KNOWN_EXACT` SHALL automatically deprioritize a candidate as known. `KNOWN_PROBABLE` and `POSSIBLE_MATCH` require reviewer confirmation.

## 2.9 Review queue

The review queue SHALL contain only:
- novel candidates above the configured confidence floor;
- possible-match candidates needing a human dedup decision;
- explicitly requested suspicious-package findings.

Default columns:
- priority;
- registry;
- package;
- version;
- finding type;
- severity;
- confidence;
- novelty state;
- exact file:line;
- scanner/rule;
- first seen;
- review state.

Selecting a finding SHALL show:
- concise package/release metadata;
- artifact hash;
- exact evidence snippet with line numbers;
- scanner reasoning/message;
- dependency context where applicable;
- advisory lookup results;
- reviewer history.

The interface SHALL never execute package code.

## 2.10 Observability

Huginn SHALL expose local metrics/logs for:
- events discovered per registry;
- scans completed/failed/deferred;
- queue depth and oldest queue age;
- average and p95 scan duration;
- artifact size;
- resource-limit rejection count;
- Semgrep finding counts by rule;
- Trivy known-CVE counts;
- dedup API success/failure/latency;
- review outcomes and false-positive counts.

Metrics SHALL be local-only by default and SHALL NOT be exposed by the public promotional site.

---

# Phase 3 — Design

## 3.1 Data model

### packages

- `id`
- `registry`
- `canonical_name`
- `display_name`
- `first_seen_at`
- `registry_created_at`
- `project_url`
- `source_repository_url`
- `latest_seen_version`
- unique: `(registry, canonical_name)`

### releases

- `id`
- `package_id`
- `version`
- `purl`
- `event_type` — NEW_PACKAGE | NEW_VERSION
- `published_at`
- `first_seen_at`
- `artifact_url`
- `registry_digest`
- `artifact_sha256`
- `artifact_size`
- `status`
- unique: `(package_id, version)`

### discovery_cursors

- `registry`
- `cursor_value`
- `last_success_at`
- `last_error_at`
- `error_count`

### jobs

- `id`
- `release_id`
- `job_type`
- `priority`
- `state`
- `attempt_count`
- `not_before`
- `lease_owner`
- `lease_expires_at`
- `created_at`
- `updated_at`
- `last_error`

### scan_runs

- `id`
- `release_id`
- `started_at`
- `finished_at`
- `status`
- `sandbox_image_digest`
- `trivy_version`
- `trivy_db_version`
- `semgrep_version`
- `semgrep_ruleset_hash`
- `cpu_limit`
- `memory_limit`
- `timeout_seconds`
- `result_hash`
- `failure_reason`

### findings

- `id`
- `scan_run_id`
- `fingerprint`
- `scanner`
- `rule_id`
- `category`
- `cwe`
- `severity`
- `confidence`
- `novelty_state`
- `file_path`
- `start_line`
- `end_line`
- `message`
- `evidence_snippet`
- `known_dependency`
- `suspicious_package`
- `review_state`
- `created_at`

Fingerprint SHALL be deterministic enough to correlate the same rule/path/semantic location across rescans without assuming line numbers never move.

### advisory_xrefs

- `id`
- `finding_id`
- `source` — NVD | OSV | REDHAT | GHSA
- `advisory_id`
- `match_type`
- `match_confidence`
- `affected_range`
- `lookup_at`
- `source_reference`
- `raw_cache_key`

### review_actions

- `id`
- `finding_id`
- `actor`
- `action`
- `notes`
- `created_at`

### disclosure_cases

- `id`
- `finding_id`
- `state`
- `vendor_contact`
- `vendor_contacted_at`
- `vendor_acknowledged_at`
- `cna`
- `cve_id`
- `fix_version`
- `public_at`
- `closed_at`
- `notes`

## 3.2 Orchestration recommendation

**Recommendation: durable queue-based orchestration with scheduled registry pollers and a single local worker pool.**

Why:
- registry discovery is fundamentally polling/follower based;
- scan work is bursty and much more expensive than discovery;
- a queue provides natural backpressure;
- SQLite gives durable restart behavior without a separate broker;
- retries and per-registry priorities are easy to model;
- the operator can pause scanners without losing discovery events;
- one-machine resource limits are simpler to enforce around a worker pool than around an event fan-out architecture.

### Scheduling model

- scheduled/follower jobs discover releases and commit them transactionally;
- each unseen release creates at most one scan job;
- worker leases one job;
- worker fetches the opaque artifact;
- worker starts isolated scan sandbox;
- normalized findings are committed transactionally;
- advisory dedup jobs run after normalization;
- qualifying candidates enter review state.

### Why not pure event-driven

A full event bus adds operational cost with little value on one machine. Registry feeds still need cursoring/polling, and local SQLite already provides durable event state.

### Why not cron-only

Cron is suitable for kicking pollers but not sufficient as the work coordinator because it does not provide durable per-release state, retries, leases, priorities, or backpressure.

## 3.3 Review queue interface

**Primary interface: local terminal UI (TUI).**

Requirements:
- bind to no TCP port;
- query SQLite read/write through the controller/review service;
- keyboard filtering by registry, severity, confidence, novelty, and state;
- side-by-side finding metadata and source snippet;
- one-key review actions with confirmation for state changes;
- external-editor integration MAY open a copied evidence file, never execute the package.

Recommended views:
1. Novel
2. Possible duplicates
3. Suspicious packages
4. Known/deprioritized
5. Rejected
6. Disclosure cases

## 3.4 Output formats

Huginn SHALL support:

### Normalized JSON
Canonical machine-readable internal format.

### JSON Lines
One normalized finding per line for local analysis and piping.

### SARIF 2.1.0
For compatibility with security tooling and offline review.

### Markdown evidence bundle
Human-readable disclosure/review artifact generated only after manual confirmation.

Markdown export SHALL include evidence and affected package metadata but SHALL not automatically include exploit payloads.

## 3.5 Configuration

Configuration SHALL use a local TOML file with:
- enabled registries;
- poll intervals;
- queue weighting;
- resource limits;
- retention;
- scanner rule selections;
- advisory-source enable/disable flags;
- local paths;
- logging level.

Secrets SHALL NOT be stored directly in the TOML file. The file SHALL reference secret names/locations only.

---

# Phase 4 — Security

## 4.1 Isolation boundary for unpacking and scanning

The package archive is untrusted from the first byte.

Required boundary:
- dedicated non-login host account for Huginn;
- rootless Podman preferred;
- pinned scanner image digest;
- no network inside scan container;
- read-only root filesystem;
- tmpfs extraction/work directory;
- artifact mounted read-only;
- rules and vulnerability DB mounted read-only;
- no writable host filesystem mount for package content;
- no container engine socket;
- no host PID/IPC namespace;
- drop all capabilities;
- no-new-privileges;
- seccomp profile;
- bounded PIDs, CPU, memory, temporary storage, file count, and wall-clock time.

Result transfer SHOULD use stdout/pipe or a narrowly controlled result channel rather than exposing a writable host directory to the untrusted archive.

The sandbox image SHALL NOT contain registry API tokens, NVD keys, GitHub tokens, SSH keys, cloud credentials, or the user's home directory.

## 4.2 Archive safety controls

Before extraction:
- validate archive type from content/magic, not filename alone;
- enforce compressed-size limit;
- inspect entry count;
- reject absolute paths;
- reject parent traversal;
- reject device nodes and special files not required for source scanning;
- validate symlink/hardlink targets;
- cap expanded bytes and nesting;
- reject malformed metadata when safe handling is uncertain.

Extraction SHALL still happen inside the isolation boundary because archive parser vulnerabilities are part of the threat model.

## 4.3 Credential handling

Most public-registry reads SHOULD use anonymous access when supported.

For APIs where credentials improve limits or are required:
- store secrets in the OS credential store/keyring or another local secret manager;
- never commit secrets to Git;
- never store tokens in scan artifacts;
- never pass advisory/API credentials into the untrusted scan sandbox;
- use the lowest-privilege token available;
- use a separate GitHub token for public advisory reads if authentication is enabled;
- rotate credentials independently of Huginn releases.

Environment variables MAY be used as an injection mechanism at process start, but long-lived plaintext `.env` files in the repository SHALL NOT be used.

Logs SHALL redact:
- authorization headers;
- API keys;
- signed URLs;
- cookies;
- secret values from configuration.

## 4.4 Rate limiting and backoff

Each remote service SHALL have an independent client-side rate limiter.

Required behavior:
- token-bucket or leaky-bucket request pacing per host;
- honor `Retry-After`;
- exponential backoff with full jitter for 429 and transient 5xx responses;
- bounded retry count;
- circuit-break/defer behavior for sustained failures;
- conditional requests using ETag/Last-Modified when supported;
- local caching of advisory lookups;
- batch OSV lookups where appropriate;
- persistent registry cursors so a restart does not replay the entire feed.

Huginn SHALL NOT assume an undocumented maximum rate. Defaults SHALL be conservative, and documented provider limits SHALL be configurable without code changes.

A rate-limit failure SHALL defer work, not drop the release.

## 4.5 Data retention and purge

Default retention policy:

### Extracted package trees
- retention: zero
- location: sandbox tmpfs only
- purge: destroyed when scan container exits

### Raw downloaded artifacts — clean/no candidate
- retention: 24 hours
- purpose: short retry window

### Raw downloaded artifacts — candidate under review
- retention: 30 days by default or until the case no longer needs revalidation
- content-addressed by SHA-256

### Raw scanner output
- retention: 30 days for rejected/noise items
- retention: 90 days for unresolved candidates

### Normalized findings and review history
- retention: long-term, because they are small and provide false-positive/dedup history

### Confirmed disclosure evidence
- retention: through disclosure closure plus a configurable archival period

### Advisory/API cache
- retention: short, source-specific TTL; refresh known-advisory status before disclosure

A daily purge task SHALL enforce both age-based retention and a global disk quota.

Deletion on SSD filesystems SHALL be treated as logical deletion; if confidentiality at rest matters, the Huginn data directory SHOULD reside on an encrypted filesystem because file-by-file secure erase is not reliable on modern storage.

## 4.6 Private/public separation

The private Huginn scanner and the public promotional site SHALL be separate systems.

Required controls:
- separate repositories;
- separate deployment identities/credentials;
- no shared database;
- no shared runtime API;
- no route from the public site to the Huginn controller;
- no public webhook into Huginn;
- no package/finding search endpoint exposed publicly;
- no live status endpoint sourced from private scanner state;
- no reuse of scanner secrets in the site deployment.

The promotional site SHOULD be a static site.

## 4.7 Public architecture disclosure rules

Public material MAY describe:
- that Huginn monitors public package registries;
- that analysis is static;
- that packages are isolated;
- that Semgrep/Trivy-style scanning and known-advisory dedup exist at a high level;
- that a human review/disclosure gate exists.

Public material SHALL NOT publish:
- private Semgrep rules;
- rule fingerprints;
- exact scoring thresholds;
- exact registry polling cadence;
- detailed dedup heuristics;
- archive limits;
- sandbox escape assumptions;
- package queue contents;
- findings under review;
- candidate package names;
- private disclosure cases;
- internal file paths;
- credentials, tokens, infrastructure addresses, or host details.

The public site SHALL use manually curated, sanitized architecture content. It SHALL NOT automatically mirror private repository documentation.

## 4.8 Supply-chain security for Huginn itself

Huginn SHALL:
- pin Python dependencies using hashes/lock files;
- pin scanner container image by digest;
- pin Trivy/Semgrep versions;
- record ruleset hashes per scan;
- verify downloaded scanner/database artifacts when upstream supports signatures/checksums;
- keep package scanning offline;
- run dependency/security updates as a separate trusted maintenance workflow;
- include tests for archive traversal, decompression limits, cursor replay, dedup ambiguity, and queue crash recovery.

## 4.9 Security boundaries and non-goals

Huginn SHALL NOT:
- execute install scripts;
- import discovered packages;
- run package tests;
- invoke package CLIs;
- emulate application requests against discovered code;
- detonate samples;
- generate or run exploit proof-of-concepts automatically;
- automatically disclose findings;
- automatically request CVEs;
- expose private findings through the promotional site.

---

# Recommended Tech Stack Per Component

| Component | Recommendation | Justification |
|---|---|---|
| Core controller | Python 3.13+ | Strong ecosystem for registry APIs, Semgrep integration, PURL handling, async I/O, local tooling, and fast iteration. |
| Async HTTP | `httpx` + `asyncio` | Connection pooling, timeouts, streaming downloads, async registry pollers, and straightforward per-host controls. |
| Data validation/schema | Pydantic v2 | Stable typed models for registry events, normalized findings, config, and scanner JSON normalization. |
| Local datastore | SQLite in WAL mode | Durable, transactional, lightweight, no daemon, appropriate for one machine. |
| ORM/migrations | SQLAlchemy 2.x + Alembic | Explicit schema, migrations, indexes, and testable transactions without requiring a database server. |
| Job queue | SQLite `jobs` table with transactional leases | Avoids Redis/Celery while still providing restart safety, retries, priorities, and backpressure. |
| Scheduler | APScheduler | Runs registry polling, advisory refresh, DB maintenance, and purge tasks in-process. |
| Package identity | `packageurl-python` | Normalizes cross-ecosystem identity for dedup and evidence bundles. |
| Registry adapters | Native HTTP clients per registry | Keeps registry semantics explicit; avoids opaque third-party scraping dependencies. |
| Artifact hashing | `hashlib.sha256` during streamed download | Low-memory content addressing and evidence integrity. |
| Archive preflight | Python archive metadata validation | Allows traversal/link/size checks before extraction while keeping actual extraction isolated. |
| Archive extraction | `bsdtar`/libarchive inside the sandbox | Mature multi-format handling; parser remains contained inside the untrusted boundary. |
| Isolation | Rootless Podman | Strong single-host isolation without giving package content access to a privileged container daemon. |
| Scanner 1 | Trivy | Dependency/CVE context, package inventory, and supported static/misconfiguration checks. |
| Scanner 2 | Semgrep | Custom and community static rules with exact file/line evidence and broad language support. |
| Trivy DB maintenance | Separate trusted updater job | Lets the package scan sandbox remain network-disabled. |
| Advisory source 1 | NVD API 2.0 | Primary CVE enrichment/reference data. |
| Advisory source 2 | OSV.dev API | Excellent package/ecosystem/version-aware vulnerability queries and batch support. |
| Advisory source 3 | Red Hat Security Data API | Independent CVE/package context and useful corroboration. |
| Advisory source 4 | GitHub Global Security Advisories REST API | Ecosystem-aware reviewed advisories plus GitHub-originated advisory coverage. |
| Normalized export | JSON + JSONL | Simple durable canonical output and easy local processing. |
| Interchange export | SARIF 2.1.0 | Standard static-analysis format for future integrations. |
| Review UI | Textual + Rich | Local-only TUI, no web server, fast filtering and evidence review with minimal attack surface. |
| Config | TOML + Pydantic Settings | Human-readable configuration with typed validation. |
| Secret storage | Python `keyring` backed by OS credential store | Keeps API keys out of the repo and config file. |
| Logging | stdlib logging or `structlog` JSON | Local searchable logs, easy redaction, low operational overhead. |
| Metrics | Local Prometheus-format file/localhost-only endpoint or SQLite metrics tables | Allows resource/queue tuning without publishing scanner state. If an HTTP endpoint is used, bind to localhost only. |
| Tests | pytest + Hypothesis + respx | Unit/property tests for archive safety, normalization, rate limiting, cursor replay, and API behavior. |
| Dependency locking | `uv` lock or equivalent hash-pinned lockfile | Reproducible private builds and lower supply-chain ambiguity. |
| Public promotional site | Separate static Astro site/repository | No backend or connection to Huginn; easy to publish sanitized high-level architecture only. |

## Initial implementation recommendation

For the first production-capable release, keep the deployment to five long-lived responsibilities inside one controller process plus ephemeral scan workers:

1. registry scheduler/adapters;
2. SQLite discovery/job store;
3. artifact fetcher;
4. rootless Podman static-scan worker;
5. dedup/review service.

Do not introduce Redis, Kubernetes, a message broker, or a remote database until a real scaling requirement exists.

## Acceptance criteria for v1

Huginn v1 is ready for continuous private use when:

- npm, PyPI, and RubyGems adapters survive restart without duplicate completed scans;
- first-publish and new-version events are distinguishable;
- package code never executes;
- unpacking and scanning occur in a no-network rootless sandbox;
- Trivy and Semgrep run concurrently within a shared resource budget;
- scanner output is normalized into one schema;
- NVD, OSV, Red Hat, and GitHub advisory checks are cached and auditable;
- known findings are deprioritized rather than discarded;
- only novel candidates above the confidence floor reach the default review queue;
- every candidate shows package/version, exact file/line, evidence, artifact hash, severity, confidence, and advisory-match state;
- manual review is required before disclosure state can advance;
- no automatic CNA/CVE submission exists;
- extracted files are ephemeral and purged at sandbox exit;
- retention and disk quota enforcement are automatic;
- the public promotional site has no technical path to the private scanner or its data.
