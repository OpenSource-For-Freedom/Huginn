# Huginn Validation Pipeline

Huginn separates scanner evidence, advisory novelty, static reachability, and human validation. No single automated state is equivalent to a confirmed vulnerability or CVE.

## Pipeline

Registry discovery -> artifact integrity -> isolated static scan -> advisory enrichment -> adjacent-version comparison -> validation scoring -> analyst queue -> manual verification

## Reachability classes

- STATIC_DATAFLOW: a Semgrep taint/dataflow rule found a configured untrusted source reaching a security-sensitive sink.
- SINK_ONLY: a dangerous primitive exists, but Huginn has not established attacker-controlled input reaching it.
- DEPENDENCY_CONTEXT: a known dependency advisory reported by Trivy.
- STATIC_INDICATOR: suspicious/malware-like static indicator.
- UNKNOWN: manual inspection required.

STATIC_DATAFLOW increases confidence but does not prove exploitability, deployment exposure, or a security boundary.

## Validation states

### HIGH_VALUE_MANUAL_CANDIDATE

A high-scoring static finding with successful package/version advisory lookup and no matching advisory. Typical inputs include:

- source-to-sink dataflow;
- high scanner confidence;
- high severity;
- runtime package path;
- absent from the immediately previous version's same rule/path when comparison succeeds.

This state means review first. It does not mean a new CVE has been established.

### NEEDS_REACHABILITY_REVIEW

A potentially security-sensitive finding where source/reachability is incomplete, commonly a sink-only heuristic.

### NEEDS_DUPLICATE_REVIEW

The exact package/version has one or more existing advisories. A human must determine whether the static finding is the same vulnerability or a distinct weakness.

### NOISE_LIKELY

A lower-scoring finding with noise signals such as tests, examples, docs, generated/minified output, or a sink-only primitive with weak evidence.

### KNOWN

An exact known dependency/advisory identifier.

### SUSPICIOUS_PACKAGE

Malware/reverse-shell-like indicators. These are routed separately and are not automatically CVE candidates.

## Adjacent-version comparison

When a current release produces a reviewable Semgrep result, Huginn attempts to locate the immediately preceding published release using registry publication timestamps.

Both versions are handled statically. Huginn does not install or execute either package.

For each current Semgrep row:

- previous_version identifies the adjacent release;
- previous_compare_status is COMPLETE, UNAVAILABLE, FAILED, or NOT_NEEDED;
- previous_compare_error records a bounded failure reason;
- previous_finding_present=true means the same Semgrep rule ID and file path appeared in the previous release;
- previous_finding_present=false with COMPLETE means that exact rule/path combination was absent;
- version_delta becomes PRESENT_IN_PREVIOUS, INTRODUCED_OR_MOVED, FIRST_RELEASE_OR_UNAVAILABLE, or UNKNOWN.

Absence in the previous release is evidence for prioritization only. Code movement, renames, and equivalent vulnerable logic can produce false deltas.

## Scoring

The validation score is 0-100 and is used only for analyst queue ordering.

Positive signals include:

- Semgrep source-to-sink/dataflow evidence;
- high scanner confidence;
- higher severity;
- NO_MATCH from package/version advisory sources;
- absent same rule/path in the prior release.

Negative signals include:

- tests/examples/docs/generated/vendor paths;
- possible advisory overlap;
- incomplete advisory lookups;
- same rule/path present in the previous release.

The score cannot change a row's manual review status to VALIDATED.

## Manual promotion gate

A row cannot pass huginn-review-validate as VALIDATED unless:

- its automated validation state is reviewable rather than KNOWN, NOISE_LIKELY, or SUSPICIOUS_PACKAGE;
- reviewer identity, decision, notes, and timestamp are supplied;
- reachability_verified=true;
- security_boundary_verified=true;
- affected_version_verified=true;
- known_advisory_verified=true.

## Current dataflow rules

The local pinned Semgrep ruleset includes taint-mode rules for selected Python and JavaScript/TypeScript sources and sinks, including:

- Python untrusted input -> eval/exec;
- Python untrusted input -> command execution;
- Python untrusted input -> unsafe deserialization;
- JavaScript/TypeScript request or process input -> child-process execution;
- JavaScript/TypeScript request input -> HTML/DOM rendering sinks.

Generic sink-only rules remain as discovery heuristics and are deliberately scored below proven static dataflow.

## Non-goals

The validation layer does not:

- execute packages;
- establish dynamic reachability;
- prove exploitability;
- infer a security boundary automatically;
- assign CVSS automatically for novel candidates;
- submit or request CVEs;
- contact maintainers automatically.
