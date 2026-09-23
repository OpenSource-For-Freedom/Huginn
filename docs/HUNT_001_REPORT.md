# Hunt 001 — Validation-Layer Baseline

**Run:** 35857568403  
**Scope:** npm + PyPI + RubyGems, 25 releases per ecosystem  
**Mode:** first publishes and new versions  
**Execution:** GitHub-hosted, rootless/no-network package scan boundary  
**Disclosure:** disabled  
**Automatic CVE submission:** disabled

## Result

Hunt 001 completed successfully across all three ecosystems.

| Metric | Result |
|---|---:|
| Package scans | 75 |
| Failed package scans | 0 |
| Findings | 32 |
| Advisory NO_MATCH findings | 32 |
| POSSIBLE_MATCH findings | 0 |
| KNOWN_EXACT findings | 0 |
| Lookup failures | 0 |
| Static source-to-sink/dataflow findings | 0 |
| High-value manual candidates | 0 |
| Needs reachability review | 31 |
| Noise-likely | 1 |

### npm

- 25 package releases scanned.
- 0 failed scans.
- 0 findings.

The npm cold-start path was changed before this hunt so a fresh state database inspects a bounded set of recent registry changes rather than only initializing a cursor.

### PyPI

- 25 package releases scanned.
- 0 failed scans.
- 32 findings.
- 0 source-to-sink/dataflow findings.
- 0 high-value manual candidates.

The findings were generic sink-only static patterns. The largest clusters were command-execution and dynamic-evaluation primitives in packages including auditcore, babelfishers, and opengate-rtion.

Because no configured taint/dataflow rule established untrusted input reaching those sinks, Huginn kept these rows in manual reachability review rather than treating them as validated vulnerabilities.

One docs/changelog finding was classified as NOISE_LIKELY. Follow-up tuning also added test-filename detection so files such as opengate_tests.py are deprioritized in future hunts.

### RubyGems

- 25 package releases scanned.
- 0 failed scans.
- 0 findings.

## Interpretation

Hunt 001 did not produce a validated novel vulnerability or a new CVE candidate suitable for disclosure.

That is a successful validation-layer result: advisory novelty alone did not promote sink-only scanner output into a vulnerability claim.

A row now requires stronger evidence before reaching the high-value queue, including combinations of:

- Semgrep source-to-sink/dataflow evidence;
- scanner confidence and severity;
- successful advisory lookups with no matching advisory;
- runtime artifact path rather than obvious test/example/docs noise;
- adjacent-version context when an earlier release exists.

Even HIGH_VALUE_MANUAL_CANDIDATE remains a manual-review state, not a confirmed CVE.

## Evidence quality follow-up

The hosted Semgrep JSON response used a placeholder rather than useful source lines in some findings. After this hunt, Huginn was changed to read a bounded, numbered source excerpt from the already-extracted package tree inside a no-network, read-only helper container.

Future review CSVs include an evidence_source field and prefer isolated_static_excerpt evidence. The source excerpt pipeline is covered by the deterministic scanner smoke test.

## Manual validation gate

A finding cannot be marked VALIDATED through huginn-review-validate unless:

- its automated validation state is reviewable;
- a reviewer supplies identity, decision, notes, and verification time;
- reachability_verified=true;
- security_boundary_verified=true;
- affected_version_verified=true;
- known_advisory_verified=true.

KNOWN, NOISE_LIKELY, and SUSPICIOUS_PACKAGE rows cannot be promoted directly to VALIDATED.

## Next hunt

The recommended next run remains review-first. Increase volume only after inspecting the top sink-only clusters and observing the next set of dataflow results with source excerpts.

No automatic disclosure or CVE request should be enabled from Hunt 001.
