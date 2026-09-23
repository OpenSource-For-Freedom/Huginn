# Hunt 002 — Expanded Coverage Validation

**Run:** 35858572689  
**Scanner head:** 8f1150b25c77b0ce67be218664f6fb89b830e51b  
**Scope:** npm + PyPI + RubyGems, up to 25 unseen releases per ecosystem  
**Mode:** first publishes and new versions  
**Execution:** GitHub-hosted, Legion Runner first, rootless/no-network package scan boundary  
**Disclosure:** disabled  
**Automatic CVE submission:** disabled

## Result

Hunt 002 completed successfully across all three ecosystem matrix legs and the aggregate job.

| Metric | Result |
|---|---:|
| Package scans | 51 |
| Failed package scans | 0 |
| Findings | 64 |
| Known dependency CVEs | 18 |
| Advisory NO_MATCH static findings | 46 |
| POSSIBLE_MATCH | 0 |
| LOOKUP_FAILED | 0 |
| Static source-to-sink/dataflow findings | 0 |
| High-value manual candidates | 0 |
| Needs reachability review | 46 |
| Critical coverage alerts | 0 |
| High coverage alerts | 1 |

Persistent release state means the configured limit is a maximum number of unseen releases. RubyGems had only one unseen release available in this run, while npm and PyPI each scanned 25.

## Security findings

### Known dependency CVEs

PyPI package `inspect-robots-dreamscale 0.1.18` shipped a lockfile containing dependencies for which Trivy reported 18 known CVEs:

- CVE-2026-25990
- CVE-2026-40192
- CVE-2026-42308
- CVE-2026-42309
- CVE-2026-42310
- CVE-2026-42311
- CVE-2026-54058
- CVE-2026-54059
- CVE-2026-54060
- CVE-2026-55379
- CVE-2026-55380
- CVE-2026-55798
- CVE-2026-59197
- CVE-2026-59198
- CVE-2026-59199
- CVE-2026-59200
- CVE-2026-59204
- CVE-2026-59205

These rows include memory-safety, integer-overflow, resource-exhaustion, out-of-bounds, command-execution, and infinite-loop weakness classes in their upstream CWE metadata.

They remain `KNOWN` intelligence and are not novel Huginn CVE candidates.

### Static NO_MATCH findings

Huginn produced 46 static findings for which the exact package/version advisory lookup returned no package-aware match.

They were distributed across:

- npm: 28 dynamic-evaluation sink findings in `bluet-mcp` versions 0.3.0 through 0.4.2;
- PyPI: command-execution, unsafe-deserialization, and XSS sink findings in `archcheck`, `gitomb`, `search-gateway`, `volcengine-python-sdk-aicc`, and `webteam-agents`.

All 46 were classified `NEEDS_REACHABILITY_REVIEW`.

None had static source-to-sink evidence, so the automated validation layer correctly produced:

- `high_value_manual_candidate_count = 0`
- `static_dataflow_count = 0`

No finding from this run is presented as a newly discovered CVE.

For `bluet-mcp`, adjacent-version comparison also showed the generic dynamic-evaluation rule/path persisted across prior versions, reducing novelty confidence rather than escalating it.

## Expanded weakness coverage

The ruleset exercised by this hunt includes coverage for:

- C/C++ unsafe buffer operations — CWE-120;
- allocation arithmetic / integer overflow — CWE-190;
- resource exhaustion — CWE-400;
- regex resource exhaustion — CWE-1333;
- command execution — CWE-78;
- dynamic code execution — CWE-95;
- unsafe deserialization — CWE-502;
- path traversal — CWE-22;
- SSRF — CWE-918;
- SQL injection — CWE-89;
- XSS — CWE-79;
- suspicious reverse-shell indicators.

Trivy also runs vulnerability, misconfiguration, and secret scanners.

The absence of a finding for a weakness class in one 51-package sample does not mean that coverage is disabled. The deterministic engine gate must pass before each ecosystem hunt begins.

## Operational coverage alerts

Hunt 002 emitted one HIGH operational alert:

- ecosystem: PyPI
- source: NVD
- stage: advisory enrichment
- condition: HTTP 429 rate limiting
- impact: advisory deduplication was incomplete for affected enrichment work
- retryable: true

This is a hunt coverage failure, not a CVE.

The packet remains usable because package scanning succeeded and the affected rows already had Trivy CVE identifiers, but NVD corroboration must be retried before using NVD absence/presence as novelty evidence.

No package scan failed and no ecosystem-wide discovery failure occurred.

## Follow-up corrections validated after Hunt 002

Two correctness/evidence improvements were made after the broad run:

1. Trivy `uv.lock` results are mapped to the PyPI advisory ecosystem, removing the unnecessary dependency-ecosystem warning for uv-managed Python packages.
2. Semgrep findings now attach bounded source excerpts read from the already-extracted tree through an isolated read-only/no-network helper, rather than relying on incomplete scanner-provided line text.

The source-excerpt pipeline passed a separate three-ecosystem live smoke run, including a deterministic assertion that the command-execution fixture contained the expected static source excerpt.

Secret findings never write the raw secret value to CSV; only a SHA-256 fingerprint is retained.

## Decision

The validation layer behaved correctly:

- known dependency CVEs stayed known;
- sink-only NO_MATCH findings stayed in manual reachability review;
- no sink-only finding was promoted to a novel vulnerability;
- advisory API failure became a first-class operational alert;
- no automatic disclosure or CVE request occurred.

The next continuous hunt can remain at 25 unseen releases per ecosystem while analyst review focuses on source-to-sink/dataflow candidates first and sink-only findings second.
