# Overnight hunt log — 2026-10-05 (03:54 UTC until 06:00 ET / 10:00 UTC)

Per-registry hunts on Primary (`hunt-each-registry.yml`, mode=all, limit=100), re-dispatched as registries finish.
Every candidate is triaged by static review in `ledger/candidate_queue.csv`. Validated findings are appended to
`ledger/validated_findings.csv` (one row per finding) and `ledger/disclosure_tracker.csv`, with a draft in
`docs/disclosures/`. Nothing is sent or published.

| Dispatched (UTC) | Registry | Run ID | Aggregate | Scanned | Candidates | Rejected | Deferred | Validated | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 03:55 | all six | dispatcher | | | | | | | round 1 |
| 03:55 | rubygems | 37261335332 | success | 62 | 0 | 0 | 0 | 0 | clean |
| 03:55 | packagist | 37261333451 | ledger updated (capture gate red: 6 of 40 failed) | 40 | 2 | 2 | 0 | 0 | 5 failed at static_scan (ScanError), 1 at artifact_resolve. Candidates: wpdb::prepare-bound lock name |
| 03:55 | npm | 37261311800 | success | 100 | 0 | 0 | 0 | 0 | 0 failed; 698 raw findings, no high-value candidates |
| 03:55 | crates | 37261320044 | success | 100 | 0 | 0 | 0 | 0 | 41 known-CVE rows |
| 03:55 | pypi | 37261318941 | success | 100 | 25 | 25 | 0 | 0 | 1 failed. Agent-runtime test teardown and own-kernel snapshots; local CLI/installer subprocesses |
| 03:55 | go | 37261319486 | success | 100 | 1 | 1 | 0 | 0 | 13,168 known-CVE rows; release-script regex |
| 04:47 | crates | 37265019275 | success | 17 | 0 | 0 | 0 | 0 | |
| 04:47 | rubygems | 37265017544 | success | 9 | 0 | 0 | 0 | 0 | |
| 04:47 | packagist | 37265020885 | success | 38 | 6 | 6 | 0 | 0 | Laravel CMS: `$request->query()` reads; app-key-gated monitoring SSO (hardening note only) |
| 04:47 | npm | 37265016078 | success | 100 | 0 | 0 | 0 | 0 | |
| 05:45 | all six | dispatcher | | | | | | | round 3 |
| 05:37 | packagist | 37268628482 | success | 0 | 0 | 0 | 0 | 0 | no new releases in window |
| 05:37 | rubygems | 37268618295 | success | 18 | 0 | 0 | 0 | 0 | |
| 05:37 | crates | 37268618311 | success | 14 | 0 | 0 | 0 | 0 | |
| 05:37 | npm | 37268622194 | success | 100 | 0 | 0 | 0 | 0 | |
| 05:37 | pypi | 37268613656 | success | 100 | 48 | 47 | 1 | 0 | 1 failed. Deferred: nontainer 0.8.11 new agentfs backend pickles kv values (guarded; not a regression; open cache trust question). Rest: local agent/CLI tools running operator commands |
| 05:37 | go | 37268623800 | success | 100 | 45 | 45 | 0 | 0 | 1 failed. Dev worktree scripts, non-SQL Query methods (ABCI, GraphQL, device), allow-listed grid filters |
| 06:50 | all six | dispatcher | | | | | | | round 4 (last that can finish before 10:00) |
