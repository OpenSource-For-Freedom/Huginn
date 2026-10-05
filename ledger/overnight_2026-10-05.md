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
| 06:38 | rubygems | 37273447211 | success | 16 | 0 | 0 | 0 | 0 | |
| 06:38 | crates | 37273444201 | success | 21 | 0 | 0 | 0 | 0 | |
| 06:38 | packagist | 37273468896 | gate failed | 40 | 25 | 25 | 0 | 0 | 5 failed at artifact_resolve (DiscoveryError: no version / dist host not allowed, i.e. policy skips); ledger still updated. Laravel `$request->query()` reads, date params validated + Carbon-normalised before DB::raw, Go template Query in a CLI scaffolder |
| 06:38 | npm | 37273444736 | success | 100 | 0 | 0 | 0 | 0 | 1 failed |
| 06:38 | pypi | 37273448279 | success | 80 | 31 | 31 | 0 | 0 | Repeats of earlier decisions (notebook UI rendering, configured hook/test commands, fixed-argv setup helpers) |
| 06:38 | go | 37273447176 | success | 100 | 1804 | 1804 | 0 | 0 | 1693 from one wiki engine and its mis-cased mirror path, 89 from another app: pgx constant SQL with bound args; test teardown innerHTML; KaTeX-port array sizing |
| 07:54 | all six | dispatcher | | | | | | | round 5 (last; go expected ~08:55) |
| 07:54 | crates | 37280438337 | success | 28 | 0 | 0 | 0 | 0 | |
| 07:54 | rubygems | 37280446988 | success | 53 | 0 | 0 | 0 | 0 | |
| 07:54 | packagist | 37280487587 | success | 40 | 58 | 58 | 0 | 0 | 1 failed. Laravel `$request->query()` reads into the query builder (bindings); validated report dates; path param with traversal checks |
| 07:54 | npm | 37280455144 | success | 100 | 0 | 0 | 0 | 0 | |
| 07:54 | pypi | 37280428961 | success | 100 | 13 | 13 | 0 | 0 | 1 failed. Repeats (notebook UI) and a deploy CLI using operator config |
| 07:54 | go | 37280447191 | success | 100 | 4 | 4 | 0 | 0 | Test kit constant SQL; agent tools fetching operator-supplied URLs |
| 08:52 | five (no go) | per-registry | | | | | | | round 6 (go skipped: could not finish by 10:00) |
| 08:52 | crates | 37286361626 | success | 13 | 0 | 0 | 0 | 0 | |
| 08:52 | rubygems | 37286364580 | success | 29 | 0 | 0 | 0 | 0 | |
| 08:52 | packagist | 37286367940 | success | 40 | 28 | 28 | 0 | 0 | 3 failed. Fleet-management webhooks (hash_equals token check, HMAC-signed links); dev-only SQL console gated on debug mode; repeats |
| 08:52 | npm | 37286370970 | success | 100 | 0 | 0 | 0 | 0 | |
| 08:52 | pypi | 37286373518 | success | 87 | 17 | 17 | 0 | 0 | 1 failed. Build tooling (vendored meson), benchmark caches, docs fixtures, a migration recipe docstring |

## Closing summary (written 09:55 UTC; no runs queued or in progress, nothing dispatched after 08:52)

- **Runs:** 33 registry runs over 6 rounds (rubygems 6, packagist 6, npm 6, crates 6, pypi 5, go 4).
- **Packages scanned:** 2045.
- **Candidates:** 2107; **rejected** 2106, **deferred** 1, **validated** 0. Queue has 0 PENDING rows.
- **New rows in `ledger/validated_findings.csv`:** none tonight (still HUGINN-2026-001 to 008; next ID HUGINN-2026-009).
- **Deferred:** nontainer 0.8.11 agentfs backend pickles kv values (guarded, not a regression of the fixed issue; open question
  on the cache trust boundary).
- **Failures:** packagist tripped the capture gate in rounds 1 and 4 (6 and 5 of 40 failed), from artifact_resolve
  DiscoveryError (no version / dist host not allowed: policy skips) and ScanError; the ledger still updated both times.
  pypi and go each ran 5 and 4 times because a long run was still in progress when the next round started.
  Single unscannable packages on npm, pypi and go. No timeouts.
- **Noise sources:** Go `tainted-sql-query` on any `.Query(` call (one wiki engine alone produced ~1,700 candidates via a
  mis-cased mirror path), PHP rule on Laravel `$request->query()`, test-teardown innerHTML. Proposal: count packagist
  policy refusals as skipped rather than failed, and tighten those three rules.
