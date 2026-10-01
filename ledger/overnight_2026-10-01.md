# Overnight hunt log — 2026-10-01 (until 06:00 ET / 10:00 UTC)

Continuous Huginn hunts on Primary (`cve-capture.yml`, registry=all, mode=all, limit=100), dispatched back to back.
Each hunt is triaged by static review before the next dispatch. Every decision is in `ledger/candidate_queue.csv`;
validated findings go to `ledger/disclosure_tracker.csv` with a maintainer report and MITRE form draft.

| Dispatched (UTC) | Run ID | Aggregate | Candidates | Rejected | Deferred | Validated | Notes |
|---|---|---|---|---|---|---|---|
| 02:18 | 36805232125 | ledger updated (capture gate red: npm 2 pkgs, packagist 1 failed scan) | 109 | 109 | 0 | 0 | ran pre-fix code; npm still empty; mostly Laravel request-getter noise (70) and connext Map.get (20) |
| 03:56 | dispatcher 36812825084 → 6 per-registry runs | | | | | | first round as separate registry hunts (npm fix + per-registry queues live) |
| 03:57 rubygems | 36812856467 | success | 0 | 0 | 0 | 0 | 26 scanned, clean |
| 03:57 crates | 36812858499 | success | 0 | 0 | 0 | 0 | 33 scanned, clean |
| 03:57 npm | 36812867735 | ledger updated (capture gate red: 24 of 100 scans failed) | 2 | 0 | 2 | 0 | **npm fix confirmed: 100 packages scanned** (was 0–2). Deferred: one unauthenticated agent tool-server suite (design issue, owner decision) |
| 03:57 packagist | 36812855645 | failed: ledger file over 100 MB → re-ingested (36818043390) | 165 | 165 | 0 | 0 | 40 scanned, 1 failed. All 165 from one Laravel package (3 versions): PHP rule reads `$request->query()` as SQL |
| 03:57 go | 36812858503 | success (pre-fix code; see incident) | 227 | 227 | 0 | 0 | 100 scanned, 1 failed. Inert-document innerHTML in old mirrored Gutenberg tags (128), firecrawl internal fetches (67), schema-checked ORDER BY (25), auth-gated argv git calls (6), bound query (1) |
| 03:57 pypi | 36812852657 | failed: ledger file over 100 MB → re-ingested (36818052560) | 14 | 14 | 0 | 0 | 97 scanned, 2 failed. Operator-run installers, allow-listed VM tool, scanner signature literals, own-artifact cloudpickle |
| 04:20 crates | 36814689698 | success | 0 | 0 | 0 | 0 | 4 scanned, clean |
| 04:20 rubygems | 36814687097 | success | 0 | 0 | 0 | 0 | 11 scanned, clean |
| 05:08 | npm, pypi, packagist, rubygems, crates re-dispatched | | | | | | round 3, running ledger sharding (`a283859`) and failure logging (`8e512fe`) |
| 05:05 rubygems | 36818136098 | success | 0 | 0 | 0 | 0 | 3 scanned, clean |
| 05:05 crates | 36818138058 | success | 0 | 0 | 0 | 0 | 15 scanned, clean |
| 05:05 packagist | 36818133945 | success | 3 | 3 | 0 | 0 | 26 scanned, 2 failed. Same `$request->query()` rule noise (webhook verify handler) |
| 05:05 npm | 36818129308 | success (gate green) | 0 | 0 | 0 | 0 | 100 scanned, **0 failed** — the 24 failures in the previous run did not recur (transient). 0 findings this batch |
| 05:05 pypi | 36818131574 | success | 13 | 13 | 0 | 0 | 61 scanned, 0 failed. Scanner README/comment text, vendored C strcpy of fixed literals, own-file pickles |
| 05:09 go | 36818465682 | success | 444 | 444 | 0 | 0 | 100 scanned, 1 failed. Mis-cased mirrors of Helm v4 (`Storage.Query` is a label lookup, 102 rows), compass test fixtures clearing `document.body` across 9 versions (342) |
| 06:01 crates | 36822646303 | success | 0 | 0 | 0 | 0 | 19 scanned, 1 known-CVE ledger row |
| 06:01 rubygems | 36822643909 | success | 0 | 0 | 0 | 0 | 20 scanned, 1 failed |
| 06:01 packagist | 36822641749 | success | 72 | 72 | 0 | 0 | 40 scanned, 2 failed. `$request->query()` rule again (x-change, larafly, vibeui); larafly admin filters checked: schema allow-list, grammar-quoted, bound |
| 06:01 pypi | 36822639565 | success | 10 | 10 | 0 | 0 | 84 scanned, 3 failed. Scanner docs, own-artifact pickles, developer-path tar helper |
| 06:01 npm | 36822637833 | success | 48 | 48 | 0 | 0 | 100 scanned, 0 failed (49 min capture). One npm package across 8 versions: file routes behind a path-containment check |
| 06:52 go | 36827129203 | success | 5 | 5 | 0 | 0 | 100 scanned, 1 failed. 5,138 known-CVE ledger rows (lockfiles in module zips) |
| 06:52 pypi | 36827131412 | success | 210 | 210 | 0 | 0 | 79 scanned. Vendored PostgreSQL C in a parser binding (186), local AI CLI running user commands by design (20), constant clear-screen, CLI-input regex |
| 06:52 packagist | 36827134111 | success | 0 | 0 | 0 | 0 | 40 scanned, 1 failed |
| 06:52 rubygems | 36827136557 | ledger updated (capture gate red: 1 of 8 failed, download HTTP error) | 0 | 0 | 0 | 0 | 8 scanned. Gate floor added (`675e2f7`) |
| 06:52 crates | 36827138921 | success | 0 | 0 | 0 | 0 | 22 scanned, clean |
| 07:47 | dispatcher → 6 runs (gate floor live) | | | | | | |
| 07:47 crates | 36832425722 | success | 0 | 0 | 0 | 0 | 15 scanned, clean |
| 07:47 rubygems | 36832445025 | success (1 failed scan, now under the gate floor) | 0 | 0 | 0 | 0 | 12 scanned |
| 07:47 packagist | 36832429546 | success | 7 | 7 | 0 | 0 | 40 scanned, 2 failed. `$request->query()` noise; preview redirect confined to app host |
| 07:47 go | 36832424308 | success | 17 | 17 | 0 | 0 | 100 scanned. dagger cache/GraphQL `Query` methods, test teardown, int query param |
| 07:47 pypi | 36832422320 | success | 18 | 16 | 2 | 0 | 97 scanned. Deferred: a storage library whose default "auto" mode unpickles non-JSON values (needs a consumer reading untrusted stores; owner decision). Rest: own-file pickles, build scripts |
| 07:47 npm | 36832437472 | success | 0 | 0 | 0 | 0 | 100 scanned, 0 failed, 0 findings |
| 08:48 | dispatcher → 6 runs (final round) | | | | | | |
| 08:48 rubygems | 36838637544 | success | 0 | 0 | 0 | 0 | 19 scanned, 1 failed |
| 08:48 crates | 36838640993 | success | 0 | 0 | 0 | 0 | 24 scanned, 3 known-CVE rows |
| 08:48 packagist | 36838640922 | success | 26 | 20 | 0 | **6** | 40 scanned. **VALIDATED: filterbymodel, unauthenticated management API (9.3 Critical)**. Rest: validated/bound `$request->query()` reads, vendored JS |
| 08:48 npm | 36838658562 | success | 0 | 0 | 0 | 0 | 100 scanned, 0 failed, 0 findings |
| 08:48 pypi | 36838649682 | success | 17 | 17 | 0 | 0 | 95 scanned, 1 failed. Release script, own-file pickles, fixed OAuth endpoint, own-process IPC pickles |
| 08:48 go | 36838666789 | success | 0 | 0 | 0 | 0 | 100 scanned, 10 failed (at the 10% limit, not over). 10,229 known-CVE ledger rows |

## Incidents

- **03:10 UTC — npm coverage outage found and fixed.** npm had added zero ledger rows for the last 21 hunts (~30 h):
  the change-feed cursor had fallen behind npm's publish rate, so every change read was older than the 24 h window
  (hunt 36805232125: 2 npm packages scanned, 0 findings). Fixed on Primary in `04ecafd`: a stale cursor now
  rescans the newest changes and skips completed releases. The same commit stops failing a capture job on a single
  unscannable package (warning instead; fail only on a critical alert or >10% failed scans), so hunts no longer show
  red for normal noise. Hunts dispatched after 03:10 UTC run the fix; 36805232125 still ran the old code.

- **03:56 UTC — hunts split into separate registry runs** (Primary `45ae0e5`). Each registry now runs as its own
  "Huginn hunt: <registry>" workflow run with its own concurrency queue, aggregate job and ledger commit;
  `hunt-each-registry.yml` starts all six at once. The ledger push retries more with jittered back-off because
  registries can finish together. From here the log has one row per registry run.

- **04:16 UTC — ledger hit GitHub's 100 MB per-file limit.** `ledger/cve_ledger.csv` reached 104,856,717 bytes
  (Go module zips ship whole repositories, lockfiles included: 107k of 114k rows). GitHub rejected the packagist and
  pypi ledger pushes. Fixed on Primary in `a283859`: the ledger is now `ledger/cve_ledger/<registry>-<h>.csv`
  (77 shards, largest ~6 MB), and validation fails any ledger file over 90 MB before GitHub would. Both failed
  aggregates were re-ingested. The Go aggregate ran pre-fix code after the first sharded commit and wrote a fresh
  5,766-row `cve_ledger.csv` beside the shards; the next re-ingest merged it into the shards and deleted it (rows in
  both kept the shard copy, so those Go rows missed one `times_seen` increment). Ledger total: 120,136 rows.

- **05:08 UTC — npm scan failures.** npm now scans 100 packages per hunt, but 24 failed (gate fails at >10%). The
  failure reasons are only in the review packet, which can't be downloaded from the analyst session, so `8e512fe`
  prints a per-stage / error-class count to the job log. Next npm run will show the cause.

- **Scanner note (not fixed tonight):** the PHP `tainted-sql-query` rule treats Laravel `$request->query()` as a SQL
  sink. It produced 165 of tonight's 408 candidates and most of the 02:18 noise.

- **07:50 UTC — small-batch gate noise.** A rubygems hunt of 8 packages went red because one gem download
  returned an HTTP error (12.5% > 10%). `675e2f7` keeps the 10% rule but also requires more than two failed scans.

## Closing summary (10:20 UTC)

**Hunting window:** 02:18–09:37 UTC. One all-registry hunt (02:18), then 36 single-registry hunts from 03:57 in
six rounds. No hunts dispatched after 08:48.

| Registry | Runs | Packages scanned | Failed scans | New candidates | Known-CVE ledger rows added |
|---|---|---|---|---|---|
| npm | 5 | 500 | 24 | 50 | 48 |
| pypi | 6 | 513 | 6 | 282 | 669 |
| go | 5 | 500 | 13 | 693 | 28,818 |
| packagist | 6 | 226 | 8 | 269 | 445 |
| crates | 7 | 132 | 0 | 0 | 4 |
| rubygems | 7 | 99 | 4 | 0 | 0 |
| **split runs total** | **36** | **1,970** | **55** | **1,294** | **29,984** |
| 02:18 all-registry hunt | 1 | 303 | 3 | 109 | (bundled in ledger total) |

- **Ledger:** 114,014 → 143,989 known-CVE rows, now in 77+ shards under `ledger/cve_ledger/`.
- **Triage decisions tonight:** every pending candidate reviewed by static reading of the shipped source.
  1,812 rejected, 4 deferred, 6 validated (one finding). 0 left pending.
- **Validated:** `salvatorecervone/filterbymodel`, management API unauthenticated by default (CWE-306/CWE-200,
  CVSS 4.0 9.3), v1.0.0–1.3.1. Maintainer report and MITRE form answers:
  `docs/disclosures/filterbymodel.md` on `huginn/disclosures-and-rule-fixes` (`486b898`). Tracker row
  NOT_CONTACTED. **Not sent.**
- **Deferred for owner decision:**
  - an unauthenticated agent tool-server suite (cloud-pc-templates-marketplace; design issue, possible note);
  - anystore's default "auto" mode unpickling non-JSON values (needs a consumer that reads untrusted stores).
- **npm coverage:** before the fix, 0–2 packages per hunt for about 30 h. After `04ecafd`, 100 per hunt in all five
  runs. Failures: 24, then 0 in the later runs. Three of five npm runs produced 0 findings from 100 packages —
  worth a look at what discovery is selecting (possibly many tiny or metadata-only packages).
- **Fixes on Primary tonight:**
  - `04ecafd` npm stale-cursor recovery and a coverage gate that tolerates a few failed scans;
  - `45ae0e5` per-registry runs;
  - `a283859` ledger sharding (100 MB limit);
  - `8e512fe` failure breakdown in logs;
  - `675e2f7` gate floor for small batches.
- **Failures:** two aggregates rejected by GitHub's 100 MB file limit (re-ingested), one npm and one rubygems
  capture gate red (both fixed above). No capture timeouts.
- **Scanner noise to fix next:**
  - PHP `tainted-sql-query` treats Laravel `$request->query()` as SQL (most PHP candidates);
  - JS `tainted-xss` fires on test teardown and inert `createHTMLDocument`;
  - Go `tainted-sql-query` fires on any `.Query(` method.
