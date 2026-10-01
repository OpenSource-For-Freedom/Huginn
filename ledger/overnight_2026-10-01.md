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
| 05:09 go | 36818465682 | running | | | | | |

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
