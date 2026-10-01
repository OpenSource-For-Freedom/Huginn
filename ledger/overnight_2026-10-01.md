# Overnight hunt log — 2026-10-01 (until 06:00 ET / 10:00 UTC)

Continuous Huginn hunts on Primary (`cve-capture.yml`, registry=all, mode=all, limit=100), dispatched back to back.
Each hunt is triaged by static review before the next dispatch. Every decision is in `ledger/candidate_queue.csv`;
validated findings go to `ledger/disclosure_tracker.csv` with a maintainer report and MITRE form draft.

| Dispatched (UTC) | Run ID | Aggregate | Candidates | Rejected | Deferred | Validated | Notes |
|---|---|---|---|---|---|---|---|
| 02:18 | 36805232125 | ledger updated (capture gate red: npm 2 pkgs, packagist 1 failed scan) | 109 | 109 | 0 | 0 | ran pre-fix code; npm still empty; mostly Laravel request-getter noise (70) and connext Map.get (20) |
| 03:56 | dispatcher 36812825084 → 6 per-registry runs | | | | | | first round as separate registry hunts (npm fix + per-registry queues live) |

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
