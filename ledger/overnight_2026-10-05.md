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
| 03:55 | crates | 37261320044 | success | see run_log | 0 | 0 | 0 | 0 | |
