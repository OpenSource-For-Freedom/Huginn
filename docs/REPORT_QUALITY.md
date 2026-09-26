# Report quality audit

Merged packets now include `report_quality.csv` and `report_quality_summary.json`.
The ledger update writes the same audit for its candidate queue. Read these qualified
labels alongside the original scanner evidence before making a disclosure decision.
Existing CSV schemas, fingerprints, analyst decisions, and raw findings are preserved.

The audit does not approve reports or establish novelty. Every unchecked, skipped,
failed, or missing advisory source is listed. Even successful no-match checks only
describe the sources checked. Automated validation scores are ranking signals.

Alerts share a review group only when their ecosystem, package, version, artifact
hash, path, line range, and finding class agree. No alert is deleted. Groups identify
overlapping locations, not proven shared root causes. Cross-version alerts remain
separate because matching line numbers alone cannot establish equivalence.

Version claims require a completed comparison against a strictly older numeric
release. Other formats, including prereleases, remain unverified. This intentionally
avoids guessing ecosystem-specific ordering and does not change release selection.
An invalid or unverified baseline produces an UNKNOWN qualified version delta.

CVSS v3 score/severity disagreements are flagged for review while retaining the
original values; advisory severity can use a different basis. Known advisory matches
still require dependency applicability review, particularly when found in lockfiles.

Run the offline regression suite with:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

The fixture file `tests/fixtures/report_quality.json` contains only synthetic metadata.
This change adds report-quality checks and does not expand scanners or start hunts.
