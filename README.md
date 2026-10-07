<p align="center"><img src="docs/assets/huginn-banner.jpg" alt="Huginn" width="100%"/></p>

# Huginn

Private static-analysis reconnaissance for newly published open-source packages.

Huginn continuously scouts supported public package registries, statically inspects new packages and releases, cross-references known vulnerability sources, and places novel candidates into a manual review queue.

Huginn does **not** execute, install, detonate, or emulate discovered packages. CVE disclosure and submission remain manual.

Owner: **OpenSource-For-Freedom**

## Project requirements

See [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) for the Planning, Architecture, Design, Security, and recommended technology stack requirements.

## Review-first CVE capture

The first runnable capture pipeline is in src/huginn and .github/workflows/cve-capture.yml.

It watches npm, PyPI, and RubyGems release activity, downloads published artifacts as opaque bytes, unpacks and scans them in rootless no-network Podman containers, enriches findings against OSV, GitHub Global Security Advisories, NVD, and Red Hat Security Data, and emits a private review packet on every run:

- review_findings.csv — every Trivy CVE/misconfiguration and Semgrep candidate with inline analyst-verification and per-source advisory/dedup columns.
- scan_manifest.csv — every package attempted, including scan failures and finding counts.
- run_summary.json — run-level totals and automation state.

Hunts run twice a month (06:17 UTC on the 1st and 15th) from `hunt-each-registry.yml` ("Huginn Hunt Each Registry"), and can also be started by hand from the Actions tab. Each run looks back 15 days, lists every release each registry published in that window, and scans a budgeted selection per registry (go 170, pypi 220, npm 220, crates 120, rubygems 130, packagist 80; new packages first, the rest spread evenly across the window). Packagist only keeps about 24 hours of change history and the crates.io listing reaches about 5 days, so those two windows are shorter. Each capture stops starting new scans after 40-105 minutes, so a full run costs about 470 Actions minutes (about 1,000 a month). Before dispatching, the run counts the minutes Huginn used in the last 7 days against `HUGINN_WEEKLY_MINUTES` (repository variable, default 500): if the full run would pass it, the batch is scaled down to fit, and it is refused when fewer than 75 minutes remain. Set `window_days` to 0 for the latest-feed behaviour.

See docs/REVIEW_WORKFLOW.md for the complete CSV inspection contract and validation requirements.
