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

Hunts are manual only (no schedule). Start `hunt-each-registry.yml` ("Huginn Hunt Each Registry") from the Actions tab: by default it looks back 7 days, lists every release each registry published in that window, and scans a budgeted selection per registry (go 150, pypi 200, npm 200, crates 100, rubygems 100, packagist 60; new packages first, the rest spread evenly across the week). Each capture also stops starting new scans after 35-95 minutes, so a full run costs about 420 Actions minutes. Before dispatching, the run checks this month's minutes and refuses to start if it would pass `HUGINN_MONTHLY_MINUTES` (repository variable, default 1900, inside the 2,000 free minutes for private repositories). Packagist only keeps about 24 hours of change history, so its window is capped at that. Set `window_days` to 0 for the old latest-feed behaviour.

See docs/REVIEW_WORKFLOW.md for the complete CSV inspection contract and validation requirements.
