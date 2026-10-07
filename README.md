<p align="center"><img src="docs/assets/huginn-banner.jpg" alt="Huginn" width="100%"/></p>

# Huginn

Private static-analysis reconnaissance for newly published open-source packages.

Huginn continuously scouts supported public package registries, statically inspects new packages and releases, cross-references known vulnerability sources, and places novel candidates into a manual review queue.

Huginn does **not** execute, install, detonate, or emulate discovered packages. CVE disclosure and submission remain manual.

Owner: **OpenSource-For-Freedom**

## Validated findings

The list of true findings is [`ledger/validated_findings.csv`](../huginn-ledger/ledger/validated_findings.csv) on the `huginn-ledger` branch: one row per validated vulnerability (`HUGINN-YYYY-NNN`) with affected versions, CVSS 4.0, CWE, disclosure draft and CVE status. Every hunt updates it: a package an analyst marks `VALIDATED` in `ledger/candidate_queue.csv` gets a new row with `PENDING` CVSS and disclosure fields, and curated rows are never overwritten.

## Project requirements

See [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) for the Planning, Architecture, Design, Security, and recommended technology stack requirements.

## Review-first CVE capture

The first runnable capture pipeline is in src/huginn and .github/workflows/cve-capture.yml.

It watches npm, PyPI, and RubyGems release activity, downloads published artifacts as opaque bytes, unpacks and scans them in rootless no-network Podman containers, enriches findings against OSV, GitHub Global Security Advisories, NVD, and Red Hat Security Data, and emits a private review packet on every run:

- review_findings.csv — every Trivy CVE/misconfiguration and Semgrep candidate with inline analyst-verification and per-source advisory/dedup columns.
- scan_manifest.csv — every package attempted, including scan failures and finding counts.
- run_summary.json — run-level totals and automation state.

Hunts run twice a month (06:17 UTC on the 1st and 15th) from `hunt-each-registry.yml` ("Huginn Hunt Each Registry"), and can also be started by hand from the Actions tab. Each run looks back 15 days, lists every release each registry published in that window, and scans a budgeted selection per registry (go 170, pypi 220, npm 220, crates 120, rubygems 130, packagist 80; new packages first, the rest spread evenly across the window). Packagist only keeps about 24 hours of change history and the crates.io listing reaches about 5 days, so those two windows are shorter. Each capture stops starting new scans after 40-105 minutes, so a full run costs about 470 Actions minutes (about 1,000 a month). Before dispatching, the run counts the minutes Huginn used in the last 7 days against `HUGINN_WEEKLY_MINUTES` (repository variable, default 500): if the full run would pass it, the batch is scaled down to fit, and it is refused when fewer than 75 minutes remain. Set `window_days` to 0 for the latest-feed behaviour.

- malicious_findings.csv — packages judged as malware by git_warden's Tier-2 rules (the same rules that confirm malicious repositories and container images), run over the same unpacked release in the same no-network container. `CONFIRMED` means Warden confirmed it on its own (a fetch-and-run install hook, a verified decode-and-exec loader, credential theft with an exfil channel, a known campaign fingerprint such as PolinRider, GlassWorm or Shai-Hulud, a YARA hit). `NEW_RISK` means a new version adds a high-risk mechanism its previous release did not have, which is how hijacked releases look. These rows never enter the CVE queue; OSM submission is a reviewed, manual step.

Malware analysis needs a `WARDEN_READ_TOKEN` repository secret (read-only access to the private git_warden repository) so the hunt can build the analyzer image from the pinned `HUGINN_WARDEN_REF`. Without it the hunt still runs and reports `MALWARE_SCAN_NOT_CONFIGURED`.

See docs/REVIEW_WORKFLOW.md for the complete CSV inspection contract and validation requirements.
