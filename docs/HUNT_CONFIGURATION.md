# Huginn Hunt Configuration

The initial validation hunt uses:

- registry: all
- mode: all
- maximum releases per ecosystem: 25
- ecosystems: npm, PyPI, RubyGems
- scanner engines: Trivy + Semgrep
- isolation: rootless Podman, no network inside package scan containers
- advisory enrichment: OSV, GitHub Security Advisories, NVD, Red Hat
- outputs: review_findings.csv, scan_manifest.csv, operational_alerts.csv, run_summary.json
- automatic disclosure: disabled
- automatic CVE submission: disabled

Security findings and operational coverage failures are intentionally separate. API, registry, artifact, scanner, and enrichment failures are coverage alerts, not CVEs.
