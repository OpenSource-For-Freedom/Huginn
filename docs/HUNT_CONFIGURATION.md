# Huginn Hunt Configuration

The initial validation hunt uses:

- registry: all
- mode: all
- maximum releases per ecosystem: 25
- ecosystems: npm, PyPI, RubyGems, crates.io, Packagist (Composer), Go modules
- scanner engines: Trivy + Semgrep
- isolation: rootless Podman, no network inside package scan containers
- advisory enrichment: OSV, GitHub Security Advisories, NVD, Red Hat
- outputs: review_findings.csv, scan_manifest.csv, operational_alerts.csv, run_summary.json
- automatic disclosure: disabled
- automatic CVE submission: disabled

Security findings and operational coverage failures are intentionally separate. API, registry, artifact, scanner, and enrichment failures are coverage alerts, not CVEs.

## Expanded ecosystem matrix

`registry=all` fans out to six isolated matrix legs (`max-parallel: 6`):

| Registry | Discovery | Artifact | Semgrep coverage |
|---|---|---|---|
| npm | replication `_changes` cursor | registry tarball | JS/TS sink + taint rules |
| pypi | RSS new + updates | sdist/wheel | Python sink + taint rules |
| rubygems | activity feeds | `.gem` | Ruby sink + taint rules |
| crates | crates.io API `sort=new` and `sort=recent-updates` | `static.crates.io` `.crate` with the index checksum | generic + C rules; Trivy `Cargo.lock` |
| packagist | Packagist release and new-package RSS | Composer dist zip (GitHub, GitLab or Bitbucket hosts only) | PHP taint rules: command, eval/include, unserialize, SQL; Trivy `composer.lock` |
| go | `index.golang.org` for the last 6 hours, tagged versions only (pseudo-versions skipped) | `proxy.golang.org` module zip | Go taint rules: command, SQL, file path; Trivy `go.mod`/`go.sum` |

Persistent per-registry state keeps each run to unseen releases, so repeated runs widen coverage instead of rescanning.
