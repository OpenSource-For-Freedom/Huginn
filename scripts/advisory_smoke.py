from __future__ import annotations

import json

from huginn.advisory import AdvisoryClient


CASES = [
    ("npm", "lodash", "4.17.23", "CVE-2026-4800"),
    ("pypi", "jinja2", "3.1.4", "CVE-2024-56326"),
    ("rubygems", "rack", "2.2.3", "CVE-2024-26141"),
]


def main() -> None:
    client = AdvisoryClient(timeout=30, retries=2)
    rows = []

    for registry, package, version, expected_cve in CASES:
        osv, ghsa = client.query_package(registry, package, version)
        combined = osv.cves | ghsa.cves
        ok = expected_cve in combined
        rows.append({
            "check": "package_version",
            "registry": registry,
            "package": package,
            "version": version,
            "expected_cve": expected_cve,
            "osv_status": osv.status,
            "osv_ids": sorted(osv.ids),
            "ghsa_status": ghsa.status,
            "ghsa_ids": sorted(ghsa.ids),
            "passed": ok,
        })
        if not ok:
            raise SystemExit(
                f"{registry}:{package}@{version} did not return expected {expected_cve}; "
                f"OSV={sorted(osv.ids)} GHSA={sorted(ghsa.ids)}"
            )

    nvd = client.query_nvd("CVE-2026-4800")
    rows.append({
        "check": "nvd_cve",
        "expected_cve": "CVE-2026-4800",
        "status": nvd.status,
        "ids": sorted(nvd.ids),
        "passed": nvd.status == "MATCH" and "CVE-2026-4800" in nvd.ids,
    })
    if not rows[-1]["passed"]:
        raise SystemExit(f"NVD did not corroborate CVE-2026-4800: {nvd.status} {sorted(nvd.ids)}")

    redhat = client.query_redhat("CVE-2026-26017")
    rows.append({
        "check": "redhat_cve",
        "expected_cve": "CVE-2026-26017",
        "status": redhat.status,
        "ids": sorted(redhat.ids),
        "passed": redhat.status == "MATCH" and "CVE-2026-26017" in redhat.ids,
    })
    if not rows[-1]["passed"]:
        raise SystemExit(f"Red Hat did not corroborate CVE-2026-26017: {redhat.status} {sorted(redhat.ids)}")

    print(json.dumps(rows, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
