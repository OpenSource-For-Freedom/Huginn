from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from huginn.advisory import AdvisoryClient


def serializable(result):
    data = asdict(result)
    for key in ("ids", "cves", "cwes", "urls"):
        data[key] = sorted(data[key])
    return data


def main() -> None:
    client = AdvisoryClient()
    osv, ghsa = client.query_package("pypi", "volcengine-python-sdk-aicc", "0.0.41")
    cves = sorted(set(osv.cves) | set(ghsa.cves))
    nvd = {cve: serializable(client.query_nvd(cve)) for cve in cves}
    redhat = {cve: serializable(client.query_redhat(cve)) for cve in cves}
    result = {
        "package": "volcengine-python-sdk-aicc",
        "version": "0.0.41",
        "osv": serializable(osv),
        "ghsa": serializable(ghsa),
        "nvd": nvd,
        "redhat": redhat,
        "public_cves_from_package_aware_sources": cves,
        "novelty_check_complete": osv.status != "ERROR" and ghsa.status != "ERROR",
    }
    out = Path("candidate-review")
    out.mkdir(exist_ok=True)
    (out / "volcengine_advisory_recheck.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
