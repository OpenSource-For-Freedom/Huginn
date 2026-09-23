from __future__ import annotations

import io
import json
import tarfile
import tempfile
from pathlib import Path

import huginn
from huginn.scanner import PodmanScanner


def main() -> None:
    package_root = Path(huginn.__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="huginn-scanner-smoke-") as td:
        root = Path(td)
        archive = root / "fixture.tar.gz"

        files = {
            "fixture/vuln.py": b"import os\ndef run(user_input):\n    os.system(user_input)\n",
            "fixture/requirements.txt": b"jinja2==3.1.4\n",
        }

        with tarfile.open(archive, "w:gz") as tf:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

        scanner = PodmanScanner(
            rules_file=package_root / "rules" / "semgrep.yml",
            archive_script=package_root / "archive.py",
        )
        outcome = scanner.scan(archive)

        semgrep_ids = {
            str(item.get("check_id") or "")
            for item in outcome.semgrep.get("results") or []
        }
        trivy_ids = {
            str(vuln.get("VulnerabilityID") or "")
            for result in outcome.trivy.get("Results") or []
            for vuln in result.get("Vulnerabilities") or []
        }

        expected_rule = "huginn.generic.command-execution"
        expected_cve = "CVE-2024-56326"

        report = {
            "semgrep_exit_code": outcome.semgrep_exit_code,
            "semgrep_result_count": len(outcome.semgrep.get("results") or []),
            "semgrep_error_count": len(outcome.semgrep.get("errors") or []),
            "semgrep_rule_ids": sorted(semgrep_ids),
            "trivy_exit_code": outcome.trivy_exit_code,
            "trivy_vulnerability_ids": sorted(trivy_ids),
            "expected_semgrep_rule": expected_rule,
            "expected_trivy_cve": expected_cve,
        }
        print(json.dumps(report, indent=2, sort_keys=True))

        if not any(rule_id == expected_rule or rule_id.endswith(f".{expected_rule}") for rule_id in semgrep_ids):
            raise SystemExit(
                f"Semgrep failed to detect {expected_rule}; got {sorted(semgrep_ids)}"
            )
        if expected_cve not in trivy_ids:
            raise SystemExit(
                f"Trivy failed to detect {expected_cve}; got {sorted(trivy_ids)}"
            )


if __name__ == "__main__":
    main()
