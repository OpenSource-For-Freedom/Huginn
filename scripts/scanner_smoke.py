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
            "fixture/vuln.py": b"import os\ndef run():\n    user_input = input()\n    os.system(user_input)\n    eval(user_input)\n",
            "fixture/network_pickle.py": b"import pickle\nimport requests\ndef load_remote(url):\n    response = requests.get(url)\n    return pickle.loads(response.content)\n",
            "fixture/noise.js": b"async function migrate(db, sql) { await db.exec(sql); }\n",
            "fixture/safe_subprocess.py": b"import subprocess\ndef run(repo):\n    return subprocess.run(['git', '-C', repo, 'status'], check=True)\n",
            "fixture/requirements.txt": b"jinja2==3.1.4\n",
            "fixture/safe_db.py": b"def store(db, sql):\n    db.exec(sql)\n",
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
        excerpts = [
            str((item.get("extra") or {}).get("huginn_excerpt") or "")
            for item in outcome.semgrep.get("results") or []
        ]
        trivy_ids = {
            str(vuln.get("VulnerabilityID") or "")
            for result in outcome.trivy.get("Results") or []
            for vuln in result.get("Vulnerabilities") or []
        }

        expected_rule = "huginn.generic.command-execution"
        expected_dynamic_rule = "huginn.python.dynamic-eval-sink"
        expected_taint_rule = "huginn.python.tainted-eval"
        expected_network_deserialization_rule = "huginn.python.network-response-unsafe-deserialization"
        expected_cve = "CVE-2024-56326"

        report = {
            "semgrep_exit_code": outcome.semgrep_exit_code,
            "semgrep_result_count": len(outcome.semgrep.get("results") or []),
            "semgrep_error_count": len(outcome.semgrep.get("errors") or []),
            "semgrep_rule_ids": sorted(semgrep_ids),
            "static_excerpt_count": sum(1 for value in excerpts if value),
            "trivy_exit_code": outcome.trivy_exit_code,
            "trivy_vulnerability_ids": sorted(trivy_ids),
            "expected_semgrep_rule": expected_rule,
            "expected_semgrep_dynamic_rule": expected_dynamic_rule,
            "expected_semgrep_taint_rule": expected_taint_rule,
            "expected_network_deserialization_rule": expected_network_deserialization_rule,
            "expected_trivy_cve": expected_cve,
        }
        print(json.dumps(report, indent=2, sort_keys=True))

        if not any(rule_id == expected_rule or rule_id.endswith(f".{expected_rule}") for rule_id in semgrep_ids):
            raise SystemExit(
                f"Semgrep failed to detect {expected_rule}; got {sorted(semgrep_ids)}"
            )
        dynamic_results = [
            item for item in outcome.semgrep.get("results") or []
            if str(item.get("check_id") or "") == expected_dynamic_rule
            or str(item.get("check_id") or "").endswith(f".{expected_dynamic_rule}")
        ]
        if not dynamic_results:
            raise SystemExit(
                f"Semgrep failed to detect {expected_dynamic_rule}; got {sorted(semgrep_ids)}"
            )
        if any(str(item.get("path") or "").endswith("safe_db.py") for item in dynamic_results):
            raise SystemExit("Dynamic-eval rules incorrectly matched member method db.exec(sql)")
        if not any(
            rule_id == expected_taint_rule or rule_id.endswith(f".{expected_taint_rule}")
            for rule_id in semgrep_ids
        ):
            raise SystemExit(
                f"Semgrep failed to detect {expected_taint_rule}; got {sorted(semgrep_ids)}"
            )
        if not any(
            rule_id == expected_network_deserialization_rule
            or rule_id.endswith(f".{expected_network_deserialization_rule}")
            for rule_id in semgrep_ids
        ):
            raise SystemExit(
                "Semgrep failed to detect network-response unsafe deserialization; "
                f"got {sorted(semgrep_ids)}"
            )

        dynamic_eval_noise = [
            item for item in outcome.semgrep.get("results") or []
            if str(item.get("path") or "").endswith("noise.js")
            and str(item.get("check_id") or "").endswith("huginn.generic.dynamic-eval")
        ]
        if dynamic_eval_noise:
            raise SystemExit("Generic dynamic-eval rule incorrectly matched db.exec(...)")

        safe_subprocess_noise = [
            item for item in outcome.semgrep.get("results") or []
            if str(item.get("path") or "").endswith("safe_subprocess.py")
            and str(item.get("check_id") or "").endswith("huginn.generic.command-execution")
        ]
        if safe_subprocess_noise:
            raise SystemExit("Generic command rule incorrectly matched safe subprocess argv execution")

        if not any("os.system(user_input)" in value for value in excerpts):
            raise SystemExit(
                "Scanner failed to attach isolated static source excerpts to Semgrep findings"
            )
        if expected_cve not in trivy_ids:
            raise SystemExit(
                f"Trivy failed to detect {expected_cve}; got {sorted(trivy_ids)}"
            )


if __name__ == "__main__":
    main()
