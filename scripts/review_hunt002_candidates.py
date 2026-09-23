from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
import urllib.request
from pathlib import Path

from huginn.discovery import USER_AGENT
from huginn.scanner import PodmanScanner


CANDIDATES = [
    {
        "package": "archcheck",
        "version": "0.26.0",
        "url": "https://files.pythonhosted.org/packages/c3/3b/edce9bd91eec2de5bf7661e3bfd93703087e6d00c41f76e566af2083e84c/archcheck-0.26.0.tar.gz",
        "sha256": "e6864a52e1bf8f549efb86ff7c455943fab7da06f3f59e9b6dbfb27443018830",
        "targets": [
            {"rule_suffix": "huginn.generic.command-execution", "path_suffix": "src/archcheck/semantic.py", "line": 997},
        ],
    },
    {
        "package": "gitomb",
        "version": "0.1.0",
        "url": "https://files.pythonhosted.org/packages/41/0b/50b59ed975c65790b2a3d177919f1aee5732e402e0c79c2a8337a8dd0ae5/gitomb-0.1.0.tar.gz",
        "sha256": "0e1a76b21de6bad958b8b18d92a859c0168e4a0ca0eaa1820df90355867d4bf6",
        "targets": [
            {"rule_suffix": "huginn.generic.command-execution", "path_suffix": "src/gitomb/git.py", "line": 14},
        ],
    },
    {
        "package": "volcengine-python-sdk-aicc",
        "version": "0.0.41",
        "url": "https://files.pythonhosted.org/packages/ce/13/2064b8ff62237f906b662a4e7bb0b7582313c8d47abf3960447d0ec8ae8c/volcengine_python_sdk_aicc-0.0.41.tar.gz",
        "sha256": "2aae4691780916114ad477ebbb6c09eaff2c597b1a60b02c8905efd4b70944ab",
        "targets": [
            {"rule_suffix": "huginn.generic.command-execution", "path_suffix": "bytedance/volcengine_aicc_sdk/asr_websocket_client.py", "line": 458},
            {"rule_suffix": "huginn.generic.unsafe-deserialization", "path_suffix": "bytedance/volcengine_aicc_sdk/deepseek_inference_client.py", "line": 277},
        ],
    },
    {
        "package": "webteam-agents",
        "version": "0.2.0",
        "url": "https://files.pythonhosted.org/packages/ed/7f/2bbac34bee9f550dbd24fe721f0713ef7ad2337c070511cd2571a6250648/webteam_agents-0.2.0.tar.gz",
        "sha256": "42f0300c7fe6bb97b5574640ff50b5747f9eee7bdc2f4a9ea71998b47eac75e7",
        "targets": [
            {"rule_suffix": "huginn.generic.command-execution", "path_suffix": "src/webteam/project.py", "line": 151},
        ],
    },
]


def download(url: str, dest: Path, expected_sha256: str) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    digest = hashlib.sha256()
    with urllib.request.urlopen(req, timeout=60) as response, dest.open("wb") as handle:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            handle.write(chunk)
    actual = digest.hexdigest()
    if actual.lower() != expected_sha256.lower():
        raise RuntimeError(f"sha256 mismatch for {url}: {actual}")


def target_match(item: dict, target: dict) -> bool:
    rule = str(item.get("check_id") or "")
    path = str(item.get("path") or "").replace("\\", "/")
    line = int((item.get("start") or {}).get("line") or 0)
    return (
        rule.endswith(target["rule_suffix"])
        and path.endswith(target["path_suffix"])
        and abs(line - int(target["line"])) <= 3
    )


def main() -> None:
    package_root = Path(__file__).resolve().parents[1] / "src" / "huginn"
    scanner = PodmanScanner(
        rules_file=package_root / "rules" / "semgrep.yml",
        archive_script=package_root / "archive.py",
        trivy_image=os.environ.get("HUGINN_TRIVY_IMAGE", "docker.io/aquasec/trivy:0.74.0"),
        semgrep_image=os.environ.get("HUGINN_SEMGREP_IMAGE", "docker.io/semgrep/semgrep:1.177.0"),
        unpack_image=os.environ.get("HUGINN_UNPACK_IMAGE", "docker.io/library/python:3.13-slim"),
        trivy_cache_volume=os.environ.get("HUGINN_TRIVY_CACHE_VOLUME"),
    )

    out_dir = Path("candidate-review")
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str]] = []
    package_summaries: list[dict] = []

    for candidate in CANDIDATES:
        with tempfile.TemporaryDirectory(prefix="huginn-review-") as td:
            artifact = Path(td) / candidate["url"].rsplit("/", 1)[-1]
            download(candidate["url"], artifact, candidate["sha256"])
            outcome = scanner.scan(artifact)
            findings = outcome.semgrep.get("results") or []
            matched = 0

            for target in candidate["targets"]:
                matches = [item for item in findings if target_match(item, target)]
                for item in matches:
                    matched += 1
                    extra = item.get("extra") or {}
                    metadata = extra.get("metadata") or {}
                    rows.append({
                        "package": candidate["package"],
                        "version": candidate["version"],
                        "artifact_sha256": candidate["sha256"],
                        "rule_id": str(item.get("check_id") or ""),
                        "path": str(item.get("path") or ""),
                        "start_line": str((item.get("start") or {}).get("line") or ""),
                        "end_line": str((item.get("end") or {}).get("line") or ""),
                        "severity": str(extra.get("severity") or ""),
                        "message": str(extra.get("message") or ""),
                        "cwe": str(metadata.get("cwe") or ""),
                        "validation_kind": str(metadata.get("huginn_validation") or ""),
                        "source_to_sink": str(metadata.get("huginn_source_to_sink") or ""),
                        "source": str(metadata.get("huginn_source") or ""),
                        "sink": str(metadata.get("huginn_sink") or ""),
                        "excerpt": str(extra.get("huginn_excerpt") or ""),
                    })

            package_summaries.append({
                "package": candidate["package"],
                "version": candidate["version"],
                "artifact_sha256": candidate["sha256"],
                "semgrep_exit_code": outcome.semgrep_exit_code,
                "trivy_exit_code": outcome.trivy_exit_code,
                "semgrep_finding_count": len(findings),
                "target_count": len(candidate["targets"]),
                "matched_target_count": matched,
                "trivy_vulnerability_count": sum(
                    len(result.get("Vulnerabilities") or [])
                    for result in outcome.trivy.get("Results") or []
                ),
            })

    columns = [
        "package", "version", "artifact_sha256", "rule_id", "path", "start_line",
        "end_line", "severity", "message", "cwe", "validation_kind",
        "source_to_sink", "source", "sink", "excerpt",
    ]
    with (out_dir / "candidate_review.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    (out_dir / "candidate_review.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (out_dir / "candidate_review_summary.json").write_text(
        json.dumps(package_summaries, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    missing = [
        item for item in package_summaries
        if item["matched_target_count"] < item["target_count"]
    ]
    if missing:
        raise SystemExit(f"one or more target findings were not reproduced: {missing}")


if __name__ == "__main__":
    main()
