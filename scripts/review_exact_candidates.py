from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from huginn.advisory import AdvisoryClient, enrich_rows
from huginn.capture import download, run_id, utc_now
from huginn.discovery import previous_release, resolve_artifact
from huginn.models import ReleaseCandidate
from huginn.reporting import REVIEW_COLUMNS, normalize_semgrep, normalize_trivy, write_csv
from huginn.scanner import PodmanScanner
from huginn.validation import apply_validation


def parse_candidate(value: str) -> ReleaseCandidate:
    registry, name, version = value.split(":", 2)
    return ReleaseCandidate(
        registry=registry,
        name=name,
        version=version,
        event_type="TARGETED_REVIEW",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Re-scan exact package versions for manual CVE review.")
    parser.add_argument("--candidate", action="append", required=True)
    parser.add_argument("--output", type=Path, default=Path("candidate-review"))
    parser.add_argument("--max-artifact-bytes", type=int, default=100 * 1024 * 1024)
    args = parser.parse_args()

    package_root = Path(__file__).resolve().parents[1] / "src" / "huginn"
    scanner = PodmanScanner(
        rules_file=Path(os.environ.get("HUGINN_RULES_FILE", package_root / "rules" / "semgrep.yml")).resolve(),
        archive_script=Path(os.environ.get("HUGINN_ARCHIVE_SCRIPT", package_root / "archive.py")).resolve(),
        trivy_image=os.environ.get("HUGINN_TRIVY_IMAGE", "docker.io/aquasec/trivy:0.74.0"),
        semgrep_image=os.environ.get("HUGINN_SEMGREP_IMAGE", "docker.io/semgrep/semgrep:1.177.0"),
        unpack_image=os.environ.get("HUGINN_UNPACK_IMAGE", "docker.io/library/python:3.13-slim"),
        trivy_cache_volume=os.environ.get("HUGINN_TRIVY_CACHE_VOLUME", "huginn-trivy-cache"),
    )
    advisory = AdvisoryClient()
    started = utc_now()
    review_run = run_id()
    rows: list[dict[str, str]] = []
    packages: list[dict[str, object]] = []

    for raw in args.candidate:
        candidate = parse_candidate(raw)
        package_result: dict[str, object] = {
            "registry": candidate.registry,
            "package_name": candidate.name,
            "package_version": candidate.version,
            "status": "STARTED",
            "error": "",
        }
        try:
            artifact = resolve_artifact(candidate)
            package_result["artifact_url"] = artifact.url
            package_result["artifact_filename"] = artifact.filename
            suffix = "".join(Path(artifact.filename).suffixes)[-20:] or ".bin"
            with tempfile.TemporaryDirectory(prefix="huginn-review-") as td:
                path = Path(td) / f"package{suffix}"
                sha256, size = download(artifact, path, args.max_artifact_bytes)
                outcome = scanner.scan(path)
                candidate_rows = normalize_trivy(
                    outcome.trivy,
                    run_id=review_run,
                    run_started=started,
                    candidate=candidate,
                    artifact=artifact,
                    sha256=sha256,
                    first_seen=started,
                )
                candidate_rows.extend(
                    normalize_semgrep(
                        outcome.semgrep,
                        run_id=review_run,
                        run_started=started,
                        candidate=candidate,
                        artifact=artifact,
                        sha256=sha256,
                        first_seen=started,
                        scanner_version=str(outcome.semgrep.get("version") or ""),
                        ruleset_hash=scanner.ruleset_hash,
                    )
                )
                enrich_rows(candidate_rows, advisory, checked_at=utc_now())

                previous_version = ""
                previous_keys: set[tuple[str, str]] = set()
                previous_status = "UNAVAILABLE"
                previous_error = ""
                try:
                    previous = previous_release(candidate)
                    if previous is not None:
                        previous_version = previous.version
                        previous_artifact = resolve_artifact(previous)
                        previous_suffix = "".join(Path(previous_artifact.filename).suffixes)[-20:] or ".bin"
                        previous_path = Path(td) / f"previous{previous_suffix}"
                        download(previous_artifact, previous_path, args.max_artifact_bytes)
                        previous_outcome = scanner.scan(previous_path)
                        previous_keys = {
                            (str(item.get("check_id") or ""), str(item.get("path") or ""))
                            for item in (previous_outcome.semgrep.get("results") or [])
                        }
                        previous_status = "COMPLETE"
                except Exception as exc:
                    previous_status = "FAILED"
                    previous_error = f"{type(exc).__name__}: {exc}"[:1000]

                apply_validation(
                    candidate_rows,
                    previous_version=previous_version,
                    previous_keys=previous_keys,
                    previous_compare_status=previous_status,
                    previous_compare_error=previous_error,
                )
                rows.extend(candidate_rows)
                package_result.update({
                    "status": "COMPLETED",
                    "artifact_sha256": sha256,
                    "artifact_size_bytes": size,
                    "finding_count": len(candidate_rows),
                    "trivy_exit_code": outcome.trivy_exit_code,
                    "semgrep_exit_code": outcome.semgrep_exit_code,
                })
        except Exception as exc:
            package_result["status"] = "FAILED"
            package_result["error"] = f"{type(exc).__name__}: {exc}"[:2000]
        packages.append(package_result)

    rows.sort(key=lambda r: (
        r.get("triage_priority", "P9"),
        r.get("package_name", ""),
        r.get("file_path", ""),
        int(float(r.get("start_line") or 0)),
    ))

    args.output.mkdir(parents=True, exist_ok=True)
    write_csv(args.output / "review_findings.csv", REVIEW_COLUMNS, rows)
    summary = {
        "run_id": review_run,
        "started_at_utc": started,
        "finished_at_utc": utc_now(),
        "packages": packages,
        "package_count": len(packages),
        "failed_packages": sum(1 for item in packages if item["status"] == "FAILED"),
        "finding_count": len(rows),
        "no_match_count": sum(1 for row in rows if row.get("dedup_status") == "NO_MATCH"),
        "known_count": sum(1 for row in rows if row.get("dedup_status") == "KNOWN_EXACT"),
        "dataflow_count": sum(1 for row in rows if row.get("reachability_state") == "STATIC_DATAFLOW"),
        "high_value_candidate_count": sum(
            1 for row in rows if row.get("validation_state") == "HIGH_VALUE_MANUAL_CANDIDATE"
        ),
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    if summary["failed_packages"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
