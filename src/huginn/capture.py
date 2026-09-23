from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from .advisory import AdvisoryClient, enrich_rows
from .discovery import USER_AGENT, discover, resolve_artifact
from .models import Artifact
from .reporting import MANIFEST_COLUMNS, REVIEW_COLUMNS, normalize_semgrep, normalize_trivy, write_csv
from .scanner import PodmanScanner
from .state import StateDB


DEFAULT_MAX_ARTIFACT = 100 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def download(artifact: Artifact, dest: Path, max_bytes: int) -> tuple[str, int]:
    req = urllib.request.Request(artifact.url, headers={"User-Agent": USER_AGENT})
    h = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(req, timeout=60) as resp, dest.open("wb") as out:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"artifact exceeds configured limit: {total}>{max_bytes}")
            h.update(chunk)
            out.write(chunk)
    digest = h.hexdigest()
    if artifact.sha256 and digest.lower() != artifact.sha256.lower():
        raise ValueError(f"artifact sha256 mismatch: expected {artifact.sha256}, got {digest}")
    artifact.size_bytes = total
    return digest, total


def capture_registry(
    registry: str,
    mode: str,
    limit: int,
    state: StateDB,
    scanner: PodmanScanner,
    advisory: AdvisoryClient,
    run: str,
    started: str,
    max_artifact_bytes: int,
) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    manifests: list[dict] = []
    batch = discover(registry, mode, limit, state)

    for candidate in batch.candidates:
        first_seen = utc_now()
        state.record_discovered(candidate.registry, candidate.name, candidate.version, candidate.event_type, first_seen)
        if state.is_completed(candidate.registry, candidate.name, candidate.version):
            continue

        manifest = {
            "run_id": run, "registry": candidate.registry, "event_type": candidate.event_type,
            "package_name": candidate.name, "package_version": candidate.version, "purl": candidate.purl,
            "published_at_utc": candidate.published_at, "first_seen_at_utc": first_seen,
            "scan_status": "STARTED", "scan_started_at_utc": utc_now(), "scan_finished_at_utc": "",
            "trivy_exit_code": "", "semgrep_exit_code": "", "finding_count": "0", "error": "",
        }
        try:
            artifact = resolve_artifact(candidate)
            manifest.update({
                "artifact_filename": artifact.filename,
                "artifact_url": artifact.url,
                "artifact_size_bytes": str(artifact.size_bytes or ""),
                "registry_digest": artifact.registry_digest,
            })
            suffix = "".join(Path(artifact.filename).suffixes)[-20:] or ".bin"
            with tempfile.TemporaryDirectory(prefix="huginn-artifact-") as td:
                artifact_path = Path(td) / f"package{suffix}"
                sha256, size = download(artifact, artifact_path, max_artifact_bytes)
                manifest["artifact_sha256"] = sha256
                manifest["artifact_size_bytes"] = str(size)

                outcome = scanner.scan(artifact_path)
                semgrep_version = str(outcome.semgrep.get("version") or "")
                rows = normalize_trivy(
                    outcome.trivy,
                    run_id=run,
                    run_started=started,
                    candidate=candidate,
                    artifact=artifact,
                    sha256=sha256,
                    first_seen=first_seen,
                )
                rows.extend(
                    normalize_semgrep(
                        outcome.semgrep,
                        run_id=run,
                        run_started=started,
                        candidate=candidate,
                        artifact=artifact,
                        sha256=sha256,
                        first_seen=first_seen,
                        scanner_version=semgrep_version,
                        ruleset_hash=scanner.ruleset_hash,
                    )
                )

                # Networked advisory lookups happen in the trusted controller after the
                # untrusted no-network scanner has exited.
                enrich_rows(rows, advisory, checked_at=utc_now())
                findings.extend(rows)

                manifest["trivy_exit_code"] = str(outcome.trivy_exit_code)
                manifest["semgrep_exit_code"] = str(outcome.semgrep_exit_code)
                manifest["finding_count"] = str(len(rows))
                manifest["scan_status"] = "COMPLETED"
                state.mark_completed(candidate.registry, candidate.name, candidate.version, sha256, utc_now())

        except Exception as exc:
            manifest["scan_status"] = "FAILED"
            manifest["error"] = f"{type(exc).__name__}: {exc}"[:4000]
            state.mark_failed(candidate.registry, candidate.name, candidate.version, manifest["error"])
        finally:
            manifest["scan_finished_at_utc"] = utc_now()
            manifests.append(manifest)

    # Cursor advancement is transactional at the batch boundary. Any failed release
    # keeps the npm checkpoint back so the changes page is replayed next run.
    if batch.checkpoint and not any(row.get("scan_status") == "FAILED" for row in manifests):
        state.set_cursors(batch.checkpoint)

    return findings, manifests


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture static package findings into review-first CSV reports.")
    parser.add_argument("--registry", choices=["npm", "pypi", "rubygems", "all"], default="all")
    parser.add_argument("--mode", choices=["all", "updates", "new"], default="all")
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument("--output", type=Path, default=Path("reports"))
    parser.add_argument(
        "--state-db",
        type=Path,
        default=Path(os.environ.get("HUGINN_STATE_DB", "~/.local/state/huginn/state.db")).expanduser(),
    )
    parser.add_argument("--max-artifact-bytes", type=int, default=DEFAULT_MAX_ARTIFACT)
    args = parser.parse_args()

    started = utc_now()
    run = run_id()
    out_dir = args.output / run
    repo_root = Path(__file__).resolve().parents[2]

    scanner = PodmanScanner(
        rules_file=repo_root / "rules" / "semgrep.yml",
        archive_script=repo_root / "src" / "huginn" / "archive.py",
        trivy_image=os.environ.get("HUGINN_TRIVY_IMAGE", "docker.io/aquasec/trivy:0.74.0"),
        semgrep_image=os.environ.get("HUGINN_SEMGREP_IMAGE", "docker.io/semgrep/semgrep:1.177.0"),
        unpack_image=os.environ.get("HUGINN_UNPACK_IMAGE", "docker.io/library/python:3.13-slim"),
        trivy_cache_volume=os.environ.get("HUGINN_TRIVY_CACHE_VOLUME", "huginn-trivy-cache"),
    )
    advisory = AdvisoryClient()
    state = StateDB(args.state_db)
    registries = ["npm", "pypi", "rubygems"] if args.registry == "all" else [args.registry]

    all_findings: list[dict] = []
    all_manifests: list[dict] = []
    for registry in registries:
        findings, manifests = capture_registry(
            registry,
            args.mode,
            args.limit,
            state,
            scanner,
            advisory,
            run,
            started,
            args.max_artifact_bytes,
        )
        all_findings.extend(findings)
        all_manifests.extend(manifests)

    all_findings.sort(
        key=lambda r: (
            r.get("triage_priority", "P9"),
            r.get("registry", ""),
            r.get("package_name", ""),
            r.get("file_path", ""),
        )
    )
    write_csv(out_dir / "review_findings.csv", REVIEW_COLUMNS, all_findings)
    write_csv(out_dir / "scan_manifest.csv", MANIFEST_COLUMNS, all_manifests)

    summary = {
        "run_id": run,
        "started_at_utc": started,
        "finished_at_utc": utc_now(),
        "registry": args.registry,
        "mode": args.mode,
        "finding_count": len(all_findings),
        "novel_no_match_count": sum(1 for row in all_findings if row.get("dedup_status") == "NO_MATCH"),
        "possible_match_count": sum(1 for row in all_findings if row.get("dedup_status") == "POSSIBLE_MATCH"),
        "known_exact_count": sum(1 for row in all_findings if row.get("dedup_status") == "KNOWN_EXACT"),
        "lookup_failed_count": sum(1 for row in all_findings if row.get("dedup_status") == "LOOKUP_FAILED"),
        "package_scan_count": len(all_manifests),
        "failed_package_scans": sum(1 for row in all_manifests if row.get("scan_status") == "FAILED"),
        "review_csv": "review_findings.csv",
        "manifest_csv": "scan_manifest.csv",
        "automatic_disclosure": False,
        "automatic_cve_submission": False,
    }
    (out_dir / "run_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(out_dir)


if __name__ == "__main__":
    main()
