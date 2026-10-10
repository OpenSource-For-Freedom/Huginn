from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from .advisory import AdvisoryClient, enrich_rows
from .alerts import alerts_from_findings, alerts_from_manifests, make_alert
from .discovery import (USER_AGENT, PolicySkip, discover, previous_release, resolve_artifact,
                        with_retries)
from .malware import MALWARE_COLUMNS, malware_row, needs_previous, summary_counts
from .window import discover_window
from .models import Artifact
from .reporting import ALERT_COLUMNS, MANIFEST_COLUMNS, REVIEW_COLUMNS, normalize_semgrep, normalize_trivy, write_csv
from .scanner import PodmanScanner
from .state import StateDB
from .validation import apply_validation


DEFAULT_MAX_ARTIFACT = 100 * 1024 * 1024


REGISTRIES = ("npm", "pypi", "rubygems", "crates", "packagist", "go")


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


class TooLarge(ValueError):
    """The artifact is over --max-artifact-bytes: a policy limit, not a fault."""


def _skip_reason(exc: Exception) -> str | None:
    """Why a release could not be scanned through no fault of the hunt, or None.

    A version the feed listed but the registry now answers 404/410 for was
    removed (yanked, or taken down, as malicious releases often are) before
    Huginn reached it; an over-size artifact is refused by policy. Both are
    recorded as SKIPPED with the reason, not as coverage failures. Anything
    else, a sha256 mismatch included, stays FAILED.
    """
    if isinstance(exc, urllib.error.HTTPError) and exc.code in (404, 410):
        return f"RemovedFromRegistry: HTTP {exc.code}"
    if isinstance(exc, TooLarge):
        return f"TooLarge: {exc}"
    return None


def download(artifact: Artifact, dest: Path, max_bytes: int) -> tuple[str, int]:
    return with_retries(lambda: _download_once(artifact, dest, max_bytes))


def _download_once(artifact: Artifact, dest: Path, max_bytes: int) -> tuple[str, int]:
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
                raise TooLarge(f"artifact exceeds configured limit: {total}>{max_bytes}")
            h.update(chunk)
            out.write(chunk)
    digest = h.hexdigest()
    if artifact.sha256 and digest.lower() != artifact.sha256.lower():
        raise ValueError(f"artifact sha256 mismatch: expected {artifact.sha256}, got {digest}")
    artifact.size_bytes = total
    return digest, total


def _malware_verdict(candidate, artifact, sha256, first_seen, run, outcome, previous_outcome,
                     known_previous_version: str, workdir: Path, scanner, max_artifact_bytes):
    """Malware row for one release, comparing with its previous release when needed.

    The previous release is scanned only for a NEW_VERSION that carries a risky
    mechanism, and reused from the CVE comparison when that already scanned it.
    Never raises: a failed comparison leaves the row on the analyzer's verdict alone.
    """
    if outcome.malware_status != "COMPLETE":
        return None
    prev_result, prev_status, prev_version = None, "NOT_NEEDED", ""
    if needs_previous(candidate, outcome.malware):
        try:
            if previous_outcome is not None and previous_outcome.malware_status == "COMPLETE":
                prev_result, prev_status = previous_outcome.malware, "COMPLETE"
                prev_version = known_previous_version
            else:
                previous = previous_release(candidate)
                if previous is None:
                    prev_status = "UNAVAILABLE"
                else:
                    prev_version = previous.version
                    prev_art = resolve_artifact(previous)
                    suffix = "".join(Path(prev_art.filename).suffixes)[-20:] or ".bin"
                    prev_path = workdir / f"malware-previous{suffix}"
                    download(prev_art, prev_path, max_artifact_bytes)
                    prev_result, prev_status, _err = scanner.malware_only(
                        prev_path, package_name=candidate.name, ecosystem=candidate.registry)
        except Exception:  # noqa: BLE001 - comparison is best effort
            prev_result, prev_status = None, "FAILED"
    return malware_row(run_id=run, candidate=candidate, artifact=artifact, sha256=sha256,
                       first_seen=first_seen, result=outcome.malware, previous=prev_result,
                       previous_version=prev_version, previous_status=prev_status)


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
    window_days: int = 0,
    max_minutes: float = 0,
    clock=time.monotonic,
    malware_sink: list[dict] | None = None,
) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    manifests: list[dict] = []
    # Budget cap: stop starting new scans once this much time has gone (0 = no cap). Discovery
    # time counts too, so the whole capture stays inside the minutes it was given.
    deadline = clock() + max_minutes * 60 if max_minutes > 0 else None
    if window_days > 0:
        batch = discover_window(registry, mode, limit, window_days, state)
    else:
        batch = discover(registry, mode, limit, state)

    for index, candidate in enumerate(batch.candidates):
        if deadline is not None and clock() >= deadline:
            print(
                f"budget: {max_minutes:g} min reached; {len(batch.candidates) - index} selected releases left unscanned",
                file=sys.stderr,
            )
            break
        first_seen = utc_now()
        state.record_discovered(candidate.registry, candidate.name, candidate.version, candidate.event_type, first_seen)
        if state.is_completed(candidate.registry, candidate.name, candidate.version):
            continue

        manifest = {
            "run_id": run, "registry": candidate.registry, "event_type": candidate.event_type,
            "package_name": candidate.name, "package_version": candidate.version, "purl": candidate.purl,
            "published_at_utc": candidate.published_at, "first_seen_at_utc": first_seen,
            "scan_status": "STARTED", "scan_started_at_utc": utc_now(), "scan_finished_at_utc": "",
            "trivy_exit_code": "", "semgrep_exit_code": "", "finding_count": "0",
            "failure_stage": "", "error": "",
            "malware_status": "", "malware_verdict": "", "malware_error": "",
        }
        stage = "artifact_resolve"
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
                stage = "artifact_download"
                sha256, size = download(artifact, artifact_path, max_artifact_bytes)
                manifest["artifact_sha256"] = sha256
                manifest["artifact_size_bytes"] = str(size)

                stage = "static_scan"
                outcome = scanner.scan(artifact_path, package_name=candidate.name,
                                       ecosystem=candidate.registry)
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
                stage = "advisory_enrichment"
                enrich_rows(rows, advisory, checked_at=utc_now())

                previous_version = ""
                previous_outcome = None
                previous_keys: set[tuple[str, str]] = set()
                previous_status = "NOT_NEEDED"
                previous_error = ""

                semgrep_candidates = [
                    row for row in rows
                    if row.get("scanner") == "semgrep"
                    and row.get("dedup_status") in {"NO_MATCH", "POSSIBLE_MATCH", "LOOKUP_FAILED"}
                ]
                if semgrep_candidates:
                    try:
                        stage = "previous_version_compare"
                        previous = previous_release(candidate)
                        if previous is None:
                            previous_status = "UNAVAILABLE"
                        else:
                            previous_version = previous.version
                            previous_artifact = resolve_artifact(previous)
                            previous_suffix = "".join(Path(previous_artifact.filename).suffixes)[-20:] or ".bin"
                            previous_path = Path(td) / f"previous{previous_suffix}"
                            download(previous_artifact, previous_path, max_artifact_bytes)
                            previous_outcome = scanner.scan(
                                previous_path, package_name=candidate.name,
                                ecosystem=candidate.registry)
                            previous_keys = {
                                (str(item.get("check_id") or ""), str(item.get("path") or ""))
                                for item in (previous_outcome.semgrep.get("results") or [])
                            }
                            previous_status = "COMPLETE"
                    except Exception as exc:
                        previous_status = "FAILED"
                        previous_error = f"{type(exc).__name__}: {exc}"[:1000]

                stage = "validation"
                apply_validation(
                    rows,
                    previous_version=previous_version,
                    previous_keys=previous_keys,
                    previous_compare_status=previous_status,
                    previous_compare_error=previous_error,
                )
                findings.extend(rows)

                stage = "malware_analysis"
                manifest["malware_status"] = outcome.malware_status
                manifest["malware_error"] = outcome.malware_error
                row = _malware_verdict(
                    candidate, artifact, sha256, first_seen, run, outcome, previous_outcome,
                    previous_version, Path(td), scanner, max_artifact_bytes)
                if row:
                    manifest["malware_verdict"] = row["verdict"]
                    if malware_sink is not None:
                        malware_sink.append(row)

                manifest["trivy_exit_code"] = str(outcome.trivy_exit_code)
                manifest["semgrep_exit_code"] = str(outcome.semgrep_exit_code)
                manifest["finding_count"] = str(len(rows))
                manifest["scan_status"] = "COMPLETED"
                state.mark_completed(candidate.registry, candidate.name, candidate.version, sha256, utc_now())

        except PolicySkip as exc:
            # Refused by policy before download (e.g. a dist host outside the allow-list). Not a
            # coverage failure, but still left retryable in state in case the metadata catches up.
            manifest["scan_status"] = "SKIPPED"
            manifest["failure_stage"] = stage
            manifest["error"] = f"{type(exc).__name__}: {exc}"[:4000]
            state.mark_failed(candidate.registry, candidate.name, candidate.version, manifest["error"])
        except Exception as exc:
            reason = _skip_reason(exc)
            manifest["scan_status"] = "SKIPPED" if reason else "FAILED"
            manifest["failure_stage"] = stage
            manifest["error"] = (reason or f"{type(exc).__name__}: {exc}")[:4000]
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
    parser.add_argument("--registry", choices=[*REGISTRIES, "all"], default="all")
    parser.add_argument("--mode", choices=["all", "updates", "new"], default="all")
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument("--output", type=Path, default=Path("reports"))
    parser.add_argument(
        "--state-db",
        type=Path,
        default=Path(os.environ.get("HUGINN_STATE_DB", "~/.local/state/huginn/state.db")).expanduser(),
    )
    parser.add_argument("--max-artifact-bytes", type=int, default=DEFAULT_MAX_ARTIFACT)
    parser.add_argument(
        "--window-days",
        type=int,
        default=0,
        help="List every release from the last N days and scan a spread-out selection (0 = latest feeds only)",
    )
    parser.add_argument(
        "--max-minutes",
        type=float,
        default=0,
        help="Stop starting new package scans after this many minutes (0 = no cap)",
    )
    args = parser.parse_args()

    started = utc_now()
    run = run_id()
    out_dir = args.output / run
    package_root = Path(__file__).resolve().parent

    scanner = PodmanScanner(
        rules_file=Path(os.environ.get("HUGINN_RULES_FILE", package_root / "rules" / "semgrep.yml")).resolve(),
        archive_script=Path(os.environ.get("HUGINN_ARCHIVE_SCRIPT", package_root / "archive.py")).resolve(),
        trivy_image=os.environ.get("HUGINN_TRIVY_IMAGE", "docker.io/aquasec/trivy:0.74.0"),
        semgrep_image=os.environ.get("HUGINN_SEMGREP_IMAGE", "docker.io/semgrep/semgrep:1.177.0"),
        unpack_image=os.environ.get("HUGINN_UNPACK_IMAGE", "docker.io/library/python:3.13-slim"),
        trivy_cache_volume=os.environ.get("HUGINN_TRIVY_CACHE_VOLUME", "huginn-trivy-cache"),
    )
    advisory = AdvisoryClient()
    state = StateDB(args.state_db)
    registries = list(REGISTRIES) if args.registry == "all" else [args.registry]

    all_findings: list[dict] = []
    all_manifests: list[dict] = []
    all_alerts: list[dict] = []
    all_malware: list[dict] = []
    for registry in registries:
        try:
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
                args.window_days,
                args.max_minutes,
                malware_sink=all_malware,
            )
        except Exception as exc:
            all_alerts.append(
                make_alert(
                    run_id=run,
                    registry=registry,
                    stage="registry_discovery",
                    alert_type="ECOSYSTEM_DISCOVERY_FAILURE",
                    source=registry,
                    message=f"{type(exc).__name__}: {exc}",
                    error_type=type(exc).__name__,
                    severity="CRITICAL",
                    retryable=True,
                    coverage_impact="ECOSYSTEM_NOT_ANALYZED",
                    recommended_action="Retry registry discovery before treating the hunt as complete.",
                )
            )
            continue
        all_findings.extend(findings)
        all_manifests.extend(manifests)
        all_alerts.extend(alerts_from_manifests(run, manifests))
        all_alerts.extend(alerts_from_findings(run, findings))

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
    malware_counts = summary_counts(all_malware, all_manifests)
    if all_manifests and malware_counts["malware_not_configured_count"]:
        all_alerts.append(make_alert(
            run_id=run, registry=args.registry, stage="malware_analysis",
            alert_type="MALWARE_SCAN_NOT_CONFIGURED", source="HUGINN_ANALYZER_IMAGE",
            message="Malicious-package analysis did not run: no analyzer image configured.",
            severity="MEDIUM", coverage_impact="MALWARE_NOT_ANALYZED",
            recommended_action="Check the 'Build malware analyzer' step of the capture job."))
    if malware_counts["malware_failed_count"]:
        all_alerts.append(make_alert(
            run_id=run, registry=args.registry, stage="malware_analysis",
            alert_type="MALWARE_SCAN_FAILED", source="huginn_analyzer.package_entry",
            message=f"{malware_counts['malware_failed_count']} package(s) were not analyzed "
                    "for malware; see malware_error in scan_manifest.csv.",
            severity="HIGH", coverage_impact="PARTIAL"))
    all_malware.sort(key=lambda r: (r.get("verdict") != "CONFIRMED", r.get("registry", ""),
                                    r.get("package_name", ""), r.get("package_version", "")))
    write_csv(out_dir / "malicious_findings.csv", MALWARE_COLUMNS, all_malware)
    write_csv(out_dir / "operational_alerts.csv", ALERT_COLUMNS, all_alerts)

    summary = {
        "run_id": run,
        "started_at_utc": started,
        "finished_at_utc": utc_now(),
        "registry": args.registry,
        "mode": args.mode,
        "window_days": args.window_days,
        "max_minutes": args.max_minutes,
        "finding_count": len(all_findings),
        "novel_no_match_count": sum(1 for row in all_findings if row.get("dedup_status") == "NO_MATCH"),
        "possible_match_count": sum(1 for row in all_findings if row.get("dedup_status") == "POSSIBLE_MATCH"),
        "known_exact_count": sum(1 for row in all_findings if row.get("dedup_status") == "KNOWN_EXACT"),
        "lookup_failed_count": sum(1 for row in all_findings if row.get("dedup_status") == "LOOKUP_FAILED"),
        "high_value_manual_candidate_count": sum(
            1 for row in all_findings if row.get("validation_state") == "HIGH_VALUE_MANUAL_CANDIDATE"
        ),
        "needs_reachability_review_count": sum(
            1 for row in all_findings if row.get("validation_state") == "NEEDS_REACHABILITY_REVIEW"
        ),
        "noise_likely_count": sum(
            1 for row in all_findings if row.get("validation_state") == "NOISE_LIKELY"
        ),
        "static_dataflow_count": sum(
            1 for row in all_findings if row.get("reachability_state") == "STATIC_DATAFLOW"
        ),
        "package_scan_count": len(all_manifests),
        "failed_package_scans": sum(1 for row in all_manifests if row.get("scan_status") == "FAILED"),
        "skipped_package_scans": sum(1 for row in all_manifests if row.get("scan_status") == "SKIPPED"),
        "operational_alert_count": len(all_alerts),
        "critical_coverage_alert_count": sum(1 for row in all_alerts if row.get("severity") == "CRITICAL"),
        "high_coverage_alert_count": sum(1 for row in all_alerts if row.get("severity") == "HIGH"),
        **malware_counts,
        "malicious_findings_csv": "malicious_findings.csv",
        "review_csv": "review_findings.csv",
        "manifest_csv": "scan_manifest.csv",
        "operational_alerts_csv": "operational_alerts.csv",
        "automatic_disclosure": False,
        "automatic_cve_submission": False,
    }
    (out_dir / "run_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(out_dir)


if __name__ == "__main__":
    main()
