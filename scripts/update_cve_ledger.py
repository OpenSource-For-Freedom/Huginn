"""Maintain Huginn's static, repository-tracked CVE ledger from a merged hunt packet.

Three CSVs live in the ledger directory (committed to the ``huginn-ledger`` branch by the
capture workflow after every hunt):

* ``cve_ledger/<registry>-<h>.csv`` - true positives only, LOW..CRITICAL, every column filled,
  sharded by registry and the first hex digit of ``ledger_id`` so no file nears GitHub's 100 MB
  per-file limit (``read_ledger`` returns all shards as one table). A row enters it when either
    - the finding is an advisory-confirmed CVE/GHSA match for the exact shipped dependency version
      (``dedup_status=KNOWN_EXACT``), or
    - an analyst promoted a candidate to ``review_status=VALIDATED`` in ``candidate_queue.csv``
      and the row passes the same rules as ``huginn.review_validate``.
* ``candidate_queue.csv`` - high-value manual candidates awaiting analyst review, full review
  columns, deduplicated by finding fingerprint. Analyst edits to review fields are preserved.
* ``run_log.csv`` - one row per hunt run.
* ``validated_findings.csv`` - the true-findings list: one row per validated vulnerability
  (``HUGINN-YYYY-NNN``). Rows are curated by the analyst (CVSS, summary, disclosure and CVE status)
  and never overwritten; every run appends a ``PENDING`` row for any package an analyst has
  marked ``VALIDATED`` in the queue that the list does not have yet.

Sink-only scanner output is never promoted automatically.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from huginn.reporting import REVIEW_COLUMNS  # noqa: E402
from huginn.review_validate import validate  # noqa: E402
from huginn.report_quality import write_quality_report  # noqa: E402

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
ADVISORY_ID = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$")
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
CANDIDATE_STATES = {"HIGH_VALUE_MANUAL_CANDIDATE"}
ANALYST_FIELDS = (
    "review_status", "reviewer", "reviewer_decision", "reviewer_notes", "reachability_verified",
    "security_boundary_verified", "affected_version_verified", "known_advisory_verified",
    "false_positive_reason", "verified_at_utc", "disclosure_status", "disclosure_reference",
)

LEDGER_COLUMNS = [
    "ledger_id", "confirmation_basis", "finding_type", "vulnerability_id", "cve_ids", "severity",
    "cvss_score", "cvss_vector", "cwe", "registry", "package_name", "package_version", "purl",
    "published_at_utc", "artifact_url", "artifact_sha256", "dependency_ecosystem", "dependency_name",
    "installed_version", "fixed_version", "file_path", "title", "advisory_source", "advisory_url",
    "first_logged_hunt", "first_logged_at_utc", "last_seen_hunt", "last_seen_at_utc", "times_seen",
    "review_status", "disclosure_status",
]
RUN_LOG_COLUMNS = [
    "hunt_id", "logged_at_utc", "ecosystems", "package_scan_count", "failed_package_scans",
    "finding_count", "known_exact_count", "high_value_manual_candidate_count", "static_dataflow_count",
    "ledger_rows_added", "ledger_rows_seen_again", "ledger_total_rows", "candidates_added",
    "candidate_queue_rows", "analyst_validated_promoted",
]

# Placeholders for facts the upstream advisory genuinely does not publish, so that a filled cell
# always states something true instead of being blank.
NOT_PUBLISHED = "NOT_PUBLISHED"
LEDGER_DIR = "cve_ledger"
LEGACY_LEDGER = "cve_ledger.csv"
# GitHub rejects pushes containing a file over 100 MB; fail before that with a clear message.
MAX_FILE_BYTES = 90 * 1024 * 1024
NOT_APPLICABLE = "NOT_APPLICABLE"
NO_FIX = "NO_FIX_AVAILABLE"
FINDINGS_FILE = "validated_findings.csv"
FINDINGS_COLUMNS = [
    "finding_id", "package", "registry", "affected_versions", "fixed_version", "severity", "cvss4_vector",
    "cvss4_score", "cwe", "summary", "validated_at_utc", "found_in_hunt", "disclosure_draft", "vendor_contact",
    "cve_id", "status",
]
PENDING = "PENDING"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def ledger_shard(row: dict[str, str]) -> str:
    return f"{row['registry'] or 'unknown'}-{row['ledger_id'][:1] or '0'}.csv"


def read_ledger(ledger_dir: Path) -> list[dict[str, str]]:
    """All ledger rows: every shard, plus the pre-shard single file if it is still present."""
    rows = read_rows(ledger_dir / LEGACY_LEDGER)
    for shard in sorted((ledger_dir / LEDGER_DIR).glob("*.csv")):
        rows.extend(read_rows(shard))
    return rows


def write_ledger(ledger_dir: Path, rows: list[dict[str, str]]) -> None:
    shards: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        shards.setdefault(ledger_shard(row), []).append(row)
    shard_dir = ledger_dir / LEDGER_DIR
    for stale in shard_dir.glob("*.csv"):
        if stale.name not in shards:
            stale.unlink()
    for name, shard_rows in shards.items():
        write_rows(shard_dir / name, LEDGER_COLUMNS, shard_rows)
    (ledger_dir / LEGACY_LEDGER).unlink(missing_ok=True)


def write_rows(path: Path, columns: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _v(row: dict[str, str], key: str) -> str:
    return (row.get(key) or "").strip()


def _cwe(row: dict[str, str]) -> str:
    raw = _v(row, "cwe") or _v(row, "advisory_cwes")
    found = sorted(set(re.findall(r"CWE-\d+", raw)))
    return ";".join(found) or NOT_PUBLISHED


def _cves(row: dict[str, str]) -> str:
    found = set(CVE_ID.findall(" ".join((_v(row, "vulnerability_id"), _v(row, "advisory_cves"),
                                          _v(row, "nvd_ids"), _v(row, "osv_ids")))))
    return ";".join(sorted(found)) or "NOT_ASSIGNED"


def ledger_key(row: dict[str, str]) -> str:
    parts = [_v(row, k) for k in ("registry", "package_name", "package_version", "vulnerability_id",
                                  "dependency_name", "installed_version", "file_path")]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]


def known_true_positive(row: dict[str, str]) -> bool:
    return (
        _v(row, "dedup_status") == "KNOWN_EXACT"
        and _v(row, "severity").upper() in SEVERITIES
        and bool(ADVISORY_ID.match(_v(row, "vulnerability_id")))
        and bool(_v(row, "dependency_name"))
        and bool(_v(row, "installed_version"))
    )


def to_ledger(row: dict[str, str], basis: str, hunt_id: str, now: str) -> dict[str, str]:
    known = basis == "ADVISORY_EXACT_MATCH"
    dependency = known or bool(_v(row, "dependency_name"))
    out = {
        "ledger_id": ledger_key(row),
        "confirmation_basis": basis,
        "finding_type": "KNOWN_DEPENDENCY_CVE" if known else "NOVEL_ANALYST_VALIDATED",
        "vulnerability_id": _v(row, "vulnerability_id") or _v(row, "rule_id"),
        "cve_ids": _cves(row),
        "severity": _v(row, "severity").upper(),
        "cvss_score": _v(row, "cvss_score") or NOT_PUBLISHED,
        "cvss_vector": _v(row, "cvss_vector") or NOT_PUBLISHED,
        "cwe": _cwe(row),
        "registry": _v(row, "registry"),
        "package_name": _v(row, "package_name"),
        "package_version": _v(row, "package_version"),
        "purl": _v(row, "purl"),
        "published_at_utc": _v(row, "published_at_utc") or NOT_PUBLISHED,
        "artifact_url": _v(row, "artifact_url"),
        "artifact_sha256": _v(row, "artifact_sha256"),
        "dependency_ecosystem": (_v(row, "dependency_ecosystem") or NOT_PUBLISHED) if dependency else NOT_APPLICABLE,
        "dependency_name": _v(row, "dependency_name") if dependency else NOT_APPLICABLE,
        "installed_version": _v(row, "installed_version") if dependency else NOT_APPLICABLE,
        "fixed_version": (_v(row, "fixed_version") or NO_FIX) if dependency else NOT_APPLICABLE,
        "file_path": _v(row, "file_path"),
        "title": _v(row, "title") or _v(row, "message")[:200] or _v(row, "vulnerability_id"),
        "advisory_source": _v(row, "advisory_source") or ("analyst review" if not known else NOT_PUBLISHED),
        "advisory_url": _v(row, "advisory_url") or _v(row, "disclosure_reference") or NOT_PUBLISHED,
        "first_logged_hunt": hunt_id,
        "first_logged_at_utc": now,
        "last_seen_hunt": hunt_id,
        "last_seen_at_utc": now,
        "times_seen": "1",
        "review_status": "KNOWN" if known else "VALIDATED",
        "disclosure_status": ("PUBLIC_ADVISORY" if known else (_v(row, "disclosure_status") or "NOT_DISCLOSED")),
    }
    return out


def blank_columns(row: dict[str, str], columns: list[str]) -> list[str]:
    return [c for c in columns if not (row.get(c) or "").strip()]


def sync_validated_findings(ledger_dir: Path, queue_rows: list[dict[str, str]], hunt_id: str, now: str) -> int:
    """Append a PENDING row to validated_findings.csv for each newly validated package.

    Existing rows are analyst-curated and left exactly as they are. Packages are matched
    case-insensitively, so mirror paths that differ only in case count as one finding.
    """
    path = ledger_dir / FINDINGS_FILE
    findings = read_rows(path)
    known = {_v(row, "package").lower() for row in findings}
    validated: dict[str, list[dict[str, str]]] = {}
    for row in queue_rows:
        if _v(row, "review_status").upper() == "VALIDATED" and _v(row, "package_name"):
            validated.setdefault(_v(row, "package_name").lower(), []).append(row)

    year = now[:4]
    numbers = [int(m.group(1)) for row in findings
               if (m := re.fullmatch(rf"HUGINN-{year}-(\d+)", _v(row, "finding_id")))]
    next_number = max(numbers, default=0) + 1
    added = 0
    for key in sorted(validated):
        if key in known:
            continue
        rows = validated[key]
        first = rows[0]
        versions = sorted({_v(r, "package_version") for r in rows if _v(r, "package_version")})
        severities = [_v(r, "severity").upper() for r in rows if _v(r, "severity").upper() in SEVERITIES]
        reference = _v(first, "disclosure_reference")
        findings.append({
            "finding_id": f"HUGINN-{year}-{next_number:03d}",
            "package": _v(first, "package_name"),
            "registry": _v(first, "registry") or "unknown",
            "affected_versions": ";".join(versions) + " (scanned; full range pending)" if versions else PENDING,
            "fixed_version": PENDING,
            "severity": min(severities, key=SEVERITIES.index) if severities else PENDING,
            "cvss4_vector": PENDING,
            "cvss4_score": PENDING,
            "cwe": _cwe(first),
            "summary": (_v(first, "reviewer_decision") or _v(first, "title") or PENDING)[:300],
            "validated_at_utc": _v(first, "verified_at_utc") or now,
            "found_in_hunt": _v(first, "run_id") or hunt_id,
            "disclosure_draft": reference if reference.startswith("docs/") else PENDING,
            "vendor_contact": "NOT_CONTACTED",
            "cve_id": "NOT_REQUESTED",
            "status": "OPEN",
        })
        known.add(key)
        next_number += 1
        added += 1
    if added:
        write_rows(path, FINDINGS_COLUMNS, findings)
    return added


def update(packet: Path, ledger_dir: Path, hunt_id: str, now: str | None = None) -> dict[str, str]:
    now = now or utc_now()
    findings = read_rows(packet / "review_findings.csv")
    summary_path = packet / "matrix_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.is_file() else {}

    queue_path = ledger_dir / "candidate_queue.csv"
    log_path = ledger_dir / "run_log.csv"

    ledger = {row["ledger_id"]: row for row in read_ledger(ledger_dir)}
    queue = {row["finding_fingerprint"]: row for row in read_rows(queue_path) if row.get("finding_fingerprint")}

    added = seen_again = candidates_added = promoted = 0
    rejected: list[str] = []

    def upsert(row: dict[str, str], basis: str) -> None:
        nonlocal added, seen_again
        entry = to_ledger(row, basis, hunt_id, now)
        missing = blank_columns(entry, LEDGER_COLUMNS)
        if missing:
            rejected.append(f"{entry['package_name']} {entry['vulnerability_id']}: blank {','.join(missing)}")
            return
        existing = ledger.get(entry["ledger_id"])
        if existing is None:
            ledger[entry["ledger_id"]] = entry
            added += 1
        elif existing.get("last_seen_hunt") != hunt_id:
            existing["last_seen_hunt"] = hunt_id
            existing["last_seen_at_utc"] = now
            existing["times_seen"] = str(int(existing.get("times_seen") or "1") + 1)
            seen_again += 1

    for row in findings:
        if known_true_positive(row):
            upsert(row, "ADVISORY_EXACT_MATCH")
        elif _v(row, "validation_state") in CANDIDATE_STATES and _v(row, "finding_fingerprint"):
            fp = _v(row, "finding_fingerprint")
            if fp in queue:
                # Keep the analyst's review fields; refresh only scanner-side evidence.
                preserved = {k: queue[fp].get(k, "") for k in ANALYST_FIELDS}
                queue[fp] = {**row, **{k: v for k, v in preserved.items() if v}}
            else:
                queue[fp] = dict(row)
                candidates_added += 1
            queue[fp]["review_status"] = _v(queue[fp], "review_status") or "PENDING"

    # Promote analyst-validated candidates that pass the review validator.
    queue_rows = sorted(queue.values(), key=lambda r: (_v(r, "triage_priority"), _v(r, "registry"),
                                                      _v(r, "package_name"), _v(r, "file_path")))
    write_rows(queue_path, REVIEW_COLUMNS, queue_rows)
    errors = validate(queue_path)
    if errors:
        raise SystemExit("candidate_queue.csv failed review validation:\n" + "\n".join(errors))
    for row in queue_rows:
        if _v(row, "review_status").upper() == "VALIDATED" and _v(row, "severity").upper() in SEVERITIES:
            before = len(ledger)
            upsert(row, "ANALYST_VALIDATED")
            promoted += len(ledger) - before

    ledger_rows = sorted(ledger.values(), key=lambda r: (SEVERITIES.index(r["severity"]) if r["severity"] in SEVERITIES else 9,
                                                         r["registry"], r["package_name"], r["package_version"],
                                                         r["vulnerability_id"]))
    write_ledger(ledger_dir, ledger_rows)

    log_rows = read_rows(log_path)
    log_entry = {
        "hunt_id": hunt_id,
        "logged_at_utc": now,
        "ecosystems": ";".join(sorted(str(s.get("registry")) for s in summary.get("ecosystem_runs", []))) or "none",
        "package_scan_count": str(summary.get("package_scan_count", 0)),
        "failed_package_scans": str(summary.get("failed_package_scans", 0)),
        "finding_count": str(summary.get("finding_count", len(findings))),
        "known_exact_count": str(summary.get("known_exact_count", 0)),
        "high_value_manual_candidate_count": str(summary.get("high_value_manual_candidate_count", 0)),
        "static_dataflow_count": str(summary.get("static_dataflow_count", 0)),
        "ledger_rows_added": str(added),
        "ledger_rows_seen_again": str(seen_again),
        "ledger_total_rows": str(len(ledger_rows)),
        "candidates_added": str(candidates_added),
        "candidate_queue_rows": str(len(queue_rows)),
        "analyst_validated_promoted": str(promoted),
    }
    log_rows = [r for r in log_rows if r.get("hunt_id") != hunt_id] + [log_entry]
    write_rows(log_path, RUN_LOG_COLUMNS, log_rows)
    write_quality_report(ledger_dir, queue_rows)
    new_findings = sync_validated_findings(ledger_dir, queue_rows, hunt_id, now)
    if new_findings:
        print(f"ledger: +{new_findings} new row(s) in {FINDINGS_FILE} (PENDING analyst details)")

    for message in rejected:
        print(f"ledger: skipped incomplete row: {message}")
    return log_entry


def check_ledger(ledger_dir: Path) -> list[str]:
    """Every ledger row must have every column filled and a LOW..CRITICAL severity."""
    errors = []
    shards = [ledger_dir / LEGACY_LEDGER, *sorted((ledger_dir / LEDGER_DIR).glob("*.csv"))]
    for shard in shards:
        name = shard.relative_to(ledger_dir).as_posix()
        for line, row in enumerate(read_rows(shard), 2):
            missing = blank_columns(row, LEDGER_COLUMNS)
            if missing:
                errors.append(f"{name} line {line}: blank {', '.join(missing)}")
            if row.get("severity") not in SEVERITIES:
                errors.append(f"{name} line {line}: severity {row.get('severity')!r} outside LOW..CRITICAL")
    for line, row in enumerate(read_rows(ledger_dir / "run_log.csv"), 2):
        missing = blank_columns(row, RUN_LOG_COLUMNS)
        if missing:
            errors.append(f"run_log.csv line {line}: blank {', '.join(missing)}")
    for path in ledger_dir.rglob("*"):
        if path.is_file() and path.stat().st_size > MAX_FILE_BYTES:
            errors.append(f"{path.relative_to(ledger_dir).as_posix()} is {path.stat().st_size} bytes; "
                          f"over the {MAX_FILE_BYTES}-byte limit kept below GitHub's 100 MB file cap")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Update Huginn's repository CVE ledger from a merged hunt packet.")
    parser.add_argument("packet", type=Path, help="directory containing merged review_findings.csv/matrix_summary.json")
    parser.add_argument("ledger_dir", type=Path)
    parser.add_argument("--hunt-id", required=True)
    args = parser.parse_args()

    entry = update(args.packet, args.ledger_dir, args.hunt_id)
    errors = check_ledger(args.ledger_dir)
    if errors:
        raise SystemExit("ledger validation failed:\n" + "\n".join(errors))
    print(
        f"ledger: +{entry['ledger_rows_added']} new true-positive row(s), "
        f"{entry['ledger_rows_seen_again']} seen again, {entry['ledger_total_rows']} total; "
        f"+{entry['candidates_added']} candidate(s), {entry['candidate_queue_rows']} in queue"
    )


if __name__ == "__main__":
    main()
