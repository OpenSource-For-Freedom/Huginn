from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from huginn.report_quality import write_quality_report


def read_csvs(root: Path, filename: str) -> tuple[list[str], list[dict[str, str]]]:
    fieldnames: list[str] = []
    rows: list[dict[str, str]] = []

    for path in sorted(root.rglob(filename)):
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            current = list(reader.fieldnames or [])
            if not current:
                continue
            if not fieldnames:
                fieldnames = current
            elif current != fieldnames:
                raise ValueError(f"CSV schema mismatch in {path}")
            rows.extend(dict(row) for row in reader)

    return fieldnames, rows


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def load_summaries(root: Path) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("run_summary.json")):
        summary = json.loads(path.read_text(encoding="utf-8"))
        summary["source_path"] = str(path.relative_to(root))
        summaries.append(summary)
    return summaries


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge Huginn ecosystem matrix artifacts.")
    parser.add_argument("input_root", type=Path)
    parser.add_argument("output_root", type=Path)
    args = parser.parse_args()

    review_fields, review_rows = read_csvs(args.input_root, "review_findings.csv")
    manifest_fields, manifest_rows = read_csvs(args.input_root, "scan_manifest.csv")
    alert_fields, alert_rows = read_csvs(args.input_root, "operational_alerts.csv")
    malware_fields, malware_rows = read_csvs(args.input_root, "malicious_findings.csv")
    summaries = load_summaries(args.input_root)

    if review_fields:
        review_rows.sort(
            key=lambda row: (
                row.get("triage_priority", "P9"),
                row.get("registry", ""),
                row.get("package_name", ""),
                row.get("package_version", ""),
                row.get("file_path", ""),
            )
        )
        write_csv(args.output_root / "review_findings.csv", review_fields, review_rows)

    if manifest_fields:
        manifest_rows.sort(
            key=lambda row: (
                row.get("registry", ""),
                row.get("package_name", ""),
                row.get("package_version", ""),
            )
        )
        write_csv(args.output_root / "scan_manifest.csv", manifest_fields, manifest_rows)

    if alert_fields:
        alert_rows.sort(
            key=lambda row: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(row.get("severity", ""), 9),
                row.get("registry", ""),
                row.get("stage", ""),
                row.get("package_name", ""),
            )
        )
        write_csv(args.output_root / "operational_alerts.csv", alert_fields, alert_rows)

    if malware_fields:
        malware_rows.sort(
            key=lambda row: (
                row.get("verdict") != "CONFIRMED",
                row.get("registry", ""),
                row.get("package_name", ""),
                row.get("package_version", ""),
            )
        )
        write_csv(args.output_root / "malicious_findings.csv", malware_fields, malware_rows)

    aggregate = {
        "ecosystem_runs": summaries,
        "ecosystem_count": len(summaries),
        "package_scan_count": sum(int(s.get("package_scan_count", 0)) for s in summaries),
        "failed_package_scans": sum(int(s.get("failed_package_scans", 0)) for s in summaries),
        "skipped_package_scans": sum(int(s.get("skipped_package_scans", 0)) for s in summaries),
        "finding_count": sum(int(s.get("finding_count", 0)) for s in summaries),
        "novel_no_match_count": sum(int(s.get("novel_no_match_count", 0)) for s in summaries),
        "possible_match_count": sum(int(s.get("possible_match_count", 0)) for s in summaries),
        "known_exact_count": sum(int(s.get("known_exact_count", 0)) for s in summaries),
        "lookup_failed_count": sum(int(s.get("lookup_failed_count", 0)) for s in summaries),
        "high_value_manual_candidate_count": sum(
            int(s.get("high_value_manual_candidate_count", 0)) for s in summaries
        ),
        "needs_reachability_review_count": sum(
            int(s.get("needs_reachability_review_count", 0)) for s in summaries
        ),
        "noise_likely_count": sum(int(s.get("noise_likely_count", 0)) for s in summaries),
        "static_dataflow_count": sum(int(s.get("static_dataflow_count", 0)) for s in summaries),
        "operational_alert_count": sum(int(s.get("operational_alert_count", 0)) for s in summaries),
        "critical_coverage_alert_count": sum(int(s.get("critical_coverage_alert_count", 0)) for s in summaries),
        "high_coverage_alert_count": sum(int(s.get("high_coverage_alert_count", 0)) for s in summaries),
        "malware_confirmed_count": sum(int(s.get("malware_confirmed_count", 0)) for s in summaries),
        "malware_new_risk_count": sum(int(s.get("malware_new_risk_count", 0)) for s in summaries),
        "malware_suspicious_count": sum(int(s.get("malware_suspicious_count", 0)) for s in summaries),
        "malware_scanned_count": sum(int(s.get("malware_scanned_count", 0)) for s in summaries),
        "malware_failed_count": sum(int(s.get("malware_failed_count", 0)) for s in summaries),
        "automatic_disclosure": False,
        "automatic_cve_submission": False,
    }
    args.output_root.mkdir(parents=True, exist_ok=True)
    write_quality_report(args.output_root, review_rows)
    (args.output_root / "matrix_summary.json").write_text(
        json.dumps(aggregate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        f"merged {len(summaries)} ecosystem run(s), "
        f"{len(manifest_rows)} package scan(s), "
        f"{len(review_rows)} finding(s), "
        f"{len(malware_rows)} malicious-package row(s), "
        f"{len(alert_rows)} operational alert(s)"
    )


if __name__ == "__main__":
    main()
