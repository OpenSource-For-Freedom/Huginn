from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from scripts.merge_hunt_reports import load_summaries, read_csvs, write_csv


class MergeHuntReportsTests(unittest.TestCase):
    def test_merges_ecosystem_csvs_and_summaries(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for registry, findings in (("npm", 2), ("pypi", 1), ("rubygems", 0)):
                packet = root / f"huginn-review-{registry}-1"
                packet.mkdir(parents=True)
                with (packet / "review_findings.csv").open("w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=["registry", "triage_priority", "package_name"])
                    writer.writeheader()
                    for i in range(findings):
                        writer.writerow({
                            "registry": registry,
                            "triage_priority": "P1",
                            "package_name": f"{registry}-{i}",
                        })
                with (packet / "scan_manifest.csv").open("w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=["registry", "package_name", "package_version"])
                    writer.writeheader()
                    writer.writerow({"registry": registry, "package_name": registry, "package_version": "1.0.0"})
                with (packet / "operational_alerts.csv").open("w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=["severity", "registry", "stage"])
                    writer.writeheader()
                    if registry == "npm":
                        writer.writerow({"severity": "HIGH", "registry": registry, "stage": "advisory_enrichment"})
                (packet / "run_summary.json").write_text(
                    json.dumps({
                        "registry": registry,
                        "package_scan_count": 1,
                        "failed_package_scans": 0,
                        "finding_count": findings,
                        "novel_no_match_count": findings,
                        "possible_match_count": 0,
                        "known_exact_count": 0,
                        "lookup_failed_count": 0,
                        "operational_alert_count": 1 if registry == "npm" else 0,
                        "critical_coverage_alert_count": 0,
                        "high_coverage_alert_count": 1 if registry == "npm" else 0,
                    }),
                    encoding="utf-8",
                )

            fields, rows = read_csvs(root, "review_findings.csv")
            self.assertEqual(fields, ["registry", "triage_priority", "package_name"])
            self.assertEqual(len(rows), 3)

            manifest_fields, manifest_rows = read_csvs(root, "scan_manifest.csv")
            self.assertEqual(len(manifest_rows), 3)
            self.assertEqual(manifest_fields, ["registry", "package_name", "package_version"])

            alert_fields, alert_rows = read_csvs(root, "operational_alerts.csv")
            self.assertEqual(alert_fields, ["severity", "registry", "stage"])
            self.assertEqual(len(alert_rows), 1)
            self.assertEqual(alert_rows[0]["registry"], "npm")

            summaries = load_summaries(root)
            self.assertEqual(len(summaries), 3)
            self.assertEqual(sum(s["finding_count"] for s in summaries), 3)

            out = root / "out.csv"
            write_csv(out, fields, rows)
            self.assertTrue(out.read_bytes().startswith(b"\xef\xbb\xbf"))

    def test_oversized_evidence_field_is_read_not_fatal(self):
        # A single scanner evidence value can exceed csv's default 128 KiB field limit
        # (minified bundles); hunt 36575404456 failed its aggregate step on exactly this.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            packet = root / "huginn-review-npm-1"
            packet.mkdir()
            big = "x" * (300 * 1024)
            with (packet / "review_findings.csv").open("w", encoding="utf-8-sig", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["registry", "evidence"])
                writer.writeheader()
                writer.writerow({"registry": "npm", "evidence": big})
            fields, rows = read_csvs(root, "review_findings.csv")
            self.assertEqual(fields, ["registry", "evidence"])
            self.assertEqual(len(rows[0]["evidence"]), len(big))


if __name__ == "__main__":
    unittest.main()
