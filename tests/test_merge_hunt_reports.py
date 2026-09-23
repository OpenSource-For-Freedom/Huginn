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
                    }),
                    encoding="utf-8",
                )

            fields, rows = read_csvs(root, "review_findings.csv")
            self.assertEqual(fields, ["registry", "triage_priority", "package_name"])
            self.assertEqual(len(rows), 3)

            manifest_fields, manifest_rows = read_csvs(root, "scan_manifest.csv")
            self.assertEqual(len(manifest_rows), 3)
            self.assertEqual(manifest_fields, ["registry", "package_name", "package_version"])

            summaries = load_summaries(root)
            self.assertEqual(len(summaries), 3)
            self.assertEqual(sum(s["finding_count"] for s in summaries), 3)

            out = root / "out.csv"
            write_csv(out, fields, rows)
            self.assertTrue(out.read_bytes().startswith(b"\xef\xbb\xbf"))


if __name__ == "__main__":
    unittest.main()
