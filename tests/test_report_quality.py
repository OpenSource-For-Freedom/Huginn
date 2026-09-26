import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from huginn.report_quality import audit_rows, write_quality_report
from scripts.merge_hunt_reports import main as merge_main


class ReportQualityTests(unittest.TestCase):
    def test_regression_fixtures(self):
        fixtures = json.loads((Path(__file__).parent / "fixtures/report_quality.json").read_text())
        for case in fixtures:
            with self.subTest(case=case["name"]):
                result = audit_rows([case["row"]])[0]
                for key, value in case["expected"].items():
                    self.assertEqual(result[key], value)

    def test_grouping_preserves_rows_and_separates_artifacts_and_locations(self):
        base = dict(registry="pypi", package_name="fixture", package_version="1.0",
                    artifact_sha256="a" * 64, file_path="module.py", start_line="20",
                    end_line="22", finding_class="static_pattern")
        rows = [dict(base, rule_id="one"), dict(base, rule_id="two"),
                dict(base, start_line="30"), dict(base, artifact_sha256="b" * 64),
                dict(base, package_version="2.0")]
        before = json.dumps(rows)
        result = audit_rows(rows)
        self.assertEqual(len(result), 5)
        self.assertEqual(result[0]["review_group"], result[1]["review_group"])
        self.assertEqual(result[0]["group_alert_count"], "2")
        self.assertEqual(len({r["review_group"] for r in result}), 4)
        self.assertEqual(json.dumps(rows), before)

    def test_incomplete_locations_are_not_collapsed(self):
        result = audit_rows([{}, {}])
        self.assertNotEqual(result[0]["review_group"], result[1]["review_group"])

    def test_cvss_disagreement_is_flagged_without_rewriting_severity(self):
        row = dict(cvss_score="5.5", cvss_vector="CVSS:3.1/AV:L", severity="HIGH")
        self.assertIn("SEVERITY_SCORE_DISAGREEMENT", audit_rows([row])[0]["quality_flags"])
        self.assertEqual(row["severity"], "HIGH")

    def test_scores_and_status_never_automatically_approve_a_report(self):
        for status in ("PENDING", "VALIDATED"):
            result = audit_rows([dict(validation_score="100", review_status=status)])[0]
            self.assertEqual(result["report_status"], "MANUAL_REVIEW_REQUIRED")
            self.assertEqual(result["score_meaning"], "AUTOMATED_RANK_NOT_CONFIRMATION")

    def test_report_files_include_zero_automatic_approvals(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write_quality_report(root, [{}])
            summary = json.loads((root / "report_quality_summary.json").read_text())
            self.assertEqual(summary["automatically_approved_reports"], 0)
            self.assertEqual(summary["raw_alert_count"], 1)
            self.assertTrue((root / "report_quality.csv").is_file())

    def test_match_is_a_completed_source_check(self):
        row = {s + "_status": "MATCH" for s in ("osv", "ghsa", "nvd", "redhat")}
        self.assertEqual(audit_rows([row])[0]["advisory_coverage"], "CHECKED_SOURCES_ONLY")

    def test_merge_entrypoint_emits_quality_files_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            packet = root / "input" / "pypi"
            packet.mkdir(parents=True)
            (packet / "review_findings.csv").write_text("package_name,novelty_state\nfixture,novel\n")
            with patch("sys.argv", ["merge", str(root / "input"), str(root / "output")]):
                merge_main()
            self.assertIn("fixture,novel", (root / "output/review_findings.csv").read_text())
            self.assertIn("UNCONFIRMED", (root / "output/report_quality.csv").read_text())
