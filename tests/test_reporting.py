from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from huginn.models import Artifact, ReleaseCandidate
from huginn.reporting import REVIEW_COLUMNS, normalize_semgrep, normalize_trivy, write_csv


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.candidate = ReleaseCandidate("pypi", "demo", "1.2.3", "NEW_VERSION")
        self.artifact = Artifact("demo-1.2.3.tar.gz", "https://example.invalid/demo.tar.gz")

    def test_trivy_vulnerability_is_known_and_reviewable(self):
        payload = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2026-1234", "PkgName": "dep", "InstalledVersion": "1.0",
            "FixedVersion": "1.1", "Severity": "HIGH", "Title": "demo vuln", "PrimaryURL": "https://example.invalid/cve"
        }]}]}
        rows = normalize_trivy(
            payload, run_id="r1", run_started="t", candidate=self.candidate,
            artifact=self.artifact, sha256="abc", first_seen="t"
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["vulnerability_id"], "CVE-2026-1234")
        self.assertEqual(rows[0]["dedup_status"], "KNOWN_EXACT")
        self.assertEqual(rows[0]["review_status"], "PENDING")

    def test_trivy_uv_dependency_maps_to_pypi(self):
        payload = {"Results": [{"Target": "uv.lock", "Type": "uv", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2026-9999",
            "PkgName": "pillow",
            "InstalledVersion": "11.3.0",
            "Severity": "HIGH",
        }]}]}
        rows = normalize_trivy(
            payload, run_id="r1", run_started="t", candidate=self.candidate,
            artifact=self.artifact, sha256="abc", first_seen="t"
        )
        self.assertEqual(rows[0]["dependency_ecosystem"], "pypi")

    def test_semgrep_has_inspection_columns(self):
        payload = {"version": "1.177.0", "results": [{
            "check_id": "huginn.generic.command-execution", "path": "demo.py",
            "start": {"line": 12}, "end": {"line": 12},
            "extra": {"severity": "ERROR", "message": "command", "lines": "os.system(x)",
                      "metadata": {"huginn_category": "command_execution", "huginn_confidence": "MEDIUM", "cwe": "CWE-78"}}
        }]}
        rows = normalize_semgrep(
            payload, run_id="r1", run_started="t", candidate=self.candidate,
            artifact=self.artifact, sha256="abc", first_seen="t", ruleset_hash="rules"
        )
        self.assertEqual(rows[0]["file_path"], "demo.py")
        self.assertEqual(rows[0]["start_line"], "12")
        self.assertEqual(rows[0]["cwe"], "CWE-78")
        for column in REVIEW_COLUMNS:
            self.assertIn(column, rows[0])

    def test_semgrep_prefers_isolated_static_excerpt(self):
        payload = {"version": "1.177.0", "results": [{
            "check_id": "huginn.generic.command-execution",
            "path": "demo.py",
            "start": {"line": 12},
            "end": {"line": 12},
            "extra": {
                "severity": "ERROR",
                "message": "command",
                "lines": "requires login",
                "huginn_excerpt": "10: x = input()\\n11: os.system(x)",
                "metadata": {
                    "huginn_category": "command_execution",
                    "huginn_confidence": "MEDIUM",
                    "cwe": "CWE-78",
                },
            },
        }]}
        rows = normalize_semgrep(
            payload, run_id="r1", run_started="t", candidate=self.candidate,
            artifact=self.artifact, sha256="abc", first_seen="t", ruleset_hash="rules"
        )
        self.assertEqual(rows[0]["evidence_source"], "isolated_static_excerpt")
        self.assertIn("os.system(x)", rows[0]["evidence"])
        self.assertNotIn("requires login", rows[0]["evidence"])

    def test_semgrep_ignores_login_placeholder_without_excerpt(self):
        payload = {"results": [{
            "check_id": "huginn.generic.dynamic-eval",
            "path": "demo.py",
            "start": {"line": 1},
            "end": {"line": 1},
            "extra": {"lines": "requires login", "metadata": {}},
        }]}
        rows = normalize_semgrep(
            payload, run_id="r1", run_started="t", candidate=self.candidate,
            artifact=self.artifact, sha256="abc", first_seen="t"
        )
        self.assertEqual(rows[0]["evidence"], "")
        self.assertEqual(rows[0]["evidence_source"], "unavailable")

    def test_trivy_secret_is_reviewable(self):
        payload = {"Results": [{"Target": "config.py", "Secrets": [{
            "RuleID": "aws-access-key-id",
            "Category": "AWS",
            "Severity": "HIGH",
            "Title": "AWS access key",
            "StartLine": 4,
            "EndLine": 4,
            "Match": "AKIAEXAMPLE",
        }]}]}
        rows = normalize_trivy(
            payload, run_id="r1", run_started="t", candidate=self.candidate,
            artifact=self.artifact, sha256="abc", first_seen="t"
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["finding_class"], "secret_exposure")
        self.assertEqual(rows[0]["cwe"], "CWE-798")
        self.assertEqual(rows[0]["dedup_status"], "NOT_APPLICABLE")
        self.assertNotIn("AKIAEXAMPLE", rows[0]["evidence"])
        self.assertTrue(rows[0]["evidence"].startswith("secret_match_sha256="))

    def test_csv_neutralizes_formula_cells(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "review.csv"
            row = {column: "" for column in REVIEW_COLUMNS}
            row["package_name"] = "=HYPERLINK(\"https://example.invalid\")"
            write_csv(path, REVIEW_COLUMNS, [row])
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                parsed = next(csv.DictReader(handle))
            self.assertTrue(parsed["package_name"].startswith("'="))

    def test_csv_has_excel_friendly_bom_and_exact_header(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "review.csv"
            write_csv(path, REVIEW_COLUMNS, [])
            raw = path.read_bytes()
            self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
            with path.open("r", encoding="utf-8-sig", newline="") as f:
                self.assertEqual(next(csv.reader(f)), REVIEW_COLUMNS)


if __name__ == "__main__":
    unittest.main()
