from __future__ import annotations

import unittest
from pathlib import Path


class EcosystemMatrixWorkflowTests(unittest.TestCase):
    def test_capture_workflow_isolated_per_ecosystem(self):
        text = Path(".github/workflows/cve-capture.yml").read_text(encoding="utf-8")

        self.assertIn('["npm","pypi","rubygems"]', text)
        self.assertIn("fail-fast: false", text)
        self.assertIn("max-parallel: 3", text)
        self.assertIn("state-{1}.db", text)
        self.assertIn("huginn-trivy-cache-${{ matrix.ecosystem }}", text)
        self.assertIn('--registry "${{ matrix.ecosystem }}"', text)
        self.assertIn("huginn-review-${{ matrix.ecosystem }}-${{ github.run_id }}", text)
        self.assertIn("Aggregate hunt", text)
        self.assertIn("scripts/merge_hunt_reports.py", text)


if __name__ == "__main__":
    unittest.main()
