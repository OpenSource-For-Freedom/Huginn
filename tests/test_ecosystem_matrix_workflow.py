from __future__ import annotations

import unittest
from pathlib import Path


class EcosystemMatrixWorkflowTests(unittest.TestCase):
    def test_capture_workflow_isolated_per_ecosystem(self):
        text = Path(".github/workflows/cve-capture.yml").read_text(encoding="utf-8")

        self.assertIn('["npm","pypi","rubygems","crates","packagist","go"]', text)
        self.assertIn("fail-fast: false", text)
        self.assertIn("max-parallel: 6", text)
        self.assertIn("runs-on: ubuntu-24.04", text)
        self.assertNotIn("self-hosted", text)
        self.assertIn("state-{1}.db", text)
        self.assertIn("actions/cache/restore@v4", text)
        self.assertIn("actions/cache/save@v4", text)
        self.assertIn("huginn-trivy-cache-${{ matrix.ecosystem }}", text)
        self.assertIn('--registry "${{ matrix.ecosystem }}"', text)
        self.assertIn("huginn-review-${{ matrix.ecosystem }}-${{ github.run_id }}", text)
        self.assertIn("Aggregate hunt", text)
        self.assertIn("scripts/merge_hunt_reports.py", text)


    def test_each_registry_runs_in_its_own_queue(self):
        text = Path(".github/workflows/cve-capture.yml").read_text(encoding="utf-8")
        self.assertIn("group: huginn-cve-capture-${{ github.ref }}-${{ inputs.registry || 'all' }}", text)
        self.assertIn("run-name:", text)

    def test_hunt_each_registry_dispatches_one_capture_per_ecosystem(self):
        text = Path(".github/workflows/hunt-each-registry.yml").read_text(encoding="utf-8")
        for ecosystem in ("npm", "pypi", "rubygems", "crates", "packagist", "go"):
            self.assertIn(f"ecosystem: {ecosystem},", text)
        self.assertIn("gh workflow run cve-capture.yml", text)
        self.assertIn('-f registry="$ECOSYSTEM"', text)
        self.assertIn("actions: write", text)
        # Inputs reach the shell through env, never by direct expression interpolation.
        self.assertNotIn("${{ inputs.mode }}\n", text.rsplit("run: |", 1)[1])

    def test_hunts_run_twice_a_month_with_a_fifteen_day_look_back(self):
        dispatcher = Path(".github/workflows/hunt-each-registry.yml").read_text(encoding="utf-8")
        capture = Path(".github/workflows/cve-capture.yml").read_text(encoding="utf-8")
        self.assertIn('cron: "17 6 1,15 * *"', dispatcher)
        self.assertNotIn("schedule:", capture)
        self.assertIn('default: "15"', dispatcher)
        self.assertIn("inputs.window_days || '15'", dispatcher)
        self.assertIn('-f window_days="$WINDOW_DAYS"', dispatcher)
        self.assertIn('--window-days "$WINDOW_DAYS"', capture)
        self.assertIn("timeout-minutes: 210", capture)
        self.assertIn('--max-minutes "$MAX_MINUTES"', capture)

    def test_hunts_are_budgeted(self):
        dispatcher = Path(".github/workflows/hunt-each-registry.yml").read_text(encoding="utf-8")
        self.assertIn("needs: budget", dispatcher)
        self.assertIn('event") == "dynamic"', dispatcher)
        self.assertIn("math.ceil(seconds / 60)", dispatcher)
        self.assertIn("vars.HUGINN_MONTHLY_MINUTES || '1900'", dispatcher)
        self.assertIn('default: "auto"', dispatcher)

if __name__ == "__main__":
    unittest.main()
