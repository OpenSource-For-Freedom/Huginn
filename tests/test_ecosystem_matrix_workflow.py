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
        self.assertIn('["npm", "pypi", "rubygems", "crates", "packagist", "go"]', text)
        self.assertIn("gh workflow run cve-capture.yml", text)
        self.assertIn('-f registry="$ECOSYSTEM"', text)
        self.assertIn("actions: write", text)
        # Inputs reach the shell through env, never by direct expression interpolation.
        self.assertNotIn("${{ inputs.mode }}\n", text.split("run: |", 1)[1])

    def test_weekly_long_run_is_scheduled_from_the_dispatcher(self):
        dispatcher = Path(".github/workflows/hunt-each-registry.yml").read_text(encoding="utf-8")
        capture = Path(".github/workflows/cve-capture.yml").read_text(encoding="utf-8")
        self.assertIn('cron: "17 6 * * 0"', dispatcher)
        self.assertIn("vars.HUGINN_SCHEDULE_ENABLED == 'true'", dispatcher)
        self.assertIn("inputs.limit || '400'", dispatcher)
        self.assertNotIn("schedule:", capture)
        self.assertIn("timeout-minutes: 330", capture)


if __name__ == "__main__":
    unittest.main()
