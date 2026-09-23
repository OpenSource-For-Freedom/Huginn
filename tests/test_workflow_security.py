from __future__ import annotations

import re
import unittest
from pathlib import Path


WORKFLOWS = Path(".github/workflows")
LEGION_PIN = "Wraith-security/legion_runner@b459e7433723418301974a1f05098607b7e8d027"


class WorkflowSecurityTests(unittest.TestCase):
    def test_every_job_starts_with_pinned_legion_runner(self):
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            jobs_match = re.search(r"(?ms)^jobs:\n(?P<body>.*)$", text)
            self.assertIsNotNone(jobs_match, f"{workflow}: missing jobs block")
            body = jobs_match.group("body")

            # Job keys are exactly two spaces under jobs:. Ignore nested blocks.
            job_starts = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\n", body))
            self.assertTrue(job_starts, f"{workflow}: no jobs found")

            for index, match in enumerate(job_starts):
                job_name = match.group(1)
                start = match.end()
                end = job_starts[index + 1].start() if index + 1 < len(job_starts) else len(body)
                job = body[start:end]
                steps = re.search(r"(?ms)^    steps:\n(?P<steps>.*)$", job)
                self.assertIsNotNone(steps, f"{workflow}:{job_name}: missing steps")

                first = re.search(
                    r"(?ms)^      - name: (?P<name>[^\n]+)\n"
                    r"        uses: (?P<uses>[^\n]+)",
                    steps.group("steps"),
                )
                self.assertIsNotNone(first, f"{workflow}:{job_name}: first step must be an action")
                self.assertEqual(first.group("name").strip(), "Legion Runner", f"{workflow}:{job_name}")
                self.assertEqual(first.group("uses").strip(), LEGION_PIN, f"{workflow}:{job_name}")


if __name__ == "__main__":
    unittest.main()
