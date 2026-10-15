from __future__ import annotations

import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import actions_budget as ab  # noqa: E402

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)


class BudgetTests(unittest.TestCase):
    def test_jobs_round_up_and_skipped_jobs_are_free(self):
        jobs = [
            {"started_at": "2026-10-13T11:00:00Z", "completed_at": "2026-10-13T11:00:20Z"},   # 1
            {"started_at": "2026-10-13T11:00:00Z", "completed_at": "2026-10-13T11:02:01Z"},   # 3
            {"started_at": "2026-10-13T11:00:00Z", "conclusion": "skipped"},
            {"started_at": None},
        ]
        self.assertEqual(ab.job_minutes(jobs, NOW), 4)

    def test_dependabot_runs_are_not_counted(self):
        pages = {"runs": {"workflow_runs": [{"id": 1, "event": "push"}, {"id": 2, "event": "dynamic"}]},
                 "jobs1": {"jobs": [{"started_at": "2026-10-13T11:00:00Z",
                                     "completed_at": "2026-10-13T11:10:00Z"}]}}

        def get(path):
            return pages["jobs1"] if "/runs/1/jobs" in path else pages["runs"]

        self.assertEqual(ab.minutes_used(get, "o/r", NOW), 10)

    def test_decide(self):
        self.assertTrue(ab.decide(400, 500, 15, False)[0])
        ok, line = ab.decide(490, 500, 15, False)
        self.assertFalse(ok)
        self.assertTrue(line.startswith("SKIPPED"))
        self.assertTrue(ab.decide(490, 500, 15, True)[0])


if __name__ == "__main__":
    unittest.main()
