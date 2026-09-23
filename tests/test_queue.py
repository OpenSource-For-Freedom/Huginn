from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from huginn.models import ReleaseCandidate
from huginn.state import StateDB


class QueueTests(unittest.TestCase):
    def test_enqueue_lease_complete(self):
        with tempfile.TemporaryDirectory() as td:
            db = StateDB(Path(td) / "state.db")
            c = ReleaseCandidate("npm", "demo", "1.0.0", "NEW_VERSION")
            now = "2026-09-22T00:00:00Z"
            db.record_discovered(c.registry, c.name, c.version, c.event_type, now)
            db.enqueue(c, now)
            leased = db.lease("run1", now, limit=10)
            self.assertEqual(len(leased), 1)
            job_id, candidate = leased[0]
            self.assertEqual(candidate.name, "demo")
            db.complete_job(job_id, now)
            self.assertEqual(db.queue_stats().get("complete"), 1)

    def test_failed_job_retries_with_backoff(self):
        with tempfile.TemporaryDirectory() as td:
            db = StateDB(Path(td) / "state.db")
            c = ReleaseCandidate("pypi", "demo", "2.0.0", "NEW_VERSION")
            now = "2026-09-22T00:00:00Z"
            db.record_discovered(c.registry, c.name, c.version, c.event_type, now)
            db.enqueue(c, now)
            job_id, _ = db.lease("run1", now, limit=1)[0]
            db.retry_job(job_id, "boom", now)
            self.assertEqual(db.queue_stats().get("retry"), 1)
            self.assertEqual(db.lease("run2", now, limit=1), [])

    def test_validation_seed_can_be_forced_back_to_pending(self):
        with tempfile.TemporaryDirectory() as td:
            db = StateDB(Path(td) / "state.db")
            c = ReleaseCandidate("npm", "demo", "1.0.0", "VALIDATION_SEED")
            now = "2026-09-22T00:00:00Z"
            db.record_discovered(c.registry, c.name, c.version, c.event_type, now)
            db.enqueue(c, now, force=True)
            job_id, _ = db.lease("run1", now, limit=1)[0]
            db.complete_job(job_id, now)
            db.enqueue(c, now, force=True)
            leased = db.lease("run2", now, limit=1)
            self.assertEqual(len(leased), 1)


if __name__ == "__main__":
    unittest.main()
