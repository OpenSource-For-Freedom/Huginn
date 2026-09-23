from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from huginn.reporting import REVIEW_COLUMNS, write_csv
from huginn.review_validate import validate


class ReviewValidateTests(unittest.TestCase):
    def test_validated_rows_require_all_manual_checks(self):
        row = {c: "" for c in REVIEW_COLUMNS}
        row.update({
            "review_status": "VALIDATED",
            "reviewer": "OpenSource-For-Freedom",
            "reviewer_decision": "confirmed",
            "reviewer_notes": "verified",
            "verified_at_utc": "2026-09-22T00:00:00Z",
        })
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "review.csv"
            write_csv(path, REVIEW_COLUMNS, [row])
            errors = validate(path)
            self.assertTrue(any("reachability_verified" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
