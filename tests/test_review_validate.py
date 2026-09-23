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
            "validation_state": "HIGH_VALUE_MANUAL_CANDIDATE",
        })
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "review.csv"
            write_csv(path, REVIEW_COLUMNS, [row])
            errors = validate(path)
            self.assertTrue(any("reachability_verified" in e for e in errors))

    def test_noise_likely_cannot_be_promoted_to_validated(self):
        row = {c: "" for c in REVIEW_COLUMNS}
        row.update({
            "review_status": "VALIDATED",
            "validation_state": "NOISE_LIKELY",
            "reviewer": "OpenSource-For-Freedom",
            "reviewer_decision": "confirmed",
            "reviewer_notes": "verified",
            "verified_at_utc": "2026-09-22T00:00:00Z",
            "reachability_verified": "true",
            "security_boundary_verified": "true",
            "affected_version_verified": "true",
            "known_advisory_verified": "true",
        })
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "review.csv"
            write_csv(path, REVIEW_COLUMNS, [row])
            errors = validate(path)
            self.assertTrue(any("cannot be promoted" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
