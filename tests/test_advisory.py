from __future__ import annotations

import unittest

from huginn.advisory import enrich_rows
from huginn.models import ReleaseCandidate


class AdvisoryTests(unittest.TestCase):
    def test_exact_identifier_is_known(self):
        rows = [{"vulnerability_id": "CVE-2021-23337", "dedup_status": "", "novelty_state": ""}]
        bundle = {
            "checked_at": "2026-09-22T00:00:00Z",
            "errors": {},
            "records": [{
                "source": "osv", "id": "GHSA-35jh-r3h4-6jhm",
                "aliases": ["CVE-2021-23337"], "exact_package_version": True
            }],
        }
        enrich_rows(rows, bundle)
        self.assertEqual(rows[0]["dedup_status"], "KNOWN_EXACT")
        self.assertEqual(rows[0]["novelty_state"], "known")

    def test_same_version_other_advisory_is_only_possible(self):
        rows = [{"vulnerability_id": "", "dedup_status": "", "novelty_state": ""}]
        bundle = {
            "checked_at": "2026-09-22T00:00:00Z",
            "errors": {},
            "records": [{
                "source": "ghsa", "id": "GHSA-example", "aliases": ["CVE-2026-0001"],
                "exact_package_version": True
            }],
        }
        enrich_rows(rows, bundle)
        self.assertEqual(rows[0]["dedup_status"], "POSSIBLE_MATCH")
        self.assertEqual(rows[0]["novelty_state"], "possible_match")

    def test_no_records_is_novel_only_when_lookups_succeeded(self):
        rows = [{"vulnerability_id": "", "dedup_status": "", "novelty_state": ""}]
        enrich_rows(rows, {"checked_at": "t", "errors": {}, "records": []})
        self.assertEqual(rows[0]["dedup_status"], "NO_MATCH")
        self.assertEqual(rows[0]["novelty_state"], "novel")


if __name__ == "__main__":
    unittest.main()
