from __future__ import annotations

import unittest
from unittest.mock import patch

from huginn.discovery import previous_release
from huginn.models import ReleaseCandidate


class PreviousReleaseTests(unittest.TestCase):
    def test_new_package_has_no_previous_release(self):
        candidate = ReleaseCandidate("pypi", "demo", "1.0.0", "NEW_PACKAGE")
        self.assertIsNone(previous_release(candidate))

    def test_npm_uses_immediately_prior_publish(self):
        candidate = ReleaseCandidate("npm", "demo", "2.0.0", "NEW_VERSION")
        packument = {
            "time": {
                "created": "2026-01-01T00:00:00Z",
                "modified": "2026-09-23T00:00:00Z",
                "1.0.0": "2026-01-01T00:00:00Z",
                "1.5.0": "2026-06-01T00:00:00Z",
                "2.0.0": "2026-09-23T00:00:00Z",
            }
        }
        with patch("huginn.discovery._npm_packument", return_value=packument):
            previous = previous_release(candidate)
        self.assertIsNotNone(previous)
        self.assertEqual(previous.version, "1.5.0")

    def test_pypi_uses_upload_time_not_version_sort(self):
        candidate = ReleaseCandidate("pypi", "demo", "2.0.0", "NEW_VERSION")
        meta = {
            "releases": {
                "1.9.0": [{"upload_time_iso_8601": "2026-08-01T00:00:00Z"}],
                "1.10.0": [{"upload_time_iso_8601": "2026-09-01T00:00:00Z"}],
                "2.0.0": [{"upload_time_iso_8601": "2026-09-23T00:00:00Z"}],
            }
        }
        with patch("huginn.discovery.pypi_project_json", return_value=meta):
            previous = previous_release(candidate)
        self.assertIsNotNone(previous)
        self.assertEqual(previous.version, "1.10.0")


if __name__ == "__main__":
    unittest.main()
