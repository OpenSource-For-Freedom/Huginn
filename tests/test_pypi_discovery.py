from __future__ import annotations

import urllib.error
import unittest
from unittest.mock import patch

from huginn.discovery import discover_pypi_feed


RSS = b"""<?xml version="1.0"?>
<rss><channel>
  <item>
    <title>display-title-that-is-not-the-api-name</title>
    <link>https://pypi.org/project/example-pkg/</link>
    <pubDate>Tue, 22 Sep 2026 00:00:00 GMT</pubDate>
  </item>
</channel></rss>
"""


class PyPIDiscoveryTests(unittest.TestCase):
    def test_new_package_uses_canonical_link_and_first_uploaded_release(self):
        meta = {
            "info": {"version": "2.0.0"},
            "releases": {
                "2.0.0": [{"upload_time_iso_8601": "2026-09-22T12:00:00Z"}],
                "1.0.0": [{"upload_time_iso_8601": "2026-09-22T10:00:00Z"}],
            },
        }
        with (
            patch("huginn.discovery._request", return_value=RSS),
            patch("huginn.discovery.pypi_project_json", return_value=meta) as project_json,
        ):
            rows = discover_pypi_feed("new", 5)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].name, "example-pkg")
        self.assertEqual(rows[0].version, "1.0.0")
        self.assertEqual(rows[0].event_type, "NEW_PACKAGE")
        self.assertEqual(rows[0].published_at, "2026-09-22T10:00:00Z")
        project_json.assert_called_once_with("example-pkg")

    def test_deleted_newest_feed_entry_is_skipped_not_fatal(self):
        error = urllib.error.HTTPError(
            "https://pypi.org/pypi/example-pkg/json",
            404,
            "Not Found",
            hdrs=None,
            fp=None,
        )
        with (
            patch("huginn.discovery._request", return_value=RSS),
            patch("huginn.discovery.pypi_project_json", side_effect=error),
        ):
            rows = discover_pypi_feed("new", 5)
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
