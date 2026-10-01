from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from huginn.discovery import discover_npm
from huginn.state import StateDB


class NpmDiscoveryTests(unittest.TestCase):
    def test_first_run_bootstraps_recent_changes_and_checkpoints_current_seq(self):
        with tempfile.TemporaryDirectory() as td:
            state = StateDB(Path(td) / "state.db")

            def fake_json(url):
                if url == "https://replicate.npmjs.com/":
                    return {"update_seq": 12345}
                if "descending=true" in url:
                    return {"results": [{"seq": 12344, "id": "fresh-demo"}]}
                if "registry.npmjs.org" in url:
                    return {
                        "time": {
                            "created": "2026-09-23T10:00:00Z",
                            "modified": "2026-09-23T10:05:00Z",
                            "1.0.0": "2026-09-23T10:00:00Z",
                        }
                    }
                raise AssertionError(url)

            with (
                patch("huginn.discovery._json", side_effect=fake_json),
                patch("huginn.discovery.datetime") as dt,
            ):
                from datetime import UTC, datetime
                dt.now.return_value = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)
                dt.fromisoformat.side_effect = datetime.fromisoformat
                batch = discover_npm("all", 10, state)

            self.assertEqual(len(batch.candidates), 1)
            self.assertEqual(batch.candidates[0].name, "fresh-demo")
            self.assertEqual(batch.candidates[0].version, "1.0.0")
            self.assertEqual(batch.candidates[0].event_type, "NEW_PACKAGE")
            self.assertEqual(batch.checkpoint["npm.sequence"], "12345")
            self.assertIn("npm.publish_window", batch.checkpoint)

    def test_recent_version_from_changed_package_is_emitted(self):
        with tempfile.TemporaryDirectory() as td:
            state = StateDB(Path(td) / "state.db")
            state.set_cursor("npm.sequence", "100")
            state.set_cursor("npm.publish_window", "2026-09-22T12:00:00Z")

            def fake_json(url):
                if url == "https://replicate.npmjs.com/":
                    return {"update_seq": 120}
                if "/registry/_changes?" in url:
                    self.assertIn("since=100", url)
                    return {"last_seq": 110, "results": [{"seq": 110, "id": "demo"}]}
                if "registry.npmjs.org" in url:
                    return {
                        "time": {
                            "created": "2020-01-01T00:00:00Z",
                            "modified": "2026-09-22T12:05:00Z",
                            "1.0.0": "2020-01-01T00:00:00Z",
                            "2.0.0": "2026-09-22T12:04:00Z",
                        }
                    }
                raise AssertionError(url)

            with patch("huginn.discovery._json", side_effect=fake_json):
                batch = discover_npm("all", 10, state)

            self.assertEqual(len(batch.candidates), 1)
            self.assertEqual(batch.candidates[0].name, "demo")
            self.assertEqual(batch.candidates[0].version, "2.0.0")
            self.assertEqual(batch.candidates[0].event_type, "NEW_VERSION")
            self.assertEqual(batch.checkpoint["npm.sequence"], "110")


    def test_stale_cursor_rescans_newest_changes(self):
        with tempfile.TemporaryDirectory() as td:
            state = StateDB(Path(td) / "state.db")
            state.set_cursor("npm.sequence", "100")
            state.set_cursor("npm.publish_window", "2026-09-20T12:00:00Z")
            requested = []

            def fake_json(url):
                requested.append(url)
                if url == "https://replicate.npmjs.com/":
                    return {"update_seq": 900000}
                if "descending=true" in url:
                    return {"results": [{"seq": 899999, "id": "fresh-demo"}]}
                if "since=" in url:
                    raise AssertionError("stale cursor must not walk forward from the old sequence")
                if "registry.npmjs.org" in url:
                    return {
                        "time": {
                            "created": "2026-01-01T00:00:00Z",
                            "modified": "2026-09-23T11:00:00Z",
                            "1.0.0": "2026-01-01T00:00:00Z",
                            "1.1.0": "2026-09-23T11:00:00Z",
                        }
                    }
                raise AssertionError(url)

            with (
                patch("huginn.discovery._json", side_effect=fake_json),
                patch("huginn.discovery.datetime") as dt,
            ):
                from datetime import UTC, datetime
                dt.now.return_value = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)
                dt.fromisoformat.side_effect = datetime.fromisoformat
                batch = discover_npm("all", 10, state)

            self.assertEqual([(c.name, c.version) for c in batch.candidates], [("fresh-demo", "1.1.0")])
            self.assertEqual(batch.candidates[0].event_type, "NEW_VERSION")
            self.assertEqual(batch.checkpoint["npm.sequence"], "900000")
            self.assertTrue(any("descending=true" in url for url in requested))

    def test_recent_scan_skips_completed_releases(self):
        with tempfile.TemporaryDirectory() as td:
            state = StateDB(Path(td) / "state.db")

            def fake_json(url):
                if url == "https://replicate.npmjs.com/":
                    return {"update_seq": 500}
                if "descending=true" in url:
                    return {"results": [{"seq": 499, "id": "done-demo"}]}
                if "registry.npmjs.org" in url:
                    return {"time": {"1.0.0": "2026-09-23T11:00:00Z"}}
                raise AssertionError(url)

            with (
                patch("huginn.discovery._json", side_effect=fake_json),
                patch("huginn.discovery.datetime") as dt,
                patch.object(state, "is_completed", return_value=True),
            ):
                from datetime import UTC, datetime
                dt.now.return_value = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)
                dt.fromisoformat.side_effect = datetime.fromisoformat
                batch = discover_npm("all", 10, state)

            self.assertEqual(batch.candidates, [])


if __name__ == "__main__":
    unittest.main()
