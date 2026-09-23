from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from huginn.discovery import discover_npm
from huginn.state import StateDB


class NpmDiscoveryTests(unittest.TestCase):
    def test_first_run_initializes_cursor_without_backlog(self):
        with tempfile.TemporaryDirectory() as td:
            state = StateDB(Path(td) / "state.db")
            with patch("huginn.discovery._json", return_value={"update_seq": 12345}):
                batch = discover_npm("all", 10, state)
            self.assertEqual(batch.candidates, [])
            self.assertEqual(batch.checkpoint["npm.sequence"], "12345")
            self.assertIn("npm.publish_window", batch.checkpoint)

    def test_recent_version_from_changed_package_is_emitted(self):
        with tempfile.TemporaryDirectory() as td:
            state = StateDB(Path(td) / "state.db")
            state.set_cursor("npm.sequence", "100")
            state.set_cursor("npm.publish_window", "2026-09-22T12:00:00Z")

            def fake_json(url):
                if "/_changes?" in url:
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


if __name__ == "__main__":
    unittest.main()
