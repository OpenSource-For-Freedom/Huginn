from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from huginn.discovery import discover_npm, seeded_candidate
from huginn.state import StateDB


class NpmDiscoveryTests(unittest.TestCase):
    def test_first_poll_bootstraps_cursor_without_history(self):
        with tempfile.TemporaryDirectory() as td:
            state = StateDB(Path(td) / "state.db")
            with patch("huginn.discovery._json", return_value={"last_seq": "123", "results": []}):
                self.assertEqual(discover_npm("updates", 10, state), [])
            self.assertEqual(state.get_cursor("npm")[0], "123")

    def test_change_reconciles_recent_packument_version(self):
        with tempfile.TemporaryDirectory() as td:
            state = StateDB(Path(td) / "state.db")
            state.set_cursor("npm", "10", "2026-09-22T00:00:00Z")
            responses = [
                {"last_seq": "11", "results": [{"seq": "11", "id": "demo"}]},
                {
                    "time": {
                        "created": "2026-09-21T00:00:00Z",
                        "modified": "2026-09-22T00:05:00Z",
                        "1.0.0": "2026-09-21T00:00:00Z",
                        "1.1.0": "2026-09-22T00:05:00Z",
                    },
                    "versions": {"1.1.0": {"dist": {"tarball": "https://example.invalid/demo.tgz"}}},
                },
            ]
            with patch("huginn.discovery._json", side_effect=responses):
                rows = discover_npm("updates", 10, state)
            self.assertEqual([(r.name, r.version, r.event_type) for r in rows], [("demo", "1.1.0", "NEW_VERSION")])
            self.assertEqual(state.get_cursor("npm")[0], "11")

    def test_seed_parser(self):
        seed = seeded_candidate("npm:lodash:4.17.20")
        self.assertEqual(seed.event_type, "VALIDATION_SEED")
        self.assertEqual(seed.registry, "npm")


if __name__ == "__main__":
    unittest.main()
