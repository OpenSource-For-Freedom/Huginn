from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from huginn.capture import capture_registry
from huginn.discovery import DiscoveryError, PolicySkip
from huginn.models import DiscoveryBatch, ReleaseCandidate
from huginn.state import StateDB


class CaptureSkipTests(unittest.TestCase):
    def _capture(self, error: Exception) -> list[dict]:
        batch = DiscoveryBatch(candidates=[ReleaseCandidate("packagist", "acme/widget", "1.0.0", "NEW_VERSION")])
        with tempfile.TemporaryDirectory() as td, \
                patch("huginn.capture.discover", return_value=batch), \
                patch("huginn.capture.resolve_artifact", side_effect=error):
            state = StateDB(Path(td) / "state.db")
            _, manifests = capture_registry(
                "packagist", "all", 10, state, MagicMock(), MagicMock(),
                run="r1", started="2026-10-07T00:00:00Z", max_artifact_bytes=1024,
            )
        return manifests

    def test_policy_refusal_is_skipped_not_failed(self):
        manifests = self._capture(PolicySkip("packagist dist host is not allowed: evil.example"))
        self.assertEqual(manifests[0]["scan_status"], "SKIPPED")
        self.assertEqual(manifests[0]["failure_stage"], "artifact_resolve")
        self.assertTrue(manifests[0]["error"].startswith("PolicySkip:"))

    def test_other_resolve_errors_still_fail(self):
        manifests = self._capture(DiscoveryError("upstream returned 500"))
        self.assertEqual(manifests[0]["scan_status"], "FAILED")


class CaptureBudgetTests(unittest.TestCase):
    def test_stops_starting_scans_after_the_budget(self):
        candidates = [ReleaseCandidate("packagist", f"acme/w{i}", "1.0.0", "NEW_VERSION") for i in range(5)]
        ticks = iter([0, 0, 30, 61, 999, 999])  # deadline set at 0; checks at 0, 30, then 61 s (> 1 min)
        with tempfile.TemporaryDirectory() as td, \
                patch("huginn.capture.discover", return_value=DiscoveryBatch(candidates=candidates)), \
                patch("huginn.capture.resolve_artifact", side_effect=PolicySkip("skip")):
            state = StateDB(Path(td) / "state.db")
            _, manifests = capture_registry(
                "packagist", "all", 10, state, MagicMock(), MagicMock(),
                run="r1", started="t", max_artifact_bytes=1024, max_minutes=1, clock=lambda: next(ticks),
            )
        self.assertEqual(len(manifests), 2)


if __name__ == "__main__":
    unittest.main()
