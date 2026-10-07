from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from huginn import window
from huginn.models import ReleaseCandidate
from huginn.state import StateDB

NOW = datetime.now(UTC)
CUTOFF = NOW - timedelta(days=7)


def rc(name: str, version: str = "1.0.0", event: str = "NEW_VERSION") -> ReleaseCandidate:
    return ReleaseCandidate("go", name, version, event)


class SelectionTests(unittest.TestCase):
    def test_spread_covers_the_whole_window(self):
        items = [rc(f"p{i}") for i in range(100)]
        picked = [c.name for c in window.spread(items, 4)]
        self.assertEqual(picked, ["p0", "p25", "p50", "p75"])

    def test_new_packages_get_half_and_mirrors_collapse(self):
        items = [rc(f"new{i}", event="NEW_PACKAGE") for i in range(10)]
        items += [rc(f"upd{i}") for i in range(10)]
        items += [rc("github.com/Acme/Lib"), rc("github.com/acme/lib")]
        chosen = window.select(items, 6, "all", None)
        self.assertEqual(sum(c.event_type == "NEW_PACKAGE" for c in chosen), 3)
        self.assertEqual(len(chosen), 6)
        all_names = [c.name.lower() for c in window.select(items, 100, "all", None)]
        self.assertEqual(all_names.count("github.com/acme/lib"), 1)

    def test_completed_releases_are_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            state = StateDB(Path(td) / "s.db")
            state.record_discovered("go", "done", "1.0.0", "NEW_VERSION", "t")
            state.mark_completed("go", "done", "1.0.0", "sha", "t")
            chosen = window.select([rc("done"), rc("todo")], 5, "all", state)
        self.assertEqual([c.name for c in chosen], ["todo"])


class SourceTests(unittest.TestCase):
    def test_go_pages_from_the_cutoff_and_drops_pseudo_versions(self):
        def line(path, version, ts):
            return json.dumps({"Path": path, "Version": version, "Timestamp": ts})
        page1 = "\n".join([line("a.io/x", "v1.0.0", "2026-10-01T00:00:00Z"),
                           line("a.io/y", "v0.0.0-20261001000000-abcdefabcdef", "2026-10-01T00:00:01Z")])
        with patch.object(window, "GO_PAGE", 2), patch.object(window.d, "_request", side_effect=[page1.encode(), b""]):
            found = window.go_window(CUTOFF, 10)
        self.assertEqual([(c.name, c.event_type) for c in found], [("a.io/x", "NEW_PACKAGE")])

    def test_pypi_reads_releases_after_the_cutoff(self):
        old, new = (CUTOFF - timedelta(hours=1)).timestamp(), (CUTOFF + timedelta(hours=1)).timestamp()

        class Client:
            def changelog_last_serial(self):
                return 100

            def changelog_since_serial(self, serial):
                events = [["old", "1.0", old, "new release", 50], ["fresh", None, new, "create", 60],
                          ["fresh", "0.1", new, "new release", 61], ["lib", "2.0", new, "new release", 62]]
                return [e for e in events if e[4] > serial]

        found = window.pypi_window(CUTOFF, 10, client=Client())
        self.assertEqual({(c.name, c.event_type) for c in found}, {("fresh", "NEW_PACKAGE"), ("lib", "NEW_VERSION")})

    def test_rubygems_binary_search_finds_the_cutoff(self):
        text = "created_at: x\n---\n" + "\n".join(f"gem{i} 1.{i} md5" for i in range(20)) + "\ngem3 2.0,-1.3 md5\n"
        stamp = {f"1.{i}": CUTOFF + timedelta(hours=i - 15) for i in range(20)}
        stamp["2.0"] = NOW
        found = window.rubygems_window(CUTOFF, 10, created_at=lambda n, v: stamp[v], text=text)
        self.assertEqual([c.name for c in found][:2], ["gem15", "gem16"])
        self.assertEqual(found[-1].name, "gem3")
        self.assertEqual(found[-1].version, "2.0")
        self.assertEqual(found[-1].event_type, "NEW_VERSION")

    def test_crates_stop_at_the_cutoff(self):
        page = {"crates": [
            {"name": "fresh", "newest_version": "0.1.0", "updated_at": NOW.isoformat(), "created_at": NOW.isoformat()},
            {"name": "stale", "newest_version": "1.0.0", "updated_at": (CUTOFF - timedelta(days=1)).isoformat(),
             "created_at": "2020-01-01T00:00:00Z"},
        ]}
        with patch.object(window.d, "_json", return_value=page):
            found = window.crates_window(CUTOFF, 10, sleep=lambda s: None)
        self.assertEqual([(c.name, c.event_type) for c in found], [("fresh", "NEW_PACKAGE")])


if __name__ == "__main__":
    unittest.main()
