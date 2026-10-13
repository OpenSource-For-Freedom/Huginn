from __future__ import annotations

import json
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from huginn import fresh, recall
from huginn.models import Artifact, ReleaseCandidate
from huginn.state import StateDB

NOW = datetime.now(UTC)


def _iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


class LowRevTests(unittest.TestCase):
    def test_new_documents_only(self):
        self.assertTrue(fresh._low_rev({"changes": [{"rev": "1-abc"}]}))
        self.assertTrue(fresh._low_rev({"changes": [{"rev": "2-abc"}]}))
        self.assertFalse(fresh._low_rev({"changes": [{"rev": "57-abc"}]}))


class NpmFreshTests(unittest.TestCase):
    def test_reads_the_feed_and_keeps_first_publishes(self):
        pages = iter([
            {"results": [{"seq": 101, "id": "new-evil", "changes": [{"rev": "1-a"}]},
                         {"seq": 102, "id": "react", "changes": [{"rev": "900-a"}]},
                         {"seq": 103, "id": "old-but-low", "changes": [{"rev": "2-a"}]}],
             "last_seq": 103},
            {"results": [], "last_seq": 103},
        ])
        docs = {
            "new-evil": {"time": {"1.0.0": _iso(NOW)}, "dist-tags": {"latest": "1.0.0"}},
            "old-but-low": {"time": {"0.1.0": _iso(NOW - timedelta(days=30))},
                            "dist-tags": {"latest": "0.1.0"}},
        }
        with tempfile.TemporaryDirectory() as td:
            state = StateDB(Path(td) / "s.db")
            found, cp = fresh.npm_fresh(NOW - timedelta(hours=8), state, head=103,
                                        seq_at=lambda c, h: 100,
                                        get_json=lambda url: next(pages),
                                        packument=lambda n: docs[n])
        self.assertEqual([c.name for c, _ in found], ["new-evil"])
        self.assertEqual(cp, {"fresh.npm.sequence": "103"})


class _Scanner:
    def __init__(self, results):
        self.results = results

    def malware_only(self, path, *, package_name="", ecosystem=""):
        return self.results[package_name], "COMPLETE", ""


def _cand(name):
    return ReleaseCandidate("npm", name, "1.0.0", "NEW_PACKAGE", _iso(NOW))


class HuntRegistryTests(unittest.TestCase):
    def _hunt(self, found, results, top=2):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        state = StateDB(Path(td.name) / "s.db")
        evil_finding = {"file": "package/index.js", "line": 1, "category": "malware_signature",
                        "rule": "polinrider-loader", "snippet": "x"}
        with patch("huginn.fresh.d.resolve_artifact",
                   side_effect=lambda c: Artifact(f"{c.name}.tgz", "https://registry.npmjs.org/x.tgz")), \
                patch("huginn.fresh.download", return_value=("ab", 10)):
            out = fresh.hunt_registry("npm", hours=8, top=top, state=state, scanner=_Scanner({
                n: ({"confirmed": True, "confidence": "auto", "bash_findings": [evil_finding],
                     "confirming_findings": [evil_finding], "egress": "family"} if r else
                    {"confirmed": False, "confidence": "none", "bash_findings": [], "confirming_findings": []})
                for n, r in results.items()}), run="r1", workdir=Path(td.name),
                deadline=time.monotonic() + 60, discover=lambda: (found, {}))
        return out, state

    def test_scans_the_riskiest_and_reports_confirmed(self):
        hook = {"versions": {"1.0.0": {"scripts": {"postinstall": "node -e \"require('https')\""}}}}
        tame = {"versions": {"1.0.0": {"description": "ok", "repository": "r"}}}
        found = [(_cand("evil-pkg"), hook), (_cand("tame-pkg"), tame), (_cand("lodahs"), tame)]
        (summary, rows, manifest), state = self._hunt(found, {"evil-pkg": True, "lodahs": False})
        self.assertEqual(summary["selected"], 2)
        self.assertEqual(summary["confirmed"], 1)
        self.assertEqual(rows[0]["package_name"], "evil-pkg")
        selected = {m["package_name"] for m in manifest if m["selected"]}
        self.assertEqual(selected, {"evil-pkg", "lodahs"})          # tame-pkg scores 0
        seen = state.fresh_seen_since("npm", "2000-01-01")
        self.assertEqual(seen["evil-pkg"]["verdict"], "CONFIRMED")
        self.assertFalse(seen["tame-pkg"]["scanned"])

    def test_a_release_is_triaged_once(self):
        found = [(_cand("lodahs"), {"versions": {"1.0.0": {}}})]
        (summary, _, _), state = self._hunt(found, {"lodahs": False})
        again = fresh.hunt_registry("npm", hours=8, top=2, state=state, scanner=None, run="r2",
                                    workdir=Path("."), deadline=0, discover=lambda: (found, {}))
        self.assertEqual(again[0]["new_packages"], 0)


class RecallTests(unittest.TestCase):
    def test_outcomes_and_caching(self):
        stamp = _iso(NOW)
        files = {
            "npm/modified_id.csv": f"{stamp},MAL-1\n{stamp},GHSA-x\n{stamp},MAL-2\n{stamp},MAL-3\n".encode(),
            "npm/MAL-1.json": json.dumps({"id": "MAL-1", "published": stamp, "affected": [
                {"package": {"ecosystem": "npm", "name": "Evil-Pkg"}}]}).encode(),
            "npm/MAL-2.json": json.dumps({"id": "MAL-2", "published": stamp, "affected": [
                {"package": {"ecosystem": "npm", "name": "tame-pkg"}}]}).encode(),
            "npm/MAL-3.json": json.dumps({"id": "MAL-3", "published": stamp, "affected": [
                {"package": {"ecosystem": "npm", "name": "never-seen"}}]}).encode(),
        }
        fetched = []

        def fetch(url):
            key = url.split(recall.OSV_BUCKET + "/", 1)[1]
            fetched.append(key)
            return files[key]

        with tempfile.TemporaryDirectory() as td:
            state = StateDB(Path(td) / "s.db")
            state.set_cursor("fresh.started", _iso(NOW - timedelta(days=1)))
            state.record_fresh("npm", "evil-pkg", "1.0.0", _iso(NOW), 7, "hook")
            state.record_fresh_scan("npm", "evil-pkg", "1.0.0", "COMPLETED", "CONFIRMED")
            state.record_fresh("npm", "tame-pkg", "1.0.0", _iso(NOW), 0, "")
            summary, rows = fresh.measure_recall("npm", state, fetch=fetch)
            fetched.clear()
            fresh.measure_recall("npm", state, fetch=fetch)
        self.assertEqual(summary["known_malicious"], 3)
        self.assertEqual((summary["flagged"], summary["not_selected"], summary["not_seen"]), (1, 1, 1))
        self.assertEqual(summary["recall_pct"], 33.3)
        self.assertEqual(fetched, ["npm/modified_id.csv"])     # advisories cached

    def test_history_before_the_hunt_is_not_blamed(self):
        old = {"id": "MAL-9", "name": "x", "published": _iso(NOW - timedelta(days=3))}
        rows = recall.classify([old], {}, NOW - timedelta(days=1))
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
