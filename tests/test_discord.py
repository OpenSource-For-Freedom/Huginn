from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from huginn.discord import build_messages, package_embed, post, summary_embed

SUMMARY = {
    "ecosystem_runs": [{"registry": "npm", "package_scan_count": 220},
                       {"registry": "pypi", "package_scan_count": 218}],
    "package_scan_count": 438, "failed_package_scans": 0, "skipped_package_scans": 3,
    "novel_no_match_count": 12, "high_value_manual_candidate_count": 2,
    "malware_confirmed_count": 1, "malware_new_risk_count": 2, "malware_scanned_count": 430,
    "critical_coverage_alert_count": 0, "high_coverage_alert_count": 0,
}
ROW = {"verdict": "CONFIRMED", "registry": "npm", "package_name": "@scope/ui-kit",
       "package_version": "2.4.1", "families": "Shai-Hulud", "confidence": "auto",
       "confirming_rules": "malware_signature/shai-hulud-ioc",
       "confirming_locations": "package/package.json", "new_in_release": "",
       "previous_version": ""}


class DiscordReportTests(unittest.TestCase):
    def test_summary_counts_cve_findings_without_naming_packages(self):
        e = summary_embed(SUMMARY, run_url="https://github.com/o/r/actions/runs/1")
        text = json.dumps(e, ensure_ascii=False)
        self.assertEqual(e["title"], "Huginn hunt complete")
        self.assertEqual(e["color"], 0xE74C3C)  # malware confirmed
        self.assertIn("438 (npm 220 · pypi 218)", text)
        self.assertIn("2 high-value candidates (details in the private review packet)", text)
        self.assertIn("1 confirmed · 2 new risk · 430 analyzed", text)
        self.assertEqual(e["url"], "https://github.com/o/r/actions/runs/1")

    def test_coverage_gaps_and_missing_analyzer_are_visible(self):
        e = summary_embed({**SUMMARY, "malware_confirmed_count": 0, "failed_package_scans": 4,
                           "malware_scanned_count": 0})
        self.assertEqual((e["title"], e["color"]), ("Huginn hunt complete (coverage gaps)", 0xE67E22))
        self.assertIn("(analyzer not configured)", json.dumps(e))
        self.assertEqual(summary_embed({"package_scan_count": 5})["color"], 0x22AA66)

    def test_package_card_links_registry_and_cannot_ping(self):
        e = package_embed(ROW)
        self.assertEqual(e["title"], "npm: @​scope/ui-kit@​2.4.1")
        self.assertEqual(e["url"], "https://www.npmjs.com/package/@scope/ui-kit/v/2.4.1")
        self.assertEqual(e["footer"]["text"], "Pending analyst validation")
        e = package_embed({**ROW, "registry": "pypi", "package_name": "evil pkg`"})
        self.assertNotIn("url", e)  # a name that would break the link gets none
        self.assertNotIn("`", json.dumps(e))

    def test_messages_batch_ten_embeds_and_never_mention(self):
        rows = [dict(ROW, package_name=f"p{i}") for i in range(30)] + [dict(ROW, verdict="NEW_RISK")]
        msgs = build_messages(SUMMARY, rows)
        self.assertEqual([len(m["embeds"]) for m in msgs], [10, 10, 8])
        self.assertTrue(all(m["allowed_mentions"] == {"parse": []} for m in msgs))
        self.assertEqual(msgs[-1]["content"], "+3 more confirmed in malicious_findings.csv")
        self.assertEqual(len(build_messages(SUMMARY, [])), 1)

    def test_post_sets_user_agent_and_survives_errors(self):
        seen = {}

        class Resp(SimpleNamespace):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def opener(req, timeout):
            seen["ua"] = req.get_header("User-agent")
            return Resp(status=204)

        self.assertTrue(post("https://discord.example/api/webhooks/1/x", {}, opener=opener))
        self.assertTrue(seen["ua"].startswith("Huginn/"))
        self.assertFalse(post("https://x", {}, opener=lambda *a, **k: (_ for _ in ()).throw(OSError())))

    def test_script_is_a_noop_without_webhook(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "matrix_summary.json").write_text(json.dumps(SUMMARY))
            with (root / "malicious_findings.csv").open("w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(ROW))
                w.writeheader()
                w.writerow(ROW)
            env = {k: v for k, v in os.environ.items() if k != "DISCORD_WEBHOOK"}
            out = subprocess.run([sys.executable, "scripts/notify_discord.py", str(root)],
                                 capture_output=True, text=True, env=env, check=True)
            self.assertIn("DISCORD_WEBHOOK not set", out.stdout)


if __name__ == "__main__":
    unittest.main()
