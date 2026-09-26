from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from huginn.reporting import REVIEW_COLUMNS
from scripts.update_cve_ledger import LEDGER_COLUMNS, RUN_LOG_COLUMNS, check_ledger, read_rows, update


def finding(**overrides):
    row = {c: "" for c in REVIEW_COLUMNS}
    row.update({
        "registry": "pypi",
        "package_name": "demo",
        "package_version": "1.0.0",
        "purl": "pkg:pypi/demo@1.0.0",
        "published_at_utc": "2026-09-26T00:00:00Z",
        "artifact_url": "https://files.example/demo-1.0.0.tar.gz",
        "artifact_sha256": "a" * 64,
        "review_status": "PENDING",
    })
    row.update(overrides)
    return row


def known_cve(**overrides):
    return finding(**{
        "finding_class": "known_dependency_vulnerability",
        "vulnerability_id": "CVE-2024-56326",
        "severity": "HIGH",
        "dedup_status": "KNOWN_EXACT",
        "dependency_ecosystem": "pip",
        "dependency_name": "jinja2",
        "installed_version": "3.1.4",
        "fixed_version": "3.1.5",
        "file_path": "requirements.txt",
        "title": "Jinja sandbox breakout",
        "advisory_source": "Trivy advisory database",
        "advisory_url": "https://avd.aquasec.com/nvd/cve-2024-56326",
        "cwe": '["CWE-693"]',
        **overrides,
    })


def candidate(**overrides):
    return finding(**{
        "finding_fingerprint": "f" * 64,
        "finding_id": "f" * 20,
        "rule_id": "rules.huginn.python.network-response-unsafe-deserialization",
        "vulnerability_id": "rules.huginn.python.network-response-unsafe-deserialization",
        "severity": "HIGH",
        "validation_state": "HIGH_VALUE_MANUAL_CANDIDATE",
        "file_path": "demo/net.py",
        "title": "network response reaches pickle.loads",
        "dedup_status": "NO_MATCH",
        "cwe": "CWE-502",
        **overrides,
    })


def write_packet(root: Path, rows, summary=None) -> Path:
    packet = root / "hunt-summary"
    packet.mkdir()
    with (packet / "review_findings.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=REVIEW_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    (packet / "matrix_summary.json").write_text(json.dumps(summary or {
        "ecosystem_runs": [{"registry": "pypi"}], "package_scan_count": 1, "finding_count": len(rows),
    }))
    return packet


class CveLedgerTests(unittest.TestCase):
    def test_known_exact_cve_is_logged_with_every_column_filled(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            packet = write_packet(root, [known_cve(fixed_version="", cvss_score="")])
            update(packet, root / "ledger", "101", now="2026-09-26T02:00:00Z")

            rows = read_rows(root / "ledger" / "cve_ledger.csv")
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual([c for c in LEDGER_COLUMNS if not row[c]], [])
            self.assertEqual(row["confirmation_basis"], "ADVISORY_EXACT_MATCH")
            self.assertEqual(row["cve_ids"], "CVE-2024-56326")
            self.assertEqual(row["fixed_version"], "NO_FIX_AVAILABLE")
            self.assertEqual(row["cvss_score"], "NOT_PUBLISHED")
            self.assertEqual(row["cwe"], "CWE-693")
            self.assertEqual(check_ledger(root / "ledger"), [])

    def test_sink_only_and_unknown_severity_findings_never_reach_the_ledger(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            packet = write_packet(root, [
                finding(rule_id="rules.huginn.generic.xss-sink", severity="MEDIUM",
                        validation_state="NEEDS_REACHABILITY_REVIEW", dedup_status="NO_MATCH"),
                known_cve(severity="UNKNOWN"),
                candidate(),
            ])
            update(packet, root / "ledger", "101")

            self.assertEqual(read_rows(root / "ledger" / "cve_ledger.csv"), [])
            queue = read_rows(root / "ledger" / "candidate_queue.csv")
            self.assertEqual([r["finding_fingerprint"] for r in queue], ["f" * 64])
            self.assertEqual(queue[0]["review_status"], "PENDING")

    def test_repeat_sightings_update_counts_and_run_log_is_complete(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for hunt in ("101", "102"):
                packet = root / "hunt-summary"
                if packet.exists():
                    for p in packet.iterdir():
                        p.unlink()
                    packet.rmdir()
                write_packet(root, [known_cve()])
                update(packet, root / "ledger", hunt)

            rows = read_rows(root / "ledger" / "cve_ledger.csv")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["times_seen"], "2")
            self.assertEqual(rows[0]["first_logged_hunt"], "101")
            self.assertEqual(rows[0]["last_seen_hunt"], "102")
            log = read_rows(root / "ledger" / "run_log.csv")
            self.assertEqual([r["hunt_id"] for r in log], ["101", "102"])
            for r in log:
                self.assertEqual([c for c in RUN_LOG_COLUMNS if not r[c]], [])

    def test_analyst_validation_is_preserved_and_promoted(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            packet = write_packet(root, [candidate()])
            update(packet, root / "ledger", "101")

            queue_path = root / "ledger" / "candidate_queue.csv"
            queue = read_rows(queue_path)
            queue[0].update({
                "review_status": "VALIDATED", "reviewer": "analyst", "reviewer_decision": "true positive",
                "reviewer_notes": "remote response reaches pickle.loads", "reachability_verified": "true",
                "security_boundary_verified": "true", "affected_version_verified": "true",
                "known_advisory_verified": "true", "verified_at_utc": "2026-09-26T03:00:00Z",
            })
            with queue_path.open("w", encoding="utf-8-sig", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=REVIEW_COLUMNS)
                writer.writeheader()
                writer.writerows(queue)

            for p in packet.iterdir():
                p.unlink()
            packet.rmdir()
            write_packet(root, [candidate()])
            entry = update(packet, root / "ledger", "102")

            self.assertEqual(entry["analyst_validated_promoted"], "1")
            self.assertEqual(read_rows(queue_path)[0]["review_status"], "VALIDATED")
            rows = read_rows(root / "ledger" / "cve_ledger.csv")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["finding_type"], "NOVEL_ANALYST_VALIDATED")
            self.assertEqual(rows[0]["dependency_name"], "NOT_APPLICABLE")
            self.assertEqual(check_ledger(root / "ledger"), [])

    def test_incomplete_analyst_validation_fails_the_run(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            packet = write_packet(root, [candidate(review_status="VALIDATED")])
            with self.assertRaises(SystemExit):
                update(packet, root / "ledger", "101")


if __name__ == "__main__":
    unittest.main()
