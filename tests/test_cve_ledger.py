from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from huginn.reporting import REVIEW_COLUMNS
from scripts.update_cve_ledger import (
    FINDINGS_COLUMNS, LEDGER_COLUMNS, RUN_LOG_COLUMNS, check_ledger, read_ledger, read_rows,
    sync_validated_findings, update, write_rows,
)


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

            rows = read_ledger(root / "ledger")
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

            self.assertEqual(read_ledger(root / "ledger"), [])
            queue = read_rows(root / "ledger" / "candidate_queue.csv")
            self.assertEqual([r["finding_fingerprint"] for r in queue], ["f" * 64])
            self.assertEqual(queue[0]["review_status"], "PENDING")
            quality = read_rows(root / "ledger" / "report_quality.csv")
            self.assertEqual(len(quality), 1)
            self.assertEqual(quality[0]["reported_novelty"], "UNCONFIRMED")
            self.assertEqual(quality[0]["report_status"], "MANUAL_REVIEW_REQUIRED")

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

            rows = read_ledger(root / "ledger")
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
            rows = read_ledger(root / "ledger")
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

    def test_ledger_is_sharded_and_legacy_single_file_is_migrated(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ledger_dir = root / "ledger"
            packet = write_packet(root, [known_cve()])
            update(packet, ledger_dir, "101", now="2026-09-26T02:00:00Z")
            (old,) = read_ledger(ledger_dir)
            # Recreate the pre-shard layout: one cve_ledger.csv holding every row.
            for shard in (ledger_dir / "cve_ledger").glob("*.csv"):
                shard.unlink()
            write_rows(ledger_dir / "cve_ledger.csv", LEDGER_COLUMNS, [old])

            update(packet, ledger_dir, "102", now="2026-09-27T02:00:00Z")

            self.assertFalse((ledger_dir / "cve_ledger.csv").exists())
            shards = sorted(p.name for p in (ledger_dir / "cve_ledger").glob("*.csv"))
            self.assertEqual(shards, [f"{old['registry']}-{old['ledger_id'][0]}.csv"])
            (row,) = read_ledger(ledger_dir)
            self.assertEqual((row["times_seen"], row["first_logged_hunt"]), ("2", "101"))
            self.assertEqual(check_ledger(ledger_dir), [])

    def test_oversized_ledger_file_fails_validation(self):
        with tempfile.TemporaryDirectory() as td:
            ledger_dir = Path(td) / "ledger"
            ledger_dir.mkdir()
            with (ledger_dir / "big.csv").open("wb") as f:
                f.truncate(91 * 1024 * 1024)
            self.assertTrue(any("big.csv" in e for e in check_ledger(ledger_dir)))


class ValidatedFindingsTests(unittest.TestCase):
    def test_new_validated_package_gets_a_pending_row_and_curated_rows_are_kept(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td)
            curated = {c: "x" for c in FINDINGS_COLUMNS}
            curated.update(finding_id="HUGINN-2026-004", package="Known/Pkg", cvss4_score="8.7")
            write_rows(ledger / "validated_findings.csv", FINDINGS_COLUMNS, [curated])
            queue = [
                {"review_status": "VALIDATED", "package_name": "known/pkg", "package_version": "2.0"},
                {"review_status": "VALIDATED", "package_name": "fresh", "package_version": "1.1", "registry": "pypi",
                 "severity": "HIGH", "cwe": "CWE-78", "reviewer_decision": "true positive: shell injection",
                 "verified_at_utc": "2026-10-07T00:00:00Z", "disclosure_reference": "docs/disclosures/fresh.md"},
                {"review_status": "REJECTED", "package_name": "noise", "package_version": "1.0"},
            ]
            self.assertEqual(sync_validated_findings(ledger, queue, "h1", "2026-10-07T00:00:00Z"), 1)
            self.assertEqual(sync_validated_findings(ledger, queue, "h2", "2026-10-08T00:00:00Z"), 0)
            rows = read_rows(ledger / "validated_findings.csv")
        self.assertEqual(rows[0]["cvss4_score"], "8.7")
        new = rows[1]
        self.assertEqual(new["finding_id"], "HUGINN-2026-005")
        self.assertEqual(new["package"], "fresh")
        self.assertEqual(new["cvss4_score"], "PENDING")
        self.assertEqual(new["disclosure_draft"], "docs/disclosures/fresh.md")
        self.assertTrue(all(new[c] for c in FINDINGS_COLUMNS))


if __name__ == "__main__":
    unittest.main()
