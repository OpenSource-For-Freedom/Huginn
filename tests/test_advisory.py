from __future__ import annotations

import unittest

from huginn.advisory import AdvisoryClient, AdvisoryResult, enrich_rows


class FakeClient(AdvisoryClient):
    def __init__(self, osv=None, ghsa=None, nvd=None, redhat=None):
        self._osv = osv or AdvisoryResult()
        self._ghsa = ghsa or AdvisoryResult()
        self._nvd = nvd or AdvisoryResult()
        self._redhat = redhat or AdvisoryResult()

    def query_package(self, registry, package, version):
        return self._osv, self._ghsa

    def query_nvd(self, cve_id):
        return self._nvd

    def query_redhat(self, cve_id):
        return self._redhat


def semgrep_row():
    return {
        "registry": "npm",
        "package_name": "demo",
        "package_version": "1.2.3",
        "known_dependency": "false",
        "dependency_ecosystem": "",
        "dependency_name": "",
        "installed_version": "",
        "vulnerability_id": "",
        "cwe": "CWE-78",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "novelty_state": "unreviewed",
        "dedup_status": "NOT_CHECKED",
    }


class AdvisoryEnrichmentTests(unittest.TestCase):
    def test_no_package_advisory_becomes_no_match(self):
        row = semgrep_row()
        enrich_rows([row], FakeClient(), checked_at="2026-09-22T00:00:00Z")
        self.assertEqual(row["dedup_status"], "NO_MATCH")
        self.assertEqual(row["novelty_state"], "novel")
        self.assertEqual(row["dedup_match_basis"], "exact_package_version_no_advisory")

    def test_partial_package_lookup_does_not_become_no_match(self):
        row = semgrep_row()
        osv = AdvisoryResult(status="ERROR", error="timeout")
        ghsa = AdvisoryResult(status="NO_MATCH")
        enrich_rows([row], FakeClient(osv=osv, ghsa=ghsa))
        self.assertEqual(row["dedup_status"], "LOOKUP_FAILED")
        self.assertEqual(row["novelty_state"], "unreviewed")
        self.assertEqual(row["nvd_status"], "SKIPPED")
        self.assertEqual(row["redhat_status"], "SKIPPED")

    def test_package_overlap_never_auto_becomes_known_exact(self):
        row = semgrep_row()
        osv = AdvisoryResult(
            status="MATCH",
            ids={"GHSA-aaaa-bbbb-cccc"},
            cves={"CVE-2026-1111"},
            cwes={"CWE-78"},
        )
        nvd = AdvisoryResult(status="MATCH", ids={"CVE-2026-1111"}, cves={"CVE-2026-1111"})
        redhat = AdvisoryResult(status="NO_MATCH")
        enrich_rows([row], FakeClient(osv=osv, nvd=nvd, redhat=redhat))
        self.assertEqual(row["dedup_status"], "POSSIBLE_MATCH")
        self.assertEqual(row["novelty_state"], "possible_match")
        self.assertEqual(row["dedup_match_basis"], "package_version+cwe")

    def test_direct_known_dependency_identifier_is_known_exact(self):
        row = semgrep_row()
        row.update({
            "known_dependency": "true",
            "dependency_ecosystem": "npm",
            "dependency_name": "dep",
            "installed_version": "1.0.0",
            "vulnerability_id": "CVE-2026-2222",
        })
        osv = AdvisoryResult(
            status="MATCH",
            ids={"CVE-2026-2222", "GHSA-dddd-eeee-ffff"},
            cves={"CVE-2026-2222"},
        )
        nvd = AdvisoryResult(status="MATCH", ids={"CVE-2026-2222"}, cves={"CVE-2026-2222"})
        enrich_rows([row], FakeClient(osv=osv, nvd=nvd))
        self.assertEqual(row["dedup_status"], "KNOWN_EXACT")
        self.assertEqual(row["novelty_state"], "known")
        self.assertEqual(row["dedup_match_basis"], "scanner_identifier")


if __name__ == "__main__":
    unittest.main()
