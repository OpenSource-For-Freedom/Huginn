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


class RateLimitTests(unittest.TestCase):
    def _err(self, code, headers=None):
        import urllib.error
        return urllib.error.HTTPError("u", code, "x", headers or {}, None)

    def test_nvd_403_is_a_rate_limit(self):
        from huginn.advisory import NVD_HOST, _rate_limited
        self.assertTrue(_rate_limited(self._err(403), NVD_HOST))

    def test_github_403_is_a_rate_limit_only_with_its_headers(self):
        from huginn.advisory import _rate_limited
        self.assertTrue(_rate_limited(self._err(403, {"Retry-After": "5"}), "api.github.com"))
        self.assertTrue(_rate_limited(self._err(403, {"X-RateLimit-Remaining": "0"}), "api.github.com"))
        self.assertFalse(_rate_limited(self._err(403), "api.github.com"))
        self.assertFalse(_rate_limited(self._err(404), "services.nvd.nist.gov"))

    def test_nvd_403_is_retried_then_succeeds(self):
        import io
        from unittest.mock import patch
        from huginn.advisory import AdvisoryClient
        client = AdvisoryClient(nvd_api_key="k", retries=2)
        responses = [self._err(403), io.BytesIO(b'{"vulnerabilities": []}')]
        def fake_urlopen(req, timeout):
            item = responses.pop(0)
            if isinstance(item, Exception):
                raise item
            class R:
                def __enter__(s): return item
                def __exit__(s, *a): return False
            return R()
        with patch("huginn.advisory.urllib.request.urlopen", fake_urlopen), \
                patch("huginn.advisory.time.sleep"):
            self.assertEqual(client.query_nvd("CVE-2026-0001").status, "NO_MATCH")
