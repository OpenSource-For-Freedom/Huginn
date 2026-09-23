from __future__ import annotations

import unittest

from huginn.alerts import alerts_from_findings, alerts_from_manifests, make_alert


class OperationalAlertTests(unittest.TestCase):
    def test_failed_package_becomes_high_coverage_alert(self):
        alerts = alerts_from_manifests("r1", [{
            "registry": "pypi",
            "package_name": "demo",
            "package_version": "1.0.0",
            "scan_status": "FAILED",
            "failure_stage": "artifact_download",
            "error": "HTTPError: 503 Service Unavailable",
        }])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["coverage_impact"], "PACKAGE_NOT_ANALYZED")
        self.assertEqual(alerts[0]["stage"], "artifact_download")

    def test_advisory_api_error_becomes_alert(self):
        alerts = alerts_from_findings("r1", [{
            "registry": "npm",
            "package_name": "demo",
            "package_version": "2.0.0",
            "osv_status": "ERROR",
            "ghsa_status": "NO_MATCH",
            "nvd_status": "SKIPPED",
            "redhat_status": "SKIPPED",
            "enrichment_error": "TimeoutError: OSV timed out",
            "previous_compare_status": "NOT_RUN",
        }])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "ADVISORY_API_RETRIEVAL_FAILURE")
        self.assertEqual(alerts[0]["source"], "osv")
        self.assertEqual(alerts[0]["coverage_impact"], "ADVISORY_DEDUP_INCOMPLETE")

    def test_discovery_alert_can_be_critical(self):
        alert = make_alert(
            run_id="r1",
            registry="rubygems",
            stage="registry_discovery",
            alert_type="ECOSYSTEM_DISCOVERY_FAILURE",
            source="rubygems",
            message="HTTP 503",
            severity="CRITICAL",
            coverage_impact="ECOSYSTEM_NOT_ANALYZED",
        )
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["status"], "OPEN")


if __name__ == "__main__":
    unittest.main()
