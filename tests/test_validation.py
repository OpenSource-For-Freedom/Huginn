from __future__ import annotations

import unittest

from huginn.validation import apply_validation


def base_row() -> dict[str, str]:
    return {
        "scanner": "semgrep",
        "rule_id": "rules.huginn.python.tainted-eval",
        "file_path": "package/app.py",
        "severity": "HIGH",
        "confidence": "HIGH",
        "dedup_status": "NO_MATCH",
        "known_dependency": "false",
        "suspicious_package": "false",
        "validation_kind": "dataflow",
        "source_to_sink": "true",
    }


class ValidationTests(unittest.TestCase):
    def test_dataflow_no_match_is_high_value_candidate(self):
        row = base_row()
        apply_validation(
            [row],
            previous_version="1.0.0",
            previous_keys=set(),
            previous_compare_status="COMPLETE",
        )
        self.assertEqual(row["validation_state"], "HIGH_VALUE_MANUAL_CANDIDATE")
        self.assertEqual(row["reachability_state"], "STATIC_DATAFLOW")
        self.assertEqual(row["analyst_queue"], "NOVEL_CANDIDATE")
        self.assertEqual(row["previous_finding_present"], "false")
        self.assertEqual(row["version_delta"], "INTRODUCED_OR_MOVED")
        self.assertGreaterEqual(int(row["validation_score"]), 70)

    def test_sink_only_rule_stays_manual(self):
        row = base_row()
        row.update({
            "rule_id": "rules.huginn.generic.dynamic-eval",
            "confidence": "LOW",
            "severity": "MEDIUM",
            "validation_kind": "sink_only",
            "source_to_sink": "false",
        })
        apply_validation([row], previous_compare_status="UNAVAILABLE")
        self.assertEqual(row["validation_state"], "NEEDS_REACHABILITY_REVIEW")
        self.assertEqual(row["reachability_state"], "SINK_ONLY")

    def test_test_path_is_deprioritized(self):
        row = base_row()
        row.update({
            "file_path": "package/tests/test_eval.py",
            "validation_kind": "sink_only",
            "source_to_sink": "false",
            "confidence": "LOW",
            "severity": "MEDIUM",
        })
        apply_validation([row], previous_compare_status="UNAVAILABLE")
        self.assertEqual(row["validation_state"], "NOISE_LIKELY")
        self.assertEqual(row["analyst_queue"], "LOW_SIGNAL")
        self.assertIn("non_runtime_path:tests", row["validation_reasons"])

    def test_dist_path_is_not_automatically_noise(self):
        row = base_row()
        row.update({
            "file_path": "package/dist/runtime.js",
            "validation_kind": "sink_only",
            "source_to_sink": "false",
            "confidence": "LOW",
            "severity": "MEDIUM",
        })
        apply_validation([row], previous_compare_status="UNAVAILABLE")
        self.assertNotEqual(row["validation_state"], "NOISE_LIKELY")
        self.assertNotIn("non_runtime_path:dist", row["validation_reasons"])

    def test_known_dependency_is_known(self):
        row = base_row()
        row.update({
            "scanner": "trivy",
            "known_dependency": "true",
            "dedup_status": "KNOWN_EXACT",
        })
        apply_validation([row])
        self.assertEqual(row["validation_state"], "KNOWN")
        self.assertEqual(row["analyst_queue"], "KNOWN")

    def test_previous_same_rule_path_reduces_score(self):
        row = base_row()
        apply_validation(
            [row],
            previous_version="1.0.0",
            previous_keys={(row["rule_id"], row["file_path"])},
            previous_compare_status="COMPLETE",
        )
        self.assertEqual(row["previous_finding_present"], "true")
        self.assertEqual(row["version_delta"], "PRESENT_IN_PREVIOUS")
        self.assertIn("same_rule_path_in_previous_version", row["validation_reasons"])


if __name__ == "__main__":
    unittest.main()
