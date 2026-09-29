from __future__ import annotations

import unittest
from pathlib import Path


class RuleCoverageTests(unittest.TestCase):
    def test_high_value_weakness_classes_are_present(self):
        text = Path("rules/semgrep.yml").read_text(encoding="utf-8")
        for category in (
            "buffer_overflow",
            "integer_overflow_allocation",
            "resource_exhaustion",
            "regex_resource_exhaustion",
            "ssrf",
            "path_traversal",
            "sql_injection",
            "command_execution",
            "dynamic_code_execution",
            "unsafe_deserialization",
            "xss_sink",
        ):
            self.assertIn(f"huginn_category: {category}", text)

        for cwe in ("CWE-120", "CWE-190", "CWE-400", "CWE-1333", "CWE-918", "CWE-22", "CWE-89"):
            self.assertIn(f"cwe: {cwe}", text)

    def test_rules_cover_all_active_ecosystem_languages_plus_native_extensions(self):
        text = Path("rules/semgrep.yml").read_text(encoding="utf-8")
        self.assertIn("languages: [python]", text)
        self.assertIn("languages: [javascript, typescript]", text)
        self.assertIn("languages: [ruby]", text)
        self.assertIn("languages: [c, cpp]", text)
        self.assertIn("languages: [php]", text)
        self.assertIn("languages: [go]", text)


if __name__ == "__main__":
    unittest.main()
