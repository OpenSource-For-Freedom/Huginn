from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from huginn.analyzer.package_entry import analyze_package, expose_package_dirs, main

ANALYZER = Path(__file__).resolve().parents[1] / "src" / "huginn" / "analyzer"


def _pkg(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp()) / "src"
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


class VendoredAnalyzerTests(unittest.TestCase):
    def test_vendored_files_match_their_recorded_sync(self):
        # Edit the rules in git_warden and run scripts/sync_analyzer.py, never here.
        source = json.loads((ANALYZER / "SOURCE.json").read_text())
        self.assertEqual(source["repository"], "OpenSource-For-Freedom/git_warden")
        self.assertRegex(source["commit"], r"^[0-9a-f]{40}$")
        for name, digest in source["files"].items():
            text = (ANALYZER / name).read_text(encoding="utf-8")
            self.assertEqual(hashlib.sha256(text.encode("utf-8")).hexdigest(), digest, name)
            self.assertTrue(text.startswith("# Vendored from git_warden"), name)

    def test_payload_in_dist_is_confirmed(self):
        src = _pkg({
            "package/package.json": json.dumps({"name": "ui-kit", "main": "dist/index.js"}),
            "package/dist/index.js": "global['_V']='8-st3';var MDy=(function(a,b){return a})"
                                     "('Cot%3t=shtP',1111436);\n",
        })
        out = analyze_package(src, "ui-kit", "npm")
        self.assertTrue(out["confirmed"])
        self.assertEqual(out["confidence"], "auto")
        self.assertEqual([f["rule"] for f in out["confirming_findings"]], ["polinrider-loader"])
        self.assertEqual(out["package"]["exposed_dirs"], ["package/pkg_dist"])
        self.assertTrue((src / "package/dist/index.js").exists())  # source untouched

    def test_install_hook_stager_is_confirmed(self):
        src = _pkg({"package/package.json": json.dumps(
            {"name": "x", "scripts": {"preinstall": "node setup_bun.js"}})})
        self.assertTrue(analyze_package(src, "x", "npm")["confirmed"])

    def test_clean_package_is_not_confirmed(self):
        src = _pkg({"package/package.json": json.dumps({"name": "pad"}),
                    "package/index.js": "module.exports = (s, n) => s.padStart(n);\n"})
        out = analyze_package(src, "pad", "npm")
        self.assertFalse(out["confirmed"])
        self.assertEqual(out["confirming_findings"], [])

    def test_nested_generated_dirs_are_exposed(self):
        root = Path(tempfile.mkdtemp())
        (root / "a/build/dist").mkdir(parents=True)
        (root / "out").mkdir()
        self.assertEqual(expose_package_dirs(root),
                         ["a/pkg_build", "a/pkg_build/pkg_dist", "pkg_out"])

    def test_cli_rejects_a_missing_tree(self):
        self.assertEqual(main([str(Path(tempfile.mkdtemp()) / "missing"),
                               "--name", "a", "--ecosystem", "pypi"]), 2)

    def test_container_copies_only_the_analyzer(self):
        cf = (Path(__file__).resolve().parents[1] / "containers/analyzer.Containerfile").read_text()
        self.assertIn("COPY src/huginn/analyzer /opt/huginn_analyzer", cf)
        self.assertIn("USER 65534:65534", cf)
        self.assertIn('ENTRYPOINT ["python", "-m", "huginn_analyzer.package_entry"]', cf)


if __name__ == "__main__":
    unittest.main()
