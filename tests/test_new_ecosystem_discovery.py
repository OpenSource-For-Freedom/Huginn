from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from huginn.discovery import (
    DiscoveryError,
    PolicySkip,
    _expand_composer_versions,
    _go_escape,
    _is_go_pseudo_version,
    discover,
    resolve_artifact,
)
from huginn.models import ReleaseCandidate


class CratesDiscoveryTests(unittest.TestCase):
    def test_new_and_updated_crates_are_deduplicated_and_yanked_skipped(self):
        pages = {
            "new": {"crates": [{"name": "fresh", "newest_version": "0.1.0", "updated_at": "2026-09-29T00:00:00Z"}]},
            "recent-updates": {"crates": [
                {"name": "fresh", "newest_version": "0.1.0"},
                {"name": "gone", "newest_version": "1.0.0", "yanked": True},
                {"name": "busy", "newest_version": "2.3.4", "repository": "https://github.com/x/busy"},
            ]},
        }
        with patch("huginn.discovery._json", side_effect=lambda url: pages[url.split("sort=")[1].split("&")[0]]):
            batch = discover("crates", "all", 10)
        got = [(c.name, c.version, c.event_type) for c in batch.candidates]
        self.assertEqual(got, [("fresh", "0.1.0", "NEW_PACKAGE"), ("busy", "2.3.4", "NEW_VERSION")])
        self.assertEqual(batch.candidates[1].purl, "pkg:cargo/busy@2.3.4")

    def test_crate_artifact_uses_static_host_and_registry_checksum(self):
        with patch("huginn.discovery._json", return_value={"version": {"checksum": "ab" * 32}}):
            artifact = resolve_artifact(ReleaseCandidate("crates", "busy", "2.3.4", "NEW_VERSION"))
        self.assertEqual(artifact.url, "https://static.crates.io/crates/busy/busy-2.3.4.crate")
        self.assertEqual(artifact.sha256, "ab" * 32)


PACKAGIST_RSS = b"""<?xml version="1.0"?>
<rss><channel>
  <item><title>acme/widget (v1.2.0)</title><guid>acme/widget v1.2.0</guid>
    <pubDate>Tue, 29 Sep 2026 12:00:00 +0000</pubDate><link>https://packagist.org/packages/acme/widget</link></item>
  <item><title>broken</title><guid>no-vendor 1.0</guid></item>
</channel></rss>
"""


class PackagistDiscoveryTests(unittest.TestCase):
    def test_release_feed_parses_vendor_package_and_version(self):
        with patch("huginn.discovery._request", return_value=PACKAGIST_RSS):
            batch = discover("packagist", "updates", 10)
        self.assertEqual([(c.name, c.version) for c in batch.candidates], [("acme/widget", "v1.2.0")])
        self.assertEqual(batch.candidates[0].purl, "pkg:composer/acme/widget@v1.2.0")

    def test_minified_metadata_is_expanded_before_matching_version(self):
        entries = [
            {"version": "v1.2.0", "dist": {"url": "https://api.github.com/repos/acme/widget/zipball/abc", "type": "zip"}, "license": ["MIT"]},
            {"version": "v1.1.0", "dist": {"url": "https://api.github.com/repos/acme/widget/zipball/def", "type": "zip"}, "license": "__unset"},
        ]
        expanded = _expand_composer_versions(entries)
        self.assertEqual(expanded[1]["dist"]["url"].rsplit("/", 1)[-1], "def")
        self.assertNotIn("license", expanded[1])

        payload = {"minified": "composer/2.0", "packages": {"acme/widget": entries}}
        with patch("huginn.discovery._json", return_value=payload):
            artifact = resolve_artifact(ReleaseCandidate("packagist", "acme/widget", "1.1.0", "NEW_VERSION"))
        self.assertTrue(artifact.url.endswith("/zipball/def"))

    def test_dist_on_untrusted_host_is_refused(self):
        payload = {"packages": {"acme/widget": [{"version": "1.0.0", "dist": {"url": "https://evil.example/w.zip"}}]}}
        with patch("huginn.discovery._json", return_value=payload):
            with self.assertRaises(PolicySkip):
                resolve_artifact(ReleaseCandidate("packagist", "acme/widget", "1.0.0", "NEW_VERSION"))

    def test_missing_version_is_a_policy_skip(self):
        payload = {"packages": {"acme/widget": [{"version": "1.0.0", "dist": {"url": "https://api.github.com/x"}}]}}
        with patch("huginn.discovery._json", return_value=payload):
            with self.assertRaises(PolicySkip) as raised:
                resolve_artifact(ReleaseCandidate("packagist", "acme/widget", "2.0.0", "NEW_VERSION"))
        self.assertIsInstance(raised.exception, DiscoveryError)


class GoDiscoveryTests(unittest.TestCase):
    def test_pseudo_versions_are_skipped_and_newest_first(self):
        lines = "\n".join(json.dumps(x) for x in [
            {"Path": "github.com/a/one", "Version": "v1.0.0", "Timestamp": "2026-09-29T00:00:00Z"},
            {"Path": "github.com/a/two", "Version": "v0.0.0-20260929000000-abcdefabcdef", "Timestamp": "2026-09-29T00:01:00Z"},
            {"Path": "github.com/a/three", "Version": "v2.1.0", "Timestamp": "2026-09-29T00:02:00Z"},
        ]).encode()
        with patch("huginn.discovery._request", return_value=lines):
            batch = discover("go", "all", 10)
        self.assertEqual([c.name for c in batch.candidates], ["github.com/a/three", "github.com/a/one"])
        self.assertEqual(batch.candidates[0].purl, "pkg:golang/github.com/a/three@v2.1.0")

    def test_pseudo_version_detection(self):
        self.assertTrue(_is_go_pseudo_version("v0.0.0-20260929000000-abcdefabcdef"))
        self.assertTrue(_is_go_pseudo_version("v1.2.4-0.20260929000000-abcdefabcdef"))
        self.assertFalse(_is_go_pseudo_version("v1.2.3"))
        self.assertFalse(_is_go_pseudo_version("v1.2.3-rc.1"))

    def test_module_proxy_url_uses_case_escaping(self):
        self.assertEqual(_go_escape("github.com/BurntSushi/toml"), "github.com/!burnt!sushi/toml")
        artifact = resolve_artifact(ReleaseCandidate("go", "github.com/BurntSushi/toml", "v1.4.0", "NEW_VERSION"))
        self.assertEqual(artifact.url, "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.4.0.zip")


if __name__ == "__main__":
    unittest.main()
