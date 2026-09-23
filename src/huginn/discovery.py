from __future__ import annotations

import json
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from .models import Artifact, ReleaseCandidate

USER_AGENT = "Huginn/0.1 (+https://github.com/OpenSource-For-Freedom/Huginn)"
PYPI_UPDATES = "https://pypi.org/rss/updates.xml"
PYPI_NEW = "https://pypi.org/rss/packages.xml"
RUBYGEMS_UPDATED = "https://rubygems.org/api/v1/activity/just_updated.json"
RUBYGEMS_NEW = "https://rubygems.org/api/v1/activity/latest.json"


class DiscoveryError(RuntimeError):
    pass


def _request(url: str, *, accept: str = "application/json", timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _split_pypi_title(title: str) -> tuple[str, str] | None:
    parts = title.strip().rsplit(" ", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    return parts[0], parts[1]


def discover_pypi(mode: str, limit: int) -> list[ReleaseCandidate]:
    url = PYPI_NEW if mode == "new" else PYPI_UPDATES
    root = ET.fromstring(_request(url, accept="application/rss+xml, application/xml;q=0.9, */*;q=0.1"))
    candidates: list[ReleaseCandidate] = []
    for item in root.findall("./channel/item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub_date = (item.findtext("pubDate") or "").strip()
        if mode == "updates":
            parsed = _split_pypi_title(title)
            if not parsed:
                continue
            name, version = parsed
        else:
            name = title
            if not name:
                continue
            meta = pypi_project_json(name)
            version = str(meta.get("info", {}).get("version") or "")
            if not version:
                continue
        candidates.append(
            ReleaseCandidate(
                registry="pypi",
                name=name,
                version=version,
                event_type="NEW_PACKAGE" if mode == "new" else "NEW_VERSION",
                published_at=pub_date,
                source_url=link,
            )
        )
        if len(candidates) >= limit:
            break
    return candidates


def pypi_project_json(name: str, version: str | None = None) -> dict:
    encoded = urllib.parse.quote(name, safe="")
    suffix = f"/{urllib.parse.quote(version, safe='')}" if version else ""
    return json.loads(_request(f"https://pypi.org/pypi/{encoded}{suffix}/json"))


def resolve_pypi_artifact(candidate: ReleaseCandidate) -> Artifact:
    meta = pypi_project_json(candidate.name, candidate.version)
    urls = meta.get("urls") or []
    preferred = [u for u in urls if u.get("packagetype") == "sdist"] or urls
    if not preferred:
        raise DiscoveryError(f"PyPI returned no artifact for {candidate.name} {candidate.version}")
    item = preferred[0]
    return Artifact(
        filename=str(item.get("filename") or "package.bin"),
        url=str(item["url"]),
        sha256=str((item.get("digests") or {}).get("sha256") or ""),
        registry_digest=str((item.get("digests") or {}).get("sha256") or ""),
        size_bytes=int(item.get("size") or 0),
    )


def discover_rubygems(mode: str, limit: int) -> list[ReleaseCandidate]:
    url = RUBYGEMS_NEW if mode == "new" else RUBYGEMS_UPDATED
    payload = json.loads(_request(url))
    candidates: list[ReleaseCandidate] = []
    for item in payload[:limit]:
        name = str(item.get("name") or "")
        version = str(item.get("version") or "")
        if not name or not version:
            continue
        candidates.append(
            ReleaseCandidate(
                registry="rubygems",
                name=name,
                version=version,
                event_type="NEW_PACKAGE" if mode == "new" else "NEW_VERSION",
                published_at=str(item.get("version_created_at") or ""),
                source_url=str(item.get("project_uri") or item.get("gem_uri") or ""),
            )
        )
    return candidates


def resolve_rubygems_artifact(candidate: ReleaseCandidate) -> Artifact:
    filename = f"{candidate.name}-{candidate.version}.gem"
    return Artifact(
        filename=filename,
        url=f"https://rubygems.org/downloads/{urllib.parse.quote(filename)}",
    )


def discover(registry: str, mode: str, limit: int) -> list[ReleaseCandidate]:
    if registry == "pypi":
        return discover_pypi(mode, limit)
    if registry == "rubygems":
        return discover_rubygems(mode, limit)
    raise DiscoveryError(f"Registry adapter not enabled in this capture release: {registry}")


def resolve_artifact(candidate: ReleaseCandidate) -> Artifact:
    if candidate.registry == "pypi":
        return resolve_pypi_artifact(candidate)
    if candidate.registry == "rubygems":
        return resolve_rubygems_artifact(candidate)
    raise DiscoveryError(f"No artifact resolver for registry: {candidate.registry}")
