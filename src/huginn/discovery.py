from __future__ import annotations

import json
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta

from .models import Artifact, ReleaseCandidate
from .state import StateDB

USER_AGENT = "Huginn/0.2 (+https://github.com/OpenSource-For-Freedom/Huginn)"
PYPI_UPDATES = "https://pypi.org/rss/updates.xml"
PYPI_NEW = "https://pypi.org/rss/packages.xml"
RUBYGEMS_UPDATED = "https://rubygems.org/api/v1/activity/just_updated.json"
RUBYGEMS_NEW = "https://rubygems.org/api/v1/activity/latest.json"
NPM_REPLICATE = "https://replicate.npmjs.com"
NPM_REGISTRY = "https://registry.npmjs.org"


class DiscoveryError(RuntimeError):
    pass


def _request(url: str, *, accept: str = "application/json", timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _json(url: str) -> dict:
    return json.loads(_request(url))


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
    return _json(f"https://pypi.org/pypi/{encoded}{suffix}/json")


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
    return Artifact(filename=filename, url=f"https://rubygems.org/downloads/{urllib.parse.quote(filename)}")


def npm_packument(name: str) -> dict:
    encoded = urllib.parse.quote(name, safe="")
    return _json(f"{NPM_REGISTRY}/{encoded}")


def _parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def discover_npm(mode: str, limit: int, state: StateDB) -> list[ReleaseCandidate]:
    cursor = state.get_cursor("npm")
    now = datetime.now(UTC)
    if cursor is None:
        payload = _json(f"{NPM_REPLICATE}/_changes?since=now&limit=1")
        state.set_cursor("npm", str(payload.get("last_seq") or "now"), now.isoformat().replace("+00:00", "Z"))
        return []

    seq, cursor_time = cursor
    qs = urllib.parse.urlencode({"since": seq, "limit": max(limit * 4, 25)})
    payload = _json(f"{NPM_REPLICATE}/_changes?{qs}")
    cutoff = (_parse_iso(cursor_time) or now) - timedelta(minutes=20)
    candidates: list[ReleaseCandidate] = []
    seen: set[tuple[str, str]] = set()

    for change in payload.get("results") or []:
        name = str(change.get("id") or "")
        if not name:
            continue
        try:
            pack = npm_packument(name)
        except Exception:
            continue
        times = pack.get("time") or {}
        created = _parse_iso(str(times.get("created") or ""))
        for version, published in sorted(
            ((v, _parse_iso(str(t))) for v, t in times.items() if v not in {"created", "modified"}),
            key=lambda item: item[1] or datetime.min.replace(tzinfo=UTC),
        ):
            if published is None or published < cutoff:
                continue
            key = (name, version)
            if key in seen or state.is_completed("npm", name, version):
                continue
            is_first = bool(created and abs((published - created).total_seconds()) <= 5)
            event_type = "NEW_PACKAGE" if is_first else "NEW_VERSION"
            if mode == "new" and event_type != "NEW_PACKAGE":
                continue
            if mode == "updates" and event_type != "NEW_VERSION":
                continue
            seen.add(key)
            candidates.append(
                ReleaseCandidate(
                    registry="npm",
                    name=name,
                    version=version,
                    event_type=event_type,
                    published_at=published.isoformat().replace("+00:00", "Z"),
                    source_url=f"https://www.npmjs.com/package/{urllib.parse.quote(name, safe='@/')}/v/{urllib.parse.quote(version, safe='')}",
                )
            )
            if len(candidates) >= limit:
                break
        if len(candidates) >= limit:
            break

    state.set_cursor(
        "npm",
        str(payload.get("last_seq") or seq),
        now.isoformat().replace("+00:00", "Z"),
    )
    return candidates


def resolve_npm_artifact(candidate: ReleaseCandidate) -> Artifact:
    pack = npm_packument(candidate.name)
    version = (pack.get("versions") or {}).get(candidate.version) or {}
    dist = version.get("dist") or {}
    url = str(dist.get("tarball") or "")
    if not url:
        raise DiscoveryError(f"npm returned no tarball for {candidate.name} {candidate.version}")
    return Artifact(
        filename=f"{candidate.name.rsplit('/', 1)[-1]}-{candidate.version}.tgz",
        url=url,
        registry_digest=str(dist.get("integrity") or dist.get("shasum") or ""),
    )


def seeded_candidate(spec: str) -> ReleaseCandidate:
    try:
        registry, name, version = spec.split(":", 2)
    except ValueError as exc:
        raise DiscoveryError("seed must be registry:name:version") from exc
    if registry not in {"npm", "pypi", "rubygems"} or not name or not version:
        raise DiscoveryError(f"invalid seed: {spec}")
    return ReleaseCandidate(
        registry=registry,
        name=name,
        version=version,
        event_type="VALIDATION_SEED",
        source_url="validation-control",
    )


def discover(registry: str, mode: str, limit: int, state: StateDB | None = None) -> list[ReleaseCandidate]:
    if registry == "pypi":
        return discover_pypi(mode, limit)
    if registry == "rubygems":
        return discover_rubygems(mode, limit)
    if registry == "npm":
        if state is None:
            raise DiscoveryError("npm discovery requires durable state")
        return discover_npm(mode, limit, state)
    raise DiscoveryError(f"Registry adapter not enabled: {registry}")


def resolve_artifact(candidate: ReleaseCandidate) -> Artifact:
    if candidate.registry == "pypi":
        return resolve_pypi_artifact(candidate)
    if candidate.registry == "rubygems":
        return resolve_rubygems_artifact(candidate)
    if candidate.registry == "npm":
        return resolve_npm_artifact(candidate)
    raise DiscoveryError(f"No artifact resolver for registry: {candidate.registry}")
