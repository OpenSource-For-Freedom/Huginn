from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from .models import Artifact, DiscoveryBatch, ReleaseCandidate

if TYPE_CHECKING:
    from .state import StateDB

USER_AGENT = "Huginn/0.2 (+https://github.com/OpenSource-For-Freedom/Huginn)"
PYPI_UPDATES = "https://pypi.org/rss/updates.xml"
PYPI_NEW = "https://pypi.org/rss/packages.xml"
RUBYGEMS_UPDATED = "https://rubygems.org/api/v1/activity/just_updated.json"
RUBYGEMS_NEW = "https://rubygems.org/api/v1/activity/latest.json"
NPM_REPLICA = "https://replicate.npmjs.com"
NPM_REGISTRY = "https://registry.npmjs.org"


class DiscoveryError(RuntimeError):
    pass


def _request(url: str, *, accept: str = "application/json", timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _json(url: str) -> dict:
    return json.loads(_request(url))


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime:
    if not value:
        return datetime.now(UTC) - timedelta(days=1)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return datetime.now(UTC) - timedelta(days=1)


def _split_pypi_title(title: str) -> tuple[str, str] | None:
    parts = title.strip().rsplit(" ", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    return parts[0], parts[1]


def _pypi_project_name(title: str, link: str) -> str:
    parsed = urllib.parse.urlparse(link)
    parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
    if parsed.hostname in {"pypi.org", "www.pypi.org"} and len(parts) >= 2 and parts[0] == "project":
        return parts[1].strip()
    return title.strip()


def _pypi_first_release(meta: dict) -> tuple[str, str]:
    releases = meta.get("releases") or {}
    earliest: tuple[datetime, str, str] | None = None
    for version, files in releases.items():
        for item in files or []:
            uploaded = str(item.get("upload_time_iso_8601") or item.get("upload_time") or "")
            if not uploaded:
                continue
            stamp = _parse_iso(uploaded)
            candidate = (stamp, str(version), uploaded)
            if earliest is None or candidate[0] < earliest[0]:
                earliest = candidate
    if earliest:
        return earliest[1], earliest[2]
    version = str((meta.get("info") or {}).get("version") or "")
    return version, ""


def discover_pypi_feed(mode: str, limit: int) -> list[ReleaseCandidate]:
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
            name = _pypi_project_name(title, link)
            if not name:
                continue
            try:
                meta = pypi_project_json(name)
            except urllib.error.HTTPError as exc:
                # RSS can briefly retain projects that were deleted/yanked or whose
                # CDN/API representation has not converged yet. Do not fail the batch.
                if exc.code == 404:
                    continue
                raise
            version, uploaded_at = _pypi_first_release(meta)
            if not version:
                continue
            if uploaded_at:
                pub_date = uploaded_at
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


def discover_pypi(mode: str, limit: int) -> DiscoveryBatch:
    modes = ("new", "updates") if mode == "all" else (mode,)
    unique: dict[tuple[str, str], ReleaseCandidate] = {}
    for selected in modes:
        for candidate in discover_pypi_feed(selected, limit):
            unique[(candidate.name, candidate.version)] = candidate
            if len(unique) >= limit:
                break
        if len(unique) >= limit:
            break
    return DiscoveryBatch(candidates=list(unique.values())[:limit])


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


def discover_rubygems_feed(mode: str, limit: int) -> list[ReleaseCandidate]:
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


def discover_rubygems(mode: str, limit: int) -> DiscoveryBatch:
    modes = ("new", "updates") if mode == "all" else (mode,)
    unique: dict[tuple[str, str], ReleaseCandidate] = {}
    for selected in modes:
        for candidate in discover_rubygems_feed(selected, limit):
            unique[(candidate.name, candidate.version)] = candidate
            if len(unique) >= limit:
                break
        if len(unique) >= limit:
            break
    return DiscoveryBatch(candidates=list(unique.values())[:limit])


def resolve_rubygems_artifact(candidate: ReleaseCandidate) -> Artifact:
    filename = f"{candidate.name}-{candidate.version}.gem"
    return Artifact(
        filename=filename,
        url=f"https://rubygems.org/downloads/{urllib.parse.quote(filename)}",
    )


def _npm_packument(name: str) -> dict:
    encoded = urllib.parse.quote(name, safe="@")
    return _json(f"{NPM_REGISTRY}/{encoded}")


def _npm_version_meta(name: str, version: str) -> dict:
    encoded_name = urllib.parse.quote(name, safe="@")
    encoded_version = urllib.parse.quote(version, safe="")
    return _json(f"{NPM_REGISTRY}/{encoded_name}/{encoded_version}")


def _first_npm_version(packument: dict) -> str:
    times = packument.get("time") or {}
    versions = [
        (version, _parse_iso(str(timestamp)))
        for version, timestamp in times.items()
        if version not in {"created", "modified"} and isinstance(timestamp, str)
    ]
    if not versions:
        return ""
    return min(versions, key=lambda item: item[1])[0]


def discover_npm(mode: str, limit: int, state: StateDB) -> DiscoveryBatch:
    cursor = state.get_cursor("npm.sequence")
    since_time = state.get_cursor("npm.publish_window")

    if not cursor:
        meta = _json(f"{NPM_REPLICA}/")
        update_seq = str(meta.get("update_seq") or "")
        if not update_seq:
            raise DiscoveryError("npm replication endpoint did not return update_seq")
        return DiscoveryBatch(
            candidates=[],
            checkpoint={"npm.sequence": update_seq, "npm.publish_window": _utc_now()},
        )

    query = urllib.parse.urlencode({"since": cursor, "limit": max(limit * 4, 50)})
    changes = _json(f"{NPM_REPLICA}/_changes?{query}")
    results = changes.get("results") or []
    last_seq = str(changes.get("last_seq") or cursor)

    # A wide overlap protects against replication/CDN timing skew. Release identity
    # in SQLite prevents overlap from creating duplicate completed scans.
    threshold = _parse_iso(since_time or "") - timedelta(hours=24)
    candidates: list[ReleaseCandidate] = []
    seen: set[tuple[str, str]] = set()

    for change in results:
        package_name = str(change.get("id") or "")
        if not package_name or package_name.startswith("_"):
            continue
        try:
            packument = _npm_packument(package_name)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                continue
            raise

        first_version = _first_npm_version(packument)
        time_map = packument.get("time") or {}
        for version, published_raw in time_map.items():
            if version in {"created", "modified"} or not isinstance(published_raw, str):
                continue
            published = _parse_iso(published_raw)
            if published < threshold:
                continue
            event_type = "NEW_PACKAGE" if version == first_version else "NEW_VERSION"
            if mode == "new" and event_type != "NEW_PACKAGE":
                continue
            if mode == "updates" and event_type != "NEW_VERSION":
                continue
            key = (package_name, version)
            if key in seen or state.is_completed("npm", package_name, version):
                continue
            seen.add(key)
            candidates.append(
                ReleaseCandidate(
                    registry="npm",
                    name=package_name,
                    version=version,
                    event_type=event_type,
                    published_at=published_raw,
                    source_url=f"https://www.npmjs.com/package/{urllib.parse.quote(package_name, safe='@/')}",
                )
            )
            if len(candidates) >= limit:
                break
        if len(candidates) >= limit:
            break

    return DiscoveryBatch(
        candidates=candidates,
        checkpoint={"npm.sequence": last_seq, "npm.publish_window": _utc_now()},
    )


def resolve_npm_artifact(candidate: ReleaseCandidate) -> Artifact:
    meta = _npm_version_meta(candidate.name, candidate.version)
    dist = meta.get("dist") or {}
    url = str(dist.get("tarball") or "")
    if not url:
        raise DiscoveryError(f"npm returned no tarball for {candidate.name} {candidate.version}")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in {"registry.npmjs.org"}:
        raise DiscoveryError(f"npm tarball host is not allowed: {parsed.hostname}")
    return Artifact(
        filename=f"{candidate.name.rsplit('/', 1)[-1]}-{candidate.version}.tgz",
        url=url,
        registry_digest=str(dist.get("integrity") or dist.get("shasum") or ""),
    )


def discover(registry: str, mode: str, limit: int, state: StateDB | None = None) -> DiscoveryBatch:
    if registry == "pypi":
        return discover_pypi(mode, limit)
    if registry == "rubygems":
        return discover_rubygems(mode, limit)
    if registry == "npm":
        if state is None:
            raise DiscoveryError("npm discovery requires durable state")
        return discover_npm(mode, limit, state)
    raise DiscoveryError(f"Registry adapter not enabled: {registry}")



def previous_release(candidate: ReleaseCandidate) -> ReleaseCandidate | None:
    """Return the immediately preceding published version for static comparison."""
    if candidate.event_type == "NEW_PACKAGE":
        return None

    versions: list[tuple[datetime, str, str]] = []

    if candidate.registry == "npm":
        packument = _npm_packument(candidate.name)
        for version, timestamp in (packument.get("time") or {}).items():
            if version in {"created", "modified"} or not isinstance(timestamp, str):
                continue
            versions.append((_parse_iso(timestamp), str(version), timestamp))

    elif candidate.registry == "pypi":
        meta = pypi_project_json(candidate.name)
        for version, files in (meta.get("releases") or {}).items():
            timestamps = [
                str(item.get("upload_time_iso_8601") or item.get("upload_time") or "")
                for item in (files or [])
            ]
            timestamps = [value for value in timestamps if value]
            if timestamps:
                earliest = min(timestamps, key=_parse_iso)
                versions.append((_parse_iso(earliest), str(version), earliest))

    elif candidate.registry == "rubygems":
        encoded = urllib.parse.quote(candidate.name, safe="")
        payload = json.loads(_request(f"https://rubygems.org/api/v1/versions/{encoded}.json"))
        for item in payload:
            version = str(item.get("number") or "")
            created = str(item.get("created_at") or item.get("built_at") or "")
            if version and created:
                versions.append((_parse_iso(created), version, created))

    else:
        return None

    current = next((entry for entry in versions if entry[1] == candidate.version), None)
    if current is None:
        return None

    earlier = [entry for entry in versions if entry[0] < current[0] and entry[1] != candidate.version]
    if not earlier:
        return None

    _, version, published = max(earlier, key=lambda entry: entry[0])
    return ReleaseCandidate(
        registry=candidate.registry,
        name=candidate.name,
        version=version,
        event_type="PREVIOUS_VERSION",
        published_at=published,
        source_url=candidate.source_url,
    )

def resolve_artifact(candidate: ReleaseCandidate) -> Artifact:
    if candidate.registry == "pypi":
        return resolve_pypi_artifact(candidate)
    if candidate.registry == "rubygems":
        return resolve_rubygems_artifact(candidate)
    if candidate.registry == "npm":
        return resolve_npm_artifact(candidate)
    raise DiscoveryError(f"No artifact resolver for registry: {candidate.registry}")
