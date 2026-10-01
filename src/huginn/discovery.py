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
NPM_CHANGES = "https://replicate.npmjs.com/registry/_changes"
NPM_REGISTRY = "https://registry.npmjs.org"
CRATES_API = "https://crates.io/api/v1/crates"
CRATES_DOWNLOAD = "https://static.crates.io/crates"
PACKAGIST_RELEASES = "https://packagist.org/feeds/releases.rss"
PACKAGIST_NEW = "https://packagist.org/feeds/packages.rss"
PACKAGIST_REPO = "https://repo.packagist.org/p2"
PACKAGIST_DIST_HOSTS = {"api.github.com", "codeload.github.com", "gitlab.com", "bitbucket.org"}
GO_INDEX = "https://index.golang.org/index"
GO_PROXY = "https://proxy.golang.org"
GO_LOOKBACK = timedelta(hours=6)


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


def _npm_candidates(
    changes: list[dict],
    threshold: datetime,
    mode: str,
    limit: int,
    state: StateDB,
) -> list[ReleaseCandidate]:
    """Turn replicate _changes rows into release candidates published after threshold."""
    candidates: list[ReleaseCandidate] = []
    seen: set[tuple[str, str]] = set()

    for change in changes:
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
        for version, published_raw in (packument.get("time") or {}).items():
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
                return candidates
    return candidates


def _npm_recent(mode: str, limit: int, state: StateDB, update_seq: str) -> DiscoveryBatch:
    """Scan the most recent changes, newest first, for releases from the last 24 hours."""
    query = urllib.parse.urlencode({"descending": "true", "limit": max(limit * 10, 250)})
    changes = _json(f"{NPM_CHANGES}?{query}")
    threshold = datetime.now(UTC) - timedelta(hours=24)
    return DiscoveryBatch(
        candidates=_npm_candidates(changes.get("results") or [], threshold, mode, limit, state),
        checkpoint={"npm.sequence": update_seq, "npm.publish_window": _utc_now()},
    )


def _npm_cursor_is_stale(cursor: str, update_seq: str, limit: int) -> bool:
    """True when the saved sequence is further behind the feed head than one window can cover."""
    try:
        return int(update_seq) - int(cursor) > max(limit * 4, 50)
    except ValueError:
        return False


def discover_npm(mode: str, limit: int, state: StateDB) -> DiscoveryBatch:
    cursor = state.get_cursor("npm.sequence")
    since_time = state.get_cursor("npm.publish_window")

    meta = _json(f"{NPM_REPLICA}/")
    update_seq = str(meta.get("update_seq") or "")
    if not update_seq:
        raise DiscoveryError("npm replication endpoint did not return update_seq")

    # npm publishes far more changes between hunts than one window reads. Walking forward
    # from an old cursor only ever reaches changes older than the publish window, so every
    # release is filtered out. When the cursor has fallen behind, rescan the newest changes.
    if not cursor or _npm_cursor_is_stale(cursor, update_seq, limit):
        return _npm_recent(mode, limit, state, update_seq)

    query = urllib.parse.urlencode({"since": cursor, "limit": max(limit * 4, 50)})
    changes = _json(f"{NPM_CHANGES}?{query}")
    last_seq = str(changes.get("last_seq") or cursor)

    # A wide overlap protects against replication/CDN timing skew. Release identity
    # in SQLite prevents overlap from creating duplicate completed scans.
    threshold = _parse_iso(since_time or "") - timedelta(hours=24)
    return DiscoveryBatch(
        candidates=_npm_candidates(changes.get("results") or [], threshold, mode, limit, state),
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


# --- crates.io -----------------------------------------------------------------------


def discover_crates(mode: str, limit: int) -> DiscoveryBatch:
    sorts = ("new", "recent-updates") if mode == "all" else (("new",) if mode == "new" else ("recent-updates",))
    unique: dict[tuple[str, str], ReleaseCandidate] = {}
    for sort in sorts:
        per_page = max(1, min(limit, 100))
        payload = _json(f"{CRATES_API}?sort={sort}&per_page={per_page}")
        for item in payload.get("crates") or []:
            name = str(item.get("name") or "")
            version = str(item.get("newest_version") or item.get("max_version") or "")
            if not name or not version or item.get("yanked"):
                continue
            unique.setdefault((name, version), ReleaseCandidate(
                registry="crates",
                name=name,
                version=version,
                event_type="NEW_PACKAGE" if sort == "new" else "NEW_VERSION",
                published_at=str(item.get("updated_at") or item.get("created_at") or ""),
                source_url=str(item.get("repository") or f"https://crates.io/crates/{name}"),
            ))
            if len(unique) >= limit:
                break
        if len(unique) >= limit:
            break
    return DiscoveryBatch(candidates=list(unique.values())[:limit])


def resolve_crates_artifact(candidate: ReleaseCandidate) -> Artifact:
    name = urllib.parse.quote(candidate.name, safe="")
    version = urllib.parse.quote(candidate.version, safe="")
    meta = _json(f"{CRATES_API}/{name}/{version}")
    checksum = str((meta.get("version") or {}).get("checksum") or "")
    return Artifact(
        filename=f"{candidate.name}-{candidate.version}.crate",
        url=f"{CRATES_DOWNLOAD}/{name}/{name}-{version}.crate",
        sha256=checksum,
        registry_digest=checksum,
    )


# --- Packagist (Composer) --------------------------------------------------------------


def _packagist_feed(url: str, event_type: str, limit: int) -> list[ReleaseCandidate]:
    root = ET.fromstring(_request(url, accept="application/rss+xml"))
    out: list[ReleaseCandidate] = []
    for item in root.iter("item"):
        guid = (item.findtext("guid") or "").strip()
        parts = guid.rsplit(" ", 1)
        if len(parts) != 2 or "/" not in parts[0]:
            continue
        out.append(ReleaseCandidate(
            registry="packagist",
            name=parts[0],
            version=parts[1],
            event_type=event_type,
            published_at=(item.findtext("pubDate") or "").strip(),
            source_url=(item.findtext("link") or "").strip(),
        ))
        if len(out) >= limit:
            break
    return out


def discover_packagist(mode: str, limit: int) -> DiscoveryBatch:
    feeds = []
    if mode in ("all", "new"):
        feeds.append((PACKAGIST_NEW, "NEW_PACKAGE"))
    if mode in ("all", "updates"):
        feeds.append((PACKAGIST_RELEASES, "NEW_VERSION"))
    unique: dict[tuple[str, str], ReleaseCandidate] = {}
    for url, event_type in feeds:
        for candidate in _packagist_feed(url, event_type, limit):
            unique.setdefault((candidate.name, candidate.version), candidate)
    return DiscoveryBatch(candidates=list(unique.values())[:limit])


def _expand_composer_versions(entries: list[dict]) -> list[dict]:
    """Undo Composer v2 metadata minification: each entry inherits unchanged keys from the previous one."""
    expanded: list[dict] = []
    current: dict = {}
    for entry in entries:
        current = dict(current)
        for key, value in entry.items():
            if value == "__unset":
                current.pop(key, None)
            else:
                current[key] = value
        expanded.append(current)
    return expanded


def resolve_packagist_artifact(candidate: ReleaseCandidate) -> Artifact:
    vendor, _, package = candidate.name.partition("/")
    path = f"{urllib.parse.quote(vendor, safe='')}/{urllib.parse.quote(package, safe='')}"
    payload = _json(f"{PACKAGIST_REPO}/{path}.json")
    entries = (payload.get("packages") or {}).get(candidate.name) or []
    if payload.get("minified") == "composer/2.0":
        entries = _expand_composer_versions(entries)
    wanted = {candidate.version, candidate.version.lstrip("v")}
    match = next((e for e in entries if str(e.get("version")) in wanted
                  or str(e.get("version", "")).lstrip("v") in wanted), None)
    if match is None:
        raise DiscoveryError(f"packagist has no version {candidate.version} for {candidate.name}")
    dist = match.get("dist") or {}
    url = str(dist.get("url") or "")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in PACKAGIST_DIST_HOSTS:
        raise DiscoveryError(f"packagist dist host is not allowed: {parsed.hostname}")
    return Artifact(
        filename=f"{package}-{candidate.version}.zip",
        url=url,
        registry_digest=str(dist.get("shasum") or dist.get("reference") or ""),
    )


# --- Go modules -----------------------------------------------------------------------


def _is_go_pseudo_version(version: str) -> bool:
    # vX.Y.Z-yyyymmddhhmmss-abcdefabcdef (optionally after a pre-release): untagged commits.
    tail = version.rsplit("-", 2)
    return len(tail) == 3 and len(tail[2]) == 12 and tail[1][-14:].isdigit()


def _go_escape(path: str) -> str:
    return "".join(f"!{c.lower()}" if c.isupper() else c for c in path)


def discover_go(mode: str, limit: int) -> DiscoveryBatch:
    since = (datetime.now(UTC) - GO_LOOKBACK).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = _request(f"{GO_INDEX}?since={since}&limit=2000").decode("utf-8", "replace")
    unique: dict[tuple[str, str], ReleaseCandidate] = {}
    for line in reversed(raw.splitlines()):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        path, version = str(item.get("Path") or ""), str(item.get("Version") or "")
        if not path or not version or _is_go_pseudo_version(version):
            continue
        event_type = "NEW_VERSION"
        if mode == "new" and not version.startswith(("v0.0.1", "v0.1.0", "v1.0.0")):
            continue
        unique.setdefault((path, version), ReleaseCandidate(
            registry="go",
            name=path,
            version=version,
            event_type=event_type,
            published_at=str(item.get("Timestamp") or ""),
            source_url=f"https://pkg.go.dev/{path}@{version}",
        ))
        if len(unique) >= limit:
            break
    return DiscoveryBatch(candidates=list(unique.values()))


def resolve_go_artifact(candidate: ReleaseCandidate) -> Artifact:
    path = urllib.parse.quote(_go_escape(candidate.name), safe="/!")
    version = urllib.parse.quote(_go_escape(candidate.version), safe="!")
    return Artifact(
        filename=f"{candidate.name.rsplit('/', 1)[-1]}-{candidate.version}.zip",
        url=f"{GO_PROXY}/{path}/@v/{version}.zip",
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
    if registry == "crates":
        return discover_crates(mode, limit)
    if registry == "packagist":
        return discover_packagist(mode, limit)
    if registry == "go":
        return discover_go(mode, limit)
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
    if candidate.registry == "crates":
        return resolve_crates_artifact(candidate)
    if candidate.registry == "packagist":
        return resolve_packagist_artifact(candidate)
    if candidate.registry == "go":
        return resolve_go_artifact(candidate)
    raise DiscoveryError(f"No artifact resolver for registry: {candidate.registry}")
