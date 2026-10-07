"""Look-back discovery: every release a registry published in the last N days.

A week of releases is far more than one hunt can scan (Go and npm alone publish hundreds of
thousands), so discovery lists the whole window and then selects what to scan:

* releases Huginn already completed are dropped;
* mirror paths that differ only in case (common on the Go proxy) collapse to one;
* first releases of new packages get up to half of the batch;
* the rest is spread evenly across the window instead of taking only the newest.

Per-registry sources and their reach:
  go        index.golang.org, paged from the cutoff (full window)
  pypi      XML-RPC changelog_since_serial, paged from the cutoff serial (full window)
  crates    crates.io recent-updates, paged back to the cutoff (newest version per crate);
            the API serves 200 pages, which is about five days of updates
  rubygems  the append-only compact index (/versions), binary-searched for the cutoff
  npm       the replicate change feed, sampled evenly across the window
  packagist metadata/changes.json, which only keeps about 24 hours, plus the RSS feeds
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import xmlrpc.client
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta

from . import discovery as d
from .models import DiscoveryBatch, ReleaseCandidate
from .state import StateDB

GO_PAGE = 2000
GO_MAX_PAGES = 1500
PYPI_XMLRPC = "https://pypi.org/pypi"
PYPI_PAGE = 50000
CRATES_MAX_PAGES = 200
CRATES_PAGE_DELAY = 1.0  # crates.io asks crawlers for at most one request per second
RUBYGEMS_VERSIONS = "https://rubygems.org/versions"
PACKAGIST_CHANGES = "https://packagist.org/metadata/changes.json"
PACKAGIST_HISTORY = timedelta(hours=23)
NPM_PAGE = 5
NPM_PROBE = 9
GO_FIRST_VERSIONS = {"v0.0.1", "v0.1.0", "v1.0.0"}


def log(message: str) -> None:
    # stdout carries the report directory for the workflow, so progress goes to stderr.
    print(f"[window] {message}", file=sys.stderr, flush=True)


def _get_json(url: str, attempts: int = 3, sleep: Callable[[float], None] = time.sleep) -> dict:
    """GET JSON, retrying connection resets and 5xx responses (registries throttle long crawls)."""
    for attempt in range(1, attempts + 1):
        try:
            return d._json(url)
        except urllib.error.HTTPError as exc:
            if exc.code < 500 or attempt == attempts:
                raise
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            if attempt == attempts:
                raise
        sleep(2 * attempt)
    raise AssertionError("unreachable")


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat().replace("+00:00", "Z")


# --- selection -------------------------------------------------------------------------


def spread(items: Sequence[ReleaseCandidate], count: int) -> list[ReleaseCandidate]:
    """Pick count items evenly across a chronologically ordered list."""
    if count <= 0:
        return []
    if len(items) <= count:
        return list(items)
    step = len(items) / count
    return [items[int(i * step)] for i in range(count)]


def select(candidates: Sequence[ReleaseCandidate], limit: int, mode: str, state: StateDB | None) -> list[ReleaseCandidate]:
    seen: set[tuple[str, str]] = set()
    kept: list[ReleaseCandidate] = []
    for c in candidates:
        if mode == "new" and c.event_type != "NEW_PACKAGE":
            continue
        if mode == "updates" and c.event_type != "NEW_VERSION":
            continue
        key = (c.name.lower(), c.version)
        if key in seen:
            continue
        seen.add(key)
        if state is not None and state.is_completed(c.registry, c.name, c.version):
            continue
        kept.append(c)
    new = [c for c in kept if c.event_type == "NEW_PACKAGE"]
    updates = [c for c in kept if c.event_type != "NEW_PACKAGE"]
    chosen_new = spread(new, min(len(new), max(limit // 2, limit - len(updates))))
    chosen = chosen_new + spread(updates, limit - len(chosen_new))
    log(f"{len(kept)} unscanned releases in window ({len(new)} new packages); selected {len(chosen)}")
    return chosen


# --- go --------------------------------------------------------------------------------


def go_window(cutoff: datetime, limit: int) -> list[ReleaseCandidate]:
    since = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    out: list[ReleaseCandidate] = []
    for page in range(GO_MAX_PAGES):
        lines = d._request(f"{d.GO_INDEX}?since={since}&limit={GO_PAGE}").decode("utf-8", "replace").splitlines()
        last = since
        for line in lines:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            path, version = str(item.get("Path") or ""), str(item.get("Version") or "")
            last = str(item.get("Timestamp") or last)
            if not path or not version or d._is_go_pseudo_version(version):
                continue
            out.append(ReleaseCandidate(
                registry="go", name=path, version=version,
                event_type="NEW_PACKAGE" if version in GO_FIRST_VERSIONS else "NEW_VERSION",
                published_at=last, source_url=f"https://pkg.go.dev/{path}@{version}",
            ))
        if len(lines) < GO_PAGE or last == since:
            break
        since = last
    log(f"go: {len(out)} tagged versions since {cutoff:%Y-%m-%d %H:%M}Z")
    return out


# --- pypi ------------------------------------------------------------------------------


def _pypi_serial_at(client, cutoff_ts: float) -> int:
    """Smallest serial whose changelog page starts at or after the cutoff (binary search)."""
    hi = int(client.changelog_last_serial())
    lo = max(0, hi - 5_000_000)
    while hi - lo > PYPI_PAGE // 2:
        mid = (lo + hi) // 2
        page = client.changelog_since_serial(mid)
        if page and page[0][2] < cutoff_ts:
            lo = mid
        else:
            hi = mid
    return lo


def pypi_window(cutoff: datetime, limit: int, client=None) -> list[ReleaseCandidate]:
    client = client or xmlrpc.client.ServerProxy(PYPI_XMLRPC)
    cutoff_ts = cutoff.timestamp()
    serial = _pypi_serial_at(client, cutoff_ts)
    created: set[str] = set()
    releases: dict[tuple[str, str], float] = {}
    while True:
        page = client.changelog_since_serial(serial)
        if not page:
            break
        for name, version, ts, action, event_serial in page:
            serial = max(serial, int(event_serial))
            if ts < cutoff_ts:
                continue
            if action == "create":
                created.add(name.lower())
            elif action == "new release" and version and (name, version) not in releases:
                releases[(name, version)] = ts
        if len(page) < PYPI_PAGE:
            break
    out = [
        ReleaseCandidate(
            registry="pypi", name=name, version=version,
            event_type="NEW_PACKAGE" if name.lower() in created else "NEW_VERSION",
            published_at=_iso(ts), source_url=f"https://pypi.org/project/{name}/{version}/",
        )
        for (name, version), ts in sorted(releases.items(), key=lambda kv: kv[1])
    ]
    log(f"pypi: {len(out)} releases, {len(created)} new projects since {cutoff:%Y-%m-%d %H:%M}Z")
    return out


# --- crates.io -------------------------------------------------------------------------


def crates_window(cutoff: datetime, limit: int, sleep: Callable[[float], None] = time.sleep) -> list[ReleaseCandidate]:
    out: list[ReleaseCandidate] = []
    reach = ""
    for page in range(1, CRATES_MAX_PAGES + 1):
        try:
            payload = _get_json(f"{d.CRATES_API}?sort=recent-updates&per_page=100&page={page}")
        except urllib.error.HTTPError as exc:
            # crates.io serves at most 200 pages (20,000 crates) of this listing.
            if exc.code == 400 and page > 1:
                break
            raise
        crates = payload.get("crates") or []
        if crates:
            reach = str(crates[-1].get("updated_at") or reach)
        reached_cutoff = False
        for item in crates:
            updated = d._parse_iso(str(item.get("updated_at") or ""))
            if updated < cutoff:
                reached_cutoff = True
                break
            name = str(item.get("name") or "")
            version = str(item.get("newest_version") or item.get("max_version") or "")
            if not name or not version or item.get("yanked"):
                continue
            created = d._parse_iso(str(item.get("created_at") or ""))
            out.append(ReleaseCandidate(
                registry="crates", name=name, version=version,
                event_type="NEW_PACKAGE" if created >= cutoff else "NEW_VERSION",
                published_at=str(item.get("updated_at") or ""),
                source_url=str(item.get("repository") or f"https://crates.io/crates/{name}"),
            ))
        if reached_cutoff or len(crates) < 100:
            break
        sleep(CRATES_PAGE_DELAY)
    out.reverse()  # the API lists newest first
    log(f"crates: {len(out)} crates updated since {cutoff:%Y-%m-%d %H:%M}Z (listing reached back to {reach or 'n/a'})")
    return out


# --- rubygems --------------------------------------------------------------------------


def _rubygems_lines(text: str) -> list[tuple[str, list[str]]]:
    body = text.split("\n---\n", 1)[-1]
    rows: list[tuple[str, list[str]]] = []
    for line in body.splitlines():
        parts = line.split(" ")
        if len(parts) < 2 or not parts[0]:
            continue
        rows.append((parts[0], [v for v in parts[1].split(",") if v and not v.startswith("-")]))
    return rows


def _rubygems_created(name: str, version: str) -> datetime | None:
    url = (f"https://rubygems.org/api/v2/rubygems/{urllib.parse.quote(name, safe='')}"
           f"/versions/{urllib.parse.quote(version, safe='')}.json")
    try:
        meta = d._json(url)
    except (urllib.error.HTTPError, json.JSONDecodeError):
        return None
    stamp = str(meta.get("version_created_at") or meta.get("created_at") or "")
    return d._parse_iso(stamp) if stamp else None


def rubygems_window(cutoff: datetime, limit: int, created_at: Callable[[str, str], datetime | None] = _rubygems_created,
                    text: str | None = None) -> list[ReleaseCandidate]:
    # The compact index is append-only: each line added after the first bulk section records
    # newly pushed versions, in push order. Binary-search the first line pushed after the cutoff.
    rows = _rubygems_lines(text if text is not None else d._request(RUBYGEMS_VERSIONS, accept="text/plain").decode("utf-8", "replace"))
    lo, hi = 0, len(rows)
    while lo < hi:
        mid = (lo + hi) // 2
        name, versions = rows[mid]
        # Platform gems are listed as "1.2.3-java"; the API is keyed by the plain number.
        stamp = created_at(name, versions[-1].split("-", 1)[0]) if versions else None
        if stamp is not None and stamp >= cutoff:
            hi = mid
        else:
            lo = mid + 1
    earlier = {name for name, _ in rows[:lo]}
    out: list[ReleaseCandidate] = []
    for name, versions in rows[lo:]:
        for version in versions:
            out.append(ReleaseCandidate(
                registry="rubygems", name=name, version=version,
                event_type="NEW_VERSION" if name in earlier else "NEW_PACKAGE",
                source_url=f"https://rubygems.org/gems/{name}",
            ))
        earlier.add(name)
    log(f"rubygems: {len(out)} versions pushed since {cutoff:%Y-%m-%d %H:%M}Z")
    return out


# --- npm -------------------------------------------------------------------------------


def _npm_change_time(seq: int) -> datetime | None:
    """Approximate when change `seq` happened: the median last-modified time of a short page.

    A package's modified time is at or after the change that listed it; most packages are not
    republished within days, so the median of a page tracks the change time closely.
    """
    rows = _get_json(f"{d.NPM_CHANGES}?{urllib.parse.urlencode({'since': seq, 'limit': NPM_PROBE})}").get("results") or []
    stamps: list[datetime] = []
    for row in rows:
        name = str(row.get("id") or "")
        if not name or name.startswith("_"):
            continue
        try:
            modified = str((d._npm_packument(name).get("time") or {}).get("modified") or "")
        except urllib.error.HTTPError:
            continue
        if modified:
            stamps.append(d._parse_iso(modified))
    if not stamps:
        return None
    return sorted(stamps)[len(stamps) // 2]


def npm_window(cutoff: datetime, limit: int, state: StateDB, change_time: Callable[[int], datetime | None] = _npm_change_time) -> list[ReleaseCandidate]:
    head = int(str(_get_json(f"{d.NPM_REPLICA}/").get("update_seq") or "0"))
    if not head:
        raise d.DiscoveryError("npm replication endpoint did not return update_seq")
    # Step back from the head until a probe lands before the cutoff, then binary-search.
    hi, back = head, 10_000
    lo = max(0, head - back)
    while lo > 0:
        stamp = change_time(lo)
        if stamp is not None and stamp < cutoff:
            break
        hi, back = lo, back * 2
        lo = max(0, head - back)
    while hi - lo > 2000:
        mid = (lo + hi) // 2
        stamp = change_time(mid)
        if stamp is not None and stamp >= cutoff:
            hi = mid
        else:
            lo = mid
    # Sample the window evenly: a short page of changes at each of `limit` points.
    probes = max(1, limit)
    step = max(1, (head - lo) // probes)
    out: list[ReleaseCandidate] = []
    for i in range(probes):
        seq = lo + i * step
        rows = _get_json(f"{d.NPM_CHANGES}?{urllib.parse.urlencode({'since': seq, 'limit': NPM_PAGE})}").get("results") or []
        out.extend(d._npm_candidates(rows, cutoff, "all", NPM_PAGE, state))
    out.sort(key=lambda c: d._parse_iso(c.published_at))
    log(f"npm: sampled {len(out)} releases across sequence {lo}..{head}")
    return out


# --- packagist -------------------------------------------------------------------------


def packagist_window(cutoff: datetime, limit: int) -> list[ReleaseCandidate]:
    floor = datetime.now(UTC) - PACKAGIST_HISTORY
    if cutoff < floor:
        log("packagist: change history only reaches about 24 hours; using the last 23 hours")
    since = max(cutoff, floor)
    payload = _get_json(f"{PACKAGIST_CHANGES}?since={int(since.timestamp()) * 10000}")
    names: dict[str, float] = {}
    for action in payload.get("actions") or []:
        name = str(action.get("package") or "")
        if action.get("type") != "update" or not name or name.endswith("~dev") or "/" not in name:
            continue
        names[name] = float(action.get("time") or 0)
    ordered = [n for n, _ in sorted(names.items(), key=lambda kv: kv[1])]
    out: list[ReleaseCandidate] = []
    for name in spread([ReleaseCandidate("packagist", n, "", "") for n in ordered], limit * 3):
        vendor, _, package = name.name.partition("/")
        try:
            meta = _get_json(f"{d.PACKAGIST_REPO}/{urllib.parse.quote(vendor, safe='')}/{urllib.parse.quote(package, safe='')}.json")
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            continue
        entries = (meta.get("packages") or {}).get(name.name) or []
        if meta.get("minified") == "composer/2.0":
            entries = d._expand_composer_versions(entries)
        stamps = [(str(e.get("version") or ""), d._parse_iso(str(e.get("time") or ""))) for e in entries if e.get("time")]
        if not stamps:
            continue
        first = min(stamps, key=lambda s: s[1])[0]
        for version, stamp in stamps:
            if stamp < since or version.startswith("dev-"):
                continue
            out.append(ReleaseCandidate(
                registry="packagist", name=name.name, version=version,
                event_type="NEW_PACKAGE" if version == first else "NEW_VERSION",
                published_at=stamp.isoformat().replace("+00:00", "Z"),
                source_url=f"https://packagist.org/packages/{name.name}",
            ))
    out.sort(key=lambda c: c.published_at)
    log(f"packagist: {len(names)} packages changed since {since:%Y-%m-%d %H:%M}Z; {len(out)} tagged releases")
    return out


# --- entry point -----------------------------------------------------------------------


def discover_window(registry: str, mode: str, limit: int, days: int, state: StateDB | None) -> DiscoveryBatch:
    cutoff = datetime.now(UTC) - timedelta(days=days)
    if registry == "go":
        found = go_window(cutoff, limit)
    elif registry == "pypi":
        found = pypi_window(cutoff, limit)
    elif registry == "crates":
        found = crates_window(cutoff, limit)
    elif registry == "rubygems":
        found = rubygems_window(cutoff, limit)
    elif registry == "npm":
        if state is None:
            raise d.DiscoveryError("npm look-back discovery needs the state database")
        found = npm_window(cutoff, limit, state)
    elif registry == "packagist":
        found = packagist_window(cutoff, limit)
    else:
        raise d.DiscoveryError(f"unsupported registry: {registry}")
    return DiscoveryBatch(candidates=select(found, limit, mode, state))
