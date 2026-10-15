"""Measure what the fresh hunt misses, against OpenSSF's malicious-packages feed.

OSV republishes every report from ossf/malicious-packages as a MAL- advisory, mostly
for every version of a package name. Each fresh run loads the MAL- advisories modified
in the last few days and checks every one against what Huginn saw:

* flagged        scanned, and the analyzer raised a malware row (any verdict)
* scanned_clean  scanned, and the analyzer found nothing: a detection gap
* not_selected   discovered, but ranked below the scan cut: a ranking gap
* unscannable    selected, but already removed or failing when Huginn got there
* not_seen       published while the fresh hunt was running, never discovered:
                 a discovery gap

Only advisories for packages published after the fresh hunt started count toward
not_seen, so the report does not blame it for history it never covered.
"""

from __future__ import annotations

import csv
import io
import json
import urllib.request
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI"}
USER_AGENT = "huginn-recall (+https://github.com/OpenSource-For-Freedom/Huginn)"


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _parse_ts(value: str) -> datetime:
    value = value.strip().replace("Z", "+00:00")
    if "." in value:                       # OSV stamps carry nanoseconds
        head, tail = value.split(".", 1)
        frac, _, tz = tail.partition("+")
        value = f"{head}.{frac[:6]}" + (f"+{tz}" if tz else "")
    stamp = datetime.fromisoformat(value)
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=UTC)


def recent_mal_ids(registry: str, since: datetime, *, fetch: Callable[[str], bytes] = _get,
                   cap: int = 400) -> list[str]:
    """MAL- advisory IDs modified since `since`, newest first (modified_id.csv is sorted)."""
    eco = OSV_ECOSYSTEM[registry]
    text = fetch(f"{OSV_BUCKET}/{eco}/modified_id.csv").decode("utf-8", "replace")
    ids: list[str] = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2:
            continue
        if _parse_ts(row[0]) < since:
            break
        if row[1].startswith("MAL-"):
            ids.append(row[1])
            if len(ids) >= cap:
                break
    return ids


def load_advisory(registry: str, mal_id: str, *, fetch: Callable[[str], bytes] = _get) -> dict | None:
    """{id, name, versions, published} for one MAL- advisory, or None."""
    eco = OSV_ECOSYSTEM[registry]
    try:
        data = json.loads(fetch(f"{OSV_BUCKET}/{eco}/{mal_id}.json"))
    except Exception:
        return None
    for affected in data.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("ecosystem") == eco and package.get("name"):
            return {"id": data.get("id", mal_id), "name": package["name"],
                    "versions": list(affected.get("versions") or []),
                    "published": data.get("published", "")}
    return None


def classify(advisories: list[dict], seen: dict[str, dict], hunt_started: datetime) -> list[dict]:
    """One row per advisory with its outcome; `seen` maps lower-case name to our record."""
    rows = []
    for adv in advisories:
        record = seen.get(adv["name"].lower())
        if record is None:
            published = adv.get("published") or ""
            if published and _parse_ts(published) < hunt_started:
                continue                    # before the fresh hunt existed
            outcome = "not_seen"
        elif record.get("verdict"):
            outcome = "flagged"
        elif record.get("scan_status") in {"FAILED", "SKIPPED"}:
            outcome = "unscannable"
        elif record.get("scanned"):
            outcome = "scanned_clean"
        else:
            outcome = "not_selected"
        rows.append({"id": adv["id"], "name": adv["name"], "outcome": outcome,
                     "triage_score": (record or {}).get("score", ""),
                     "triage_reasons": (record or {}).get("reasons", "")})
    return rows


def summarize(rows: list[dict]) -> dict:
    counts = Counter(r["outcome"] for r in rows)
    known = sum(counts.values())
    return {
        "known_malicious": known,
        "flagged": counts["flagged"],
        "scanned_clean": counts["scanned_clean"],
        "not_selected": counts["not_selected"],
        "unscannable": counts["unscannable"],
        "not_seen": counts["not_seen"],
        "recall_pct": round(100 * counts["flagged"] / known, 1) if known else None,
    }


def measure(registry: str, seen: dict[str, dict], hunt_started: datetime, *, days: int = 4,
            fetch: Callable[[str], bytes] = _get, cap: int = 400) -> tuple[dict, list[dict]]:
    since = datetime.now(UTC) - timedelta(days=days)
    advisories = []
    for mal_id in recent_mal_ids(registry, since, fetch=fetch, cap=cap):
        adv = load_advisory(registry, mal_id, fetch=fetch)
        if adv:
            advisories.append(adv)
    rows = classify(advisories, seen, hunt_started)
    return summarize(rows), rows
