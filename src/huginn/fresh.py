"""Fresh malware hunt: every new npm and PyPI package from the last hours, ranked, scanned.

The twice-monthly window hunt samples a few hundred releases out of hundreds of
thousands, weeks after publication, when malicious packages have already been taken
down. This hunt runs every few hours instead:

1. discover every package first published since the last run (npm replicate change
   feed, PyPI XML-RPC changelog), not a sample;
2. rank them by metadata alone (huginn.triage) and keep the riskiest few;
3. download and run only the malware analyzer on those (no Trivy/Semgrep), in the
   same no-network sandbox as the window hunt;
4. measure recall against OSV's MAL- advisories (huginn.recall), so every run says
   how much known malware it caught, ranked too low, reached too late or never saw.

    python -m huginn.fresh --registries npm,pypi --hours 8 --top 12 --out reports/fresh/RUN
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import discovery as d
from . import recall
from . import window as w
from .capture import DEFAULT_MAX_ARTIFACT, _skip_reason, download
from .malware import MALWARE_COLUMNS, malware_row
from .models import ReleaseCandidate
from .reporting import write_csv
from .state import StateDB
from .triage import Triage, rank, score_npm, score_pypi

NPM_PAGE = 2000
NPM_MAX_CHANGES = 400_000
MAX_METADATA = 900           # packuments / project JSONs fetched per registry per run
RECALL_DAYS = 4
MANIFEST_COLUMNS = [
    "registry", "package_name", "package_version", "published_at_utc", "triage_score",
    "triage_reasons", "selected", "scan_status", "verdict", "error",
]


def log(message: str) -> None:
    print(f"[fresh] {message}", file=sys.stderr, flush=True)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _low_rev(change: dict) -> bool:
    """A change to a brand-new npm document: its revision number is still 1 or 2.

    Publishing a new package creates the document (rev 1) and the dist-tag update
    can follow at once (rev 2). Established packages are at rev 10s to 1000s, so this
    keeps first publishes without fetching a packument for every change.
    """
    revs = [str(c.get("rev") or "") for c in change.get("changes") or []]
    if not revs:
        return True                         # no rev reported: let the packument decide
    try:
        return min(int(r.split("-", 1)[0]) for r in revs if r) <= 2
    except ValueError:
        return True


# --- discovery ------------------------------------------------------------------------


def npm_fresh(cutoff: datetime, state: StateDB, *, max_metadata: int = MAX_METADATA,
              get_json=w._get_json, packument=d._npm_packument, head=None,
              seq_at=None) -> tuple[list[tuple[ReleaseCandidate, dict]], dict]:
    """New npm packages first published after `cutoff`, with their packuments."""
    head = head if head is not None else w.npm_head()
    cursor = state.get_cursor("fresh.npm.sequence")
    start = int(cursor) if cursor and cursor.isdigit() else 0
    if not start or head - start > NPM_MAX_CHANGES:
        start = (seq_at or w.npm_seq_at)(cutoff, head)
        start = max(start, head - NPM_MAX_CHANGES)
    names: dict[str, None] = {}
    seq, read = start, 0
    while seq < head:
        page = get_json(f"{d.NPM_CHANGES}?since={seq}&limit={NPM_PAGE}")
        rows = page.get("results") or []
        if not rows:
            break
        for row in rows:
            name = str(row.get("id") or "")
            if name and not name.startswith("_") and not row.get("deleted") and _low_rev(row):
                names.pop(name, None)
                names[name] = None          # newest last
        read += len(rows)
        nxt = int(str(page.get("last_seq") or rows[-1].get("seq") or head))
        if nxt <= seq:
            break                           # the feed stopped advancing
        seq = nxt
    log(f"npm: read {read} changes ({start}..{seq}); {len(names)} low-revision documents")

    found: list[tuple[ReleaseCandidate, dict]] = []
    for name in list(names)[-max_metadata:]:
        try:
            doc = packument(name)
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):
                continue                    # already unpublished
            raise
        first = d._first_npm_version(doc)
        times = doc.get("time") or {}
        if not first or d._parse_iso(str(times.get(first, ""))) < cutoff:
            continue                        # not a first publish inside the window
        latest = str((doc.get("dist-tags") or {}).get("latest") or first)
        found.append((ReleaseCandidate(
            registry="npm", name=name, version=latest, event_type="NEW_PACKAGE",
            published_at=str(times.get(latest) or times.get(first)),
            source_url=f"https://www.npmjs.com/package/{name}"), doc))
    log(f"npm: {len(found)} new packages since {cutoff:%Y-%m-%d %H:%M}Z")
    return found, {"fresh.npm.sequence": str(seq)}


def pypi_fresh(cutoff: datetime, *, max_metadata: int = MAX_METADATA, window=w.pypi_window,
               project_json=d.pypi_project_json) -> tuple[list[tuple[ReleaseCandidate, dict]], dict]:
    """New PyPI projects created after `cutoff` (their newest release), with project JSON."""
    latest: dict[str, ReleaseCandidate] = {}
    for c in window(cutoff, 0):
        if c.event_type == "NEW_PACKAGE":
            latest[c.name.lower()] = c      # releases come oldest first
    found: list[tuple[ReleaseCandidate, dict]] = []
    for c in list(latest.values())[-max_metadata:]:
        try:
            project = project_json(c.name)
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):
                continue
            raise
        found.append((c, project))
    log(f"pypi: {len(found)} new projects since {cutoff:%Y-%m-%d %H:%M}Z")
    return found, {}


def _score(registry: str, c: ReleaseCandidate, meta: dict) -> Triage:
    return score_npm(c.name, c.version, meta) if registry == "npm" else score_pypi(c.name, c.version, meta)


# --- one registry ---------------------------------------------------------------------


def hunt_registry(registry: str, *, hours: float, top: int, state: StateDB, scanner, run: str,
                  workdir: Path, deadline: float, discover=None,
                  max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT) -> tuple[dict, list[dict], list[dict]]:
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    if discover is None:
        discover = (lambda: npm_fresh(cutoff, state)) if registry == "npm" else (lambda: pypi_fresh(cutoff))
    found, checkpoint = discover()

    now = _utc_now()
    scored: list[tuple[tuple[ReleaseCandidate, dict], Triage]] = []
    for c, meta in found:
        if state.fresh_known(registry, c.name, c.version):
            continue
        t = _score(registry, c, meta)
        state.record_fresh(registry, c.name, c.version, now, t.score, "; ".join(t.reasons))
        scored.append(((c, meta), t))
    chosen = rank(scored, top)
    chosen_keys = {(item[0].name, item[0].version) for item, _ in chosen}
    log(f"{registry}: {len(scored)} unseen new packages, {len(chosen)} selected "
        f"(scores {[t.score for _, t in chosen]})")

    manifest = {(c.name, c.version): {
        "registry": registry, "package_name": c.name, "package_version": c.version,
        "published_at_utc": c.published_at, "triage_score": t.score,
        "triage_reasons": "; ".join(t.reasons), "selected": (c.name, c.version) in chosen_keys,
        "scan_status": "", "verdict": "", "error": ""} for (c, _), t in scored}
    rows: list[dict] = []
    for (c, _meta), _t in chosen:
        entry = manifest[(c.name, c.version)]
        if time.monotonic() > deadline:
            entry["scan_status"] = "NOT_STARTED"
            continue
        try:
            artifact = d.resolve_artifact(c)
            suffix = "".join(Path(artifact.filename).suffixes)[-20:] or ".bin"
            with tempfile.TemporaryDirectory(prefix="huginn-fresh-", dir=workdir) as td:
                path = Path(td) / f"package{suffix}"
                sha256, _ = download(artifact, path, max_artifact_bytes)
                result, status, error = scanner.malware_only(path, package_name=c.name, ecosystem=registry)
            entry["scan_status"] = "COMPLETED" if status == "COMPLETE" else "FAILED"
            entry["error"] = error or ""
            row = malware_row(run_id=run, candidate=c, artifact=artifact, sha256=sha256,
                              first_seen=now, result=result) if status == "COMPLETE" else None
            if row:
                rows.append(row)
                entry["verdict"] = row["verdict"]
        except Exception as exc:
            reason = _skip_reason(exc)
            entry["scan_status"] = "SKIPPED" if reason else "FAILED"
            entry["error"] = (reason or f"{type(exc).__name__}: {exc}")[:500]
        state.record_fresh_scan(registry, c.name, c.version, entry["scan_status"], entry["verdict"])
    state.set_cursors(checkpoint)

    summary = {
        "registry": registry, "new_packages": len(scored), "selected": len(chosen),
        "scanned": sum(1 for e in manifest.values() if e["scan_status"] == "COMPLETED"),
        "failed": sum(1 for e in manifest.values() if e["scan_status"] == "FAILED"),
        "removed_or_skipped": sum(1 for e in manifest.values() if e["scan_status"] == "SKIPPED"),
        "confirmed": sum(1 for r in rows if r["verdict"] == "CONFIRMED"),
        "suspicious": sum(1 for r in rows if r["verdict"] == "SUSPICIOUS"),
    }
    return summary, rows, list(manifest.values())


def measure_recall(registry: str, state: StateDB, *, fetch=recall._get) -> tuple[dict, list[dict]]:
    """Recall over the last RECALL_DAYS, caching advisories so each run fetches only new ones."""
    started = state.get_cursor("fresh.started") or _utc_now()
    since = datetime.now(UTC) - timedelta(days=RECALL_DAYS)
    advisories = []
    for mal_id in recall.recent_mal_ids(registry, since, fetch=fetch):
        adv = state.cached_advisory(mal_id)
        if adv is None:
            adv = recall.load_advisory(registry, mal_id, fetch=fetch)
            if adv is None:
                continue
            state.cache_advisory(registry, adv)
        advisories.append(adv)
    seen = state.fresh_seen_since(registry, (datetime.now(UTC) - timedelta(days=7)).isoformat())
    rows = recall.classify(advisories, seen, recall._parse_ts(started))
    return recall.summarize(rows), rows


# --- reporting ------------------------------------------------------------------------


def discord_messages(summaries: list[dict], recalls: dict[str, dict], rows: list[dict],
                     run_url: str = "") -> list[dict]:
    from .discord import _GREEN, _RED, package_embed

    confirmed = [r for r in rows if r.get("verdict") == "CONFIRMED"]
    fields = [{
        "name": s["registry"],
        "value": (f"{s['new_packages']} new · {s['scanned']} scanned · {s['confirmed']} confirmed"
                  f" · {s['suspicious']} suspicious · {s['removed_or_skipped']} already removed"),
        "inline": False} for s in summaries]
    for registry, r in recalls.items():
        if r.get("known_malicious"):
            fields.append({"name": f"{registry} recall (OSV MAL-, {RECALL_DAYS} days)", "value": (
                f"{r['known_malicious']} known · {r['flagged']} flagged · {r['scanned_clean']} scanned clean"
                f" · {r['not_selected']} ranked out · {r['unscannable']} removed first"
                f" · {r['not_seen']} not seen"), "inline": False})
    embed = {"author": {"name": "🐦‍⬛ Huginn: fresh malware hunt"},
             "title": "Fresh hunt complete", "color": _RED if confirmed else _GREEN,
             "fields": fields[:25], "footer": {"text": "Static analysis only, nothing executed"}}
    if run_url.startswith("https://github.com/"):
        embed["url"] = run_url
    embeds = [embed] + [package_embed(r) for r in confirmed[:9]]
    return [{"allowed_mentions": {"parse": []}, "embeds": embeds}]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--registries", default="npm,pypi")
    ap.add_argument("--hours", type=float, default=8.0, help="look back this far on the first run")
    ap.add_argument("--top", type=int, default=12, help="packages scanned per registry")
    ap.add_argument("--max-minutes", type=float, default=30.0)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--state", type=Path, default=Path(os.environ.get(
        "HUGINN_FRESH_STATE_DB", ".huginn-state/fresh.db")))
    ap.add_argument("--discord", choices=["never", "findings", "always"], default="findings")
    ap.add_argument("--run-url", default="")
    args = ap.parse_args(argv)

    from .scanner import PodmanScanner

    package_root = Path(__file__).resolve().parent
    scanner = PodmanScanner(
        rules_file=package_root / "rules" / "semgrep.yml",
        archive_script=package_root / "archive.py",
        unpack_image=os.environ.get("HUGINN_UNPACK_IMAGE", "docker.io/library/python:3.13-slim"),
    )
    if not scanner.analyzer_image:
        print("HUGINN_ANALYZER_IMAGE is not set; the fresh hunt needs the malware analyzer",
              file=sys.stderr)
        return 2
    state = StateDB(args.state)
    if not state.get_cursor("fresh.started"):
        state.set_cursor("fresh.started", _utc_now())
    run = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    args.out.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + args.max_minutes * 60

    summaries, all_rows, manifest, recalls, recall_rows = [], [], [], {}, []
    for registry in [r.strip() for r in args.registries.split(",") if r.strip()]:
        try:
            summary, rows, entries = hunt_registry(
                registry, hours=args.hours, top=args.top, state=state, scanner=scanner,
                run=run, workdir=args.out, deadline=deadline)
        except Exception as exc:          # one registry down must not lose the other
            log(f"{registry}: hunt failed: {type(exc).__name__}: {exc}")
            summary, rows, entries = {"registry": registry, "error": f"{type(exc).__name__}: {exc}"[:300],
                                      "new_packages": 0, "selected": 0, "scanned": 0, "failed": 0,
                                      "removed_or_skipped": 0, "confirmed": 0, "suspicious": 0}, [], []
        summaries.append(summary)
        all_rows += rows
        manifest += entries
        try:
            recalls[registry], rrows = measure_recall(registry, state)
            recall_rows += [dict(r, registry=registry) for r in rrows]
        except Exception as exc:
            log(f"{registry}: recall unavailable: {type(exc).__name__}: {exc}")
        log(f"{registry}: {json.dumps(summary)} recall {json.dumps(recalls.get(registry, {}))}")

    write_csv(args.out / "malicious_findings.csv", MALWARE_COLUMNS, all_rows)
    write_csv(args.out / "fresh_manifest.csv", MANIFEST_COLUMNS, manifest)
    write_csv(args.out / "recall.csv", ["registry", "id", "name", "outcome", "triage_score", "triage_reasons"],
              recall_rows)
    (args.out / "fresh_summary.json").write_text(json.dumps(
        {"run": run, "registries": summaries, "recall": recalls}, indent=2) + "\n", encoding="utf-8")

    webhook = os.environ.get("DISCORD_WEBHOOK", "").strip()
    found = any(r.get("verdict") == "CONFIRMED" for r in all_rows)
    if webhook and (args.discord == "always" or (args.discord == "findings" and found)):
        from .discord import post
        for body in discord_messages(summaries, recalls, all_rows, args.run_url):
            post(webhook, body)
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
