"""Actions minutes Huginn used in the last 7 days, against HUGINN_WEEKLY_MINUTES.

    GH_TOKEN=... GITHUB_REPOSITORY=o/r python3 scripts/actions_budget.py --planned 15

Counts every job of every run created in the last 7 days (Dependabot's "dynamic"
runs are not billed), each rounded up to the minute the way Actions bills it. Writes
`ok`, `used` and `remaining` to GITHUB_OUTPUT: ok is false when the planned run would
take the week past the budget, unless IGNORE_BUDGET=true. Never fails the job itself.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import urllib.request
from datetime import UTC, datetime, timedelta


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def job_minutes(jobs: list[dict], now: datetime) -> int:
    used = 0
    for job in jobs:
        if not job.get("started_at") or job.get("conclusion") == "skipped":
            continue
        end = _ts(job["completed_at"]) if job.get("completed_at") else now
        seconds = (end - _ts(job["started_at"])).total_seconds()
        if seconds > 0:
            used += max(1, math.ceil(seconds / 60))
    return used


def minutes_used(get, repo: str, now: datetime) -> int:
    since = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    used, page = 0, 1
    while True:
        runs = get(f"/repos/{repo}/actions/runs?created=%3E%3D{since}&per_page=100&page={page}")["workflow_runs"]
        for run in runs:
            if run.get("event") == "dynamic":
                continue
            used += job_minutes(get(f"/repos/{repo}/actions/runs/{run['id']}/jobs?filter=all&per_page=100")["jobs"], now)
        if len(runs) < 100:
            return used
        page += 1


def decide(used: int, budget: int, planned: int, ignore: bool) -> tuple[bool, str]:
    remaining = budget - used
    if remaining >= planned:
        return True, f"OK: {remaining} of {budget} minutes left, this run plans {planned}"
    if ignore:
        return True, f"BYPASSED by ignore_budget: {remaining} of {budget} minutes left"
    return False, f"SKIPPED: {remaining} of {budget} minutes left, this run plans {planned}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--planned", type=int, required=True, help="minutes this run is expected to use")
    args = ap.parse_args(argv)
    api, token = os.environ.get("GITHUB_API_URL", "https://api.github.com"), os.environ["GH_TOKEN"]

    def get(path: str) -> dict:
        req = urllib.request.Request(f"{api}{path}", headers={
            "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)

    budget = int(os.environ.get("BUDGET") or 500)
    try:
        used = minutes_used(get, os.environ["GITHUB_REPOSITORY"], datetime.now(UTC))
    except Exception as exc:              # never block a hunt on a reporting failure
        used = 0
        print(f"::warning::could not measure Actions usage: {type(exc).__name__}: {exc}")
    ok, line = decide(used, budget, args.planned, os.environ.get("IGNORE_BUDGET") == "true")
    print(f"Minutes used in the last 7 days: {used}\nBudget check: {line}")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
            out.write(f"ok={'true' if ok else 'false'}\nused={used}\nremaining={budget - used}\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
            out.write(f"### Actions budget\n\n- Used in the last 7 days: {used} of {budget}\n- {line}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
