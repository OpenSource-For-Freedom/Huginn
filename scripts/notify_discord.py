"""Post a merged hunt (scripts/merge_hunt_reports.py output) to Discord.

    DISCORD_WEBHOOK=... python3 scripts/notify_discord.py hunt-summary [--run-url URL]

No-op without DISCORD_WEBHOOK. Never fails the job: a Discord outage only
prints a warning.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from huginn.discord import build_messages, post


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("summary_root", type=Path)
    ap.add_argument("--run-url", default="")
    args = ap.parse_args(argv)
    webhook = os.environ.get("DISCORD_WEBHOOK", "").strip()
    if not webhook:
        print("DISCORD_WEBHOOK not set; skipping the Discord report")
        return 0
    summary_path = args.summary_root / "matrix_summary.json"
    if not summary_path.is_file():
        print(f"::warning::no {summary_path}; nothing to report")
        return 0
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    rows: list[dict] = []
    malware_csv = args.summary_root / "malicious_findings.csv"
    if malware_csv.is_file():
        with malware_csv.open(encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
    messages = build_messages(summary, rows, run_url=args.run_url)
    sent = sum(post(webhook, body) for body in messages)
    if sent < len(messages):
        print(f"::warning::Discord report: {sent} of {len(messages)} message(s) posted")
    else:
        print(f"Discord report posted ({sent} message(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
