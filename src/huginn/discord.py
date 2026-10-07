"""Post a finished hunt to Discord, alongside Warden and Knorr reports.

One message per hunt: a summary card (packages scanned per registry, CVE
review counts, malware verdicts, coverage problems) and one card per
CONFIRMED malicious package.

CVE candidates are counts only. They are unpatched, undisclosed
vulnerabilities, so package names stay in the private review packet. Malware
is named, as Warden and Knorr do: warning people off it is the point.
"""

from __future__ import annotations

import json
import re
import urllib.request
from typing import Any, Callable

from .discovery import USER_AGENT

_REGISTRY_URL: dict[str, Callable[[str, str], str]] = {
    "npm": lambda n, v: f"https://www.npmjs.com/package/{n}/v/{v}",
    "pypi": lambda n, v: f"https://pypi.org/project/{n}/{v}/",
    "rubygems": lambda n, v: f"https://rubygems.org/gems/{n}/versions/{v}",
    "crates": lambda n, v: f"https://crates.io/crates/{n}/{v}",
    "packagist": lambda n, v: f"https://packagist.org/packages/{n}#{v}",
    "go": lambda n, v: f"https://pkg.go.dev/{n}@{v}",
}
_RED, _ORANGE, _GREEN = 0xE74C3C, 0xE67E22, 0x22AA66
_MAX_PACKAGE_CARDS = 27  # three messages of ten embeds, summary included
_SAFE_URL = re.compile(r"^https://[\w.-]+/[\w@%./:#+~=-]*$")


def _safe(value: Any, limit: int = 1024) -> str:
    """Plain text for an embed: no pings, no code-fence or link breakout."""
    text = str(value or "").replace("@", "@​").replace("`", "'")
    text = re.sub(r"[\r\n]+", " ", text) if limit <= 256 else text
    return text[:limit]


def _n(summary: dict, key: str) -> int:
    try:
        return int(summary.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def summary_embed(summary: dict, *, run_url: str = "") -> dict:
    runs = summary.get("ecosystem_runs") or []
    per_registry = " · ".join(
        f"{_safe(r.get('registry'), 40)} {_n(r, 'package_scan_count')}" for r in runs
    ) or "none"
    scanned = _n(summary, "package_scan_count")
    failed = _n(summary, "failed_package_scans")
    confirmed = _n(summary, "malware_confirmed_count")
    critical = _n(summary, "critical_coverage_alert_count")
    high = _n(summary, "high_coverage_alert_count")
    gaps = failed or critical or high
    color = _RED if confirmed else (_ORANGE if gaps else _GREEN)
    title = "Huginn hunt complete" + (" (coverage gaps)" if gaps else "")
    malware = (f"{confirmed} confirmed · {_n(summary, 'malware_new_risk_count')} new risk "
               + (f"· {_n(summary, 'malware_suspicious_count')} suspicious (no egress) "
                  if _n(summary, "malware_suspicious_count") else "")
               + f"· {_n(summary, 'malware_scanned_count')} analyzed")
    if not _n(summary, "malware_scanned_count") and scanned:
        malware += " (analyzer not configured)"
    embed = {
        "author": {"name": "🐦‍⬛ Huginn: package registry hunt"},
        "title": title,
        "color": color,
        "fields": [
            {"name": "Packages scanned", "value": f"{scanned} ({per_registry})"[:1024], "inline": False},
            {"name": "CVE review", "value": (
                f"{_n(summary, 'novel_no_match_count')} novel findings · "
                f"{_n(summary, 'high_value_manual_candidate_count')} high-value candidates "
                "(details in the private review packet)"), "inline": False},
            {"name": "Malicious packages", "value": malware, "inline": False},
            {"name": "Coverage", "value": (
                f"{failed} failed · {_n(summary, 'skipped_package_scans')} skipped · "
                f"{critical} critical / {high} high alerts"), "inline": False},
        ],
        "footer": {"text": "Huginn · static analysis only, nothing executed"},
    }
    if run_url and _SAFE_URL.match(run_url):
        embed["url"] = run_url
    return embed


def package_embed(row: dict) -> dict:
    registry, name, version = (row.get("registry", ""), row.get("package_name", ""),
                               row.get("package_version", ""))
    link = _REGISTRY_URL.get(registry, lambda n, v: "")(name, version)
    fields = [
        {"name": "Family", "value": _safe(row.get("families") or "unattributed"), "inline": True},
        {"name": "Confidence", "value": _safe(row.get("confidence") or "n/a"), "inline": True},
        {"name": "Rules", "value": _safe(row.get("confirming_rules") or "n/a"), "inline": False},
        {"name": "Where (file:line)", "value": _safe(row.get("confirming_locations") or "n/a"),
         "inline": False},
    ]
    if row.get("new_in_release"):
        fields.append({"name": f"New since {_safe(row.get('previous_version'), 64)}",
                       "value": _safe(row.get("new_in_release")), "inline": False})
    embed = {
        "author": {"name": "🐦‍⬛ Huginn: confirmed malicious package"},
        "title": _safe(f"{registry}: {name}@{version}", 256),
        "color": _RED,
        "fields": fields,
        "footer": {"text": "Pending analyst validation"},
    }
    if link and _SAFE_URL.match(link):
        embed["url"] = link
    return embed


def build_messages(summary: dict, malware_rows: list[dict], *, run_url: str = "") -> list[dict]:
    """Discord webhook bodies: the summary first, ten embeds per message."""
    confirmed = [r for r in malware_rows if r.get("verdict") == "CONFIRMED"]
    embeds = [summary_embed(summary, run_url=run_url)]
    embeds += [package_embed(r) for r in confirmed[:_MAX_PACKAGE_CARDS]]
    messages = []
    for i in range(0, len(embeds), 10):
        messages.append({"allowed_mentions": {"parse": []}, "embeds": embeds[i:i + 10]})
    extra = len(confirmed) - _MAX_PACKAGE_CARDS
    if extra > 0:
        messages[-1]["content"] = f"+{extra} more confirmed in malicious_findings.csv"
    return messages


def post(webhook: str, body: dict, *, opener=urllib.request.urlopen) -> bool:
    req = urllib.request.Request(
        webhook, data=json.dumps(body).encode("utf-8"),
        # Discord rejects urllib's default User-Agent with 403.
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with opener(req, timeout=20) as resp:
            return 200 <= getattr(resp, "status", 200) < 300
    except Exception:  # noqa: BLE001 - a failed post must not fail the hunt
        return False
