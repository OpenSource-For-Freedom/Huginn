"""Conservative, offline quality checks for captured report metadata.

This module does not scan packages, infer exploitability, or approve disclosures.
Original scanner fields remain available beside the qualified report labels.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

QUALITY_COLUMNS = [
    "finding_fingerprint", "registry", "package_name", "package_version",
    "review_group", "group_alert_count", "advisory_coverage", "unchecked_sources",
    "reported_novelty", "version_order", "reported_version_delta",
    "score_meaning", "report_status", "quality_flags",
]
SOURCES = ("osv", "ghsa", "nvd", "redhat")


def version_order(row: dict[str, str]) -> str:
    """Only compare unambiguous numeric releases; never guess prerelease order."""
    current, previous = row.get("package_version", ""), row.get("previous_version", "")
    if not previous:
        return "NO_BASELINE"
    if not all(re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*", v)
               for v in (current, previous)):
        return "UNVERIFIED"
    a, b = [int(p) for p in current.split(".")], [int(p) for p in previous.split(".")]
    width = max(len(a), len(b))
    a += [0] * (width - len(a))
    b += [0] * (width - len(b))
    return "OLDER_BASELINE" if b < a else "INVALID_BASELINE"


def audit_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    results = []
    for index, row in enumerate(rows):
        flags = []
        unchecked = [s for s in SOURCES if row.get(s + "_status", "").upper()
                     not in {"NO_MATCH", "MATCH"}]
        coverage = "INCOMPLETE" if unchecked else "CHECKED_SOURCES_ONLY"
        known = row.get("dedup_status") == "KNOWN_EXACT"
        novelty = "KNOWN_ADVISORY_MATCH" if known else "UNCONFIRMED"
        if row.get("novelty_state", "").lower() == "novel":
            flags.append("NOVELTY_NOT_ESTABLISHED")
        if unchecked:
            flags.append("ADVISORY_COVERAGE_INCOMPLETE")
        order = version_order(row)
        delta = row.get("version_delta", "") or "UNKNOWN"
        if order != "OLDER_BASELINE" or row.get("previous_compare_status") != "COMPLETE":
            if delta != "UNKNOWN":
                flags.append("VERSION_DELTA_UNVERIFIED")
            delta = "UNKNOWN"
        # Group only identical locations within the same exact artifact and class.
        # A group indicates overlapping alerts, not a confirmed shared root cause.
        keys = ("registry", "package_name", "package_version", "artifact_sha256",
                "file_path", "start_line", "end_line", "finding_class")
        parts = [row.get(k, "") for k in keys]
        located = all(parts) and all(re.fullmatch(r"[1-9][0-9]*", row.get(k, ""))
                                     for k in ("start_line", "end_line"))
        located = located and int(row["end_line"]) >= int(row["start_line"])
        if not located:
            parts += [row.get("finding_fingerprint", ""), str(index)]
        group = hashlib.sha256(json.dumps(parts).encode()).hexdigest()[:24]
        score = row.get("cvss_score", "")
        vector = row.get("cvss_vector", "")
        if score and vector.startswith("CVSS:3."):
            try:
                number = float(score)
                expected = ("CRITICAL" if number >= 9 else "HIGH" if number >= 7
                            else "MEDIUM" if number >= 4 else "LOW" if number > 0 else "NONE")
                if not 0 <= number <= 10:
                    flags.append("CVSS_SCORE_INVALID")
                elif expected != row.get("severity", "").upper():
                    flags.append("SEVERITY_SCORE_DISAGREEMENT")
            except ValueError:
                flags.append("CVSS_SCORE_INVALID")
        results.append({
            **{k: row.get(k, "") for k in QUALITY_COLUMNS[:4]},
            "review_group": group, "group_alert_count": "1",
            "advisory_coverage": coverage, "unchecked_sources": ";".join(unchecked),
            "reported_novelty": novelty, "version_order": order,
            "reported_version_delta": delta, "score_meaning": "AUTOMATED_RANK_NOT_CONFIRMATION",
            "report_status": "DEPENDENCY_APPLICABILITY_REVIEW" if known else "MANUAL_REVIEW_REQUIRED",
            "quality_flags": ";".join(flags),
        })
    counts = Counter(r["review_group"] for r in results)
    for result in results:
        result["group_alert_count"] = str(counts[result["review_group"]])
    return results


def write_quality_report(root: Path, rows: list[dict[str, str]]) -> None:
    from .reporting import write_csv

    audited = audit_rows(rows)
    write_csv(root / "report_quality.csv", QUALITY_COLUMNS, audited)
    summary = {
        "raw_alert_count": len(rows),
        "review_location_group_count": len({r["review_group"] for r in audited}),
        "incomplete_advisory_checks": sum(r["advisory_coverage"] == "INCOMPLETE" for r in audited),
        "unverified_version_deltas": sum("VERSION_DELTA_UNVERIFIED" in r["quality_flags"] for r in audited),
        "automatically_approved_reports": 0,
        "note": "Groups are overlapping alerts, not confirmed vulnerabilities. Raw scanner claims remain unverified.",
    }
    (root / "report_quality_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
