from __future__ import annotations

from collections.abc import Iterable


NOISE_PATH_PARTS = {
    "test", "tests", "testing", "example", "examples", "demo", "demos",
    "docs", "doc", "fixtures", "fixture", "vendor", "generated", "dist",
}


def _path_noise(path: str) -> list[str]:
    normalized = path.replace("\\", "/").lower()
    parts = {part for part in normalized.split("/") if part}
    reasons: list[str] = []
    overlap = sorted(parts & NOISE_PATH_PARTS)
    if overlap:
        reasons.append("non_runtime_path:" + ",".join(overlap))
    if normalized.endswith((".min.js", ".map")):
        reasons.append("generated_or_minified")
    return reasons


def _int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def apply_validation(
    rows: list[dict[str, str]],
    *,
    previous_version: str = "",
    previous_keys: set[tuple[str, str]] | None = None,
    previous_compare_status: str = "NOT_RUN",
    previous_compare_error: str = "",
) -> list[dict[str, str]]:
    previous_keys = previous_keys or set()

    for row in rows:
        row["previous_compare_status"] = previous_compare_status
        row["previous_compare_error"] = previous_compare_error
        reasons: list[str] = []
        score = 0

        known = row.get("known_dependency", "").lower() == "true"
        suspicious = row.get("suspicious_package", "").lower() == "true"
        scanner = row.get("scanner", "")
        dedup = row.get("dedup_status", "")
        severity = row.get("severity", "").upper()
        confidence = row.get("confidence", "").upper()
        rule_id = row.get("rule_id", "")
        path = row.get("file_path", "")
        validation_kind = row.get("validation_kind", "") or "sink_only"
        source_to_sink = row.get("source_to_sink", "").lower() == "true"

        noise = _path_noise(path)
        reasons.extend(noise)

        if known and dedup == "KNOWN_EXACT":
            row["validation_state"] = "KNOWN"
            row["validation_score"] = "0"
            row["validation_reasons"] = "known_dependency_cve"
            row["reachability_state"] = "DEPENDENCY_CONTEXT"
            row["reachability_basis"] = "known dependency advisory"
            row["shipped_code_assessment"] = "DEPENDENCY"
            row["analyst_queue"] = "KNOWN"
            row["previous_version"] = previous_version
            row["previous_finding_present"] = ""
            row["version_delta"] = "NOT_APPLICABLE"
            continue

        if suspicious:
            row["validation_state"] = "SUSPICIOUS_PACKAGE"
            row["validation_score"] = "0"
            row["validation_reasons"] = "malware_or_reverse_shell_indicator"
            row["reachability_state"] = "STATIC_INDICATOR"
            row["reachability_basis"] = "suspicious-package rule"
            row["shipped_code_assessment"] = "REQUIRES_REVIEW"
            row["analyst_queue"] = "SUSPICIOUS"
            row["previous_version"] = previous_version
            row["previous_finding_present"] = ""
            row["version_delta"] = "UNKNOWN"
            continue

        if scanner == "semgrep":
            if validation_kind == "dataflow" or source_to_sink:
                score += 45
                reasons.append("static_source_to_sink")
                row["reachability_state"] = "STATIC_DATAFLOW"
                row["reachability_basis"] = "Semgrep taint/dataflow rule"
            else:
                score += 10
                reasons.append("sink_only_pattern")
                row["reachability_state"] = "SINK_ONLY"
                row["reachability_basis"] = "dangerous primitive without proven source"

            if severity == "CRITICAL":
                score += 25
            elif severity == "HIGH":
                score += 20
            elif severity == "MEDIUM":
                score += 10

            if confidence == "HIGH":
                score += 20
            elif confidence == "MEDIUM":
                score += 10

            if dedup == "NO_MATCH":
                score += 20
                reasons.append("no_package_version_advisory_match")
            elif dedup == "POSSIBLE_MATCH":
                score -= 5
                reasons.append("possible_existing_advisory")
            elif dedup == "LOOKUP_FAILED":
                score -= 10
                reasons.append("advisory_lookup_incomplete")

            key = (rule_id, path)
            row["previous_version"] = previous_version
            if previous_version:
                if key in previous_keys:
                    row["previous_finding_present"] = "true"
                    row["version_delta"] = "PRESENT_IN_PREVIOUS"
                    score -= 10
                    reasons.append("same_rule_path_in_previous_version")
                else:
                    row["previous_finding_present"] = "false"
                    row["version_delta"] = "INTRODUCED_OR_MOVED"
                    score += 15
                    reasons.append("absent_from_previous_rule_path")
            else:
                row["previous_finding_present"] = ""
                row["version_delta"] = "FIRST_RELEASE_OR_UNAVAILABLE"

            if noise:
                score -= 30
                row["shipped_code_assessment"] = "NOISE_LIKELY_PATH"
            else:
                row["shipped_code_assessment"] = "SHIPPED_ARTIFACT_PATH"

            score = max(0, min(100, score))

            if dedup == "POSSIBLE_MATCH":
                state = "NEEDS_DUPLICATE_REVIEW"
                queue = "POSSIBLE_MATCH"
            elif noise and score < 50:
                state = "NOISE_LIKELY"
                queue = "LOW_SIGNAL"
            elif score >= 70 and dedup == "NO_MATCH":
                state = "HIGH_VALUE_MANUAL_CANDIDATE"
                queue = "NOVEL_CANDIDATE"
            else:
                state = "NEEDS_REACHABILITY_REVIEW"
                queue = "MANUAL_REVIEW"

            row["validation_state"] = state
            row["validation_score"] = str(score)
            row["validation_reasons"] = ";".join(reasons)
            row["analyst_queue"] = queue
            continue

        # Non-Semgrep, non-known results remain manual unless explicitly classified.
        row["validation_state"] = "NEEDS_MANUAL_REVIEW"
        row["validation_score"] = str(score)
        row["validation_reasons"] = ";".join(reasons) or "non_semgrep_static_result"
        row["reachability_state"] = "UNKNOWN"
        row["reachability_basis"] = "manual inspection required"
        row["shipped_code_assessment"] = "REQUIRES_REVIEW"
        row["analyst_queue"] = "MANUAL_REVIEW"
        row["previous_version"] = previous_version
        row["previous_finding_present"] = ""
        row["version_delta"] = "UNKNOWN"

    return rows


def previous_finding_keys(rows: Iterable[dict[str, str]]) -> set[tuple[str, str]]:
    return {
        (row.get("rule_id", ""), row.get("file_path", ""))
        for row in rows
        if row.get("scanner") == "semgrep"
    }
