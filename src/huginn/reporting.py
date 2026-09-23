from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from .models import Artifact, ReleaseCandidate


REVIEW_COLUMNS = [
    "run_id", "run_started_at_utc", "finding_id", "finding_fingerprint", "triage_priority",
    "registry", "event_type", "package_name", "package_version", "purl", "published_at_utc", "first_seen_at_utc",
    "artifact_filename", "artifact_url", "artifact_sha256", "artifact_size_bytes", "registry_digest",
    "scanner", "scanner_version", "rule_id", "ruleset_hash", "finding_class", "vulnerability_id", "advisory_source",
    "advisory_url", "severity", "confidence", "novelty_state", "cvss_score", "cvss_vector", "cwe",
    "file_path", "start_line", "end_line", "dependency_ecosystem", "dependency_name", "installed_version", "fixed_version",
    "title", "message", "evidence", "source", "sink", "known_dependency", "suspicious_package",
    "dedup_status", "dedup_sources", "dedup_identifiers", "dedup_checked_at_utc",
    "dedup_match_basis", "enrichment_status", "enrichment_error",
    "osv_status", "osv_ids", "ghsa_status", "ghsa_ids", "nvd_status", "nvd_ids",
    "redhat_status", "redhat_ids", "advisory_cves", "advisory_cwes",
    "validation_kind", "source_to_sink", "validation_state", "validation_score", "validation_reasons",
    "reachability_state", "reachability_basis", "shipped_code_assessment", "analyst_queue",
    "previous_version", "previous_compare_status", "previous_compare_error", "previous_finding_present", "version_delta",
    "review_status", "reviewer", "reviewer_decision", "reviewer_notes", "reachability_verified",
    "security_boundary_verified", "affected_version_verified", "known_advisory_verified", "false_positive_reason",
    "verified_at_utc", "disclosure_status", "disclosure_reference",
]

MANIFEST_COLUMNS = [
    "run_id", "registry", "event_type", "package_name", "package_version", "purl", "published_at_utc", "first_seen_at_utc",
    "artifact_filename", "artifact_url", "artifact_sha256", "artifact_size_bytes", "registry_digest", "scan_status",
    "scan_started_at_utc", "scan_finished_at_utc", "trivy_exit_code", "semgrep_exit_code", "finding_count", "error",
]


def _flat(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return str(value).replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")


def _fingerprint(*parts: Any) -> str:
    payload = "\x1f".join(_flat(p) for p in parts).encode("utf-8", "replace")
    return hashlib.sha256(payload).hexdigest()


def _priority(severity: str, confidence: str, novelty: str) -> str:
    sev = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}.get(severity.upper(), 4)
    conf = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(confidence.upper(), 2)
    nov = {"novel": 0, "unreviewed": 1, "possible_match": 2, "known": 3}.get(novelty.lower(), 1)
    return f"P{min(4, 1 + sev + conf + nov)}"


def _base(run_id: str, run_started: str, candidate: ReleaseCandidate, artifact: Artifact, sha256: str, first_seen: str) -> dict[str, str]:
    return {
        "run_id": run_id,
        "run_started_at_utc": run_started,
        "registry": candidate.registry,
        "event_type": candidate.event_type,
        "package_name": candidate.name,
        "package_version": candidate.version,
        "purl": candidate.purl,
        "published_at_utc": candidate.published_at,
        "first_seen_at_utc": first_seen,
        "artifact_filename": artifact.filename,
        "artifact_url": artifact.url,
        "artifact_sha256": sha256,
        "artifact_size_bytes": str(artifact.size_bytes or ""),
        "registry_digest": artifact.registry_digest,
        "review_status": "PENDING",
        "reviewer": "",
        "reviewer_decision": "",
        "reviewer_notes": "",
        "reachability_verified": "",
        "security_boundary_verified": "",
        "affected_version_verified": "",
        "known_advisory_verified": "",
        "false_positive_reason": "",
        "verified_at_utc": "",
        "validation_kind": "",
        "source_to_sink": "",
        "validation_state": "UNVALIDATED",
        "validation_score": "0",
        "validation_reasons": "",
        "reachability_state": "UNKNOWN",
        "reachability_basis": "",
        "shipped_code_assessment": "UNKNOWN",
        "analyst_queue": "UNCLASSIFIED",
        "previous_version": "",
        "previous_compare_status": "NOT_RUN",
        "previous_compare_error": "",
        "previous_finding_present": "",
        "version_delta": "UNKNOWN",
        "disclosure_status": "NOT_READY",
        "disclosure_reference": "",
    }


def normalize_trivy(payload: dict[str, Any], *, run_id: str, run_started: str, candidate: ReleaseCandidate,
                    artifact: Artifact, sha256: str, first_seen: str, scanner_version: str = "") -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for result in payload.get("Results") or []:
        target = _flat(result.get("Target"))
        result_type = _flat(result.get("Type")).lower()
        dependency_ecosystem = {
            "npm": "npm",
            "yarn": "npm",
            "pnpm": "npm",
            "pip": "pypi",
            "pipenv": "pypi",
            "poetry": "pypi",
            "python-pkg": "pypi",
            "bundler": "rubygems",
            "gemspec": "rubygems",
        }.get(result_type, "")
        for vuln in result.get("Vulnerabilities") or []:
            vuln_id = _flat(vuln.get("VulnerabilityID"))
            severity = _flat(vuln.get("Severity") or "UNKNOWN")
            cvss_score = ""
            cvss_vector = ""
            cvss = vuln.get("CVSS") or {}
            for source in ("nvd", "redhat"):
                item = cvss.get(source) or {}
                if item:
                    cvss_score = _flat(item.get("V3Score") or item.get("V2Score"))
                    cvss_vector = _flat(item.get("V3Vector") or item.get("V2Vector"))
                    break
            row = _base(run_id, run_started, candidate, artifact, sha256, first_seen)
            row.update({
                "scanner": "trivy",
                "scanner_version": scanner_version or _flat(payload.get("SchemaVersion")),
                "rule_id": vuln_id,
                "ruleset_hash": "",
                "finding_class": "known_dependency_vulnerability",
                "vulnerability_id": vuln_id,
                "advisory_source": "Trivy advisory database",
                "advisory_url": _flat(vuln.get("PrimaryURL")),
                "severity": severity,
                "confidence": "HIGH",
                "novelty_state": "known",
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "cwe": _flat(vuln.get("CweIDs") or []),
                "file_path": target,
                "start_line": "",
                "end_line": "",
                "dependency_ecosystem": dependency_ecosystem,
                "dependency_name": _flat(vuln.get("PkgName")),
                "installed_version": _flat(vuln.get("InstalledVersion")),
                "fixed_version": _flat(vuln.get("FixedVersion")),
                "title": _flat(vuln.get("Title")),
                "message": _flat(vuln.get("Description")),
                "evidence": _flat({"pkg_id": vuln.get("PkgID"), "status": vuln.get("Status")}),
                "source": "dependency inventory",
                "sink": vuln_id,
                "known_dependency": "true",
                "suspicious_package": "false",
                "dedup_status": "KNOWN_EXACT",
                "dedup_sources": "trivy",
                "dedup_identifiers": vuln_id,
                "dedup_checked_at_utc": run_started,
            })
            fp = _fingerprint(candidate.registry, candidate.name, candidate.version, "trivy", vuln_id, target, vuln.get("PkgName"))
            row["finding_fingerprint"] = fp
            row["finding_id"] = fp[:20]
            row["triage_priority"] = _priority(severity, "HIGH", "known")
            rows.append(row)

        for mis in result.get("Misconfigurations") or []:
            severity = _flat(mis.get("Severity") or "UNKNOWN")
            rule = _flat(mis.get("ID"))
            row = _base(run_id, run_started, candidate, artifact, sha256, first_seen)
            row.update({
                "scanner": "trivy",
                "scanner_version": scanner_version,
                "rule_id": rule,
                "ruleset_hash": "",
                "finding_class": "misconfiguration",
                "vulnerability_id": "",
                "advisory_source": "",
                "advisory_url": _flat(mis.get("PrimaryURL")),
                "severity": severity,
                "confidence": "MEDIUM",
                "novelty_state": "unreviewed",
                "cvss_score": "",
                "cvss_vector": "",
                "cwe": "",
                "file_path": target,
                "start_line": _flat((mis.get("CauseMetadata") or {}).get("StartLine")),
                "end_line": _flat((mis.get("CauseMetadata") or {}).get("EndLine")),
                "dependency_ecosystem": "",
                "dependency_name": "",
                "installed_version": "",
                "fixed_version": "",
                "title": _flat(mis.get("Title")),
                "message": _flat(mis.get("Description") or mis.get("Message")),
                "evidence": _flat((mis.get("CauseMetadata") or {}).get("Code")),
                "source": "static configuration",
                "sink": rule,
                "known_dependency": "false",
                "suspicious_package": "false",
                "dedup_status": "NOT_CHECKED",
                "dedup_sources": "",
                "dedup_identifiers": "",
                "dedup_checked_at_utc": "",
            })
            fp = _fingerprint(candidate.registry, candidate.name, candidate.version, "trivy", rule, target, row["start_line"])
            row["finding_fingerprint"] = fp
            row["finding_id"] = fp[:20]
            row["triage_priority"] = _priority(severity, "MEDIUM", "unreviewed")
            rows.append(row)
    return [{col: _flat(row.get(col, "")) for col in REVIEW_COLUMNS} for row in rows]


def normalize_semgrep(payload: dict[str, Any], *, run_id: str, run_started: str, candidate: ReleaseCandidate,
                      artifact: Artifact, sha256: str, first_seen: str, scanner_version: str = "",
                      ruleset_hash: str = "") -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for finding in payload.get("results") or []:
        extra = finding.get("extra") or {}
        metadata = extra.get("metadata") or {}
        severity = _flat(extra.get("severity") or "WARNING").upper()
        severity = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW", "INVENTORY": "LOW"}.get(severity, severity)
        confidence = _flat(metadata.get("confidence") or metadata.get("huginn_confidence") or "MEDIUM").upper()
        start = finding.get("start") or {}
        end = finding.get("end") or {}
        rule = _flat(finding.get("check_id"))
        category = _flat(metadata.get("huginn_category") or metadata.get("category") or "static_pattern")
        suspicious = str(metadata.get("suspicious_package", False)).lower()
        validation_kind = _flat(metadata.get("huginn_validation") or "sink_only")
        source_to_sink = str(metadata.get("huginn_source_to_sink", False)).lower()
        row = _base(run_id, run_started, candidate, artifact, sha256, first_seen)
        row.update({
            "scanner": "semgrep",
            "scanner_version": scanner_version or _flat(payload.get("version")),
            "rule_id": rule,
            "ruleset_hash": ruleset_hash,
            "finding_class": category,
            "vulnerability_id": "",
            "advisory_source": "",
            "advisory_url": _flat(metadata.get("source") or metadata.get("references") or ""),
            "severity": severity,
            "confidence": confidence,
            "novelty_state": "unreviewed",
            "cvss_score": "",
            "cvss_vector": "",
            "cwe": _flat(metadata.get("cwe") or ""),
            "file_path": _flat(finding.get("path")),
            "start_line": _flat(start.get("line")),
            "end_line": _flat(end.get("line")),
            "dependency_ecosystem": "",
            "dependency_name": "",
            "installed_version": "",
            "fixed_version": "",
            "title": _flat(metadata.get("shortlink") or rule),
            "message": _flat(extra.get("message")),
            "evidence": _flat(extra.get("lines") or extra.get("metavars") or ""),
            "source": _flat(metadata.get("huginn_source") or "manual inspection required"),
            "sink": _flat(metadata.get("huginn_sink") or category),
            "known_dependency": "false",
            "suspicious_package": suspicious,
            "validation_kind": validation_kind,
            "source_to_sink": source_to_sink,
            "dedup_status": "NOT_CHECKED",
            "dedup_sources": "",
            "dedup_identifiers": "",
            "dedup_checked_at_utc": "",
        })
        fp = _fingerprint(candidate.registry, candidate.name, candidate.version, "semgrep", rule, row["file_path"], row["start_line"])
        row["finding_fingerprint"] = fp
        row["finding_id"] = fp[:20]
        row["triage_priority"] = _priority(severity, confidence, "unreviewed")
        rows.append(row)
    return [{col: _flat(row.get(col, "")) for col in REVIEW_COLUMNS} for row in rows]


def write_csv(path: Path, columns: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore", quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _flat(row.get(k, "")) for k in columns})
