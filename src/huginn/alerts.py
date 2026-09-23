from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Iterable


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def make_alert(
    *,
    run_id: str,
    registry: str,
    stage: str,
    alert_type: str,
    source: str,
    message: str,
    severity: str = "MEDIUM",
    package_name: str = "",
    package_version: str = "",
    endpoint: str = "",
    error_type: str = "",
    retryable: bool = True,
    coverage_impact: str = "PARTIAL",
    affected_findings: int = 0,
    recommended_action: str = "Review and retry before treating the hunt as complete.",
) -> dict[str, str]:
    material = "".join([
        run_id, registry, package_name, package_version, stage, alert_type, source, message
    ]).encode("utf-8", "replace")
    alert_id = hashlib.sha256(material).hexdigest()[:20]
    return {
        "run_id": run_id,
        "detected_at_utc": utc_now(),
        "alert_id": alert_id,
        "severity": severity,
        "registry": registry,
        "package_name": package_name,
        "package_version": package_version,
        "stage": stage,
        "alert_type": alert_type,
        "source": source,
        "endpoint": endpoint,
        "message": message[:2000],
        "error_type": error_type,
        "retryable": str(bool(retryable)).lower(),
        "coverage_impact": coverage_impact,
        "affected_findings": str(affected_findings),
        "recommended_action": recommended_action,
        "status": "OPEN",
    }


def alerts_from_manifests(run_id: str, manifests: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    alerts: list[dict[str, str]] = []
    for row in manifests:
        if row.get("scan_status") != "FAILED":
            continue
        error = row.get("error", "")
        stage = row.get("failure_stage", "") or "package_capture"
        alerts.append(
            make_alert(
                run_id=run_id,
                registry=row.get("registry", ""),
                package_name=row.get("package_name", ""),
                package_version=row.get("package_version", ""),
                stage=stage,
                alert_type="PACKAGE_COVERAGE_FAILURE",
                source="huginn_capture",
                message=error or "Package capture failed.",
                error_type=(error.split(":", 1)[0] if ":" in error else ""),
                severity="HIGH",
                retryable=True,
                coverage_impact="PACKAGE_NOT_ANALYZED",
                recommended_action="Retry the package capture and inspect scan_manifest.csv before closing the hunt.",
            )
        )
    return alerts


def alerts_from_findings(run_id: str, rows: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    alerts: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    for row in rows:
        registry = row.get("registry", "")
        package = row.get("package_name", "")
        version = row.get("package_version", "")

        source_statuses = {
            "osv": row.get("osv_status", ""),
            "ghsa": row.get("ghsa_status", ""),
            "nvd": row.get("nvd_status", ""),
            "redhat": row.get("redhat_status", ""),
        }
        for source, status in source_statuses.items():
            if status != "ERROR":
                continue
            key = (registry, package, version, "advisory", source)
            if key in seen:
                continue
            seen.add(key)
            alerts.append(
                make_alert(
                    run_id=run_id,
                    registry=registry,
                    package_name=package,
                    package_version=version,
                    stage="advisory_enrichment",
                    alert_type="ADVISORY_API_RETRIEVAL_FAILURE",
                    source=source,
                    message=row.get("enrichment_error", "") or f"{source} advisory lookup failed.",
                    severity="HIGH",
                    retryable=True,
                    coverage_impact="ADVISORY_DEDUP_INCOMPLETE",
                    affected_findings=1,
                    recommended_action=f"Retry {source} enrichment before concluding the finding is novel.",
                )
            )

        if row.get("previous_compare_status") == "FAILED":
            key = (registry, package, version, "previous_compare", "")
            if key not in seen:
                seen.add(key)
                alerts.append(
                    make_alert(
                        run_id=run_id,
                        registry=registry,
                        package_name=package,
                        package_version=version,
                        stage="previous_version_compare",
                        alert_type="VERSION_COMPARISON_FAILURE",
                        source="registry_previous_version",
                        message=row.get("previous_compare_error", "") or "Previous-version comparison failed.",
                        severity="MEDIUM",
                        retryable=True,
                        coverage_impact="NOVELTY_CONFIDENCE_REDUCED",
                        affected_findings=1,
                        recommended_action="Retry previous-version comparison before escalating novelty confidence.",
                    )
                )

    return alerts
