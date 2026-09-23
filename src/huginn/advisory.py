from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import Any

from .models import Artifact, ReleaseCandidate
from .reporting import REVIEW_COLUMNS


USER_AGENT = "Huginn/0.2 (+https://github.com/OpenSource-For-Freedom/Huginn)"


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _request_json(url: str, *, data: dict | None = None, headers: dict[str, str] | None = None, timeout: int = 25) -> Any:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _ecosystem(registry: str) -> str:
    return {"pypi": "PyPI", "rubygems": "RubyGems", "npm": "npm"}[registry]


def _github_ecosystem(registry: str) -> str:
    return {"pypi": "pip", "rubygems": "rubygems", "npm": "npm"}[registry]


def _ids(record: dict[str, Any]) -> set[str]:
    values = {str(record.get("id") or ""), str(record.get("cve_id") or ""), str(record.get("ghsa_id") or "")}
    values.update(str(x) for x in (record.get("aliases") or []))
    return {v for v in values if v}


def _record(source: str, *, primary: str, aliases: list[str] | None = None, url: str = "",
            summary: str = "", severity: str = "", cwe: list[str] | None = None, exact: bool = False) -> dict[str, Any]:
    return {
        "source": source,
        "id": primary,
        "aliases": sorted(set(aliases or [])),
        "url": url,
        "summary": summary,
        "severity": severity.upper(),
        "cwe": sorted(set(cwe or [])),
        "exact_package_version": exact,
    }


def query_osv(candidate: ReleaseCandidate) -> list[dict[str, Any]]:
    payload = _request_json(
        "https://api.osv.dev/v1/query",
        data={"package": {"name": candidate.name, "ecosystem": _ecosystem(candidate.registry)}, "version": candidate.version},
    )
    records = []
    for vuln in payload.get("vulns") or []:
        aliases = [str(x) for x in vuln.get("aliases") or []]
        refs = vuln.get("references") or []
        url = next((str(x.get("url")) for x in refs if x.get("url")), "")
        cwes = []
        db = vuln.get("database_specific") or {}
        cwes.extend(str(x) for x in db.get("cwe_ids") or [])
        severity = str(db.get("severity") or "")
        records.append(_record(
            "osv", primary=str(vuln.get("id") or ""), aliases=aliases, url=url,
            summary=str(vuln.get("summary") or ""), severity=severity, cwe=cwes, exact=True,
        ))
    return records


def query_ghsa(candidate: ReleaseCandidate) -> list[dict[str, Any]]:
    params = urllib.parse.urlencode({
        "ecosystem": _github_ecosystem(candidate.registry),
        "affects": f"{candidate.name}@{candidate.version}",
        "per_page": 100,
    })
    headers = {"X-GitHub-Api-Version": "2022-11-28", "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = _request_json(f"https://api.github.com/advisories?{params}", headers=headers)
    records = []
    for adv in payload or []:
        aliases = [x for x in [str(adv.get("cve_id") or "")] if x]
        cwes = [str(x.get("cwe_id")) for x in adv.get("cwes") or [] if x.get("cwe_id")]
        records.append(_record(
            "ghsa", primary=str(adv.get("ghsa_id") or adv.get("cve_id") or ""), aliases=aliases,
            url=str(adv.get("html_url") or ""), summary=str(adv.get("summary") or ""),
            severity=str(adv.get("severity") or ""), cwe=cwes, exact=True,
        ))
    return records


def query_nvd(candidate: ReleaseCandidate, cve_ids: set[str]) -> list[dict[str, Any]]:
    headers = {}
    key = os.environ.get("NVD_API_KEY", "").strip()
    if key:
        headers["apiKey"] = key
    urls: list[tuple[str, bool]] = []
    if cve_ids:
        for cve in sorted(cve_ids)[:20]:
            urls.append(("https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({"cveId": cve}), True))
    else:
        urls.append(("https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({
            "keywordSearch": candidate.name, "resultsPerPage": 20
        }), False))
    records = []
    for url, exact_id in urls:
        payload = _request_json(url, headers=headers)
        for item in payload.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            cve_id = str(cve.get("id") or "")
            descriptions = cve.get("descriptions") or []
            summary = next((str(d.get("value")) for d in descriptions if d.get("lang") == "en"), "")
            refs = cve.get("references") or []
            ref = next((str(r.get("url")) for r in refs if r.get("url")), "")
            cwes = []
            for weakness in cve.get("weaknesses") or []:
                for desc in weakness.get("description") or []:
                    value = str(desc.get("value") or "")
                    if value.startswith("CWE-"):
                        cwes.append(value)
            records.append(_record(
                "nvd", primary=cve_id, url=ref or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                summary=summary, cwe=cwes, exact=exact_id,
            ))
    return records


def query_redhat(candidate: ReleaseCandidate, cve_ids: set[str]) -> list[dict[str, Any]]:
    base = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
    params: list[tuple[dict[str, Any], bool]] = []
    if cve_ids:
        params.append(({"ids": ",".join(sorted(cve_ids)[:20]), "per_page": 100}, True))
    else:
        params.append(({"package": candidate.name, "per_page": 50}, False))
    records = []
    for query, exact_id in params:
        payload = _request_json(base + "?" + urllib.parse.urlencode(query))
        for cve in payload or []:
            cve_id = str(cve.get("CVE") or cve.get("name") or "")
            records.append(_record(
                "redhat", primary=cve_id,
                url=str(cve.get("resource_url") or (f"https://access.redhat.com/security/cve/{cve_id}" if cve_id else "")),
                summary=str(cve.get("bugzilla_description") or ""),
                severity=str(cve.get("severity") or ""), cwe=[str(cve.get("CWE") or "")] if cve.get("CWE") else [],
                exact=exact_id,
            ))
    return records


def collect(candidate: ReleaseCandidate) -> dict[str, Any]:
    checked = _now()
    records: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    for source, func in (("osv", query_osv), ("ghsa", query_ghsa)):
        try:
            records.extend(func(candidate))
        except Exception as exc:
            errors[source] = f"{type(exc).__name__}: {exc}"[:500]

    cve_ids: set[str] = set()
    for record in records:
        for ident in _ids(record):
            if ident.startswith("CVE-"):
                cve_ids.add(ident)

    for source, func in (("nvd", query_nvd), ("redhat", query_redhat)):
        try:
            records.extend(func(candidate, cve_ids))
        except Exception as exc:
            errors[source] = f"{type(exc).__name__}: {exc}"[:500]

    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        key = (str(record.get("source")), str(record.get("id")))
        if key[1]:
            unique[key] = record
    return {"checked_at": checked, "records": list(unique.values()), "errors": errors}


def enrich_rows(rows: list[dict[str, str]], bundle: dict[str, Any]) -> list[dict[str, str]]:
    records = bundle.get("records") or []
    checked = str(bundle.get("checked_at") or "")
    all_ids: set[str] = set()
    exact_ids: set[str] = set()
    sources: set[str] = set()
    for record in records:
        ids = _ids(record)
        all_ids.update(ids)
        if record.get("exact_package_version"):
            exact_ids.update(ids)
        sources.add(str(record.get("source") or ""))

    for row in rows:
        current = str(row.get("vulnerability_id") or "")
        if current and current in all_ids:
            row["dedup_status"] = "KNOWN_EXACT"
            row["novelty_state"] = "known"
        elif exact_ids:
            row["dedup_status"] = "POSSIBLE_MATCH"
            row["novelty_state"] = "possible_match"
        elif records:
            row["dedup_status"] = "POSSIBLE_MATCH"
            row["novelty_state"] = "possible_match"
        elif bundle.get("errors"):
            row["dedup_status"] = "LOOKUP_FAILED"
        else:
            row["dedup_status"] = "NO_MATCH"
            row["novelty_state"] = "novel"
        row["dedup_sources"] = ";".join(sorted(s for s in sources if s))
        row["dedup_identifiers"] = ";".join(sorted(all_ids))
        row["dedup_checked_at_utc"] = checked
    return rows


def advisory_rows(bundle: dict[str, Any], *, run_id: str, run_started: str, candidate: ReleaseCandidate,
                  artifact: Artifact, sha256: str, first_seen: str) -> list[dict[str, str]]:
    rows = []
    seen: set[str] = set()
    for record in bundle.get("records") or []:
        ids = _ids(record)
        cve = next((x for x in sorted(ids) if x.startswith("CVE-")), "")
        canonical = cve or str(record.get("id") or "")
        if not canonical or canonical in seen or not record.get("exact_package_version"):
            continue
        seen.add(canonical)
        row = {column: "" for column in REVIEW_COLUMNS}
        row.update({
            "run_id": run_id,
            "run_started_at_utc": run_started,
            "finding_fingerprint": hashlib.sha256(
                f"{candidate.registry}\x1f{candidate.name}\x1f{candidate.version}\x1f{canonical}".encode()
            ).hexdigest(),
            "finding_id": hashlib.sha256(
                f"{candidate.registry}\x1f{candidate.name}\x1f{candidate.version}\x1f{canonical}".encode()
            ).hexdigest()[:20],
            "triage_priority": "P4",
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
            "scanner": "advisory-enrichment",
            "scanner_version": "1",
            "rule_id": canonical,
            "finding_class": "known_package_advisory",
            "vulnerability_id": canonical,
            "advisory_source": str(record.get("source") or ""),
            "advisory_url": str(record.get("url") or ""),
            "severity": str(record.get("severity") or "UNKNOWN"),
            "confidence": "HIGH",
            "novelty_state": "known",
            "cwe": ";".join(record.get("cwe") or []),
            "title": str(record.get("summary") or canonical),
            "message": "Exact package/version advisory match returned by public advisory source.",
            "evidence": f"exact affected package/version: {candidate.name}@{candidate.version}",
            "source": str(record.get("source") or ""),
            "sink": canonical,
            "known_dependency": "false",
            "suspicious_package": "false",
            "dedup_status": "KNOWN_EXACT",
            "dedup_sources": str(record.get("source") or ""),
            "dedup_identifiers": ";".join(sorted(ids)),
            "dedup_checked_at_utc": str(bundle.get("checked_at") or ""),
            "review_status": "PENDING",
            "disclosure_status": "NOT_READY",
        })
        rows.append(row)
    return rows
