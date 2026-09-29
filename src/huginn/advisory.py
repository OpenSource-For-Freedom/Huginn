from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .discovery import USER_AGENT


OSV_API = "https://api.osv.dev/v1/query"
GHSA_API = "https://api.github.com/advisories"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REDHAT_API = "https://access.redhat.com/hydra/rest/securitydata/cve"

OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "rubygems": "RubyGems", "crates": "crates.io", "packagist": "Packagist", "go": "Go"}
GHSA_ECOSYSTEM = {"npm": "npm", "pypi": "pip", "rubygems": "rubygems", "crates": "rust", "packagist": "composer", "go": "go"}


@dataclass(slots=True)
class AdvisoryResult:
    status: str = "NO_MATCH"
    ids: set[str] = field(default_factory=set)
    cves: set[str] = field(default_factory=set)
    cwes: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    error: str = ""


class AdvisoryClient:
    def __init__(
        self,
        *,
        github_token: str | None = None,
        nvd_api_key: str | None = None,
        timeout: int = 30,
        retries: int = 3,
    ):
        self.github_token = github_token or os.environ.get("HUGINN_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        self.nvd_api_key = nvd_api_key or os.environ.get("NVD_API_KEY")
        self.timeout = timeout
        self.retries = retries
        self._package_cache: dict[tuple[str, str, str], tuple[AdvisoryResult, AdvisoryResult]] = {}
        self._nvd_cache: dict[str, AdvisoryResult] = {}
        self._redhat_cache: dict[str, AdvisoryResult] = {}
        self._last_request: dict[str, float] = {}

    def _paced(self, host: str) -> None:
        # Conservative unauthenticated pacing; authenticated APIs can tolerate this easily.
        minimum = 0.65 if host == "services.nvd.nist.gov" and not self.nvd_api_key else 0.10
        previous = self._last_request.get(host, 0.0)
        delay = minimum - (time.monotonic() - previous)
        if delay > 0:
            time.sleep(delay)
        self._last_request[host] = time.monotonic()

    def _request_json(
        self,
        url: str,
        *,
        method: str = "GET",
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        parsed = urllib.parse.urlparse(url)
        allowed = {
            "api.osv.dev",
            "api.github.com",
            "services.nvd.nist.gov",
            "access.redhat.com",
        }
        if parsed.scheme != "https" or parsed.hostname not in allowed:
            raise ValueError(f"advisory host is not allowed: {parsed.hostname}")

        payload = None if body is None else json.dumps(body).encode("utf-8")
        request_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        }
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        if headers:
            request_headers.update(headers)

        for attempt in range(self.retries + 1):
            self._paced(parsed.hostname or "")
            req = urllib.request.Request(url, data=payload, headers=request_headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    return json.loads(response.read())
            except urllib.error.HTTPError as exc:
                retryable = exc.code == 429 or 500 <= exc.code < 600
                if not retryable or attempt >= self.retries:
                    raise
                retry_after = exc.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    delay = min(30.0, float(retry_after))
                else:
                    delay = min(30.0, (2 ** attempt) + 0.25 * (attempt + 1))
                time.sleep(delay)
            except urllib.error.URLError:
                if attempt >= self.retries:
                    raise
                time.sleep(min(10.0, (2 ** attempt) + 0.25 * (attempt + 1)))
        raise RuntimeError("unreachable advisory retry state")

    @staticmethod
    def _collect_osv(payload: dict[str, Any]) -> AdvisoryResult:
        result = AdvisoryResult()
        vulns = payload.get("vulns") or []
        if vulns:
            result.status = "MATCH"
        for vuln in vulns:
            vuln_id = str(vuln.get("id") or "")
            if vuln_id:
                result.ids.add(vuln_id)
                if vuln_id.startswith("CVE-"):
                    result.cves.add(vuln_id)
            for alias in vuln.get("aliases") or []:
                alias = str(alias)
                result.ids.add(alias)
                if alias.startswith("CVE-"):
                    result.cves.add(alias)
            for reference in vuln.get("references") or []:
                url = str((reference or {}).get("url") or "")
                if url:
                    result.urls.add(url)
            database_specific = vuln.get("database_specific") or {}
            for cwe in database_specific.get("cwe_ids") or []:
                result.cwes.add(str(cwe).upper())
        return result

    @staticmethod
    def _collect_ghsa(payload: list[dict[str, Any]]) -> AdvisoryResult:
        result = AdvisoryResult()
        if payload:
            result.status = "MATCH"
        for advisory in payload:
            ghsa = str(advisory.get("ghsa_id") or "")
            cve = str(advisory.get("cve_id") or "")
            if ghsa:
                result.ids.add(ghsa)
            if cve:
                result.ids.add(cve)
                result.cves.add(cve)
            html_url = str(advisory.get("html_url") or "")
            if html_url:
                result.urls.add(html_url)
            for cwe in advisory.get("cwes") or []:
                cwe_id = str((cwe or {}).get("cwe_id") or "").upper()
                if cwe_id:
                    result.cwes.add(cwe_id)
        return result

    def query_osv(self, registry: str, package: str, version: str) -> AdvisoryResult:
        ecosystem = OSV_ECOSYSTEM[registry]
        try:
            payload = self._request_json(
                OSV_API,
                method="POST",
                body={"package": {"name": package, "ecosystem": ecosystem}, "version": version},
            )
            return self._collect_osv(payload)
        except Exception as exc:
            return AdvisoryResult(status="ERROR", error=f"{type(exc).__name__}: {exc}"[:500])

    def query_ghsa(self, registry: str, package: str, version: str) -> AdvisoryResult:
        ecosystem = GHSA_ECOSYSTEM[registry]
        query = urllib.parse.urlencode(
            {"ecosystem": ecosystem, "affects": f"{package}@{version}", "per_page": "100"}
        )
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        try:
            payload = self._request_json(f"{GHSA_API}?{query}", headers=headers)
            return self._collect_ghsa(payload if isinstance(payload, list) else [])
        except Exception as exc:
            return AdvisoryResult(status="ERROR", error=f"{type(exc).__name__}: {exc}"[:500])

    def query_package(self, registry: str, package: str, version: str) -> tuple[AdvisoryResult, AdvisoryResult]:
        key = (registry, package, version)
        if key not in self._package_cache:
            self._package_cache[key] = (
                self.query_osv(registry, package, version),
                self.query_ghsa(registry, package, version),
            )
        return self._package_cache[key]

    def query_nvd(self, cve_id: str) -> AdvisoryResult:
        if cve_id in self._nvd_cache:
            return self._nvd_cache[cve_id]
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        query = urllib.parse.urlencode({"cveId": cve_id})
        try:
            payload = self._request_json(f"{NVD_API}?{query}", headers=headers)
            vulns = payload.get("vulnerabilities") or []
            result = AdvisoryResult(status="MATCH" if vulns else "NO_MATCH")
            for item in vulns:
                cve = item.get("cve") or {}
                found_id = str(cve.get("id") or "")
                if found_id:
                    result.ids.add(found_id)
                    result.cves.add(found_id)
                for weakness in cve.get("weaknesses") or []:
                    for desc in weakness.get("description") or []:
                        value = str((desc or {}).get("value") or "").upper()
                        if value.startswith("CWE-"):
                            result.cwes.add(value)
                for reference in cve.get("references") or []:
                    url = str((reference or {}).get("url") or "")
                    if url:
                        result.urls.add(url)
        except Exception as exc:
            result = AdvisoryResult(status="ERROR", error=f"{type(exc).__name__}: {exc}"[:500])
        self._nvd_cache[cve_id] = result
        return result

    def query_redhat(self, cve_id: str) -> AdvisoryResult:
        if cve_id in self._redhat_cache:
            return self._redhat_cache[cve_id]
        encoded = urllib.parse.quote(cve_id, safe="")
        try:
            payload = self._request_json(f"{REDHAT_API}/{encoded}.json")
            found_id = str(payload.get("name") or payload.get("CVE") or payload.get("cve") or cve_id)
            result = AdvisoryResult(status="MATCH")
            if found_id:
                result.ids.add(found_id)
                if found_id.startswith("CVE-"):
                    result.cves.add(found_id)
            cwe = str(payload.get("CWE") or payload.get("cwe") or "").upper()
            if cwe.startswith("CWE-"):
                result.cwes.add(cwe)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                result = AdvisoryResult(status="NO_MATCH")
            else:
                result = AdvisoryResult(status="ERROR", error=f"HTTPError: {exc.code}")
        except Exception as exc:
            result = AdvisoryResult(status="ERROR", error=f"{type(exc).__name__}: {exc}"[:500])
        self._redhat_cache[cve_id] = result
        return result


def _split_cwes(value: str) -> set[str]:
    normalized = value.replace("[", " ").replace("]", " ").replace('"', " ").replace("'", " ")
    pieces = normalized.replace(",", " ").replace(";", " ").split()
    return {piece.upper() for piece in pieces if piece.upper().startswith("CWE-")}


def _priority(severity: str, confidence: str, novelty: str) -> str:
    sev = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}.get(severity.upper(), 4)
    conf = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(confidence.upper(), 2)
    nov = {"novel": 0, "unreviewed": 1, "possible_match": 2, "known": 3}.get(novelty.lower(), 1)
    return f"P{min(4, 1 + sev + conf + nov)}"


def _joined(values: set[str]) -> str:
    return ";".join(sorted(v for v in values if v))


def enrich_rows(rows: list[dict[str, str]], client: AdvisoryClient, checked_at: str | None = None) -> list[dict[str, str]]:
    checked_at = checked_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")

    for row in rows:
        if row.get("finding_class") in {"secret_exposure", "misconfiguration"}:
            row["osv_status"] = "SKIPPED"
            row["ghsa_status"] = "SKIPPED"
            row["nvd_status"] = "SKIPPED"
            row["redhat_status"] = "SKIPPED"
            row["enrichment_status"] = "NOT_APPLICABLE"
            row["enrichment_error"] = ""
            row["dedup_status"] = "NOT_APPLICABLE"
            row["dedup_match_basis"] = "finding_class_not_advisory_dedup"
            row["dedup_sources"] = ""
            row["dedup_checked_at_utc"] = checked_at
            continue

        registry = row.get("registry", "")
        known_dependency = row.get("known_dependency", "").lower() == "true"
        lookup_registry = row.get("dependency_ecosystem", "") if known_dependency else registry
        package = row.get("dependency_name", "") if known_dependency else row.get("package_name", "")
        version = row.get("installed_version", "") if known_dependency else row.get("package_version", "")

        pre_errors: list[str] = []
        if lookup_registry not in OSV_ECOSYSTEM:
            pre_errors.append("dependency ecosystem unavailable for package-aware advisory lookup")
            lookup_registry = ""
        if not package or not version:
            row["enrichment_status"] = "SKIPPED"
            row["enrichment_error"] = "missing package or version for advisory lookup"
            continue

        if lookup_registry:
            osv, ghsa = client.query_package(lookup_registry, package, version)
        else:
            osv, ghsa = AdvisoryResult(status="SKIPPED"), AdvisoryResult(status="SKIPPED")
        ids = set(osv.ids) | set(ghsa.ids)
        cves = set(osv.cves) | set(ghsa.cves)
        cwes = set(osv.cwes) | set(ghsa.cwes)
        errors = pre_errors + [x.error for x in (osv, ghsa) if x.error]

        row["osv_status"] = osv.status
        row["osv_ids"] = _joined(osv.ids)
        row["ghsa_status"] = ghsa.status
        row["ghsa_ids"] = _joined(ghsa.ids)
        row["advisory_cves"] = _joined(cves)
        row["advisory_cwes"] = _joined(cwes)

        direct_id = row.get("vulnerability_id", "")
        if direct_id.startswith("CVE-"):
            cves.add(direct_id)

        nvd_ids: set[str] = set()
        redhat_ids: set[str] = set()
        nvd_states: set[str] = set()
        redhat_states: set[str] = set()

        # Bound corroboration fan-out for packages with a large advisory history.
        for cve_id in sorted(cves)[:10]:
            nvd = client.query_nvd(cve_id)
            redhat = client.query_redhat(cve_id)
            nvd_states.add(nvd.status)
            redhat_states.add(redhat.status)
            nvd_ids.update(nvd.ids)
            redhat_ids.update(redhat.ids)
            cwes.update(nvd.cwes)
            cwes.update(redhat.cwes)
            if nvd.error:
                errors.append(f"NVD {cve_id}: {nvd.error}")
            if redhat.error:
                errors.append(f"Red Hat {cve_id}: {redhat.error}")

        row["nvd_status"] = (
            "MATCH" if "MATCH" in nvd_states
            else "ERROR" if "ERROR" in nvd_states
            else "NO_MATCH" if nvd_states
            else "SKIPPED"
        )
        row["nvd_ids"] = _joined(nvd_ids)
        row["redhat_status"] = (
            "MATCH" if "MATCH" in redhat_states
            else "ERROR" if "ERROR" in redhat_states
            else "NO_MATCH" if redhat_states
            else "SKIPPED"
        )
        row["redhat_ids"] = _joined(redhat_ids)
        row["advisory_cves"] = _joined(cves)
        row["advisory_cwes"] = _joined(cwes)

        row_cwes = _split_cwes(row.get("cwe", ""))
        overlap = row_cwes & cwes

        if direct_id and (direct_id in ids or direct_id in cves or known_dependency):
            dedup_status = "KNOWN_EXACT"
            novelty = "known"
            basis = "scanner_identifier"
        elif ids:
            dedup_status = "POSSIBLE_MATCH"
            novelty = "possible_match"
            basis = "package_version+cwe" if overlap else "package_version"
        elif "ERROR" in {osv.status, ghsa.status}:
            dedup_status = "LOOKUP_FAILED"
            novelty = "unreviewed"
            basis = "lookup_failed"
        else:
            dedup_status = "NO_MATCH"
            novelty = "novel"
            basis = "exact_package_version_no_advisory"

        row["dedup_status"] = dedup_status
        row["novelty_state"] = novelty
        row["dedup_match_basis"] = basis
        row["dedup_sources"] = "osv;ghsa;nvd;redhat"
        row["dedup_identifiers"] = _joined(ids | cves | nvd_ids | redhat_ids)
        row["dedup_checked_at_utc"] = checked_at
        row["enrichment_status"] = "PARTIAL" if errors else "COMPLETE"
        row["enrichment_error"] = " | ".join(errors)[:2000]
        row["triage_priority"] = _priority(row.get("severity", "UNKNOWN"), row.get("confidence", "LOW"), novelty)

    return rows
