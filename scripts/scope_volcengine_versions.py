from __future__ import annotations

import hashlib
import json
import tempfile
import urllib.request
from pathlib import Path

from huginn.archive import extract
from huginn.discovery import USER_AGENT

PACKAGE = "volcengine-python-sdk-aicc"
METADATA_URL = f"https://pypi.org/pypi/{PACKAGE}/json"
MAX_ARTIFACT_BYTES = 25 * 1024 * 1024

PATTERNS = {
    "attest_must_default_false": "attest_must: bool = False",
    "fail_open_public_key_acceptance": "if pub_key and not self.config.attest_must",
    "unsafe_pickle_response": "pickle.loads(encrypt_key.decrypt",
    "secure_default_true": "is_secure: bool = True",
    "legacy_version_branch": 'if self.dp_version < "3.1"',
}


def request_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.loads(response.read())


def download(url: str, path: Path, expected_sha256: str) -> str:
    digest = hashlib.sha256()
    total = 0
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as response, path.open("wb") as handle:
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES:
                raise RuntimeError(f"artifact too large: {url}")
            digest.update(chunk)
            handle.write(chunk)
    actual = digest.hexdigest()
    if expected_sha256 and actual.lower() != expected_sha256.lower():
        raise RuntimeError(f"sha256 mismatch for {url}")
    return actual


def first_upload(files: list[dict]) -> str:
    values = [
        str(item.get("upload_time_iso_8601") or item.get("upload_time") or "")
        for item in files
        if item.get("upload_time_iso_8601") or item.get("upload_time")
    ]
    return min(values) if values else ""


def artifact_for(files: list[dict]) -> dict | None:
    candidates = [x for x in files if not x.get("yanked")]
    if not candidates:
        candidates = files
    sdists = [x for x in candidates if x.get("packagetype") == "sdist"]
    wheels = [x for x in candidates if x.get("packagetype") == "bdist_wheel"]
    chosen = (sdists or wheels or candidates)
    return chosen[0] if chosen else None


def scan_tree(root: Path) -> tuple[dict[str, bool], dict[str, list[dict]]]:
    found = {name: False for name in PATTERNS}
    evidence = {name: [] for name in PATTERNS}
    for path in root.rglob("*"):
        if not path.is_file() or path.stat().st_size > 2_000_000:
            continue
        if path.suffix.lower() not in {".py", ".txt", ".md", ".toml"}:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        for number, line in enumerate(lines, 1):
            for name, needle in PATTERNS.items():
                if needle in line:
                    found[name] = True
                    if len(evidence[name]) < 5:
                        evidence[name].append({
                            "path": rel,
                            "line": number,
                            "text": line.strip()[:500],
                        })
    return found, evidence


def main() -> None:
    meta = request_json(METADATA_URL)
    releases = meta.get("releases") or {}
    ordered = sorted(
        (
            (first_upload(files), version, files)
            for version, files in releases.items()
            if files
        ),
        key=lambda item: item[0],
    )

    rows = []
    for uploaded, version, files in ordered:
        artifact = artifact_for(files)
        if not artifact:
            continue
        url = str(artifact.get("url") or "")
        sha = str((artifact.get("digests") or {}).get("sha256") or "")
        filename = str(artifact.get("filename") or f"{version}.bin")
        try:
            with tempfile.TemporaryDirectory(prefix="huginn-volc-scope-") as td:
                td_path = Path(td)
                archive = td_path / filename
                actual_sha = download(url, archive, sha)
                tree = td_path / "tree"
                extract(archive, tree)
                found, evidence = scan_tree(tree)
            error = ""
        except Exception as exc:
            actual_sha = ""
            found = {name: False for name in PATTERNS}
            evidence = {name: [] for name in PATTERNS}
            error = f"{type(exc).__name__}: {exc}"[:1000]

        rows.append({
            "version": version,
            "uploaded_at": uploaded,
            "filename": filename,
            "artifact_url": url,
            "artifact_sha256": actual_sha or sha,
            "patterns": found,
            "evidence": evidence,
            "full_chain_present": all(found.values()),
            "error": error,
        })

    affected = [row["version"] for row in rows if row["full_chain_present"]]
    output = {
        "package": PACKAGE,
        "pypi_latest_version": str((meta.get("info") or {}).get("version") or ""),
        "release_count": len(rows),
        "affected_versions_with_full_static_chain": affected,
        "first_affected_version": affected[0] if affected else "",
        "last_affected_version": affected[-1] if affected else "",
        "releases": rows,
    }
    out = Path("candidate-review")
    out.mkdir(exist_ok=True)
    (out / "volcengine_version_scope.json").write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "latest": output["pypi_latest_version"],
        "release_count": output["release_count"],
        "affected_count": len(affected),
        "first_affected": output["first_affected_version"],
        "last_affected": output["last_affected_version"],
    }, indent=2))


if __name__ == "__main__":
    main()
