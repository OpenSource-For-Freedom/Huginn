from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path


CHECK_URLS = [
    "https://replicate.npmjs.com/",
    "https://registry.npmjs.org/lodash",
    "https://pypi.org/pypi/pip/json",
    "https://rubygems.org/api/v1/activity/latest.json",
    "https://api.osv.dev/v1/query",
    "https://api.github.com/advisories?ecosystem=npm&per_page=1",
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
    "https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=1",
]


def run(*args: str) -> tuple[int, str]:
    cp = subprocess.run(args, capture_output=True, text=True, check=False)
    return cp.returncode, (cp.stdout or cp.stderr or "").strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a host before Huginn package capture.")
    parser.add_argument("--state-db", default=os.environ.get("HUGINN_STATE_DB", "~/.local/state/huginn/state.db"))
    parser.add_argument("--network", action="store_true", help="also test required public API endpoints")
    args = parser.parse_args()

    checks: list[dict[str, object]] = []

    def record(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    record("non_root_user", os.geteuid() != 0, f"uid={os.geteuid()}")

    podman = shutil.which("podman")
    record("podman_present", bool(podman), podman or "not found")

    if podman:
        code, version = run("podman", "--version")
        record("podman_version", code == 0, version)
        code, rootless = run("podman", "info", "--format", "{{.Host.Security.Rootless}}")
        record("podman_rootless", code == 0 and rootless.lower() == "true", rootless or "unknown")

    state_path = Path(args.state_db).expanduser()
    state_dir = state_path.parent
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        probe = state_dir / ".huginn-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        record("state_directory_writable", True, str(state_dir))
    except Exception as exc:
        record("state_directory_writable", False, f"{state_dir}: {exc}")

    free = shutil.disk_usage(state_dir if state_dir.exists() else Path.home()).free
    record("disk_free", free >= 5 * 1024**3, f"{free / 1024**3:.1f} GiB free")

    for command in ("python3", "git"):
        path = shutil.which(command)
        record(f"{command}_present", bool(path), path or "not found")

    if args.network:
        token = os.environ.get("HUGINN_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        for url in CHECK_URLS:
            headers = {"User-Agent": "Huginn/runner-doctor"}
            if url.startswith("https://api.github.com/") and token:
                headers["Authorization"] = f"Bearer {token}"
                headers["Accept"] = "application/vnd.github+json"
            request = urllib.request.Request(url, headers=headers)
            if "api.osv.dev/v1/query" in url:
                request = urllib.request.Request(
                    url,
                    data=b'{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.23"}',
                    headers={**headers, "Content-Type": "application/json"},
                    method="POST",
                )
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    record(f"network:{url}", 200 <= response.status < 400, f"HTTP {response.status}")
            except Exception as exc:
                record(f"network:{url}", False, f"{type(exc).__name__}: {exc}")

    failed = [item for item in checks if not item["ok"]]
    print(json.dumps({"checks": checks, "failed": len(failed)}, indent=2))
    if failed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
