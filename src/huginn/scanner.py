from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

from .models import ScanOutcome


class ScanError(RuntimeError):
    pass


class PodmanScanner:
    def __init__(
        self,
        *,
        rules_file: Path,
        archive_script: Path,
        trivy_image: str = "docker.io/aquasec/trivy:0.74.0",
        semgrep_image: str = "docker.io/semgrep/semgrep:1.177.0",
        unpack_image: str = "docker.io/library/python:3.13-slim",
        trivy_cache_volume: str | None = None,
        timeout_seconds: int = 600,
    ):
        self.rules_file = rules_file.resolve()
        self.archive_script = archive_script.resolve()
        self.trivy_image = trivy_image
        self.semgrep_image = semgrep_image
        self.unpack_image = unpack_image
        self.trivy_cache_volume = (
            trivy_cache_volume
            or os.environ.get("HUGINN_TRIVY_CACHE_VOLUME")
            or "huginn-trivy-cache"
        )
        self.timeout_seconds = timeout_seconds

    @property
    def ruleset_hash(self) -> str:
        return hashlib.sha256(self.rules_file.read_bytes()).hexdigest()

    def _run(self, args: list[str], *, allowed: set[int] = {0}) -> subprocess.CompletedProcess[str]:
        cp = subprocess.run(args, text=True, capture_output=True, timeout=self.timeout_seconds, check=False)
        if cp.returncode not in allowed:
            stderr = (cp.stderr or cp.stdout or "").strip()
            raise ScanError(f"command failed ({cp.returncode}): {' '.join(args[:5])}: {stderr[:2000]}")
        return cp

    def _base_security(self) -> list[str]:
        return [
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "256",
            "--memory", "2g",
            "--cpus", "2",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=128m",
        ]

    def scan(self, artifact_path: Path) -> ScanOutcome:
        if not shutil.which("podman"):
            raise ScanError("podman is required and was not found in PATH")

        token = uuid.uuid4().hex
        source_volume = f"huginn-scan-{token}"
        scan_cache = f"huginn-trivy-scan-{token}"
        self._run(["podman", "volume", "create", source_volume])
        self._run(["podman", "volume", "create", scan_cache])

        try:
            # Copy the trusted persistent DB into an ephemeral per-scan cache.
            # The untrusted Trivy process never receives write access to the persistent cache.
            trusted_cache = self.trivy_cache_volume
            if Path(trusted_cache).is_absolute():
                trusted_mount = f"{Path(trusted_cache).resolve()}:/trusted:ro,Z"
            else:
                trusted_mount = f"{trusted_cache}:/trusted:ro"

            seed_cache = [
                "podman", "run", "--rm", *self._base_security(),
                "-v", trusted_mount,
                "-v", f"{scan_cache}:/cache:rw",
                self.unpack_image,
                "python", "-c",
                (
                    "from pathlib import Path; import shutil; "
                    "db=Path('/trusted/db/trivy.db'); "
                    "assert db.is_file(), 'trusted Trivy DB missing at /trusted/db/trivy.db'; "
                    "shutil.copytree('/trusted', '/cache', dirs_exist_ok=True)"
                ),
            ]
            self._run(seed_cache)

            unpack = [
                "podman", "run", "--rm", *self._base_security(),
                "-v", f"{artifact_path.resolve()}:/input/package:ro,Z",
                "-v", f"{self.archive_script}:/opt/huginn_archive.py:ro,Z",
                "-v", f"{source_volume}:/work:rw",
                self.unpack_image,
                "python", "/opt/huginn_archive.py", "/input/package", "/work/src",
            ]
            self._run(unpack)

            trivy_cmd = [
                "podman", "run", "--rm", *self._base_security(),
                "-v", f"{source_volume}:/scan:ro",
                "-v", f"{scan_cache}:/root/.cache/trivy:rw",
                self.trivy_image,
                "--cache-dir", "/root/.cache/trivy",
                "fs", "--skip-db-update", "--format", "json", "--scanners", "vuln,misconfig,secret", "/scan/src",
            ]
            trivy = self._run(trivy_cmd)

            semgrep_cmd = [
                "podman", "run", "--rm", *self._base_security(),
                "-v", f"{source_volume}:/scan:ro",
                "-v", f"{self.rules_file}:/rules/semgrep.yml:ro,Z",
                "-e", "EIO_BACKEND=posix",
                "-e", "HOME=/tmp",
                "-e", "XDG_CACHE_HOME=/tmp/.cache",
                "-e", "SEMGREP_SEND_METRICS=off",
                self.semgrep_image,
                "semgrep", "scan", "--config", "/rules/semgrep.yml", "--json",
                "--metrics=off", "--disable-version-check",
                "--no-git-ignore", "--scan-unknown-extensions", "/scan/src",
            ]
            semgrep = self._run(semgrep_cmd, allowed={0, 1})
            semgrep_payload = json.loads(semgrep.stdout or "{}")
            semgrep_results = semgrep_payload.get("results") or []
            semgrep_errors = semgrep_payload.get("errors") or []
            if semgrep.returncode != 0 and not semgrep_results:
                detail = json.dumps(semgrep_errors[:5], ensure_ascii=False)[:2000]
                raise ScanError(
                    f"Semgrep exited {semgrep.returncode} without findings; "
                    f"analysis errors: {detail or 'none reported'}"
                )

            return ScanOutcome(
                trivy=json.loads(trivy.stdout or "{}"),
                semgrep=semgrep_payload,
                trivy_exit_code=trivy.returncode,
                semgrep_exit_code=semgrep.returncode,
            )
        finally:
            subprocess.run(
                ["podman", "volume", "rm", "-f", source_volume],
                capture_output=True, text=True, check=False,
            )
            subprocess.run(
                ["podman", "volume", "rm", "-f", scan_cache],
                capture_output=True, text=True, check=False,
            )
