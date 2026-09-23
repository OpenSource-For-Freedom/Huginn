from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
import uuid
from pathlib import Path

from huginn.discovery import USER_AGENT


CANDIDATES = [
    {
        "package": "archcheck",
        "version": "0.26.0",
        "url": "https://files.pythonhosted.org/packages/c3/3b/edce9bd91eec2de5bf7661e3bfd93703087e6d00c41f76e566af2083e84c/archcheck-0.26.0.tar.gz",
        "sha256": "e6864a52e1bf8f549efb86ff7c455943fab7da06f3f59e9b6dbfb27443018830",
        "files": [
            {"suffix": "src/archcheck/semantic.py", "start": 900, "end": 1030},
        ],
    },
    {
        "package": "gitomb",
        "version": "0.1.0",
        "url": "https://files.pythonhosted.org/packages/41/0b/50b59ed975c65790b2a3d177919f1aee5732e402e0c79c2a8337a8dd0ae5/gitomb-0.1.0.tar.gz",
        "sha256": "0e1a76b21de6bad958b8b18d92a859c0168e4a0ca0eaa1820df90355867d4bf6",
        "files": [
            {"suffix": "src/gitomb/git.py", "start": 1, "end": 260},
        ],
    },
    {
        "package": "volcengine-python-sdk-aicc",
        "version": "0.0.41",
        "url": "https://files.pythonhosted.org/packages/ce/13/2064b8ff62237f906b662a4e7bb0b7582313c8d47abf3960447d0ec8ae8c/volcengine_python_sdk_aicc-0.0.41.tar.gz",
        "sha256": "2aae4691780916114ad477ebbb6c09eaff2c597b1a60b02c8905efd4b70944ab",
        "files": [
            {"suffix": "bytedance/volcengine_aicc_sdk/deepseek_inference_client.py", "start": 1, "end": 330},
            {"suffix": "bytedance/volcengine_aicc_sdk/asr_websocket_client.py", "start": 400, "end": 500},
        ],
    },
    {
        "package": "webteam-agents",
        "version": "0.2.0",
        "url": "https://files.pythonhosted.org/packages/ed/7f/2bbac34bee9f550dbd24fe721f0713ef7ad2337c070511cd2571a6250648/webteam_agents-0.2.0.tar.gz",
        "sha256": "42f0300c7fe6bb97b5574640ff50b5747f9eee7bdc2f4a9ea71998b47eac75e7",
        "files": [
            {"suffix": "src/webteam/project.py", "start": 1, "end": 320},
        ],
    },
]


def base_security() -> list[str]:
    return [
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256",
        "--memory", "1g",
        "--cpus", "1",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
    ]


def run(args: list[str]) -> str:
    cp = subprocess.run(args, text=True, capture_output=True, check=False, timeout=300)
    if cp.returncode:
        raise RuntimeError((cp.stderr or cp.stdout or "")[:2000])
    return cp.stdout


def download(url: str, dest: Path, expected: str) -> None:
    h = hashlib.sha256()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as response, dest.open("wb") as handle:
        while chunk := response.read(1024 * 1024):
            h.update(chunk)
            handle.write(chunk)
    if h.hexdigest().lower() != expected.lower():
        raise RuntimeError(f"sha256 mismatch: {url}")


def main() -> None:
    package_root = Path(__file__).resolve().parents[1] / "src" / "huginn"
    archive_script = package_root / "archive.py"
    unpack_image = os.environ.get("HUGINN_UNPACK_IMAGE", "docker.io/library/python:3.13-slim")
    output: list[dict] = []

    helper = r"""
import json, os
from pathlib import Path
root = Path('/scan/src').resolve()
queries = json.loads(os.environ['HUGINN_TRACE_QUERIES'])
result = []
files = [p for p in root.rglob('*') if p.is_file()]
for q in queries:
    suffix = q['suffix'].replace('\\','/')
    matches = [p for p in files if str(p).replace('\\','/').endswith(suffix)]
    for p in matches:
        try:
            lines = p.read_text(encoding='utf-8', errors='replace').splitlines()
        except Exception:
            continue
        start = max(1, int(q.get('start', 1)))
        end = min(len(lines), int(q.get('end', len(lines))))
        text = '\n'.join(f'{i}: {lines[i-1]}' for i in range(start, end + 1))
        result.append({'suffix': suffix, 'path': str(p), 'start': start, 'end': end, 'text': text})
print(json.dumps(result, ensure_ascii=False))
"""

    for candidate in CANDIDATES:
        with tempfile.TemporaryDirectory(prefix="huginn-trace-") as td:
            artifact = Path(td) / candidate["url"].rsplit("/", 1)[-1]
            download(candidate["url"], artifact, candidate["sha256"])
            volume = f"huginn-trace-{uuid.uuid4().hex}"
            run(["podman", "volume", "create", volume])
            try:
                run([
                    "podman", "run", "--rm", *base_security(),
                    "-v", f"{artifact.resolve()}:/input/package:ro,Z",
                    "-v", f"{archive_script.resolve()}:/opt/huginn_archive.py:ro,Z",
                    "-v", f"{volume}:/work:rw",
                    unpack_image,
                    "python", "/opt/huginn_archive.py", "/input/package", "/work/src",
                ])
                raw = run([
                    "podman", "run", "--rm", *base_security(),
                    "-v", f"{volume}:/scan:ro",
                    "-e", f"HUGINN_TRACE_QUERIES={json.dumps(candidate['files'], separators=(',', ':'))}",
                    unpack_image,
                    "python", "-c", helper,
                ])
                output.append({
                    "package": candidate["package"],
                    "version": candidate["version"],
                    "artifact_sha256": candidate["sha256"],
                    "sections": json.loads(raw or "[]"),
                })
            finally:
                subprocess.run(["podman", "volume", "rm", "-f", volume], capture_output=True, text=True)

    out = Path("candidate-review")
    out.mkdir(parents=True, exist_ok=True)
    (out / "candidate_trace.json").write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
