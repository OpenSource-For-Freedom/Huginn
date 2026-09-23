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
        "package": "volcengine-python-sdk-aicc",
        "version": "0.0.41",
        "url": "https://files.pythonhosted.org/packages/ce/13/2064b8ff62237f906b662a4e7bb0b7582313c8d47abf3960447d0ec8ae8c/volcengine_python_sdk_aicc-0.0.41.tar.gz",
        "sha256": "2aae4691780916114ad477ebbb6c09eaff2c597b1a60b02c8905efd4b70944ab",
        "terms": [
            "encrypt_with_response", "jeddak_secure_channel", "dp_version",
            "DeepSeekClient(", "base_url", "pickle.loads", "pickle.dumps",
            "Project-URL", "Homepage", "Repository",
        ],
    },
    {
        "package": "webteam-agents",
        "version": "0.2.0",
        "url": "https://files.pythonhosted.org/packages/ed/7f/2bbac34bee9f550dbd24fe721f0713ef7ad2337c070511cd2571a6250648/webteam_agents-0.2.0.tar.gz",
        "sha256": "42f0300c7fe6bb97b5574640ff50b5747f9eee7bdc2f4a9ea71998b47eac75e7",
        "terms": [
            "check_project(", "commands", "webteam.json", "approved",
            "subprocess.Popen(", "Project-URL", "Homepage", "Repository",
        ],
    },
]


def security() -> list[str]:
    return [
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "256",
        "--memory", "1g", "--cpus", "1",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
    ]


def run(args: list[str]) -> str:
    cp = subprocess.run(args, text=True, capture_output=True, check=False, timeout=300)
    if cp.returncode:
        raise RuntimeError((cp.stderr or cp.stdout or "")[:2000])
    return cp.stdout


def download(url: str, path: Path, expected: str) -> None:
    digest = hashlib.sha256()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as response, path.open("wb") as handle:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            handle.write(chunk)
    if digest.hexdigest().lower() != expected.lower():
        raise RuntimeError("artifact SHA mismatch")


SEARCH_HELPER = r"""
import json, os
from pathlib import Path
root = Path('/scan/src').resolve()
terms = json.loads(os.environ['HUGINN_TERMS'])
rows = []
for path in root.rglob('*'):
    if not path.is_file() or path.stat().st_size > 512000:
        continue
    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    except Exception:
        continue
    for term in terms:
        for i, line in enumerate(lines, 1):
            if term.lower() in line.lower():
                lo=max(1,i-3); hi=min(len(lines),i+3)
                excerpt='\n'.join(f'{n}: {lines[n-1]}' for n in range(lo,hi+1))
                rows.append({'term':term,'path':str(path),'line':i,'excerpt':excerpt})
                if sum(1 for r in rows if r['term']==term) >= 30:
                    break
print(json.dumps(rows, ensure_ascii=False))
"""


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    archive = root / "src" / "huginn" / "archive.py"
    image = os.environ.get("HUGINN_UNPACK_IMAGE", "docker.io/library/python:3.13-slim")
    output = []

    for candidate in CANDIDATES:
        with tempfile.TemporaryDirectory(prefix="huginn-prov-") as td:
            artifact = Path(td) / candidate["url"].rsplit("/", 1)[-1]
            download(candidate["url"], artifact, candidate["sha256"])
            volume = f"huginn-prov-{uuid.uuid4().hex}"
            run(["podman", "volume", "create", volume])
            try:
                run([
                    "podman", "run", "--rm", *security(),
                    "-v", f"{artifact.resolve()}:/input/package:ro,Z",
                    "-v", f"{archive.resolve()}:/opt/huginn_archive.py:ro,Z",
                    "-v", f"{volume}:/work:rw",
                    image, "python", "/opt/huginn_archive.py", "/input/package", "/work/src",
                ])
                raw = run([
                    "podman", "run", "--rm", *security(),
                    "-v", f"{volume}:/scan:ro",
                    "-e", f"HUGINN_TERMS={json.dumps(candidate['terms'], separators=(',', ':'))}",
                    image, "python", "-c", SEARCH_HELPER,
                ])
                output.append({
                    "package": candidate["package"],
                    "version": candidate["version"],
                    "artifact_sha256": candidate["sha256"],
                    "matches": json.loads(raw or "[]"),
                })
            finally:
                subprocess.run(["podman", "volume", "rm", "-f", volume], capture_output=True, text=True)

    out = Path("candidate-review")
    out.mkdir(exist_ok=True)
    (out / "candidate_provenance.json").write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
