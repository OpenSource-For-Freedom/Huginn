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


TARGETS = [
    {
        "package": "bluet-mcp",
        "version": "0.4.2",
        "url": "https://registry.npmjs.org/bluet-mcp/-/bluet-mcp-0.4.2.tgz",
        "sha256": "84c91bbe07e9c8c47d9bf448d3d581f3c31ff68dece2dc370232be6ab5843c9f",
        "sections": [
            {"suffix": "package/mcp.mjs", "start": 400, "end": 590},
        ],
        "terms": ["eval(", "exec(", "Function(", "tool(", "setRequestHandler", "CallToolRequestSchema"],
    },
    {
        "package": "archcheck",
        "version": "0.26.0",
        "url": "https://files.pythonhosted.org/packages/c3/3b/edce9bd91eec2de5bf7661e3bfd93703087e6d00c41f76e566af2083e84c/archcheck-0.26.0.tar.gz",
        "sha256": "e6864a52e1bf8f549efb86ff7c455943fab7da06f3f59e9b6dbfb27443018830",
        "sections": [
            {"suffix": "src/archcheck/templates/report.html", "start": 270, "end": 930},
        ],
        "terms": ["innerHTML", "textContent", "escape", "JSON.stringify", "report.html"],
    },
    {
        "package": "search-gateway",
        "version": "1.0.3.post20260923",
        "url": "https://files.pythonhosted.org/packages/e5/50/8ecf37e98da343a58e9b9bdfb43fe8cc96b732a8b5098ce67535f57e72ca/search_gateway-1.0.3.post20260923.tar.gz",
        "sha256": "1dceb87b9d92d72af87ad23265b8b24a8d962d40ad4ad57195bfb376d51c769b",
        "sections": [
            {"suffix": "search_gateway/static/assets/index-CT4xRkVZ.js", "start": 1, "end": 320},
        ],
        "terms": [
            "innerHTML", "dangerouslySetInnerHTML", "document.write", "sanitize", "DOMPurify",
            "textContent", "replaceChildren", "panelHtml", "escape", "vendor_name",
            "keyword", "snippet", "message", "api_key", "logs"
        ],
    },
]


def sec() -> list[str]:
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


def fetch(url: str, path: Path, expected: str) -> None:
    h = hashlib.sha256()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as response, path.open("wb") as handle:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            handle.write(chunk)
    if h.hexdigest().lower() != expected.lower():
        raise RuntimeError(f"SHA mismatch for {url}")


HELPER = r"""
import json, os
from pathlib import Path
root = Path('/scan/src').resolve()
sections = json.loads(os.environ['HUGINN_SECTIONS'])
terms = json.loads(os.environ['HUGINN_TERMS'])
files = [p for p in root.rglob('*') if p.is_file()]
out_sections=[]; out_matches=[]
for q in sections:
    suffix=q['suffix'].replace('\\','/')
    for p in files:
        if str(p).replace('\\','/').endswith(suffix):
            try: lines=p.read_text(encoding='utf-8',errors='replace').splitlines()
            except Exception: continue
            start=max(1,int(q['start'])); end=min(len(lines),int(q['end']))
            out_sections.append({'suffix':suffix,'path':str(p),'start':start,'end':end,'text':'\n'.join(f'{i}: {lines[i-1]}' for i in range(start,end+1))})
for p in files:
    if p.stat().st_size > 1000000: continue
    try: lines=p.read_text(encoding='utf-8',errors='replace').splitlines()
    except Exception: continue
    for term in terms:
        count=0
        for i,line in enumerate(lines,1):
            if term.lower() in line.lower():
                lo=max(1,i-2); hi=min(len(lines),i+2)
                out_matches.append({'term':term,'path':str(p),'line':i,'excerpt':'\n'.join(f'{n}: {lines[n-1]}' for n in range(lo,hi+1))})
                count+=1
                if count>=20: break
print(json.dumps({'sections':out_sections,'matches':out_matches},ensure_ascii=False))
"""


def main() -> None:
    root=Path(__file__).resolve().parents[1]
    archive=root/"src"/"huginn"/"archive.py"
    image=os.environ.get("HUGINN_UNPACK_IMAGE","docker.io/library/python:3.13-slim")
    output=[]
    for target in TARGETS:
        with tempfile.TemporaryDirectory(prefix="huginn-secondary-") as td:
            artifact=Path(td)/target["url"].rsplit("/",1)[-1]
            fetch(target["url"],artifact,target["sha256"])
            vol=f"huginn-secondary-{uuid.uuid4().hex}"
            run(["podman","volume","create",vol])
            try:
                run(["podman","run","--rm",*sec(),"-v",f"{artifact.resolve()}:/input/package:ro,Z","-v",f"{archive.resolve()}:/opt/huginn_archive.py:ro,Z","-v",f"{vol}:/work:rw",image,"python","/opt/huginn_archive.py","/input/package","/work/src"])
                raw=run(["podman","run","--rm",*sec(),"-v",f"{vol}:/scan:ro","-e",f"HUGINN_SECTIONS={json.dumps(target['sections'],separators=(',',':'))}","-e",f"HUGINN_TERMS={json.dumps(target['terms'],separators=(',',':'))}",image,"python","-c",HELPER])
                output.append({"package":target["package"],"version":target["version"],"artifact_sha256":target["sha256"],**json.loads(raw or "{}")})
            finally:
                subprocess.run(["podman","volume","rm","-f",vol],capture_output=True,text=True)
    out=Path("candidate-review"); out.mkdir(exist_ok=True)
    (out/"secondary_candidates.json").write_text(json.dumps(output,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")


if __name__ == "__main__":
    main()
