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

URL="https://files.pythonhosted.org/packages/ce/13/2064b8ff62237f906b662a4e7bb0b7582313c8d47abf3960447d0ec8ae8c/volcengine_python_sdk_aicc-0.0.41.tar.gz"
SHA="2aae4691780916114ad477ebbb6c09eaff2c597b1a60b02c8905efd4b70944ab"
FILES=[
 {"suffix":"bytedance/volcengine_aicc_sdk/deepseek_inference_client.py","start":1,"end":180},
 {"suffix":"bytedance/volcengine_aicc_sdk/secure_http_client.py","start":1,"end":220},
 {"suffix":"bytedance/jeddak_secure_channel/client.py","start":1,"end":180},
 {"suffix":"bytedance/jeddak_secure_channel/config.py","start":1,"end":260},
 {"suffix":"bytedance/jeddak_secure_channel/crypto/envelope.py","start":1,"end":310},
 {"suffix":"bytedance/jeddak_secure_channel/crypto/aes.py","start":1,"end":220},
 {"suffix":"bytedance/jeddak_secure_channel/ra.py","start":1,"end":850},
]


def sec():
 return ["--network","none","--read-only","--cap-drop","ALL","--security-opt","no-new-privileges","--pids-limit","256","--memory","1g","--cpus","1","--tmpfs","/tmp:rw,noexec,nosuid,nodev,size=64m"]


def run(args):
 cp=subprocess.run(args,text=True,capture_output=True,check=False,timeout=300)
 if cp.returncode: raise RuntimeError((cp.stderr or cp.stdout or "")[:2000])
 return cp.stdout


def main():
 root=Path(__file__).resolve().parents[1]; archive=root/"src"/"huginn"/"archive.py"
 image=os.environ.get("HUGINN_UNPACK_IMAGE","docker.io/library/python:3.13-slim")
 with tempfile.TemporaryDirectory(prefix="huginn-jsc-") as td:
  art=Path(td)/"package.tar.gz"; h=hashlib.sha256()
  req=urllib.request.Request(URL,headers={"User-Agent":USER_AGENT})
  with urllib.request.urlopen(req,timeout=60) as resp, art.open("wb") as f:
   while True:
    chunk=resp.read(1024*1024)
    if not chunk: break
    h.update(chunk); f.write(chunk)
  if h.hexdigest()!=SHA: raise RuntimeError("sha mismatch")
  vol=f"huginn-jsc-{uuid.uuid4().hex}"; run(["podman","volume","create",vol])
  try:
   run(["podman","run","--rm",*sec(),"-v",f"{art.resolve()}:/input/package:ro,Z","-v",f"{archive.resolve()}:/opt/huginn_archive.py:ro,Z","-v",f"{vol}:/work:rw",image,"python","/opt/huginn_archive.py","/input/package","/work/src"])
   helper=r"""import json,os
from pathlib import Path
root=Path('/scan/src').resolve(); qs=json.loads(os.environ['QS']); files=[p for p in root.rglob('*') if p.is_file()]; out=[]
for q in qs:
 s=q['suffix'].replace('\\','/')
 for p in files:
  if str(p).replace('\\','/').endswith(s):
   lines=p.read_text(encoding='utf-8',errors='replace').splitlines(); a=max(1,q['start']); b=min(len(lines),q['end'])
   out.append({'suffix':s,'path':str(p),'text':'\n'.join(f'{i}: {lines[i-1]}' for i in range(a,b+1))})
print(json.dumps(out,ensure_ascii=False))"""
   raw=run(["podman","run","--rm",*sec(),"-v",f"{vol}:/scan:ro","-e",f"QS={json.dumps(FILES,separators=(',',':'))}",image,"python","-c",helper])
   out=Path("candidate-review"); out.mkdir(exist_ok=True)
   (out/"volcengine_jsc_trace.json").write_text(json.dumps(json.loads(raw),indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
  finally:
   subprocess.run(["podman","volume","rm","-f",vol],capture_output=True,text=True)


if __name__=="__main__": main()
