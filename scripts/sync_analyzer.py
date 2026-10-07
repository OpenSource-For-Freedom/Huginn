"""Copy git_warden's Tier-2 analyzer into Huginn (src/huginn/analyzer).

    python scripts/sync_analyzer.py /path/to/git_warden

Huginn runs the same malware rules as Warden and Knorr without depending on
the private git_warden repository at hunt time. Re-run this after Warden's
rules change; it records the source commit and a hash of every file in
src/huginn/analyzer/SOURCE.json, and tests/test_analyzer.py fails if a
vendored file is edited by hand instead of synced.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

DEST = Path(__file__).resolve().parents[1] / "src" / "huginn" / "analyzer"
# Everything analyze_repo needs for a package (all standard library).
FILES = [
    "scanning/bash_scanner.py", "scanning/content_scanner.py", "scanning/egress.py",
    "scanning/ioc.py",
    "scanning/manifest_scanner.py", "scanning/package_spread.py", "scanning/signatures.py",
    "scanning/tier2.py", "scanning/yara_rules.py",
]
HEADER = ("# Vendored from git_warden ({src}) by scripts/sync_analyzer.py.\n"
          "# Do not edit here: change it in git_warden and re-sync.\n")


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sync(warden: Path, dest: Path = DEST) -> dict:
    src_root = warden / "src" / "git_warden"
    commit = subprocess.run(["git", "-C", str(warden), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    dest.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for rel in FILES:
        name = Path(rel).name
        text = HEADER.format(src=f"src/git_warden/{rel} @ {commit[:12]}")
        text += (src_root / rel).read_text(encoding="utf-8")
        (dest / name).write_text(text, encoding="utf-8")
        hashes[name] = digest(text)
    source = {"repository": "OpenSource-For-Freedom/git_warden", "commit": commit,
              "files": hashes}
    (dest / "SOURCE.json").write_text(json.dumps(source, indent=2) + "\n", encoding="utf-8")
    return source


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("warden", type=Path, help="a git_warden checkout")
    args = ap.parse_args(argv)
    source = sync(args.warden)
    print(f"synced {len(source['files'])} files from git_warden {source['commit'][:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
