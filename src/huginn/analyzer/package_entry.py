"""Analyze one unpacked registry release for malware (runs inside the sandbox).

    python -m huginn_analyzer.package_entry /scan/src --name N --ecosystem E --work /work

Runs the vendored Tier-2 analysis over the read-only unpacked tree and prints
one JSON object. The tree is copied into ``--work`` (a tmpfs) first; dist/,
build/ and out/ are renamed pkg_* so they are scanned, because in a published
package they are the code that runs. Nothing is installed or executed.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .tier2 import analyze_repo

_GENERATED_DIRS = {"dist", "build", "out"}
_SKIP_COPY = shutil.ignore_patterns(".git", "node_modules")
_MAX_FINDINGS = 200


def _finding(f) -> dict:
    return {"file": f.file, "line": f.line, "category": f.category, "rule": f.rule,
            "snippet": f.snippet}


def expose_package_dirs(root: Path) -> list[str]:
    """Rename generated-output dirs so the scanners read them. Returns where they went."""
    for path in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if path.is_dir() and not path.is_symlink() and path.name in _GENERATED_DIRS:
            target = path.with_name(f"pkg_{path.name}")
            if not target.exists():
                path.rename(target)
    return sorted(str(p.relative_to(root)) for p in root.rglob("pkg_*")
                  if p.is_dir() and p.name[4:] in _GENERATED_DIRS)


def analyze_package(src: Path, name: str, ecosystem: str, work: Path | None = None,
                    *, runner=subprocess.run) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="pkg-", dir=str(work) if work else None))
    try:
        root = tmp / "pkg"
        shutil.copytree(src, root, symlinks=True, ignore=_SKIP_COPY)
        exposed = expose_package_dirs(root)
        result = analyze_repo(root, f"{ecosystem}:{name}", runner=runner)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return {
        "full_name": result.full_name,
        "confirmed": result.confirmed,
        "confidence": result.confidence,
        "bash_score": result.bash_score,
        "scanners": result.scanners,
        "bash_findings": [_finding(f) for f in result.bash_findings][:_MAX_FINDINGS],
        "confirming_findings": [_finding(f) for f in result.confirming_findings],
        "egress": result.egress,
        "egress_findings": [_finding(f) for f in result.egress_findings],
        "package": {"name": name, "ecosystem": ecosystem, "exposed_dirs": exposed},
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("src", type=Path)
    ap.add_argument("--name", required=True)
    ap.add_argument("--ecosystem", required=True)
    ap.add_argument("--work", type=Path, default=None)
    args = ap.parse_args(argv)
    if not args.src.is_dir():
        print(json.dumps({"error": f"not a directory: {args.src}"}))
        return 2
    print(json.dumps(analyze_package(args.src, args.name, args.ecosystem, args.work)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
