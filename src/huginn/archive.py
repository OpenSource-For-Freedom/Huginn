from __future__ import annotations

import argparse
import shutil
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


class UnsafeArchive(ValueError):
    pass


def _safe_rel(name: str) -> Path:
    normalized = name.replace("\\", "/")
    p = PurePosixPath(normalized)
    if p.is_absolute() or any(part == ".." for part in p.parts):
        raise UnsafeArchive(f"unsafe archive path: {name}")
    if not p.parts:
        raise UnsafeArchive("empty archive path")
    return Path(*p.parts)


def _limits(files: int, expanded: int, max_files: int, max_expanded: int) -> None:
    if files > max_files:
        raise UnsafeArchive(f"archive file-count limit exceeded: {files}>{max_files}")
    if expanded > max_expanded:
        raise UnsafeArchive(f"archive expanded-size limit exceeded: {expanded}>{max_expanded}")


def extract_zip(path: Path, dest: Path, max_files: int, max_expanded: int) -> None:
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        expanded = sum(i.file_size for i in infos)
        _limits(len(infos), expanded, max_files, max_expanded)
        for info in infos:
            rel = _safe_rel(info.filename)
            target = dest / rel
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise UnsafeArchive(f"zip symlink rejected: {info.filename}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out, length=1024 * 1024)


def extract_tar(path: Path, dest: Path, max_files: int, max_expanded: int) -> None:
    with tarfile.open(path, "r:*") as tf:
        members = tf.getmembers()
        expanded = sum(m.size for m in members if m.isfile())
        _limits(len(members), expanded, max_files, max_expanded)
        for member in members:
            rel = _safe_rel(member.name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise UnsafeArchive(f"special/link entry rejected: {member.name}")
            target = dest / rel
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, target.open("wb") as out:
                shutil.copyfileobj(src, out, length=1024 * 1024)


def extract_gem(path: Path, dest: Path, max_files: int, max_expanded: int) -> None:
    outer = dest.parent / "gem-outer"
    outer.mkdir(parents=True, exist_ok=True)
    extract_tar(path, outer, max_files, max_expanded)
    data = outer / "data.tar.gz"
    if not data.exists():
        raise UnsafeArchive("RubyGem has no data.tar.gz payload")
    extract_tar(data, dest, max_files, max_expanded)
    shutil.rmtree(outer, ignore_errors=True)


def extract(path: Path, dest: Path, max_files: int = 20000, max_expanded: int = 512 * 1024 * 1024) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    lower = path.name.lower()
    if lower.endswith(".gem"):
        return extract_gem(path, dest, max_files, max_expanded)
    if lower.endswith((".zip", ".whl")) or zipfile.is_zipfile(path):
        return extract_zip(path, dest, max_files, max_expanded)
    if tarfile.is_tarfile(path):
        return extract_tar(path, dest, max_files, max_expanded)
    raise UnsafeArchive(f"unsupported archive format: {path.name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("dest", type=Path)
    parser.add_argument("--max-files", type=int, default=20000)
    parser.add_argument("--max-expanded", type=int, default=512 * 1024 * 1024)
    args = parser.parse_args()
    extract(args.archive, args.dest, args.max_files, args.max_expanded)


if __name__ == "__main__":
    main()
