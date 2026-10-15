"""Rank fresh releases by how likely they are to be malware, before downloading anything.

A registry publishes thousands of new packages a day and a hunt can scan a few dozen,
so what gets scanned decides what gets caught. Every signal here comes from registry
metadata Huginn fetches anyway (the npm packument, the PyPI project JSON); nothing is
installed or executed.

The signals are the shapes malicious packages keep taking:

* an npm install hook (preinstall/install/postinstall), worse when it fetches or
  runs something;
* a name one edit away from a popular package (typosquat), or a popular name with
  a decoy suffix;
* a dependency-confusion version (a first release numbered 90.0.0 or 99.x);
* a PyPI release shipped only as an sdist, so setup.py runs at install;
* no description and no repository: nothing for a reviewer to check.

Scores are additive and only rank; the analyzer still decides what is malicious.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Most-downloaded package names: typosquats aim at these.
POPULAR = {
    "npm": [
        "react", "react-dom", "lodash", "axios", "express", "chalk", "commander", "debug",
        "moment", "request", "async", "uuid", "dotenv", "typescript", "webpack", "vue",
        "jquery", "next", "eslint", "prettier", "jest", "mocha", "yargs", "colors",
        "body-parser", "cors", "mongoose", "socket.io", "redux", "bluebird", "underscore",
        "classnames", "inquirer", "glob", "minimist", "semver", "rimraf", "mkdirp",
        "node-fetch", "ws", "babel-core", "core-js", "tslib", "rxjs", "zod", "ethers",
        "web3", "puppeteer", "discord.js", "electron", "nodemailer", "jsonwebtoken",
        "bcrypt", "bcryptjs", "sharp", "sequelize", "pg", "mysql", "mysql2", "redis",
        "openai", "@solana/web3.js", "bignumber.js", "crypto-js", "dayjs", "date-fns",
        "cross-env", "nodemon", "concurrently", "vite", "tailwindcss", "postcss",
    ],
    "pypi": [
        "requests", "urllib3", "numpy", "pandas", "boto3", "botocore", "setuptools",
        "pip", "wheel", "six", "python-dateutil", "certifi", "idna", "charset-normalizer",
        "pyyaml", "cryptography", "pydantic", "typing-extensions", "jinja2", "click",
        "flask", "django", "fastapi", "sqlalchemy", "pytest", "matplotlib", "scipy",
        "pillow", "beautifulsoup4", "selenium", "scrapy", "tensorflow", "torch",
        "transformers", "openai", "colorama", "termcolor", "tqdm", "rich", "psutil",
        "paramiko", "pycryptodome", "web3", "solana", "discord.py", "discord",
        "pyautogui", "pynput", "opencv-python", "aiohttp", "httpx", "websockets",
        "keyring", "pywin32", "pyinstaller", "virtualenv", "black", "requests-toolbelt",
    ],
}
# Suffixes a decoy adds to a real name (lodash-utils, requests-py, colorama-api).
_DECOY_SUFFIX = re.compile(r"[-_.]?(?:js|py|py3|python|utils?|tools?|sdk|api|lib|helper|"
                           r"core|plus|pro|dev|fix|fixed|new|latest|patch|node|cli)$", re.I)
# An install hook that reaches out or runs something other than a local build.
_HOOK_NETWORK = re.compile(r"https?://|\bcurl\b|\bwget\b|\bnode\s+-e\b|powershell|"
                           r"\bbash\s+-c\b|\bsh\s+-c\b|\bpython\d?\s+-c\b|base64|\beval\b", re.I)
_NPM_HOOKS = ("preinstall", "install", "postinstall")


@dataclass
class Triage:
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    def add(self, points: int, reason: str) -> None:
        self.score += points
        self.reasons.append(reason)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower().split("/")[-1])


def _edit_distance_1(a: str, b: str) -> bool:
    """True when a and b differ by exactly one insert, delete, substitute or swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return (len(diff) == 2 and diff[1] == diff[0] + 1
                and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(long_)):
        if long_[:i] + long_[i + 1:] == short:
            return True
    return False


def typosquat_target(registry: str, name: str) -> str:
    """The popular package this name imitates, or ''."""
    candidate = _norm(name)
    popular_names = POPULAR.get(registry, [])
    if candidate in {_norm(p) for p in popular_names}:
        return ""                          # a popular package itself (mysql2 is not a mysql squat)
    for popular in popular_names:
        target = _norm(popular)
        if len(target) >= 4 and _edit_distance_1(candidate, target):
            return popular
        stripped = _DECOY_SUFFIX.sub("", candidate)
        if stripped != candidate and stripped == target:
            return popular
    return ""


def _confusion_version(version: str) -> bool:
    match = re.match(r"(\d+)\.", version or "")
    return bool(match) and int(match.group(1)) >= 90


def score_npm(name: str, version: str, packument: dict) -> Triage:
    t = Triage()
    manifest = (packument.get("versions") or {}).get(version) or {}
    scripts = manifest.get("scripts") or {}
    hooks = {k: str(scripts[k]) for k in _NPM_HOOKS if scripts.get(k)}
    if hooks:
        t.add(4, "install hook: " + ", ".join(sorted(hooks)))
        if any(_HOOK_NETWORK.search(body) for body in hooks.values()):
            t.add(3, "install hook fetches or runs code")
    target = typosquat_target("npm", name)
    if target:
        t.add(4, f"name imitates {target}")
    if _confusion_version(version):
        t.add(3, f"dependency-confusion version {version}")
    if not (manifest.get("description") or packument.get("description")):
        t.add(1, "no description")
    if not (manifest.get("repository") or packument.get("repository")):
        t.add(1, "no repository")
    if manifest.get("bin") and hooks:
        t.add(1, "install hook plus bin entry")
    return t


def score_pypi(name: str, version: str, project: dict) -> Triage:
    t = Triage()
    info = project.get("info") or {}
    files = project.get("urls") or (project.get("releases") or {}).get(version) or []
    kinds = {str(f.get("packagetype") or "") for f in files}
    if kinds and "bdist_wheel" not in kinds:
        t.add(2, "sdist only: setup.py runs at install")
    target = typosquat_target("pypi", name)
    if target:
        t.add(4, f"name imitates {target}")
    if _confusion_version(version):
        t.add(3, f"dependency-confusion version {version}")
    if not (info.get("summary") or "").strip():
        t.add(1, "no summary")
    urls = info.get("project_urls") or {}
    if not (urls or (info.get("home_page") or "").strip()):
        t.add(1, "no project links")
    if len((info.get("description") or "").strip()) < 40:
        t.add(1, "no readme")
    return t


def rank(scored: list[tuple[object, Triage]], top: int, minimum: int = 1) -> list[tuple[object, Triage]]:
    """The `top` highest-scoring items at or above `minimum`, stable for ties."""
    keep = [item for item in scored if item[1].score >= minimum]
    keep.sort(key=lambda item: -item[1].score)
    return keep[:max(0, top)]
