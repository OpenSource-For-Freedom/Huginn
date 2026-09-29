from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ReleaseCandidate:
    registry: str
    name: str
    version: str
    event_type: str
    published_at: str = ""
    source_url: str = ""

    @property
    def purl(self) -> str:
        ecosystem = {"pypi": "pypi", "rubygems": "gem", "npm": "npm", "crates": "cargo", "packagist": "composer", "go": "golang"}.get(self.registry, self.registry)
        safe_name = self.name.replace("@", "%40") if self.registry == "npm" else self.name
        return f"pkg:{ecosystem}/{safe_name}@{self.version}"


@dataclass(slots=True)
class DiscoveryBatch:
    candidates: list[ReleaseCandidate] = field(default_factory=list)
    checkpoint: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class Artifact:
    filename: str
    url: str
    sha256: str = ""
    registry_digest: str = ""
    size_bytes: int = 0


@dataclass(slots=True)
class ScanOutcome:
    trivy: dict[str, Any] = field(default_factory=dict)
    semgrep: dict[str, Any] = field(default_factory=dict)
    trivy_exit_code: int | None = None
    semgrep_exit_code: int | None = None
