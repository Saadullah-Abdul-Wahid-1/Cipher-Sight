"""Scan summary: the structured result returned by every scan."""

from __future__ import annotations

from dataclasses import dataclass, field

from imagehunter import __version__
from imagehunter.models.finding import Finding

SCHEMA_VERSION = "1.0"

LIMITATIONS = [
    "Findings describe file structure and are rule-based hints. They do not prove that a flag is present.",
    "Structure is parsed for PNG, JPEG and BMP only. Other formats are identified by signature alone.",
    "This build does not run any external tool. Optional integrations are reported by check-tools.",
]


@dataclass
class ScanSummary:
    scan_id: str
    started_at: str
    finished_at: str
    status: str                     # completed | completed_with_warnings
    input: dict
    findings: list[Finding]
    properties: dict
    analyzers: list[dict]
    warnings: list[str]
    workspace: str
    app_version: str = __version__
    schema_version: str = SCHEMA_VERSION
    limitations: list[str] = field(default_factory=lambda: list(LIMITATIONS))
    execution_log: list[dict] = field(default_factory=list)
    evidence_graph: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "findings"}
        d["findings"] = [f.to_dict() for f in self.findings]
        return d
