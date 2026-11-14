"""Analyzer contract.

An analyzer receives a read-only view of one artifact and returns findings,
properties and warnings. It must not write to the GUI, touch the original file,
or write arbitrary paths. Cross-analyzer data goes through ctx.shared, which the
pipeline runs in a fixed order.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from imagehunter.config.settings import Settings
from imagehunter.models.artifact import Artifact
from imagehunter.models.finding import Finding


@dataclass
class AnalyzerContext:
    artifact: Artifact
    data: bytes
    settings: Settings
    shared: dict = field(default_factory=dict)
    cancel_event: object | None = None


@dataclass
class AnalyzerResult:
    findings: list[Finding] = field(default_factory=list)
    properties: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class Analyzer(ABC):
    name: str = "base"

    @abstractmethod
    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        """Analyse ctx.data and return results. Must not raise for malformed input."""
