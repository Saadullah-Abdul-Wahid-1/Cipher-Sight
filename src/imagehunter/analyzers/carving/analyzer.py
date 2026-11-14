"""Looks for embedded payload signatures, weighting hits by their position."""

from __future__ import annotations

from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.analyzers.carving.embedded import scan_embedded


class EmbeddedSignatureAnalyzer(Analyzer):
    name = "carving.embedded"

    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        res = AnalyzerResult()
        res.findings = scan_embedded(ctx.data, ctx.shared.get("structure_end"))
        return res
