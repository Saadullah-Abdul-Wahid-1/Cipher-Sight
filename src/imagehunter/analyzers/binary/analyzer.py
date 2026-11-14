"""Runs the structure parser for the detected format and reports data after its end."""

from __future__ import annotations

from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.analyzers.binary.signatures import detect_format
from imagehunter.analyzers.binary.structure import parse_bmp, parse_jpeg, parse_png
from imagehunter.models.finding import Finding

PARSERS = {"png": parse_png, "jpeg": parse_jpeg, "bmp": parse_bmp}


class BinaryStructureAnalyzer(Analyzer):
    name = "binary.structure"

    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        res = AnalyzerResult()
        data = ctx.data
        fmt = detect_format(data[:16])
        res.properties["structure_parser"] = fmt if fmt in PARSERS else None

        if fmt not in PARSERS:
            ctx.shared["structure_end"] = None
            return res

        findings, end = PARSERS[fmt](data)
        res.findings.extend(findings)
        ctx.shared["structure_end"] = end
        res.properties["structure_end"] = end

        if end is not None and end < len(data):
            extra = len(data) - end
            res.findings.append(Finding(
                kind="appended_data", category="structure",
                description=f"{extra} bytes after the end of the {fmt.upper()} structure",
                confidence_label="High", offset=end, length=extra,
                evidence={"format": fmt},
            ))
        return res
