"""Printable ASCII strings with byte offsets. Input is capped by settings.max_strings."""

from __future__ import annotations

import re

from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult


class StringsAnalyzer(Analyzer):
    name = "text.strings"

    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        res = AnalyzerResult()
        min_len = ctx.settings.min_string_length
        cap = ctx.settings.max_strings
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        matches = list(pattern.finditer(ctx.data))
        # Full list for later analyzers (smart words). Properties below keep their original shape.
        ctx.shared["ascii_runs"] = [(m.start(), m.group().decode("ascii")) for m in matches]
        res.properties.update(
            min_length=min_len,
            string_count=len(matches),
            strings=[{"offset": m.start(), "text": m.group().decode("ascii")} for m in matches[:cap]],
            list_truncated=len(matches) > cap,
        )
        return res
