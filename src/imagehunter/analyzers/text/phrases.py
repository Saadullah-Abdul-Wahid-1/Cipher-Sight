"""Searches the raw bytes for expected phrases configured by the analyst.

Match rule (explainable, not a learned score):
  exact-case occurrence            -> High
  case-insensitive occurrence only -> Medium
Nothing is configured by default, so this analyzer reports nothing until phrases are set.
"""

from __future__ import annotations

from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.models.finding import Finding

MAX_PER_PHRASE = 50
CONTEXT_BYTES = 40


def _printable(chunk: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)


class PhraseAnalyzer(Analyzer):
    name = "text.phrases"

    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        res = AnalyzerResult()
        phrases = list(ctx.settings.expected_phrases)
        res.properties["configured_phrases"] = len(phrases)
        if not phrases:
            res.properties["skipped"] = "no expected phrases configured"
            return res

        data = ctx.data
        lowered = data.lower()          # ASCII-only lowering; keeps offsets identical
        for phrase in phrases:
            needle = phrase.encode("utf-8")
            needle_lower = needle.lower()
            count = 0
            i = lowered.find(needle_lower)
            while i >= 0 and count < MAX_PER_PHRASE:
                exact = data[i:i + len(needle)] == needle
                start = max(0, i - CONTEXT_BYTES)
                end = min(len(data), i + len(needle) + CONTEXT_BYTES)
                res.findings.append(Finding(
                    kind="expected_phrase", category="phrase",
                    description=f"expected phrase {phrase!r} found "
                                f"({'exact case' if exact else 'case-insensitive'})",
                    confidence_label="High" if exact else "Medium",
                    offset=i, length=len(needle),
                    evidence={
                        "phrase": phrase,
                        "match": "exact" if exact else "case-insensitive",
                        "encoding": "raw bytes, UTF-8 compared",
                        "context": _printable(data[start:end]),
                        "context_offset": start,
                    },
                ))
                count += 1
                i = lowered.find(needle_lower, i + 1)
        res.properties["phrase_matches"] = len(res.findings)
        return res
