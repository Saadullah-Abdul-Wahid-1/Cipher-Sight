"""Splits normalized text into lines and sentences, keeping the boundaries needed for positional clues."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from imagehunter.analyzers.password_intelligence.normalize import TOKEN

# A sentence ends at . ! or ? only when whitespace or the line end follows, so "a.b@example.org" and
# "example.org" stay whole.
_SENTENCE = re.compile(r"(?:[^.!?]|[.!?](?=\S))+[.!?]*")


@dataclass
class Segment:
    source: str
    base: int                              # approximate byte offset of the source text
    text: str                              # one sentence, normalized, original spacing kept
    tokens: list[tuple[str, int, int]] = field(default_factory=list)   # (value, start, end) in text


@dataclass
class SourceSplit:
    segments: list[Segment]
    line_first_letters: list[str]          # first letter of each non-empty line (acrostic input)


def split_source(source: str, base: int, normalized: str) -> SourceSplit:
    segments: list[Segment] = []
    first_letters: list[str] = []
    for line in normalized.split("\n"):
        if not line.strip():
            continue
        m = TOKEN.search(line)
        if m:
            first_letters.append(m.group()[0])
        for piece in _SENTENCE.finditer(line):
            text = piece.group().strip()
            tokens = [(t.group(), t.start(), t.end()) for t in TOKEN.finditer(text)]
            if tokens:
                segments.append(Segment(source=source, base=base, text=text, tokens=tokens))
    return SourceSplit(segments=segments, line_first_letters=first_letters)
