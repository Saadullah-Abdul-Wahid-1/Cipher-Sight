"""Decoy assessment for flag-format candidates.

A decoy is a flag-shaped string that the challenge author planted to mislead
the analyst, usually with wording such as "not the flag" or "keep looking".

This module only *labels* a candidate as LIKELY DECOY and records why. It never
rejects or confirms anything: confirmation and rejection remain analyst
decisions (see report_data.classify_flags). A decoy label is therefore
reversible and every candidate stays visible in the report.

Two sources of evidence are checked:
  1. The flag body itself, after leetspeak normalisation
     (e.g. CTF{n0t_th3_fl4g_keep_l00king} -> "not the flag keep looking").
  2. Nearby text recovered from the same image (phrase contexts within a byte window).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Phrases are matched against normalised text, where separators such as _ - . and
# spaces are collapsed to single spaces. Keep entries lowercase and space-separated.
DECOY_PHRASES: tuple[str, ...] = (
    "not the flag",
    "not this flag",
    "not a flag",
    "not it",
    "fake flag",
    "false flag",
    "decoy",
    "keep looking",
    "keep searching",
    "keep digging",
    "try again",
    "nice try",
    "not correct",
    "this is not",
    "wrong flag",
    "not real",
    "nope",
)

# Leetspeak substitutions applied before phrase matching.
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_SEPARATORS = re.compile(r"[^a-z]+")
_PATTERNS = tuple(
    (phrase, re.compile(r"(?<![a-z])" + r"\s+".join(map(re.escape, phrase.split())) + r"(?![a-z])"))
    for phrase in DECOY_PHRASES
)

# Byte window around a flag finding in which nearby text counts as context.
CONTEXT_WINDOW_BYTES = 512


def normalise(text: str) -> str:
    """Lowercase, undo common leetspeak and turn every non-letter run into one space."""
    folded = text.lower().translate(_LEET)
    return " ".join(part for part in _SEPARATORS.split(folded) if part)


def decoy_phrases_in(text: str) -> list[str]:
    """Return the decoy phrases found in text, in table order, without duplicates."""
    normalised = normalise(text)
    return [phrase for phrase, pattern in _PATTERNS if pattern.search(normalised)]


@dataclass
class DecoyAssessment:
    is_likely_decoy: bool
    reasons: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return "LIKELY DECOY" if self.is_likely_decoy else "UNVERIFIED"


def assess_candidate(value: str, offset: int | None, context_items: list[dict]) -> DecoyAssessment:
    """Classify one flag-format candidate.

    value          the extracted flag text.
    offset         byte offset of the candidate in its source, if known.
    context_items  [{"offset": int, "text": str, "source": str}] of nearby text.

    A hit in the flag body or in nearby context marks it LIKELY DECOY. The reasons
    list says exactly which phrase matched and where, so an analyst can overrule it.
    """
    reasons: list[str] = []
    for phrase in decoy_phrases_in(value):
        reasons.append(f"flag text contains decoy wording {phrase!r}")

    for item in context_items:
        item_offset = item.get("offset")
        if offset is not None and item_offset is not None and abs(item_offset - offset) > CONTEXT_WINDOW_BYTES:
            continue
        for phrase in decoy_phrases_in(item.get("text", "")):
            reasons.append(f"nearby text from {item.get('source', 'image')} contains {phrase!r}")

    return DecoyAssessment(is_likely_decoy=bool(reasons), reasons=reasons)


def context_items_from_findings(findings: list[dict]) -> list[dict]:
    """Collect nearby-text items (expected-phrase contexts) from a summary's findings."""
    items = []
    for f in findings:
        ev = f.get("evidence", {})
        text = ev.get("context")
        if not text:
            continue
        items.append({"offset": ev.get("context_offset", f.get("offset")), "text": text,
                      "source": f.get("id", "finding")})
    return items
