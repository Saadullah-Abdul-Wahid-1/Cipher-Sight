"""Clue-language detection, negation handling, structured patterns and positional clue helpers.

Clue terms are detection patterns. Finding one never means the nearby text is the answer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# group -> (strength key, terms). Multi-word terms are matched as token sequences.
CLUE_GROUPS: dict[str, tuple[str, tuple[str, ...]]] = {
    "password_strong": ("clue_strong", ("password", "passphrase", "passcode", "secret", "unlock", "pin")),
    "password_medium": ("clue_medium", ("key", "code", "pass", "remember", "clue", "hint", "answer")),
    "position": ("clue_weak", ("first", "last", "beginning", "ending", "start", "end", "middle",
                               "beneath", "above", "inside", "outside")),
    "selection": ("clue_weak", ("every second", "every other", "alternate", "odd", "even", "initial",
                                "initials", "first letter", "last letter", "capitalized", "acrostic")),
    "combination": ("clue_weak", ("join", "concatenate", "combine", "reverse", "backwards", "together",
                                  "without spaces")),
    "context": ("clue_context", ("pet", "birthplace", "favorite", "year", "name", "journey", "archive",
                                 "lighthouse", "shadow", "moon", "raven")),
}
NEGATORS = frozenset({"no", "not", "never", "without", "none", "nothing", "neither", "isn't", "don't",
                      "doesn't", "aren't", "wasn't", "won't"})
NEGATION_WINDOW = 3
SELECTION_GATES = {
    "acrostic_or_initials": ("initial", "initials", "first letter", "first letters", "acrostic"),
    "every_nth": ("every second", "every other", "alternate", "odd", "even"),
    "reverse": ("reverse", "reversed", "backwards"),
}

KEYVAL = re.compile(r"\b(password|passphrase|passcode|pass|key|secret|code|pin)\s*(?:=|:|\bis\b)\s*"
                    r"[\"']?([^\s\"',;]{1,64})", re.IGNORECASE)
QUOTED = re.compile(r"[\"\u201c]([^\"\u201d\n]{2,64})[\"\u201d]")
DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/\d{4}\b")
YEAR = re.compile(r"\b(?:19|20)\d{2}\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,10}\b")
URL = re.compile(r"https?://[^\s\"'<>]{1,200}")
NEGATED_BEFORE = re.compile(r"(?:\b(?:no|not|never|without|none|nothing|neither)\b\W*){1}(?:\w+\W+){0,2}$",
                            re.IGNORECASE)


@dataclass(frozen=True)
class ClueHit:
    term: str
    group: str
    strength: int           # weight key name, resolved against settings weights by the caller
    start: int              # character offset inside the segment


def find_clues(segment_text: str, tokens: list[tuple[str, int, int]]) -> list[ClueHit]:
    """Find clue terms in token order. A hit is dropped when a negator appears just before it."""
    lowered = [t[0].lower() for t in tokens]
    hits: list[ClueHit] = []
    for group, (strength, terms) in CLUE_GROUPS.items():
        for term in terms:
            parts = term.split()
            n = len(parts)
            for i in range(len(lowered) - n + 1):
                if lowered[i:i + n] != parts:
                    continue
                if not (term == "without spaces") and _negated(lowered, i):
                    continue
                hits.append(ClueHit(term, group, strength, tokens[i][1]))
    hits.sort(key=lambda h: h.start)
    return hits


def _negated(lowered: list[str], index: int) -> bool:
    before = lowered[max(0, index - NEGATION_WINDOW):index]
    return any(w in NEGATORS for w in before)


def gate_present(text_lower: str, gate: str) -> bool:
    return any(re.search(r"\b" + re.escape(t) + r"\b", text_lower) for t in SELECTION_GATES[gate])


def positional_clue_active(text_lower: str) -> bool:
    return gate_present(text_lower, "acrostic_or_initials")


def has_negated_key_clue(text: str, start: int) -> bool:
    prefix = text[max(0, start - 40):start]
    return bool(NEGATED_BEFORE.search(prefix))
