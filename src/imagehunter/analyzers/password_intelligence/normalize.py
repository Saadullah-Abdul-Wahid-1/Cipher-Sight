"""Normalization and tokenization. Evidence text is never modified; these functions return new strings."""

from __future__ import annotations

import re
import unicodedata

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_REPEAT = re.compile(r"(.)\1{9,}")
# Letters/digits, with internal apostrophes (incl. typographic) and hyphens. Underscore splits.
TOKEN = re.compile(r"[^\W_]+(?:['\u2019\-][^\W_]+)*")


def normalize(text: str) -> str:
    """NFC, line endings, control characters. Internal spacing is kept, so phrase candidates keep the
    original spacing. Only leading and trailing spaces on each line are removed."""
    t = unicodedata.normalize("NFC", text)
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    t = _CONTROL.sub(" ", t)
    return "\n".join(line.strip(" \t") for line in t.split("\n"))


def is_binary_like(text: str) -> bool:
    if not text:
        return True
    bad = sum(1 for c in text if not (c.isprintable() or c in "\n\t"))
    return bad / len(text) > 0.2


_WORD = re.compile(r"[A-Za-z]{3,}")
# Frequent English letter pairs. Real text has many of them; random letters rarely do.
_COMMON_PAIRS = frozenset(
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve "
    "co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur".split())


def looks_like_text(text: str) -> bool:
    """Keep a run only if most of it is letters, it has a 3+ letter word, and its letter pairs look
    like English. Printable runs from compressed data ('013C306', 'BHvb') fail the pair test."""
    if not text:
        return False
    letters = sum(1 for c in text if c.isalpha())
    if letters / len(text) < 0.5 or not _WORD.search(text):
        return False
    pairs = 0
    common = 0
    for word in re.findall(r"[A-Za-z]+", text):
        w = word.lower()
        for i in range(len(w) - 1):
            pairs += 1
            if w[i:i + 2] in _COMMON_PAIRS:
                common += 1
    if pairs < 6:
        return False
    return common / pairs >= 0.2


def is_repetitive(text: str) -> bool:
    return bool(_REPEAT.search(text))


def casefold_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()
