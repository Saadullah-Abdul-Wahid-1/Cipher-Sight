"""Bounded candidate transformations. Each returns (value, chain-step) pairs; the caller keeps the original."""

from __future__ import annotations

LEET = {"a": ("@", "4"), "e": ("3",), "i": ("1",), "o": ("0",), "s": ("$", "5"), "t": ("7",)}


def case_variants(value: str) -> list[tuple[str, str]]:
    out = []
    for step, form in (("lowercase", value.lower()), ("uppercase", value.upper()), ("title_case", value.title())):
        if form != value:
            out.append((form, step))
    return out


def leet_variants(value: str, max_variants: int) -> list[tuple[str, str]]:
    """The fully substituted form plus single substitutions, never a Cartesian product."""
    if len(value) > 24:
        return []
    out: list[tuple[str, str]] = []
    full = "".join(LEET.get(c.lower(), (c,))[0] if c.lower() in LEET else c for c in value)
    if full != value:
        out.append((full, "leetspeak:all"))
    for i, c in enumerate(value):
        for sub in LEET.get(c.lower(), ()):
            if len(out) >= max_variants:
                return out
            candidate = value[:i] + sub + value[i + 1:]
            if candidate != value:
                out.append((candidate, f"leetspeak:pos{i}"))
    return out[:max_variants]


def separator_variants(phrase: str) -> list[tuple[str, str]]:
    if " " not in phrase:
        return []
    return [(phrase.replace(" ", ""), "separator:none"),
            (phrase.replace(" ", "-"), "separator:hyphen"),
            (phrase.replace(" ", "_"), "separator:underscore")]


def reverse_variant(value: str) -> tuple[str, str]:
    return value[::-1], "reverse"
