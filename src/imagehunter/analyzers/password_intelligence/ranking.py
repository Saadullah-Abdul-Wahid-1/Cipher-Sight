"""Explainable scoring, deduplication and priority labels.

The score is an analyst-review priority from 0 to 100. It is not a probability, and it is never a
statement that a candidate is the password. Every component is returned in the breakdown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from imagehunter.analyzers.password_intelligence.normalize import casefold_key

PHRASE_TYPES = frozenset({"phrase", "every_nth", "first_letters", "acrostic"})
HIGH_AT = 50
MEDIUM_AT = 30
MAX_OCCURRENCES = 10
MAX_VARIANTS = 10
MIXED = re.compile(r"[a-z][A-Z]|[A-Za-z]\d|\d[A-Za-z]")


@dataclass
class Instance:
    value: str
    ctype: str
    chain: list[str]
    source: str
    offset: int
    context: str
    token_norms: list[str]
    clue_points: int = 0          # already weighted, from the strongest nearby clue
    phrase_near: bool = False
    date_near: bool = False
    caps_digits: bool = False
    stopword_only: bool = False


@dataclass
class Group:
    key: str
    instances: list[Instance] = field(default_factory=list)


def group_instances(instances: list[Instance]) -> dict[str, Group]:
    groups: dict[str, Group] = {}
    for inst in instances:
        key = casefold_key(inst.value)
        groups.setdefault(key, Group(key)).instances.append(inst)
    return groups


def has_caps_or_digits(value: str) -> bool:
    return bool(MIXED.search(value)) or (any(c.isdigit() for c in value) and any(c.isalpha() for c in value))


def score_group(group: Group, weights: dict[str, int], freq: dict[str, int], common: frozenset[str]) -> dict:
    insts = group.instances
    sources = {i.source for i in insts}
    clue = max((i.clue_points for i in insts), default=0)
    phrase = any(i.phrase_near and i.ctype in PHRASE_TYPES for i in insts)
    caps = any(i.caps_digits for i in insts)
    date = any(i.date_near for i in insts)
    rarity = _rarity(insts, weights, freq, common)
    corr = min(weights["corroboration"], 5 * (len(sources) - 1)) if len(sources) >= 2 else 0
    breakdown = {
        "clue_context": clue,
        "rarity": rarity,
        "corroboration": corr,
        "phrase_near_clue": weights["phrase_near_clue"] if phrase else 0,
        "caps_or_digits": weights["caps_digits"] if caps else 0,
        "date_near_clue": weights["date_near_clue"] if date else 0,
    }
    # A transformed form only counts as transformed if no untransformed form of it was found.
    plain = any(not i.chain for i in insts)
    penalty = weights["transform_penalty"] if (not plain and any(i.chain for i in insts)) else 0
    breakdown["transform_penalty"] = -penalty
    total = max(0, min(100, sum(breakdown.values())))
    return {"score": total, "breakdown": breakdown, "source_count": len(sources)}


def _rarity(insts, weights, freq, common) -> int:
    best = 0
    for inst in insts:
        norms = [t for t in inst.token_norms if t not in common]
        if not norms:
            continue
        lowest = min(freq.get(t, 1) for t in norms)
        if lowest == 1 and max(len(t) for t in norms) >= 5:
            best = max(best, weights["rarity"])
        elif lowest <= 3:
            best = max(best, weights["rarity"] // 2)
    return best


def priority_of(score: int) -> str:
    if score >= HIGH_AT:
        return "High"
    if score >= MEDIUM_AT:
        return "Medium"
    return "Low"


def reasons_for(breakdown: dict) -> list[str]:
    text = {
        "transform_penalty": "transformed form only (penalty applied)",
        "clue_context": "clue language nearby",
        "rarity": "rare token in this artifact",
        "corroboration": "repeated in independent sources",
        "phrase_near_clue": "phrase appears near clue language",
        "caps_or_digits": "unusual capitalization or digits",
        "date_near_clue": "date or year near clue language",
    }
    return [text[k] for k, v in breakdown.items() if v != 0]


def build_candidates(groups: dict[str, Group], weights: dict[str, int], freq: dict[str, int],
                     common: frozenset[str], min_score: int, include_low: bool) -> list[dict]:
    out = []
    for key, group in groups.items():
        scored = score_group(group, weights, freq, common)
        if scored["score"] < min_score:
            continue
        prio = priority_of(scored["score"])
        if prio == "Low" and not include_low:
            continue
        best = max(group.instances, key=lambda i: (i.clue_points, len(i.value), -len(i.chain), i.value))
        types = sorted({i.ctype for i in group.instances})
        occ = []
        seen = set()
        for inst in sorted(group.instances, key=lambda i: (i.source, i.offset)):
            marker = (inst.source, inst.offset)
            if marker in seen or len(occ) >= MAX_OCCURRENCES:
                continue
            seen.add(marker)
            occ.append({"source": inst.source, "offset": inst.offset, "context": inst.context,
                        "transform_chain": inst.chain})
        variants = sorted({i.value for i in group.instances})[:MAX_VARIANTS]
        out.append({
            "value": best.value,
            "type": best.ctype,
            "types": types,
            "transform_chain": best.chain,
            "score": scored["score"],
            "priority": prio,
            "breakdown": scored["breakdown"],
            "reasons": reasons_for(scored["breakdown"]),
            "source_count": scored["source_count"],
            "occurrences": occ,
            "variants": variants,
            "status": "candidate",
        })
    out.sort(key=lambda c: (-c["score"], casefold_key(c["value"]), c["type"], c["value"]))
    return out
