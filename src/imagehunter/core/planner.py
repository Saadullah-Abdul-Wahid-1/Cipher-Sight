"""Investigation planner: decides how hard the analysis should work, from cheap evidence.

The planner runs before the analyzers. It only inspects structure and signatures (no pixel decoding),
records each trigger with its evidence, and returns the settings the analyzers should use.

Modes:
  quick     no smart words, no decoding, single-channel LSB, no leads
  standard  current defaults (the behaviour of v0.10 and earlier)
  deep      3-channel LSB streams, leads on, deeper decoding, larger budgets
  auto      standard, escalated to deep when a trigger fires

Nothing here adds findings. The plan is recorded in the summary so the analyst can see why work was done.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

from imagehunter.analyzers.binary.analyzer import PARSERS
from imagehunter.analyzers.binary.signatures import IMAGE_EXTENSIONS, detect_format
from imagehunter.analyzers.carving.embedded import scan_embedded

MODES = ("quick", "standard", "deep", "auto")
DEEP_LIMITS = {"lsb_max_channels": 3, "lsb_unknown_prefix_leads": True, "decoding_max_depth": 4,
               "decoding_max_nodes": 6000, "decoding_xor_budget": 20_000_000}


@dataclass
class Plan:
    mode_requested: str
    mode_applied: str
    settings: object
    triggers: list = field(default_factory=list)
    decisions: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"mode_requested": self.mode_requested, "mode_applied": self.mode_applied,
                "triggers": self.triggers, "decisions": self.decisions}


def find_triggers(data: bytes, path: str) -> tuple[list, str | None, int | None]:
    """Cheap structural evidence that hidden or appended data may exist."""
    triggers = []
    fmt = detect_format(data[:16])
    ext = ""
    if "." in path.replace("\\", "/").rsplit("/", 1)[-1]:
        ext = "." + path.rsplit(".", 1)[-1].lower()
    if fmt is None:
        triggers.append({"trigger": "unknown_format", "detail": "no known file signature"})
    elif ext in IMAGE_EXTENSIONS and IMAGE_EXTENSIONS[ext] != fmt:
        triggers.append({"trigger": "extension_mismatch",
                         "detail": f"extension {ext} but contents are {fmt.upper()}"})

    structure_end = None
    if fmt in PARSERS:
        findings, structure_end = PARSERS[fmt](data)
        for f in findings:
            triggers.append({"trigger": f.kind, "detail": f.description})
        if structure_end is not None and structure_end < len(data):
            triggers.append({"trigger": "appended_data",
                             "detail": f"{len(data) - structure_end} bytes after the {fmt.upper()} structure"})
    for f in scan_embedded(data, appended_from=structure_end):
        if f.confidence_label == "High":
            triggers.append({"trigger": f.kind, "detail": f.description})
    return triggers, fmt, structure_end


def _with(settings, **changes):
    return dataclasses.replace(settings, **changes)


def _apply(settings, mode: str):
    if mode == "quick":
        return _with(settings, smart_words_enabled=False, decoding_enabled=False,
                     lsb_max_channels=1, lsb_unknown_prefix_leads=False)
    if mode == "deep":
        return _with(settings, lsb_max_channels=max(settings.lsb_max_channels, DEEP_LIMITS["lsb_max_channels"]),
                     lsb_unknown_prefix_leads=True,
                     decoding_max_depth=max(settings.decoding_max_depth, DEEP_LIMITS["decoding_max_depth"]),
                     decoding_max_nodes=max(settings.decoding_max_nodes, DEEP_LIMITS["decoding_max_nodes"]),
                     decoding_xor_budget=max(settings.decoding_xor_budget, DEEP_LIMITS["decoding_xor_budget"]))
    return settings                                     # standard


def plan_investigation(data: bytes, path: str, settings) -> Plan:
    requested = settings.investigation_mode
    if requested not in MODES:
        raise ValueError(f"unknown investigation_mode {requested!r}")
    triggers, fmt, _ = find_triggers(data, path)
    decisions = []
    if requested == "auto":
        applied = "deep" if triggers else "standard"
        decisions.append(f"auto: {'escalated to deep' if triggers else 'no triggers, standard budgets'}")
    else:
        applied = requested
        decisions.append(f"mode {requested} set by settings")
    if triggers:
        names = sorted({t["trigger"] for t in triggers})
        decisions.append("triggers: " + ", ".join(names))
    decisions.append(f"format {fmt or 'unknown'}")
    return Plan(requested, applied, _apply(settings, applied), triggers, decisions)
