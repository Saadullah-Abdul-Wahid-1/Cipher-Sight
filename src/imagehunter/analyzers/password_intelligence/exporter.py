"""Export ranked candidates. Exports can contain sensitive text: the CLI and GUI warn before writing.

TXT is a plain wordlist: one candidate value per line, in ranking order, no scores.
JSON keeps the full record: score, breakdown, provenance and transformation chain.
Output is deterministic for identical inputs.
"""

from __future__ import annotations

import json
from pathlib import Path

WARNING = ("Exported candidates may contain sensitive text from the image. Store and share them carefully. "
           "They are unverified candidates, not confirmed passwords.")


def smart_block(summary: dict) -> dict:
    return (summary.get("properties", {}) or {}).get("text.smart_words", {}) or {}


def write_txt(path: str | Path, summary: dict) -> int:
    seen, lines = set(), []
    for c in smart_block(summary).get("candidates", []):
        if c["value"] not in seen:
            seen.add(c["value"])
            lines.append(c["value"])
    Path(path).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return len(lines)


def write_json(path: str | Path, summary: dict) -> int:
    block = smart_block(summary)
    doc = {
        "warning": WARNING,
        "scan_id": summary.get("scan_id"),
        "source_file": summary.get("input", {}).get("path"),
        "source_sha256": summary.get("input", {}).get("sha256"),
        "note": block.get("note"),
        "total_candidates": block.get("total_candidates", 0),
        "returned": block.get("returned", 0),
        "truncated": block.get("truncated", False),
        "candidates": block.get("candidates", []),
    }
    Path(path).write_text(json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    return len(doc["candidates"])
