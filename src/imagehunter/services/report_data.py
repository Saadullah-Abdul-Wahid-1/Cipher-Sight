"""Builds one report view from the scan summary dict.

The HTML report, the GUI dashboard and the tests all read from this view, so the
numbers shown in each place come from the same code and cannot drift apart.

Verification status rules:
  Candidate  every regex or pattern match starts here. This is the only default.
  Confirmed  only when an analyst decision (verifications mapping) says so.
  Rejected   only when an analyst decision says so.
  Likely Decoy  set automatically when decoy wording appears in the flag text or nearby text.
                It is a label with recorded reasons; an analyst decision can still override it.
No automatic process ever sets Confirmed or Rejected.
"""

from __future__ import annotations

import importlib
import platform
import sys
from datetime import datetime
from pathlib import Path

from imagehunter.core.status import CANCELLED, ERROR, FINDINGS, PARTIAL, SKIPPED, count_by_status
from imagehunter.services.flag_triage import assess_candidate, context_items_from_findings

VERIFICATION_STATUSES = ("Confirmed", "Candidate", "Likely Decoy", "Rejected")
_DECISIONS = {"confirmed": "Confirmed", "rejected": "Rejected"}

# Modules the report must describe as "not executed" when they are absent.
PLANNED_MODULES = {
    "metadata": ("Metadata (EXIF, XMP, IPTC, GPS)", "Phase 3 is not implemented in this build."),
    "decoders": ("Decoded representations (UTF-8, UTF-16, Base64, hex)",
                 "Decoder stage is not implemented in this build."),
    "extraction": ("Embedded payload extraction", "Embedded data is detected but not extracted."),
    "palette": ("Palette (indexed colour) analysis", "Not implemented in this build."),
    "jpeg_stego": ("JPEG steganography tools", "Not implemented; only JPEG marker structure is parsed."),
}


def _parse_ts(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def duration_seconds(started: str | None, finished: str | None) -> float | None:
    a, b = _parse_ts(started), _parse_ts(finished)
    if a is None or b is None:
        return None
    return round((b - a).total_seconds(), 3)


def classify_flags(summary: dict, verifications: dict[str, str] | None = None) -> dict:
    """Split flag-format matches into confirmed, candidate and rejected lists.

    verifications maps a flag value to 'confirmed' or 'rejected'. Any other value is an error.
    """
    verifications = verifications or {}
    for value, decision in verifications.items():
        if decision not in _DECISIONS:
            raise ValueError(f"unknown verification decision {decision!r} for {value!r}")

    source = Path(summary.get("input", {}).get("path", "")).name or "unknown"
    out = {"Confirmed": [], "Candidate": [], "Rejected": [], "Likely Decoy": [],
           "Strong Candidate": [], "Weak Candidate": []}
    all_findings = summary.get("findings", [])
    context_items = context_items_from_findings(all_findings)
    seen_values = set()
    for f in all_findings:
        if f.get("kind") not in ("lsb_flag_candidate", "lsb_unknown_prefix_lead", "metadata_flag_candidate", "decoded_flag_candidate", "derived_flag_candidate", "palette_index_lsb_flag_candidate", "ocr_flag_candidate"):
            continue
        ev = f.get("evidence", {})
        value = ev.get("text", "")
        if value and value in seen_values:
            continue
        if value:
            seen_values.add(value)
        status = _DECISIONS.get(verifications.get(value, ""), "Candidate")
        decoy_reasons: list[str] = []
        if status == "Candidate":
            # Labelling only: an analyst decision above always wins, and a decoy label
            # never rejects the candidate. It stays listed with its reasons.
            assessment = assess_candidate(value, ev.get("byte_offset", f.get("offset")), context_items)
            if assessment.is_likely_decoy:
                status = "Likely Decoy"
                decoy_reasons = assessment.reasons
        experiments = ev.get("experiments", [])
        first = experiments[0] if experiments else {}
        if f.get("kind") == "metadata_flag_candidate":
            technique = f"metadata text: {ev.get('location', '')}"
        elif f.get("kind") == "decoded_flag_candidate":
            technique = f"decoded: {ev.get('chain_text', '')}"
        else:
            technique = (f"LSB bit plane {first.get('bit')}, channel {first.get('channel')}, "
                         f"{first.get('traversal')} order, {first.get('bit_order')}, "
                         f"XOR key 0x{first.get('xor_key', 0):02X}") if first else ""
        tier = ("Verified" if status == "Confirmed" else
                "Weak Candidate" if f.get("confidence_label") == "Low" else "Strong Candidate")
        if status == "Candidate":
            out[tier].append({"value": value, "status": tier, "source_file": source,
                              "method": f.get("method", ""), "evidence_ref": f.get("id", ""),
                              "confidence": f.get("confidence_label", "")})
        out[status].append({
            "value": value,
            "evidence_tier": tier,
            "status": status,
            "decoy_reasons": decoy_reasons,
            "source_file": source,
            "method": f.get("method", ""),
            "technique": technique,
            "byte_offset": ev.get("byte_offset", f.get("offset")),
            "pixel_index": f.get("offset"),
            "first_pixel": ev.get("first_pixel"),
            "evidence_ref": f.get("id", ""),
            "experiments": experiments,
            "confidence": f.get("confidence_label", ""),
        })
    return {"confirmed": out["Confirmed"], "candidates": out["Candidate"], "rejected": out["Rejected"],
            "likely_decoys": out["Likely Decoy"],
            "verified": out["Confirmed"], "strong_candidates": out["Strong Candidate"],
            "weak_candidates": out["Weak Candidate"]}


def phrase_matches(summary: dict) -> list[dict]:
    source = Path(summary.get("input", {}).get("path", "")).name or "unknown"
    rows = []
    for f in summary.get("findings", []):
        if f.get("kind") != "expected_phrase":
            continue
        ev = f.get("evidence", {})
        rows.append({
            "phrase": ev.get("phrase", ""),
            "source_file": source,
            "method": f.get("method", ""),
            "encoding": ev.get("encoding", ""),
            "offset": f.get("offset"),
            "context": ev.get("context", ""),
            "match": ev.get("match", ""),
            "confidence": f.get("confidence_label", ""),
            "evidence_ref": f.get("id", ""),
        })
    return rows


def _embedded(summary: dict) -> list[dict]:
    return [f for f in summary.get("findings", []) if f.get("category") == "embedded"]


def _tool_versions() -> dict:
    from imagehunter import __version__
    versions = {"ImageHunter": __version__, "Python": platform.python_version(),
                "Platform": f"{platform.system()} {platform.release()}"}
    for module, label in (("PIL", "Pillow"), ("numpy", "numpy")):
        try:
            versions[label] = getattr(importlib.import_module(module), "__version__", "unknown")
        except ImportError:
            versions[label] = "not installed"
    return versions


def build_view(summary: dict, verifications: dict[str, str] | None = None) -> dict:
    identity = summary.get("properties", {}).get("image.identity", {})
    inp = summary.get("input", {})
    flags = classify_flags(summary, verifications)
    phrases = phrase_matches(summary)
    analyzers = summary.get("analyzers", [])
    errors = [a for a in analyzers if a.get("status") == ERROR]
    counts = count_by_status(analyzers)
    dims = None
    if identity.get("width") and identity.get("height"):
        dims = f"{identity['width']} x {identity['height']}"
    metrics = {
        "modules_total": counts["total"],
        "modules_executed": counts["executed"],
        "modules_with_findings": counts[FINDINGS],
        "modules_partial": counts[PARTIAL],
        "modules_skipped": counts[SKIPPED],
        "modules_failed": counts[ERROR],
        "modules_cancelled": counts[CANCELLED],
        "total_findings": len(summary.get("findings", [])),
        "confirmed_flags": len(flags["confirmed"]),
        "flag_candidates": len(flags["candidates"]),
        "rejected_flags": len(flags["rejected"]),
        "likely_decoy_flags": len(flags["likely_decoys"]),
        "phrase_matches": len(phrases),
        "embedded_items": len(_embedded(summary)),
        "warnings": len(summary.get("warnings", [])),
        "errors": (sum(1 for e in summary.get("execution_log", []) if e.get("level") == "ERROR")
                   or len(errors)),
        "duration_seconds": duration_seconds(summary.get("started_at"), summary.get("finished_at")),
    }
    return {
        "file_name": Path(inp.get("path", "")).name or "unknown",
        "file_path": inp.get("path", ""),
        "started_at": summary.get("started_at"),
        "finished_at": summary.get("finished_at"),
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "duration_seconds": metrics["duration_seconds"],
        "format": identity.get("pillow_format") or identity.get("signature_format") or "unknown",
        "signature_format": identity.get("signature_format"),
        "size": inp.get("size"),
        "dimensions": dims,
        "mode": identity.get("mode"),
        "frames": identity.get("frames"),
        "sha256": inp.get("sha256"),
        "status": summary.get("status"),
        "scan_id": summary.get("scan_id"),
        "analyzers": analyzers,
        "warnings": summary.get("warnings", []),
        "properties": summary.get("properties", {}),
        "findings": summary.get("findings", []),
        "flags": flags,
        "phrases": phrases,
        "embedded": _embedded(summary),
        "execution_log": summary.get("execution_log", []),
        "limitations": summary.get("limitations", []),
        "workspace": summary.get("workspace", ""),
        "planned_modules": PLANNED_MODULES,
        "tool_versions": _tool_versions(),
        "metrics": metrics,
    }
