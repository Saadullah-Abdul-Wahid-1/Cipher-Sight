"""Embedded signature scan and ZIP listing."""

from __future__ import annotations

import io
import zipfile

from imagehunter.analyzers.binary.signatures import EMBEDDED_SIGNATURES
from imagehunter.models.finding import Finding

MAX_ZIP_ENTRIES = 50


def scan_embedded(data: bytes, appended_from: int | None) -> list[Finding]:
    """Hits at or after `appended_from` are High (outside the image structure).
    Hits inside the structure are Low: compressed data can contain any byte pattern.
    Only the first hit per signature type is reported; the total count is recorded."""
    findings: list[Finding] = []
    for kind, sig in EMBEDDED_SIGNATURES:
        hits = _find_all(data, sig, start=1)
        if not hits:
            continue
        first = hits[0]
        outside = appended_from is not None and first >= appended_from
        evidence = {"signature": kind, "hit_count": len(hits), "inside_structure": not outside}
        if kind == "zip" and outside:
            evidence["zip_entries"], evidence["zip_encrypted"] = _list_zip(data[first:])
        findings.append(Finding(
            kind=f"embedded_{kind}",
            category="embedded",
            description=f"{kind.upper()} signature at offset {first}"
                        + (" after the image structure" if outside else " inside the image structure"),
            confidence_label="High" if outside else "Low",
            offset=first,
            length=len(data) - first if outside else None,
            evidence=evidence,
        ))
    return findings


def _find_all(data: bytes, sig: bytes, start: int = 0) -> list[int]:
    hits, i = [], data.find(sig, start)
    while i >= 0:
        hits.append(i)
        i = data.find(sig, i + 1)
    return hits


def _list_zip(blob: bytes) -> tuple[list[str], bool]:
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            names = zf.namelist()[:MAX_ZIP_ENTRIES]
            encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
            return names, encrypted
    except (zipfile.BadZipFile, ValueError, OSError):
        return [], False
