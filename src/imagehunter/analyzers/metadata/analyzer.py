"""Metadata analyzer: PNG text and profile chunks, EXIF/GPS, XMP summary, and anomaly checks.

Values are recorded as properties with their location. Findings are raised only for things that
deserve review: flag-shaped text inside metadata, oversized blocks, conflicting timestamps and
GPS coordinates. Ordinary comments do not create findings.

Privacy: GPS coordinates are shown only in the local report. Nothing is sent over the network.
"""

from __future__ import annotations

from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.analyzers.metadata.exif import read_exif, timestamp_conflicts
from imagehunter.analyzers.metadata.png_text import XMP_KEYWORD, parse_png_text, xmp_summary
from imagehunter.analyzers.stego.lsb import flag_pattern
from imagehunter.models.finding import Finding

PRIVACY_NOTE = ("GPS coordinates, if present, are shown only in this local report. "
                "CipherSight does not transmit them or the image.")
MAX_TEXT_IN_PROPS = 300


class MetadataAnalyzer(Analyzer):
    name = "metadata.extract"

    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        res = AnalyzerResult()
        data = ctx.data
        cap = ctx.settings.metadata_max_bytes
        pattern = flag_pattern(ctx.settings.flag_prefixes)

        records, icc_info, warnings, oversized = parse_png_text(data, cap)
        res.warnings.extend(warnings)
        res.properties["png_text"] = [
            {"chunk": r.chunk, "offset": r.offset, "keyword": r.keyword,
             "text": r.text[:MAX_TEXT_IN_PROPS], "text_truncated": len(r.text) > MAX_TEXT_IN_PROPS,
             "compressed": r.compressed, "length": r.length}
            for r in records
        ]
        res.properties["icc_profile"] = icc_info.get("icc_profile")
        texts = ctx.shared.setdefault("metadata_texts", [])
        for r in records:
            if r.keyword != XMP_KEYWORD.decode():
                texts.append((f"metadata:{r.chunk} {r.keyword}", r.offset, r.text))

        xmp_records = [r for r in records if r.keyword == XMP_KEYWORD.decode()]
        if xmp_records:
            res.properties["xmp"] = xmp_summary(xmp_records[0])
        else:
            res.properties["xmp"] = None

        for block in oversized:
            res.findings.append(Finding(
                kind="metadata_large_block", category="metadata",
                description=f"{block['chunk']} block at offset {block['offset']} exceeds the "
                            f"{cap}-byte metadata limit and was not read in full",
                confidence_label="Medium", offset=block["offset"],
                evidence={"chunk": block["chunk"], "keyword": block["keyword"], "limit": cap},
            ))

        # Flag-shaped text inside metadata is a candidate, same rule as LSB matches.
        for r in records:
            for m in pattern.finditer(r.raw_bytes):
                res.findings.append(self._flag(m.group().decode("latin-1"), f"{r.chunk} keyword "
                                               f"{r.keyword!r} at offset {r.offset}", r.offset,
                                               {"chunk": r.chunk, "keyword": r.keyword}))

        exif = read_exif(data)
        res.warnings.extend(exif["warnings"])
        res.properties["exif"] = {
            "present": exif["present"],
            "fields": exif["fields"],
            "timestamps": exif["timestamps"],
            "gps": exif["gps"],
            "privacy_note": PRIVACY_NOTE if exif["gps"] else None,
        }
        for tag, value in exif["fields"].items():
            raw = value.encode("utf-8", errors="replace")
            for m in pattern.finditer(raw):
                res.findings.append(self._flag(m.group().decode("latin-1"), f"EXIF {tag}", None,
                                               {"exif_field": tag}))

        for tag, value in exif["fields"].items():
            ctx.shared.setdefault("metadata_texts", []).append((f"metadata:EXIF {tag}", 0, value))

        conflicts = timestamp_conflicts(exif["timestamps"])
        for a, va, b, vb in conflicts:
            res.findings.append(Finding(
                kind="metadata_timestamp_conflict", category="metadata",
                description=f"EXIF {a} ({va}) and {b} ({vb}) disagree",
                confidence_label="Medium",
                evidence={"field_a": a, "value_a": va, "field_b": b, "value_b": vb},
            ))

        if exif["gps"]:
            res.findings.append(Finding(
                kind="metadata_gps_present", category="metadata",
                description="GPS coordinates are present in EXIF. " + PRIVACY_NOTE,
                confidence_label="Medium",
                evidence={"gps": exif["gps"], "privacy": PRIVACY_NOTE},
            ))

        res.properties["counts"] = {"png_text": len(records), "oversized": len(oversized),
                                    "exif_fields": len(exif["fields"])}
        return res

    @staticmethod
    def _flag(text: str, where: str, offset, evidence: dict) -> Finding:
        ev = dict(evidence)
        ev.update({"text": text, "location": where})
        return Finding(
            kind="metadata_flag_candidate", category="metadata",
            description=f"flag-format text {text!r} found in metadata ({where})",
            confidence_label="High", offset=offset, evidence=ev,
        )
