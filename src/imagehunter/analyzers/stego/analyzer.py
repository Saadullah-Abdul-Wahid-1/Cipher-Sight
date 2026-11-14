"""LSB / bit-plane analyzer. Runs only on lossless formats (PNG, BMP)."""

from __future__ import annotations

from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.analyzers.stego.channels import alpha_stats, to_pixel_array
from imagehunter.analyzers.stego.lsb import channel_sequences, readable_body, scan_sequences
from imagehunter.models.finding import Finding

LOSSLESS = ("png", "bmp")


def rank_flag_groups(grouped):
    """Order distinct flag-format texts for analyst review. Returns [(text, group, score, breakdown)].

    Score (higher is more worth reviewing):
      support       10 per independent experiment that recovered the text, capped at 4 experiments
      readable       5 if the body looks like language or a CTF-style phrase
      plane0         4 if recovered from the least significant bit plane
      plain          3 if recovered with no XOR at all
    Ties keep the earlier position in the image. This ranking cannot tell a decoy from the real flag
    when both are equally simple; it only orders them for review.
    """
    scored = []
    for text, group in grouped.items():
        body = text.split("{", 1)[1].rstrip("}").encode("latin-1") if "{" in text else b""
        breakdown = {
            "support": 10 * min(len(group), 4),
            "readable": 5 if readable_body(body) else 0,
            "plane0": 4 if any(h.bit == 0 for h in group) else 0,
            "plain": 3 if any(h.xor_key == 0 and not h.key for h in group) else 0,
        }
        first_pos = min(h.pixel_index for h in group)
        scored.append((-sum(breakdown.values()), first_pos, text, group, breakdown))
    scored.sort(key=lambda item: (item[0], item[1], item[2]))
    return [(text, group, -neg, breakdown) for neg, _, text, group, breakdown in scored]


class LsbFlagAnalyzer(Analyzer):
    name = "stego.lsb"

    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        res = AnalyzerResult()
        fmt = ctx.shared.get("detected_format")
        if fmt not in LOSSLESS:
            res.properties["skipped"] = (f"LSB analysis needs a lossless format (PNG or BMP); "
                                         f"detected {fmt or 'unknown'}")
            return res

        max_pixels = ctx.settings.max_pixels
        try:
            from PIL import Image
            import io
            with Image.open(io.BytesIO(ctx.data)) as probe:
                w, h = probe.size
            if w * h > max_pixels:
                res.warnings.append(f"LSB scan skipped: {w}x{h} exceeds max_pixels={max_pixels}")
                res.properties["skipped"] = "image too large for the configured max_pixels"
                return res
            arr, names, mode = to_pixel_array(ctx.data)
        except Exception as exc:  # decode failure is a warning, never a crash
            res.warnings.append(f"LSB scan skipped: could not decode pixels ({type(exc).__name__}: {exc})")
            return res

        res.properties.update(mode=mode, channels=names, alpha=alpha_stats(arr, names),
                              experiments=len(channel_sequences(names, ctx.settings.lsb_max_channels)) * 8 * 2 * 2 * 256)

        settings = ctx.settings
        flag_hits, lead_hits = scan_sequences(
            arr, names, settings.stego_max_bytes, settings.flag_prefixes,
            max_channels=settings.lsb_max_channels, leads=settings.lsb_unknown_prefix_leads,
            repeating_key_max=settings.lsb_repeating_key_max)
        hits = flag_hits

        # One finding per distinct text. Keep every experiment that produced it as evidence.
        grouped: dict[str, list[LsbHit]] = {}
        for h in hits:
            grouped.setdefault(h.text, []).append(h)

        ranked = rank_flag_groups(grouped)
        for rank, (text, group, score, breakdown) in enumerate(ranked, start=1):
            first = min(group, key=lambda h: (h.pixel_index, h.channel, h.bit))
            configs = [
                {"channel": h.channel, "bit": h.bit, "traversal": h.traversal,
                 "bit_order": h.bit_order, "xor_key": h.xor_key, "bit_shift": h.bit_shift,
                 "xor_key_hex": h.key.hex() if h.key else f"{h.xor_key:02X}"}
                for h in group
            ]
            key_text = (f"repeating xor key {first.key.hex()}" if first.key
                        else f"xor 0x{first.xor_key:02X}")
            shift_text = f", bit shift {first.bit_shift}" if first.bit_shift else ""
            note = ""
            if len(ranked) > 1:
                note = (f" [rank {rank} of {len(ranked)}; several flag-format texts were recovered, "
                        f"review all of them. The ranking is a review aid, not verification.]")
            res.findings.append(Finding(
                kind="lsb_flag_candidate",
                category="stego",
                description=f"flag-format text {text!r} decoded from LSB data "
                            f"(channel {first.channel}, bit {first.bit}, {first.traversal} order, "
                            f"{first.bit_order}, {key_text}{shift_text}); first pixel {first.first_pixel}.{note}",
                confidence_label="High",
                offset=first.pixel_index,
                evidence={"text": text, "experiments": configs,
                          "first_pixel": list(first.first_pixel), "byte_offset": first.byte_offset,
                          "rank": rank, "candidates_total": len(ranked),
                          "rank_score": score, "rank_breakdown": breakdown},
            ))

        # Unknown-prefix leads: readable text, prefix not configured. Low confidence, never a candidate.
        lead_groups: dict[str, list[LsbHit]] = {}
        for h in lead_hits:
            lead_groups.setdefault(h.text, []).append(h)
        for text, group in lead_groups.items():
            first = min(group, key=lambda h: (h.pixel_index, h.channel, h.bit))
            res.findings.append(Finding(
                kind="lsb_unknown_prefix_lead",
                category="stego",
                description=f"readable text {text!r} with an unconfigured prefix (channel {first.channel}, "
                            f"bit {first.bit}, {first.traversal} order, {first.bit_order}, "
                            f"xor 0x{first.xor_key:02X}). Lead only: add the prefix to flag_prefixes to "
                            f"report it as a candidate.",
                confidence_label="Low",
                offset=first.pixel_index,
                evidence={"text": text,
                          "experiments": [{"channel": h.channel, "bit": h.bit, "traversal": h.traversal,
                                           "bit_order": h.bit_order, "xor_key": h.xor_key} for h in group],
                          "first_pixel": list(first.first_pixel), "byte_offset": first.byte_offset},
            ))
        res.properties["lead_count"] = len(lead_groups)
        res.properties["channel_sequences"] = len(channel_sequences(names, settings.lsb_max_channels))
        res.properties["candidate_count"] = len(grouped)
        return res
