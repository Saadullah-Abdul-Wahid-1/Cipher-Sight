"""Bounded indexed-palette and palette-index steganography inspection."""
from __future__ import annotations

import io
import re
from collections import Counter

import numpy as np
from PIL import Image

from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.models.finding import Finding


class PaletteAnalyzer(Analyzer):
    """Inspect indexed images without treating unusual palettes as proof of steganography."""

    name = "image.palette"

    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        result = AnalyzerResult()
        try:
            with Image.open(io.BytesIO(ctx.data)) as image:
                if image.mode != "P":
                    result.properties["skipped"] = f"indexed palette analysis not applicable to mode {image.mode}"
                    return result
                width, height = image.size
                pixels = width * height
                if pixels <= 0 or pixels > ctx.settings.max_pixels:
                    result.warnings.append(
                        f"palette analysis skipped: {pixels} pixels exceeds limit {ctx.settings.max_pixels}"
                    )
                    return result

                indices = np.asarray(image, dtype=np.uint8).reshape(-1)
                counts = np.bincount(indices, minlength=256)
                palette = image.getpalette() or []
                palette_entries = min(len(palette) // 3, 256)
                used = int(np.count_nonzero(counts[:palette_entries]))
                unused = [i for i in range(palette_entries) if counts[i] == 0]
                used_colors = []
                for index in range(palette_entries):
                    if counts[index]:
                        start = index * 3
                        used_colors.append((palette[start] if len(palette) > start else 0,
                                            palette[start + 1] if len(palette) > start + 1 else 0,
                                            palette[start + 2] if len(palette) > start + 2 else 0))
                unique_rgb = len(set(used_colors))
                result.properties.update(
                    indexed=True, palette_entries=palette_entries, used_indices=used,
                    unused_palette_indices=unused[:128], unused_indices_truncated=len(unused) > 128,
                    unique_used_rgb_colors=unique_rgb,
                    most_used_indices=[{"index": int(i), "pixels": int(counts[i])}
                                       for i in np.argsort(counts)[::-1][:min(10, used)] if counts[i]],
                    index_lsb_one_ratio=round(float(np.mean(indices & 1)), 6),
                )

                prefixes = sorted((p.encode("ascii") for p in ctx.settings.flag_prefixes), key=len, reverse=True)
                pattern = re.compile(rb"(?:" + b"|".join(re.escape(p) for p in prefixes)
                                     + rb")\{[\x20-\x7e]{1,100}?\}")
                packed = np.packbits(indices & 1, bitorder="big")
                stream = packed[:ctx.settings.stego_max_bytes].tobytes()
                matches = list(pattern.finditer(stream))
                for match in matches:
                    candidate = match.group().decode("ascii", errors="replace")
                    result.findings.append(Finding(
                        kind="palette_index_lsb_flag_candidate", category="stego",
                        description=f"Flag-shaped text recovered from indexed pixel values: {candidate}",
                        confidence_label="Medium",
                        evidence={"text": candidate, "method": "palette-index LSB, MSB-first",
                                  "byte_offset": match.start(), "verification": "candidate_only"}))

        except Exception as exc:
            result.warnings.append(f"palette analysis failed safely: {type(exc).__name__}: {exc}")
        return result
