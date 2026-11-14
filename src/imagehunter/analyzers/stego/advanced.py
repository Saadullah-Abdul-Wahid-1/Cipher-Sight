"""Bounded advanced steganography experiments.

Adds pixel-stride/offset and reverse traversal checks plus per-channel bit-plane
statistics. This is a heuristic extension, not a universal steganography detector.
"""
from __future__ import annotations

import re

from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.analyzers.stego.channels import to_pixel_array
from imagehunter.models.finding import Finding


def bitplane_statistics(arr, names: list[str]) -> dict:
    """Return reproducible entropy and one-bit ratios for every channel/bit plane."""
    import numpy as np

    output = {}
    for ci, name in enumerate(names):
        plane_stats = {}
        channel = arr[:, :, ci]
        for bit in range(8):
            bits = ((channel >> bit) & 1).astype(np.uint8)
            ones = int(bits.sum())
            total = int(bits.size)
            p1 = ones / total if total else 0.0
            p0 = 1.0 - p1
            entropy = 0.0
            for p in (p0, p1):
                if p > 0:
                    entropy -= p * __import__("math").log2(p)
            plane_stats[str(bit)] = {
                "ones_ratio": round(p1, 6),
                "zeros_ratio": round(p0, 6),
                "entropy_bits": round(entropy, 6),
            }
        output[name] = plane_stats
    return output


def _pack(bits, msb_first: bool) -> bytes:
    import numpy as np
    usable = (len(bits) // 8) * 8
    if usable < 8:
        return b""
    groups = bits[:usable].reshape(-1, 8).astype(np.uint16)
    weights = (128 >> np.arange(8)) if msb_first else (1 << np.arange(8))
    return (groups * weights.astype(np.uint16)).sum(axis=1).astype(np.uint8).tobytes()


class AdvancedStegoAnalyzer(Analyzer):
    """Search a bounded set of pixel skipping, offset, reverse, and bit-order layouts."""

    name = "stego.advanced"

    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        res = AnalyzerResult()
        fmt = ctx.shared.get("detected_format")
        if fmt not in ("png", "bmp"):
            res.properties["skipped"] = "advanced pixel-domain analysis currently supports PNG and BMP"
            return res
        try:
            from PIL import Image
            import io
            with Image.open(io.BytesIO(ctx.data)) as image:
                width, height = image.size
            if width * height > ctx.settings.max_pixels:
                res.properties["skipped"] = "image exceeds configured max_pixels"
                return res
            arr, names, mode = to_pixel_array(ctx.data)
        except Exception as exc:
            res.warnings.append(f"advanced stego analysis could not decode pixels: {type(exc).__name__}: {exc}")
            return res

        stats = bitplane_statistics(arr, names)
        res.properties.update(mode=mode, bitplane_statistics=stats)

        # Keep this search deliberately bounded. Existing LSB analysis handles contiguous
        # streams; this analyzer adds sparse/reversed layouts that it does not cover.
        prefixes = tuple(ctx.settings.flag_prefixes)
        pattern = re.compile(rb"(?:" + b"|".join(re.escape(p.encode("ascii")) for p in
                            sorted(prefixes, key=len, reverse=True)) + rb")\{[\x20-\x7e]{1,100}?\}")
        needles = tuple(p.encode("ascii") for p in prefixes)
        max_bytes = min(ctx.settings.stego_max_bytes, 8192)
        experiments = []
        for ci, channel in enumerate(names):
            for bit in (0, 1):
                plane = ((arr[:, :, ci] >> bit) & 1).reshape(-1)
                for stride in (2, 3):
                    for offset in range(stride):
                        for reverse in (False, True):
                            for msb_first in (False, True):
                                experiments.append((channel, bit, stride, offset, reverse, msb_first, plane))
        # Fixed cap protects against combinatorial growth on RGBA images.
        max_experiments = 48
        if len(experiments) > max_experiments:
            step = len(experiments) / max_experiments
            experiments = [experiments[int(i * step)] for i in range(max_experiments)]

        hits = {}
        for channel, bit, stride, offset, reverse, msb_first, plane in experiments:
            sampled = plane[offset::stride][: max_bytes * 8]
            if reverse:
                sampled = sampled[::-1]
            stream = _pack(sampled, msb_first)
            if not stream:
                continue
            # Single-byte XOR is tested only against configured flag prefixes.
            for key in range(256):
                raw = bytes(value ^ key for value in stream)
                if not any(needle in raw for needle in needles):
                    continue
                for match in pattern.finditer(raw):
                    value = match.group().decode("latin-1")
                    cfg = (channel, bit, stride, offset, reverse, msb_first, key, match.start())
                    hits.setdefault(value, set()).add(cfg)

        for value, configs in sorted(hits.items()):
            config_list = [
                {"channel": c, "bit_plane": b, "pixel_stride": s, "pixel_offset": o,
                 "reverse": rev, "bit_order": "MSB-first" if msb else "LSB-first",
                 "xor_key": f"0x{k:02X}", "byte_offset": pos}
                for c, b, s, o, rev, msb, k, pos in sorted(configs)
            ]
            res.findings.append(Finding(
                kind="advanced_lsb_flag_candidate", category="stego",
                description=f"flag-format text {value!r} recovered using sparse/reversed pixel traversal",
                confidence_label="High",
                evidence={"text": value, "experiments": config_list},
            ))
        res.properties.update(experiments_run=len(experiments), candidate_count=len(hits),
                              max_decoded_bytes=max_bytes,
                              search_scope={"bit_planes": [0, 1], "pixel_strides": [2, 3],
                                            "directions": ["forward", "reverse"],
                                            "xor_keys": 256, "max_experiments": max_experiments})
        return res
