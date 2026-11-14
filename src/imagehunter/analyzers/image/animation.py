"""Bounded animated-image analysis focused on GIF frame-level evidence."""
from __future__ import annotations

import io
import re

from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.models.finding import Finding


class AnimatedImageAnalyzer(Analyzer):
    """Inspect GIF frames independently without writing extracted frames to disk."""

    name = "image.animation"
    MAX_FRAMES = 100
    MAX_TOTAL_PIXELS = 20_000_000

    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        result = AnalyzerResult()
        if ctx.shared.get("detected_format") != "gif":
            result.properties["skipped"] = "frame analysis currently targets GIF files"
            return result

        try:
            from PIL import Image, ImageChops
            image = Image.open(io.BytesIO(ctx.data))
            frame_count = min(int(getattr(image, "n_frames", 1)), self.MAX_FRAMES)
            total_pixels = 0
            previous = None
            frame_rows = []
            candidates = {}
            prefixes = sorted((p.encode("ascii") for p in ctx.settings.flag_prefixes), key=len, reverse=True)
            flag_re = re.compile(rb"(?:" + b"|".join(re.escape(p) for p in prefixes) + rb")\{[\x20-\x7e]{1,100}?\}")

            for index in range(frame_count):
                image.seek(index)
                frame = image.convert("RGB")
                pixels = frame.width * frame.height
                if pixels > ctx.settings.max_pixels or total_pixels + pixels > self.MAX_TOTAL_PIXELS:
                    result.warnings.append(f"GIF frame {index} skipped: cumulative pixel budget reached")
                    break
                total_pixels += pixels
                duration = image.info.get("duration")
                disposal = getattr(image, "disposal_method", None)
                changed_ratio = None
                if previous is not None:
                    import numpy as np
                    diff = ImageChops.difference(previous, frame).convert("L")
                    changed = int(np.count_nonzero(np.asarray(diff)))
                    changed_ratio = round(changed / pixels, 6) if pixels else 0.0
                frame_rows.append({"index": index, "width": frame.width, "height": frame.height,
                                   "duration_ms": duration, "disposal": disposal,
                                   "changed_pixel_ratio": changed_ratio})

                # Examine only the red-channel LSB stream; this keeps work predictable.
                import numpy as np
                red = np.frombuffer(frame.getchannel("R").tobytes(), dtype=np.uint8)
                packed = np.packbits(red & 1, bitorder="big")
                stream = packed[:ctx.settings.stego_max_bytes].tobytes()
                for match in flag_re.finditer(stream):
                    text = match.group().decode("ascii", errors="replace")
                    candidates.setdefault(text, []).append({"frame": index, "channel": "R", "bit_plane": 0,
                                                            "bit_order": "MSB-first", "byte_offset": match.start()})
                previous = frame.copy()

            result.properties.update(frame_count=int(getattr(image, "n_frames", 1)),
                                     frames_analyzed=len(frame_rows), total_pixels=total_pixels,
                                     frame_details=frame_rows,
                                     limits={"max_frames": self.MAX_FRAMES,
                                             "max_total_pixels": self.MAX_TOTAL_PIXELS})
            for text, locations in sorted(candidates.items()):
                result.findings.append(Finding(
                    kind="gif_frame_lsb_flag_candidate", category="stego",
                    description=f"Flag-shaped text recovered from GIF frame pixel data: {text}",
                    confidence_label="Medium",
                    evidence={"text": text, "locations": locations, "verification": "candidate_only"}))
            image.close()
        except Exception as exc:
            result.warnings.append(f"GIF frame analysis failed safely: {type(exc).__name__}: {exc}")
        return result
