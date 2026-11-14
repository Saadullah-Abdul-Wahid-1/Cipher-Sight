"""Identifies the real format, checks the extension, and reads image properties with Pillow.

Decoder failures become warnings, not findings: a file Pillow cannot open may still
hold data we want to inspect.
"""

from __future__ import annotations

import io
from pathlib import Path

from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.analyzers.binary.signatures import IMAGE_EXTENSIONS, detect_format
from imagehunter.models.finding import Finding


def _frame_count(img) -> int:
    try:
        return int(getattr(img, "n_frames", 1))
    except Exception:
        return 1


class ImageIdentityAnalyzer(Analyzer):
    name = "image.identity"

    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        from PIL import Image

        res = AnalyzerResult()
        data = ctx.data
        name = Path(ctx.artifact.path).name
        ext = Path(ctx.artifact.path).suffix.lower()
        fmt = detect_format(data[:16])
        ctx.shared["detected_format"] = fmt

        res.properties.update(signature_format=fmt, extension=ext, file_size=len(data))

        expected = IMAGE_EXTENSIONS.get(ext)
        if fmt is None:
            res.findings.append(Finding(
                kind="unknown_format", category="identity",
                description="no known file signature at offset 0",
                confidence_label="Low", offset=0,
            ))
        elif expected is not None and fmt != expected:
            res.findings.append(Finding(
                kind="extension_mismatch", category="identity",
                description=f"{name!r} has an image extension but its contents are {fmt.upper()}",
                confidence_label="High", offset=0,
                evidence={"extension": ext, "expected_format": expected, "detected_format": fmt},
            ))

        try:
            with Image.open(io.BytesIO(data)) as img:
                res.properties.update(
                    pillow_format=img.format,
                    mode=img.mode,
                    width=img.width,
                    height=img.height,
                    frames=_frame_count(img),
                )
        except Exception as exc:  # any decoder failure is a warning, never a crash
            res.warnings.append(f"decoder warning: Pillow could not read the image ({type(exc).__name__}: {exc})")
        return res
