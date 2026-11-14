"""Tests for bounded GIF frame analysis."""
import io
import unittest

from PIL import Image

from imagehunter.analyzers.base import AnalyzerContext
from imagehunter.analyzers.image.animation import AnimatedImageAnalyzer
from imagehunter.config.settings import load_settings
from imagehunter.models.artifact import Artifact


class GifAnimationTests(unittest.TestCase):
    @staticmethod
    def make_gif(payload: bytes) -> bytes:
        bits = [(byte >> shift) & 1 for byte in payload for shift in range(7, -1, -1)]
        image = Image.new("P", (len(bits), 1))
        palette = [0, 0, 0, 1, 0, 0] + [0, 0, 0] * 254
        image.putpalette(palette)
        image.putdata(bits)
        out = io.BytesIO()
        image.save(out, format="GIF")
        return out.getvalue()

    def context(self, data: bytes, fmt="gif"):
        artifact = Artifact(id="A001", role="original", path="sample.gif", working_path="sample.gif",
                            sha256="0" * 64, size=len(data))
        return AnalyzerContext(artifact, data, load_settings(), {"detected_format": fmt})

    def test_extracts_flag_candidate_from_frame_lsb(self):
        data = self.make_gif(b"CTF{gif_frame_test}")
        result = AnimatedImageAnalyzer().run(self.context(data))
        self.assertTrue(any(f.evidence.get("text") == "CTF{gif_frame_test}" for f in result.findings))
        finding = next(f for f in result.findings if f.evidence.get("text") == "CTF{gif_frame_test}")
        self.assertEqual(finding.confidence_label, "Medium")
        self.assertEqual(finding.evidence["verification"], "candidate_only")

    def test_non_gif_is_skipped(self):
        result = AnimatedImageAnalyzer().run(self.context(b"not gif", "png"))
        self.assertIn("skipped", result.properties)
        self.assertFalse(result.findings)

    def test_frame_analysis_reports_limits_and_frame_count(self):
        data = self.make_gif(b"hello world")
        result = AnimatedImageAnalyzer().run(self.context(data))
        self.assertEqual(result.properties["frames_analyzed"], 1)
        self.assertEqual(result.properties["frame_count"], 1)
        self.assertLessEqual(result.properties["total_pixels"], AnimatedImageAnalyzer.MAX_TOTAL_PIXELS)


if __name__ == "__main__":
    unittest.main()
