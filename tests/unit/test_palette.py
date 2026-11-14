"""Tests for indexed-palette inspection and candidate provenance."""
import io
import unittest

from PIL import Image

from imagehunter.analyzers.base import AnalyzerContext
from imagehunter.analyzers.image.palette import PaletteAnalyzer
from imagehunter.config.settings import load_settings
from imagehunter.models.artifact import Artifact


class PaletteAnalyzerTests(unittest.TestCase):
    def context(self, data, max_pixels=20_000_000):
        from dataclasses import replace
        artifact = Artifact(id="A001", role="original", path="indexed.png",
                            working_path="indexed.png", sha256="0" * 64, size=len(data))
        settings = replace(load_settings(), max_pixels=max_pixels)
        return AnalyzerContext(artifact, data, settings, {})

    @staticmethod
    def make_indexed(payload=b"ordinary"):
        bits = [(byte >> shift) & 1 for byte in payload for shift in range(7, -1, -1)]
        image = Image.new("P", (len(bits), 1))
        image.putpalette([0, 0, 0, 255, 255, 255] + [0, 0, 0] * 254)
        image.putdata(bits)
        out = io.BytesIO()
        image.save(out, format="PNG")
        return out.getvalue()

    def test_reports_palette_inventory(self):
        result = PaletteAnalyzer().run(self.context(self.make_indexed()))
        self.assertTrue(result.properties["indexed"])
        self.assertEqual(result.properties["used_indices"], 2)
        self.assertIn("unused_palette_indices", result.properties)

    def test_recovers_palette_index_lsb_candidate(self):
        result = PaletteAnalyzer().run(self.context(self.make_indexed(b"CTF{palette_test}")))
        finding = next(f for f in result.findings
                       if f.kind == "palette_index_lsb_flag_candidate")
        self.assertEqual(finding.evidence["text"], "CTF{palette_test}")
        self.assertEqual(finding.evidence["verification"], "candidate_only")

    def test_non_indexed_image_is_skipped(self):
        image = Image.new("RGB", (2, 2), (10, 20, 30))
        out = io.BytesIO()
        image.save(out, format="PNG")
        result = PaletteAnalyzer().run(self.context(out.getvalue()))
        self.assertIn("skipped", result.properties)

    def test_pixel_limit_is_respected(self):
        result = PaletteAnalyzer().run(self.context(self.make_indexed(), max_pixels=1))
        self.assertTrue(any("exceeds limit" in w for w in result.warnings))


if __name__ == "__main__":
    unittest.main()
