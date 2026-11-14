"""Phase 2 unit tests: format detection, structure parsers on malformed input, Pillow identity, strings."""

import os
import tempfile
import unittest
from pathlib import Path

from imagehunter.analyzers.base import AnalyzerContext
from imagehunter.analyzers.binary.signatures import detect_format
from imagehunter.analyzers.binary.structure import parse_bmp, parse_jpeg, parse_png
from imagehunter.analyzers.image.identity import ImageIdentityAnalyzer
from imagehunter.analyzers.text.strings import StringsAnalyzer
from imagehunter.config.settings import Settings
from imagehunter.models.artifact import Artifact
from tests.fixtures.generate import make_png, make_real_samples


def _ctx(path: str, data: bytes, settings=None, shared=None):
    art = Artifact(id="A001", role="original", path=path, working_path=path,
                   sha256="0" * 64, size=len(data))
    return AnalyzerContext(artifact=art, data=data, settings=settings or Settings(), shared=shared or {})


class DetectFormatTests(unittest.TestCase):
    def test_known_signatures(self):
        self.assertEqual(detect_format(make_png()[:16]), "png")
        self.assertEqual(detect_format(b"PK\x03\x04rest"), "zip")
        self.assertEqual(detect_format(b"GIF89a....."), "gif")
        self.assertIsNone(detect_format(b"\x00\x01\x02"))


class MalformedStructureTests(unittest.TestCase):
    """Malformed input must yield findings, never exceptions or hangs."""

    def test_png_huge_chunk_length_is_truncated(self):
        findings, end = parse_png(b"\x89PNG\r\n\x1a\n" + b"\xff\xff\xff\xff" + b"IDAT" + b"abc")
        self.assertIsNone(end)
        self.assertEqual(findings[0].kind, "png_truncated")

    def test_png_only_signature_is_truncated(self):
        findings, end = parse_png(b"\x89PNG\r\n\x1a\n")
        self.assertIsNone(end)
        self.assertEqual(findings[0].kind, "png_truncated")

    def test_jpeg_scan_without_eoi_is_truncated(self):
        findings, end = parse_jpeg(b"\xff\xd8\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x12\x34")
        self.assertIsNone(end)
        self.assertEqual(findings[0].kind, "jpeg_truncated")

    def test_jpeg_bad_marker_is_malformed(self):
        findings, end = parse_jpeg(b"\xff\xd8\x12\x34\x56")
        self.assertIsNone(end)
        self.assertEqual(findings[0].kind, "jpeg_malformed")

    def test_jpeg_zero_length_segment_rejected(self):
        _, end = parse_jpeg(b"\xff\xd8\xff\xe0\x00\x00\x00\x00")
        self.assertIsNone(end)

    def test_bmp_implausible_size_rejected(self):
        findings, end = parse_bmp(b"BM" + b"\x00\x00\x00\x00" + b"\x00" * 20)
        self.assertIsNone(end)
        self.assertEqual(findings[0].kind, "bmp_malformed")


class IdentityAnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.samples = make_real_samples()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _run(self, name, data):
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return ImageIdentityAnalyzer().run(_ctx(path, data))

    def test_real_jpeg_properties(self):
        res = self._run("real.jpg", self.samples["real.jpg"])
        self.assertEqual(res.properties["pillow_format"], "JPEG")
        self.assertEqual((res.properties["width"], res.properties["height"]), (8, 6))
        self.assertEqual(res.properties["mode"], "RGB")
        self.assertEqual(res.properties["frames"], 1)
        self.assertEqual(res.findings, [])

    def test_real_bmp_properties(self):
        res = self._run("real.bmp", self.samples["real.bmp"])
        self.assertEqual(res.properties["pillow_format"], "BMP")
        self.assertEqual((res.properties["width"], res.properties["height"]), (8, 6))
        self.assertEqual(res.properties["mode"], "RGB")

    def test_animated_gif_frame_count(self):
        res = self._run("anim.gif", self.samples["anim.gif"])
        self.assertEqual(res.properties["pillow_format"], "GIF")
        self.assertEqual(res.properties["frames"], 2)
        self.assertEqual((res.properties["width"], res.properties["height"]), (4, 4))

    def test_clean_png_grayscale_mode(self):
        res = self._run("clean.png", make_png())
        self.assertEqual(res.properties["mode"], "L")
        self.assertEqual(res.properties["signature_format"], "png")

    def test_misnamed_file_gets_high_extension_mismatch(self):
        res = self._run("renamed.jpg", make_png())
        f = res.findings[0]
        self.assertEqual(f.kind, "extension_mismatch")
        self.assertEqual(f.confidence_label, "High")
        self.assertEqual(f.evidence["detected_format"], "png")

    def test_unknown_signature_is_low_finding(self):
        res = self._run("noise.bin", b"\x00\x01\x02\x03" * 10)
        self.assertEqual(res.findings[0].kind, "unknown_format")
        self.assertEqual(res.findings[0].confidence_label, "Low")
        self.assertTrue(res.warnings)  # Pillow cannot open it: a warning, not a crash

    def test_undecodable_jpeg_structure_is_warning_not_error(self):
        from tests.fixtures.generate import make_jpeg_structure
        res = self._run("synthetic.jpg", make_jpeg_structure())
        self.assertEqual(res.properties["signature_format"], "jpeg")
        self.assertIsInstance(res.warnings, list)  # either decodes or warns; never raises

    def test_empty_bytes_do_not_crash(self):
        res = self._run("empty.bin", b"\x01")
        self.assertIsNone(res.properties["signature_format"])


class StringsAnalyzerTests(unittest.TestCase):
    def test_finds_strings_with_offsets(self):
        data = b"\x00\x00CTF{hello_world}\x00\x01ab\x00flag"
        res = StringsAnalyzer().run(_ctx("x.bin", data, Settings(min_string_length=4)))
        texts = {s["text"]: s["offset"] for s in res.properties["strings"]}
        self.assertEqual(texts["CTF{hello_world}"], 2)
        self.assertIn("flag", texts)
        self.assertNotIn("ab", texts)  # shorter than min_string_length

    def test_list_capped_but_count_complete(self):
        data = b"\x00".join([b"string%02d" % i for i in range(10)])
        res = StringsAnalyzer().run(_ctx("x.bin", data, Settings(max_strings=3)))
        self.assertEqual(res.properties["string_count"], 10)
        self.assertEqual(len(res.properties["strings"]), 3)
        self.assertTrue(res.properties["list_truncated"])


if __name__ == "__main__":
    unittest.main()
