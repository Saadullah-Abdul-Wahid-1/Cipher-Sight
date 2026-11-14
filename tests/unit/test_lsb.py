"""Phase 4: LSB / bit-plane extraction, checked with known-answer fixtures (encoder in generate.py)."""

import io
import tempfile
import unittest

import numpy as np
from PIL import Image

from imagehunter.analyzers.base import AnalyzerContext
from imagehunter.analyzers.stego.analyzer import LsbFlagAnalyzer
from imagehunter.analyzers.stego.channels import alpha_stats, render_bitplane, to_pixel_array
from imagehunter.analyzers.stego.lsb import flag_pattern, pack_bits, scan_pixels
from imagehunter.config.settings import Settings
from imagehunter.models.artifact import Artifact
from tests.fixtures.generate import embed_lsb, make_noise_rgb, make_png, make_signal_hunt_like, REAL_FLAG, DECOY_FLAG

PREFIXES = ("THM", "CTF", "FLAG", "flag", "HTB", "picoCTF")


def _png_bytes(arr, mode="RGB"):
    buf = io.BytesIO()
    Image.fromarray(arr, mode).save(buf, format="PNG")
    return buf.getvalue()


def _ctx(data: bytes, name="x.png", settings=None, detected="png"):
    art = Artifact(id="A001", role="original", path=name, working_path=name,
                   sha256="0" * 64, size=len(data))
    return AnalyzerContext(artifact=art, data=data, settings=settings or Settings(),
                           shared={"detected_format": detected})


class UnknownPrefixDefaultTests(unittest.TestCase):
    def test_default_analyzer_reports_unknown_prefix_leetspeak_as_weak_candidate(self):
        arr = make_noise_rgb(96, 64, 4242)
        value = "RHL{t3st_fl4g_lsb_42}"
        embed_lsb(arr, 0, 0, "row", "MSB-first", value.encode(), xor_key=0, start_index=0)
        data = _png_bytes(arr)
        result = LsbFlagAnalyzer().run(_ctx(data))
        self.assertTrue(Settings().lsb_unknown_prefix_leads)
        self.assertIn(value, [f.evidence.get("text") for f in result.findings])
        hit = next(f for f in result.findings if f.evidence.get("text") == value)
        self.assertEqual(hit.kind, "lsb_unknown_prefix_lead")
        self.assertEqual(hit.confidence_label, "Low")


class PatternTests(unittest.TestCase):
    def test_prefix_pattern_matches_only_configured_prefixes(self):
        p = flag_pattern(PREFIXES)
        self.assertEqual(p.findall(b"x " + REAL_FLAG.encode() + b" y"), [REAL_FLAG.encode()])
        self.assertEqual(p.findall(b"CTF{a b} flag{x}"), [b"CTF{a b}", b"flag{x}"])
        self.assertEqual(p.findall(b"random {{{{ junk }}"), [])

    def test_body_stops_at_first_closing_brace(self):
        self.assertEqual(flag_pattern(PREFIXES).findall(b"THM{a}b}"), [b"THM{a}"])


class PackBitsTests(unittest.TestCase):
    def test_lsb_first_and_msb_first(self):
        bits = np.array([1, 0, 0, 0, 0, 0, 0, 0], dtype=np.uint8)
        self.assertEqual(pack_bits(bits, "LSB-first").tolist(), [1])
        self.assertEqual(pack_bits(bits, "MSB-first").tolist(), [128])

    def test_partial_byte_dropped(self):
        self.assertEqual(pack_bits(np.ones(12, dtype=np.uint8), "LSB-first").tolist(), [255])


class KnownAnswerTests(unittest.TestCase):
    """Embed a payload with a known configuration, then check the analyzer recovers exactly that configuration."""

    def _find(self, arr, channels, configs_expected):
        hits = scan_pixels(arr, channels, max_bytes=65536, prefixes=PREFIXES)
        return {(h.text, h.channel, h.bit, h.traversal, h.bit_order, h.xor_key) for h in hits}

    def test_row_lsb_first_plain(self):
        arr = make_noise_rgb(64, 48, 1)
        embed_lsb(arr, 1, 0, "row", "LSB-first", b"CTF{row_lsb}", 0, 0)
        found = self._find(arr, ["R", "G", "B"], None)
        self.assertIn(("CTF{row_lsb}", "G", 0, "row", "LSB-first", 0), found)

    def test_column_msb_first_with_xor(self):
        arr = make_noise_rgb(64, 48, 2)
        embed_lsb(arr, 0, 0, "column", "MSB-first", b"flag{col_msb}", xor_key=0x5A, start_index=0)
        found = self._find(arr, ["R", "G", "B"], None)
        self.assertIn(("flag{col_msb}", "R", 0, "column", "MSB-first", 0x5A), found)

    def test_higher_bit_plane_is_found(self):
        arr = make_noise_rgb(64, 48, 3)
        embed_lsb(arr, 2, 3, "row", "LSB-first", b"HTB{plane3}", 0, 0)
        found = self._find(arr, ["R", "G", "B"], None)
        self.assertIn(("HTB{plane3}", "B", 3, "row", "LSB-first", 0), found)
        self.assertFalse([f for f in found if f[2] == 0 and f[0] == "HTB{plane3}"])

    def test_alpha_channel_payload(self):
        rgba = np.dstack([make_noise_rgb(64, 48, 4), np.full((48, 64), 255, np.uint8)])
        embed_lsb(rgba, 3, 0, "row", "LSB-first", b"THM{alpha}", 0, 0)
        data = _png_bytes(rgba, "RGBA")
        res = LsbFlagAnalyzer().run(_ctx(data))
        self.assertEqual([f.evidence["text"] for f in res.findings], ["THM{alpha}"])
        self.assertEqual(res.findings[0].evidence["experiments"][0]["channel"], "A")
        self.assertTrue(res.properties["alpha"]["present"])

    def test_grayscale_payload(self):
        gray = make_noise_rgb(64, 48, 5)[:, :, 0].copy()
        arr3 = gray[:, :, None]
        embed_lsb(arr3, 0, 0, "row", "LSB-first", b"CTF{gray}", 0, 0)
        res = LsbFlagAnalyzer().run(_ctx(_png_bytes(arr3[:, :, 0], "L")))
        self.assertEqual([f.evidence["text"] for f in res.findings], ["CTF{gray}"])
        self.assertEqual(res.properties["mode"], "L")

    def test_clean_noise_has_no_findings(self):
        data = _png_bytes(make_noise_rgb(128, 96, 6))
        res = LsbFlagAnalyzer().run(_ctx(data))
        self.assertEqual(res.findings, [])
        self.assertEqual(res.warnings, [])


class AnalyzerBehaviourTests(unittest.TestCase):
    def test_signal_hunt_like_image_yields_both_layers_with_exact_locations(self):
        res = LsbFlagAnalyzer().run(_ctx(make_signal_hunt_like()))
        flags = [f for f in res.findings if f.kind == "lsb_flag_candidate"]
        by_text = {f.evidence["text"]: f for f in flags}
        self.assertEqual(set(by_text), {REAL_FLAG, DECOY_FLAG})

        real = by_text[REAL_FLAG]
        self.assertEqual(real.evidence["first_pixel"], [37, 0])
        want = {"channel": "B", "bit": 0, "traversal": "column", "bit_order": "LSB-first", "xor_key": 0x37}
        self.assertTrue(any(all(e.get(k) == v for k, v in want.items()) for e in real.evidence["experiments"]))
        self.assertEqual(real.confidence_label, "High")

        decoy = by_text[DECOY_FLAG]
        self.assertEqual(decoy.evidence["first_pixel"], [0, 0])
        want = {"channel": "R", "bit": 0, "traversal": "row", "bit_order": "MSB-first", "xor_key": 0}
        self.assertTrue(any(all(e.get(k) == v for k, v in want.items()) for e in decoy.evidence["experiments"]))

    def test_jpeg_is_skipped_with_reason(self):
        res = LsbFlagAnalyzer().run(_ctx(b"\xff\xd8\xff\xe0junk", name="x.jpg", detected="jpeg"))
        self.assertIn("lossless", res.properties["skipped"])
        self.assertEqual(res.findings, [])

    def test_oversized_image_skipped_with_warning(self):
        settings = Settings(max_pixels=100)            # 20x20 = 400 pixels > 100
        res = LsbFlagAnalyzer().run(_ctx(_png_bytes(make_noise_rgb(20, 20, 9)), settings=settings))
        self.assertTrue(res.warnings)
        self.assertIn("max_pixels", res.warnings[0])

    def test_bitplane_render_matches_source_bit(self):
        arr = make_noise_rgb(16, 8, 7)
        arr[:, :, 1] = 0b10101010
        plane = render_bitplane(arr, "G", 1, ["R", "G", "B"])
        self.assertEqual(plane.mode, "L")
        self.assertEqual(plane.size, (16, 8))
        self.assertEqual(set(np.array(plane).ravel().tolist()), {255})

    def test_alpha_stats_absent_for_rgb(self):
        arr = make_noise_rgb(4, 4, 8)
        self.assertEqual(alpha_stats(arr, ["R", "G", "B"]), {"present": False})


if __name__ == "__main__":
    unittest.main()
