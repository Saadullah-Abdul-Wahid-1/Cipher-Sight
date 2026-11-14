"""Metadata analyzer: PNG text chunks, compression limits, XMP summary, EXIF, GPS privacy, anomalies."""

import zlib
import unittest

from imagehunter.analyzers.base import AnalyzerContext
from imagehunter.analyzers.metadata.analyzer import MetadataAnalyzer, PRIVACY_NOTE
from imagehunter.analyzers.metadata.png_text import XMP_KEYWORD, parse_png_text
from imagehunter.config.settings import Settings
from imagehunter.models.artifact import Artifact
from tests.fixtures.generate import (DECOY_FLAG, REAL_FLAG, make_exif_jpeg, make_png,
                                     make_png_with_chunks)


def _ctx(data: bytes, settings: Settings | None = None, name="x.png"):
    art = Artifact(id="A001", role="original", path=name, working_path=name, sha256="0" * 64, size=len(data))
    return AnalyzerContext(artifact=art, data=data, settings=settings or Settings(), shared={})


def _run(data: bytes, settings: Settings | None = None, name="x.png"):
    return MetadataAnalyzer().run(_ctx(data, settings, name))


def _text(keyword: bytes, value: bytes) -> bytes:
    return keyword + b"\x00" + value


def _ztxt(keyword: bytes, value: bytes) -> bytes:
    return keyword + b"\x00\x00" + zlib.compress(value)


def _itxt(keyword: bytes, value: bytes, compressed=False) -> bytes:
    body = keyword + b"\x00" + bytes([1 if compressed else 0, 0]) + b"\x00" + b"\x00"
    return body + (zlib.compress(value) if compressed else value)


class PngTextTests(unittest.TestCase):
    def test_tEXt_zTXt_iTXt_all_read_with_offsets(self):
        data = make_png_with_chunks([
            (b"tEXt", _text(b"Author", b"alice")),
            (b"zTXt", _ztxt(b"Comment", b"compressed hello")),
            (b"iTXt", _itxt(b"Note", "unicode ✓".encode("utf-8"))),
        ])
        res = _run(data)
        props = {r["keyword"]: r for r in res.properties["png_text"]}
        self.assertEqual(props["Author"]["text"], "alice")
        self.assertEqual(props["Comment"]["text"], "compressed hello")
        self.assertTrue(props["Comment"]["compressed"])
        self.assertEqual(props["Note"]["text"], "unicode ✓")
        self.assertGreater(props["Author"]["offset"], 0)
        self.assertEqual(res.findings, [])          # ordinary comments are not findings

    def test_flag_inside_compressed_text_is_a_candidate(self):
        data = make_png_with_chunks([(b"zTXt", _ztxt(b"Comment", ("note: " + REAL_FLAG).encode()))])
        res = _run(data)
        flags = [f for f in res.findings if f.kind == "metadata_flag_candidate"]
        self.assertEqual([f.evidence["text"] for f in flags], [REAL_FLAG])
        self.assertEqual(flags[0].confidence_label, "High")
        self.assertEqual(flags[0].evidence["chunk"], "zTXt")

    def test_flag_in_plain_text_and_xmp_both_found(self):
        xmp = b"<x:xmpmeta><rdf:Description><xmp:CreatorTool>Tool " + DECOY_FLAG.encode() + b"</xmp:CreatorTool></rdf:Description></x:xmpmeta>"
        data = make_png_with_chunks([(b"tEXt", _text(b"Title", REAL_FLAG.encode())),
                                     (b"iTXt", _itxt(XMP_KEYWORD, xmp))])
        found = {f.evidence["text"] for f in _run(data).findings if f.kind == "metadata_flag_candidate"}
        self.assertEqual(found, {REAL_FLAG, DECOY_FLAG})

    def test_oversized_text_reported_not_read(self):
        big = b"A" * 5000
        data = make_png_with_chunks([(b"tEXt", _text(b"Blob", big))])
        res = _run(data, Settings(metadata_max_bytes=1024))
        kinds = [f.kind for f in res.findings]
        self.assertIn("metadata_large_block", kinds)
        self.assertEqual([r["keyword"] for r in res.properties["png_text"]], [])

    def test_decompression_bomb_is_capped(self):
        bomb = zlib.compress(b"\x00" * 5_000_000)           # 5 MB out, tiny in
        data = make_png_with_chunks([(b"zTXt", b"Bomb\x00\x00" + bomb)])
        self.assertLess(len(bomb), 20_000)
        res = _run(data, Settings(metadata_max_bytes=65536))
        self.assertIn("metadata_large_block", [f.kind for f in res.findings])

    def test_corrupt_compressed_chunk_is_warning_not_crash(self):
        data = make_png_with_chunks([(b"zTXt", b"Broken\x00\x00not-zlib-data")])
        res = _run(data)
        self.assertTrue(any("invalid" in w for w in res.warnings))

    def test_truncated_png_does_not_crash(self):
        data = make_png_with_chunks([(b"tEXt", _text(b"A", b"b"))])[:40]
        records, info, warnings, oversized = parse_png_text(data, 65536)
        self.assertEqual(records, [])

    def test_clean_png_no_findings(self):
        res = _run(make_png())
        self.assertEqual(res.findings, [])
        self.assertEqual(res.properties["png_text"], [])


class ExifTests(unittest.TestCase):
    def test_timestamp_conflict_is_a_finding(self):
        data = make_exif_jpeg({"DateTime": "2026:01:01 10:00:00", "DateTimeOriginal": "2024:05:05 08:00:00"})
        res = _run(data, name="x.jpg")
        conflicts = [f for f in res.findings if f.kind == "metadata_timestamp_conflict"]
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].confidence_label, "Medium")

    def test_equal_timestamps_are_not_a_conflict(self):
        data = make_exif_jpeg({"DateTime": "2026:01:01 10:00:00", "DateTimeOriginal": "2026:01:01 10:00:00"})
        self.assertFalse([f for f in _run(data, name="x.jpg").findings if f.kind == "metadata_timestamp_conflict"])

    def test_gps_present_gives_privacy_warning_and_no_network(self):
        data = make_exif_jpeg(gps=True)
        res = _run(data, name="x.jpg")
        gps = [f for f in res.findings if f.kind == "metadata_gps_present"]
        self.assertEqual(len(gps), 1)
        self.assertIn(PRIVACY_NOTE, gps[0].description)
        self.assertIsNotNone(res.properties["exif"]["gps"])
        self.assertEqual(res.properties["exif"]["privacy_note"], PRIVACY_NOTE)

    def test_exif_software_and_flag_in_comment_field(self):
        data = make_exif_jpeg(software="Tool " + REAL_FLAG)
        res = _run(data, name="x.jpg")
        self.assertEqual(res.properties["exif"]["fields"]["Software"], "Tool " + REAL_FLAG)
        self.assertIn(REAL_FLAG, [f.evidence["text"] for f in res.findings if f.kind == "metadata_flag_candidate"])

    def test_jpeg_without_exif_has_no_findings(self):
        from PIL import Image
        import io
        buf = io.BytesIO(); Image.new("RGB", (8, 8)).save(buf, format="JPEG")
        res = _run(buf.getvalue(), name="plain.jpg")
        self.assertFalse(res.properties["exif"]["present"])
        self.assertEqual(res.findings, [])

    def test_random_bytes_do_not_crash(self):
        import os
        res = _run(os.urandom(2048), name="noise.bin")
        self.assertIsNotNone(res)


if __name__ == "__main__":
    unittest.main()
