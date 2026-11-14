"""End-to-end: run_scan on synthetic fixtures, compared with recorded ground truth."""

import tempfile
import unittest

from pathlib import Path

from imagehunter.core.status import EXECUTED
from imagehunter.core.pipeline import run_scan
from imagehunter.services.hash_service import sha256_file
from tests.fixtures.generate import build_fixtures, write_fixtures


class FixtureGroundTruthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.fixtures = {fx.filename: fx for fx in build_fixtures()}
        write_fixtures(root / "samples")
        cls.summaries = {name: run_scan(root / "samples" / name, workspace_base=root / "ws")
                         for name in cls.fixtures}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _findings(self, name, kind=None):
        return [f for f in self.summaries[name].findings if kind is None or f.kind == kind]

    def test_every_fixture_has_exactly_the_expected_finding_kinds(self):
        for name, fx in self.fixtures.items():
            with self.subTest(fixture=name):
                self.assertEqual({f.kind for f in self.summaries[name].findings}, fx.expect_kinds)

    def test_every_expected_offset_matches_ground_truth(self):
        for name, fx in self.fixtures.items():
            for kind, offset in fx.expect_offsets.items():
                with self.subTest(fixture=name, kind=kind):
                    found = self._findings(name, kind)
                    self.assertTrue(found)
                    self.assertEqual(found[0].offset, offset)

    def test_clean_png_has_no_findings_and_completed_status(self):
        s = self.summaries["clean.png"]
        self.assertEqual(s.findings, [])
        self.assertEqual(s.status, "completed")

    def test_appended_zip_details(self):
        zip_f = self._findings("appended_zip.png", "embedded_zip")[0]
        self.assertEqual(zip_f.confidence_label, "High")
        self.assertEqual(zip_f.evidence["zip_entries"], ["flag.txt"])
        self.assertFalse(zip_f.evidence["zip_encrypted"])
        appended = self._findings("appended_zip.png", "appended_data")[0]
        self.assertEqual(appended.length, len(self.fixtures["appended_zip.png"].data) - 102)

    def test_appended_text_is_29_bytes_high(self):
        f = self._findings("appended_text.jpg", "appended_data")[0]
        self.assertEqual(f.length, 29)
        self.assertEqual(f.confidence_label, "High")

    def test_bad_crc_and_truncation_are_medium(self):
        self.assertEqual(self._findings("bad_crc.png", "png_crc_mismatch")[0].confidence_label, "Medium")
        self.assertEqual(self._findings("truncated.png", "png_truncated")[0].confidence_label, "Medium")

    def test_strings_recovered_from_appended_zip(self):
        texts = [s["text"] for s in self.summaries["appended_zip.png"].properties["text.strings"]["strings"]]
        # The zip stores "flag.txt" and its content with no separator, so the printable
        # run is "flag.txtCTF{...}". Matching the flag as a substring is the correct check.
        self.assertTrue(any("CTF{fixture_appended_zip}" in t for t in texts), texts)

    def test_every_finding_has_id_source_and_method(self):
        for name, s in self.summaries.items():
            for f in s.findings:
                with self.subTest(fixture=name, id=f.id):
                    self.assertTrue(f.id.startswith("F"))
                    if f.kind == "derived_flag_candidate":
                        self.assertTrue(f.source_artifact_id.startswith("D"))
                    else:
                        self.assertEqual(f.source_artifact_id, "A001")
                    self.assertTrue(f.method)

    def test_original_unchanged_after_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "appended_zip.png"
            src.write_bytes(self.fixtures["appended_zip.png"].data)
            before = sha256_file(src)
            summary = run_scan(src, workspace_base=Path(tmp) / "ws")
            self.assertEqual(sha256_file(src), before)
            self.assertEqual(summary.input["sha256"], before)

    def test_scan_summary_written_to_reports_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "clean.png"
            src.write_bytes(self.fixtures["clean.png"].data)
            s = run_scan(src, workspace_base=Path(tmp) / "ws")
            report = Path(s.workspace) / "reports" / "scan_summary.json"
            self.assertTrue(report.is_file())

    def test_crashing_analyzer_recorded_and_scan_continues(self):
        from imagehunter.analyzers.base import Analyzer, AnalyzerResult
        from imagehunter.analyzers import default_analyzers

        class Boom(Analyzer):
            name = "test.boom"
            def run(self, ctx):
                raise RuntimeError("simulated parser crash")

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "appended.bmp"
            src.write_bytes(self.fixtures["appended.bmp"].data)
            analyzers = [Boom()] + default_analyzers()
            s = run_scan(src, workspace_base=Path(tmp) / "ws", analyzers=analyzers)
            statuses = {a["name"]: a["status"] for a in s.analyzers}
            self.assertEqual(statuses["test.boom"], "error")
            self.assertIn(statuses["binary.structure"], EXECUTED)
            self.assertEqual(s.status, "completed_with_warnings")
            self.assertTrue(any(f.kind == "appended_data" for f in s.findings))


if __name__ == "__main__":
    unittest.main()
