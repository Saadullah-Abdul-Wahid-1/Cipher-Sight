"""Window logic that does not need a display: summary text, headless scan, and tkinter-free import."""

import importlib
import sys
import tempfile
import unittest
from pathlib import Path

from imagehunter.ui.app import scan_file
from imagehunter.ui.summary import format_summary
from tests.fixtures.generate import build_fixtures


class SummaryFormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        fx = {f.filename: f for f in build_fixtures()}
        cls.zip_path = Path(cls.tmp.name) / "appended_zip.png"
        cls.zip_path.write_bytes(fx["appended_zip.png"].data)
        cls.clean_path = Path(cls.tmp.name) / "clean.png"
        cls.clean_path.write_bytes(fx["clean.png"].data)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_text_lists_findings_with_confidence_and_zip_contents(self):
        d = scan_file(str(self.zip_path), workspace_base=str(Path(self.tmp.name) / "ws"))
        text = format_summary(d)
        self.assertIn("Findings: 3", text)
        self.assertIn("[High] appended_data", text)
        self.assertIn("[High] embedded_zip", text)
        self.assertIn("zip contents: flag.txt", text)
        self.assertIn(d["input"]["sha256"], text)
        self.assertIn("Limitations:", text)

    def test_clean_file_reports_no_findings(self):
        d = scan_file(str(self.clean_path), workspace_base=str(Path(self.tmp.name) / "ws2"))
        text = format_summary(d)
        self.assertIn("Findings: 0", text)
        self.assertIn("No structural anomalies", text)

    def test_formatter_tolerates_missing_keys(self):
        text = format_summary({})
        self.assertIn("Status:", text)
        self.assertIn("Findings: 0", text)

    def test_scan_file_returns_same_result_as_pipeline(self):
        d = scan_file(str(self.zip_path), workspace_base=str(Path(self.tmp.name) / "ws3"))
        self.assertEqual(d["schema_version"], "1.0")
        self.assertEqual([f["kind"] for f in d["findings"]], ["appended_data", "embedded_zip", "derived_flag_candidate"])


class HeadlessImportTests(unittest.TestCase):
    def test_ui_modules_import_without_tkinter_at_module_level(self):
        # tkinter must be imported only inside run_gui(), so the package works without Tk.
        src = (Path(__file__).resolve().parents[2] / "src" / "imagehunter" / "ui" / "app.py").read_text()
        top_level = [line for line in src.splitlines() if line.startswith(("import tkinter", "from tkinter"))]
        self.assertEqual(top_level, [])
        importlib.import_module("imagehunter.ui.app")


if __name__ == "__main__":
    unittest.main()
