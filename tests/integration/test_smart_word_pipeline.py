"""End to end: smart words inside the real pipeline, CLI exports, HTML report, and regression checks.

The planted value is generated fresh on every run. No answer or expected password is stored in the repo.
"""

import json
import secrets
import subprocess
import sys
import tempfile
import unittest

from pathlib import Path

from imagehunter.core.status import EXECUTED
from imagehunter.core.pipeline import run_scan
from imagehunter.services.report_html import build_report_html
from tests.fixtures.generate import make_png_with_chunks

ROOT = Path(__file__).resolve().parents[2]


def _text_png(text: str) -> bytes:
    return make_png_with_chunks([(b"tEXt", b"Comment\x00" + text.encode("utf-8"))])


class SmartWordPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.secret = "Quartz" + secrets.token_hex(3)              # generated per run, never stored
        cls.path = cls.root / "planted.png"
        cls.path.write_bytes(_text_png(
            f"Lighthouse keeper journal. The password is {cls.secret}. Remember the moonlit harbor."))
        cls.summary = run_scan(cls.path, workspace_base=cls.root / "ws")
        cls.block = cls.summary.properties["text.smart_words"]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _candidate(self, value):
        return next(c for c in self.block["candidates"] if c["value"] == value)

    def test_planted_value_ranked_with_clue_and_provenance(self):
        c = self._candidate(self.secret)
        self.assertIn(c["priority"], ("High", "Medium"))
        self.assertGreater(c["breakdown"]["clue_context"], 0)
        self.assertEqual(c["status"], "candidate")                  # never reported as verified
        occ = c["occurrences"][0]
        self.assertIn("password is", occ["context"])
        self.assertTrue(occ["source"])
        self.assertIsInstance(occ["offset"], int)

    def test_scores_are_explained_and_bounded(self):
        for c in self.block["candidates"]:
            self.assertEqual(c["score"], min(100, max(0, sum(c["breakdown"].values()))))
            self.assertIn(c["priority"], ("High", "Medium", "Low"))
            self.assertIn("breakdown", c)
            self.assertTrue(c["id"].startswith("W"))

    def test_clue_is_not_a_positive_hint_when_negated(self):
        path = self.root / "negated.png"
        path.write_bytes(_text_png("There is no password here. Harbor lantern."))
        summary = run_scan(path, workspace_base=self.root / "ws2")
        block = summary.properties["text.smart_words"]
        self.assertFalse([c for c in block["candidates"] if c["type"] == "structured_value"])

    def test_existing_analyzers_still_report_as_before(self):
        props = self.summary.properties
        self.assertIn("strings", props["text.strings"])
        self.assertIn("configured_phrases", props["text.phrases"])
        self.assertIn("counts", props["metadata.extract"])
        self.assertTrue(any(a["name"] == "text.smart_words" and a["status"] in EXECUTED
                            for a in self.summary.analyzers))
        self.assertFalse([f for f in self.summary.findings if f.kind == "smart_candidate"])

    def test_html_report_shows_section_and_escapes_candidates(self):
        hostile = self.root / "hostile.png"
        hostile.write_bytes(_text_png("The password is <img src=x onerror=alert(1)> thanks."))
        summary = run_scan(hostile, workspace_base=self.root / "ws3")
        page = build_report_html(summary.to_dict())
        self.assertIn("Smart word candidates", page)
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;img", page)

    def test_disabled_setting_produces_no_candidates(self):
        from dataclasses import replace
        from imagehunter.config.settings import Settings
        summary = run_scan(self.path, settings=replace(Settings(), smart_words_enabled=False),
                           workspace_base=self.root / "ws4")
        self.assertEqual(summary.properties["text.smart_words"], {"enabled": False})


class SmartWordCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.secret = "Quartz" + secrets.token_hex(3)
        cls.img = cls.root / "cli.png"
        cls.img.write_bytes(_text_png(f"The password is {cls.secret}. Remember the lighthouse."))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _run(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "main.py"), "scan", str(self.img),
                               "--workdir", str(self.root / "ws"), *args],
                              capture_output=True, text=True, timeout=180)

    def test_txt_and_json_exports_written_with_provenance(self):
        txt, js = self.root / "c.txt", self.root / "c.json"
        proc = self._run("--smart-words", "--export-candidates", str(txt),
                         "--export-candidates-json", str(js))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(self.secret, txt.read_text(encoding="utf-8").splitlines())
        doc = json.loads(js.read_text(encoding="utf-8"))
        self.assertIn("warning", doc)
        self.assertIn("not confirmed passwords", doc["warning"])
        entry = next(c for c in doc["candidates"] if c["value"] == self.secret)
        self.assertTrue(entry["occurrences"][0]["context"])

    def test_min_score_bounds_are_validated(self):
        proc = self._run("--min-score", "101")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--min-score", proc.stderr)

    def test_min_score_filters_output(self):
        proc = self._run("--smart-words", "--min-score", "90")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        block = data["properties"]["text.smart_words"]
        self.assertTrue(all(c["score"] >= 90 for c in block["candidates"]))


if __name__ == "__main__":
    unittest.main()
