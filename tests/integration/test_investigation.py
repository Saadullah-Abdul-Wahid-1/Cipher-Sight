"""Autonomous investigation: planner triggers and modes, cancellation, time budget, evidence graph.

Flags are generated per run. The nested scenario is: text -> base64 -> zlib -> ZIP -> flag."""

import base64
import dataclasses
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import zlib
from pathlib import Path

from imagehunter.core.status import EXECUTED
from imagehunter.analyzers import default_analyzers
from imagehunter.analyzers.base import Analyzer, AnalyzerResult
from imagehunter.config.settings import ConfigError, Settings
from imagehunter.core.planner import plan_investigation
from imagehunter.core.pipeline import run_scan
from imagehunter.services.evidence_graph import evidence_class
from tests.fixtures.generate import build_fixtures, make_png_with_chunks, make_zip

ROOT = Path(__file__).resolve().parents[2]


def _flag():
    return "CTF{" + secrets.token_hex(5) + "}"


class PlannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = {f.filename: f for f in build_fixtures()}

    def test_appended_zip_triggers_structure_and_embedded_evidence(self):
        p = plan_investigation(self.fx["appended_zip.png"].data, "a.png", Settings())
        kinds = {t["trigger"] for t in p.triggers}
        self.assertIn("appended_data", kinds)
        self.assertIn("embedded_zip", kinds)

    def test_clean_png_has_no_triggers(self):
        p = plan_investigation(self.fx["clean.png"].data, "clean.png", Settings())
        self.assertEqual(p.triggers, [])

    def test_extension_mismatch_is_a_trigger(self):
        p = plan_investigation(self.fx["renamed_as.jpg"].data, "renamed_as.jpg", Settings())
        self.assertIn("extension_mismatch", {t["trigger"] for t in p.triggers})

    def test_auto_escalates_only_when_triggered(self):
        auto = Settings(investigation_mode="auto")
        self.assertEqual(plan_investigation(self.fx["appended_zip.png"].data, "a.png", auto).mode_applied, "deep")
        self.assertEqual(plan_investigation(self.fx["clean.png"].data, "c.png", auto).mode_applied, "standard")

    def test_deep_mode_raises_budgets_and_quick_lowers_them(self):
        base = Settings()
        deep = plan_investigation(b"x" * 10, "x.bin", dataclasses.replace(base, investigation_mode="deep"))
        self.assertEqual(deep.settings.lsb_max_channels, 3)
        self.assertTrue(deep.settings.lsb_unknown_prefix_leads)
        self.assertGreaterEqual(deep.settings.decoding_max_depth, 4)
        quick = plan_investigation(b"x" * 10, "x.bin", dataclasses.replace(base, investigation_mode="quick"))
        self.assertFalse(quick.settings.smart_words_enabled)
        self.assertFalse(quick.settings.decoding_enabled)
        self.assertEqual(quick.settings.lsb_max_channels, 1)

    def test_standard_mode_leaves_settings_unchanged(self):
        s = Settings()
        p = plan_investigation(b"x" * 10, "x.bin", s)
        self.assertEqual(p.settings, s)

    def test_invalid_mode_and_budget_rejected(self):
        with self.assertRaises(ConfigError):
            Settings(investigation_mode="turbo").validate()
        with self.assertRaises(ConfigError):
            Settings(investigation_time_budget_seconds=-1).validate()


class PipelineControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.clean = cls.root / "clean.png"
        cls.clean.write_bytes({f.filename: f for f in build_fixtures()}["clean.png"].data)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_plan_recorded_in_properties(self):
        s = run_scan(self.clean, workspace_base=self.root / "ws")
        inv = s.properties["investigation"]
        self.assertEqual(inv["mode_applied"], "standard")
        self.assertIsNone(inv["stop_reason"])
        self.assertEqual(inv["analyzers_run"], len(default_analyzers()))

    def test_cancel_stops_remaining_analyzers_and_reports_cancelled(self):
        cancel = threading.Event()

        def on_event(e):
            if e.module == "image.identity" and e.level == "SUCCESS":
                cancel.set()

        s = run_scan(self.clean, workspace_base=self.root / "ws2", cancel_event=cancel, on_event=on_event)
        statuses = {a["name"]: a["status"] for a in s.analyzers}
        self.assertIn(statuses["image.identity"], EXECUTED)
        self.assertEqual(statuses["binary.structure"], "cancelled")
        self.assertEqual(s.status, "cancelled")
        self.assertEqual(s.properties["investigation"]["stop_reason"], "cancelled by user")

    def test_time_budget_skips_later_analyzers(self):
        class Slow(Analyzer):
            name = "test.slow"

            def run(self, ctx):
                time.sleep(0.4)
                return AnalyzerResult()

        s = run_scan(self.clean, workspace_base=self.root / "ws3",
                     settings=Settings(investigation_time_budget_seconds=0.1),
                     analyzers=[Slow()] + default_analyzers())
        statuses = {a["name"]: a for a in s.analyzers}
        self.assertIn(statuses["test.slow"]["status"], EXECUTED)
        self.assertEqual(statuses["image.identity"]["status"], "skipped")
        self.assertIn("time budget", statuses["image.identity"]["message"])
        self.assertEqual(s.status, "completed_with_warnings")


class NestedEvidenceTests(unittest.TestCase):
    """text -> base64 -> zlib -> ZIP (stored) -> flag. Every link must be visible in the evidence graph."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.flag = _flag()
        zip_bytes = make_zip({"note.txt": f"the answer is {cls.flag}\n".encode()})
        payload = base64.b64encode(zlib.compress(zip_bytes)).decode()
        cls.path = cls.root / "nested.png"
        cls.path.write_bytes(make_png_with_chunks([(b"tEXt", b"Comment\x00" + payload.encode())]))
        cls.summary = run_scan(cls.path, workspace_base=cls.root / "ws")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_flag_found_with_full_chain(self):
        flags = [f for f in self.summary.findings if f.kind == "decoded_flag_candidate"]
        self.assertEqual([f.evidence["text"] for f in flags], [self.flag])
        self.assertEqual(flags[0].evidence["chain_text"], "base64 > zlib(max_output=65536)")

    def test_zip_signature_found_inside_decoded_artifact(self):
        sig = [f for f in self.summary.findings if f.kind == "decoded_file_signature"]
        self.assertEqual(sig[0].evidence["format"], "zip")
        self.assertEqual(sig[0].evidence["chain_text"], "base64 > zlib(max_output=65536)")

    def test_graph_links_artifacts_in_order_and_findings_to_their_source(self):
        g = self.summary.evidence_graph
        nodes = {n["id"]: n for n in g["nodes"]}
        art = [n for n in g["nodes"] if n["type"] == "decoded_artifact"]
        by_label = {n["label"]: n["id"] for n in art}
        self.assertIn("base64", by_label)
        self.assertIn("base64 > zlib(max_output=65536)", by_label)
        edge = [e for e in g["edges"] if e["from"] == by_label["base64"]
                and e["to"] == by_label["base64 > zlib(max_output=65536)"]]
        self.assertEqual(edge[0]["method"], "zlib")
        flag_node = next(n for n in g["nodes"] if n["type"] == "finding" and n["label"] == "decoded_flag_candidate")
        flag_edge = next(e for e in g["edges"] if e["to"] == flag_node["id"])
        self.assertEqual(flag_edge["from"], by_label["base64 > zlib(max_output=65536)"])
        self.assertEqual(nodes["A001"]["type"], "artifact")

    def test_evidence_classes(self):
        self.assertEqual(evidence_class("appended_data"), "deterministic")
        self.assertEqual(evidence_class("decoded_file_signature"), "deterministic")
        self.assertEqual(evidence_class("lsb_flag_candidate"), "heuristic")
        self.assertEqual(evidence_class("lsb_unknown_prefix_lead"), "heuristic")

    def test_no_ai_or_verified_nodes_exist(self):
        classes = {n["evidence_class"] for n in self.summary.evidence_graph["nodes"]}
        self.assertFalse(classes & {"ai_hypothesis", "verified"})


class CliModeTests(unittest.TestCase):
    def test_mode_flag_is_applied(self):
        with tempfile.TemporaryDirectory() as tmp:
            img = Path(tmp) / "c.png"
            img.write_bytes({f.filename: f for f in build_fixtures()}["clean.png"].data)
            proc = subprocess.run([sys.executable, str(ROOT / "main.py"), "scan", str(img), "--mode", "deep",
                                   "--workdir", str(Path(tmp) / "ws"), "--log-level", "ERROR"],
                                  capture_output=True, text=True, timeout=300)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            import json
            inv = json.loads(proc.stdout)["properties"]["investigation"]
            self.assertEqual(inv["mode_applied"], "deep")


if __name__ == "__main__":
    unittest.main()
