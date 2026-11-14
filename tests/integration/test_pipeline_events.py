"""Live events and reports from the real pipeline: success, failure, and no duplicate or invented messages."""

import json
import tempfile
import unittest
from pathlib import Path

from imagehunter.analyzers import default_analyzers
from imagehunter.analyzers.base import Analyzer, AnalyzerResult
from imagehunter.config.settings import load_settings
from imagehunter.core.pipeline import run_scan
from imagehunter.core.validation import ValidationError
from imagehunter.services.report_html import build_report_html
from tests.fixtures.generate import build_fixtures, make_signal_hunt_like, REAL_FLAG, DECOY_FLAG


class _Boom(Analyzer):
    name = "test.boom"

    def run(self, ctx):
        raise RuntimeError("simulated parser crash")


class PipelineEventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.fixtures = {f.filename: f for f in build_fixtures()}
        cls.sample = cls.root / "appended_zip.png"
        cls.sample.write_bytes(cls.fixtures["appended_zip.png"].data)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _scan(self, path, analyzers=None, verifications=None):
        seen = []
        summary = run_scan(path, workspace_base=self.root / "ws", analyzers=analyzers,
                           on_event=seen.append, verifications=verifications)
        return summary, seen

    def test_success_events_match_real_operations(self):
        summary, seen = self._scan(self.sample)
        msgs = [e.message for e in seen]
        hash_ok = [e for e in seen if e.operation == "SHA-256" and e.level == "SUCCESS"]
        self.assertEqual(len(hash_ok), 1)
        self.assertIn(summary.input["sha256"], hash_ok[0].message)
        findings_events = [e for e in seen if e.level == "FINDING"]
        self.assertEqual(len(findings_events), len(summary.findings))
        self.assertTrue(any("HTML report written" in m for m in msgs))
        self.assertTrue(any(e.level == "SUCCESS" and e.module == "scan" for e in seen))

    def test_progress_is_monotonic_and_reaches_100(self):
        _, seen = self._scan(self.sample)
        pcts = [e.percent for e in seen if e.percent is not None]
        self.assertEqual(pcts, sorted(pcts))
        self.assertEqual(pcts[-1], 100)

    def test_crashing_analyzer_logs_error_and_no_success_for_it(self):
        analyzers = [_Boom()] + default_analyzers()
        summary, seen = self._scan(self.sample, analyzers=analyzers)
        boom_events = [e for e in seen if e.module == "test.boom"]
        self.assertTrue(any(e.level == "ERROR" and e.status == "error" for e in boom_events))
        self.assertFalse(any(e.level == "SUCCESS" and e.module == "test.boom" for e in boom_events))
        self.assertEqual(summary.status, "completed_with_warnings")
        self.assertTrue(any(a["name"] == "test.boom" and a["status"] == "error" for a in summary.analyzers))
        page = Path(summary.workspace, "reports", "scan_report.html").read_text(encoding="utf-8")
        self.assertIn("FAILED", page)
        self.assertIn("simulated parser crash", page)

    def test_validation_failure_emits_error_and_raises(self):
        seen = []
        with self.assertRaises(ValidationError):
            run_scan(self.root / "missing.png", workspace_base=self.root / "ws", on_event=seen.append)
        self.assertEqual(seen[-1].level, "ERROR")
        self.assertIn("Validation failed", seen[-1].message)

    def test_reports_written_and_legacy_json_identical(self):
        summary, _ = self._scan(self.sample)
        reports = Path(summary.workspace) / "reports"
        names = {p.name for p in reports.iterdir()}
        self.assertTrue({"scan_report.json", "scan_summary.json", "scan_report.html"} <= names)
        self.assertEqual((reports / "scan_report.json").read_text(), (reports / "scan_summary.json").read_text())
        data = json.loads((reports / "scan_report.json").read_text())
        self.assertEqual(len(data["findings"]), len(summary.findings))

    def test_report_log_has_no_duplicate_events(self):
        summary, _ = self._scan(self.sample)
        keys = [(e["ts"], e["module"], e["operation"], e["message"]) for e in summary.execution_log]
        self.assertEqual(len(keys), len(set(keys)))

    def test_report_log_matches_live_events_up_to_report_step(self):
        summary, seen = self._scan(self.sample)
        live = [e.to_dict() for e in seen]
        cut = next(i for i, e in enumerate(live) if e["operation"] == "Generate reports")
        self.assertEqual(summary.execution_log, live[:cut + 1])

    def test_signal_hunt_like_scan_reports_candidates_not_confirmed(self):
        path = self.root / "hunt.png"
        path.write_bytes(make_signal_hunt_like())
        summary, _ = self._scan(path)
        page = Path(summary.workspace, "reports", "scan_report.html").read_text(encoding="utf-8")
        self.assertIn("No confirmed flags found.", page)
        self.assertIn(REAL_FLAG, page)
        self.assertIn(DECOY_FLAG, page)
        self.assertIn("lsb_flag_candidate", {f.kind for f in summary.findings})

    def test_analyst_confirmation_reflected_in_saved_html(self):
        path = self.root / "hunt2.png"
        path.write_bytes(make_signal_hunt_like())
        summary, _ = self._scan(path, verifications={REAL_FLAG: "confirmed"})
        page = Path(summary.workspace, "reports", "scan_report.html").read_text(encoding="utf-8")
        self.assertNotIn("No confirmed flags found.", page)
        self.assertIn("Confirmed", page)


class PhraseAnalyzerTests(unittest.TestCase):
    def test_configured_phrases_found_with_offsets_and_case_rule(self):
        from imagehunter.analyzers.base import AnalyzerContext
        from imagehunter.analyzers.text.phrases import PhraseAnalyzer
        from imagehunter.config.settings import Settings
        from imagehunter.models.artifact import Artifact

        data = b"xx Secret yy secret zz hidden"
        art = Artifact(id="A001", role="original", path="x.bin", working_path="x.bin",
                       sha256="0" * 64, size=len(data))
        settings = Settings(expected_phrases=("secret", "hidden", "absent"))
        res = PhraseAnalyzer().run(AnalyzerContext(artifact=art, data=data, settings=settings, shared={}))
        by = {(f.evidence["phrase"], f.offset): f for f in res.findings}
        self.assertEqual(set(k[0] for k in by), {"secret", "hidden"})
        # "Secret" at 3 is case-insensitive only; "secret" at 13 is exact; "hidden" at 23 is exact.
        self.assertEqual(by[("secret", 3)].confidence_label, "Medium")
        self.assertEqual(by[("secret", 3)].evidence["match"], "case-insensitive")
        self.assertEqual(by[("secret", 13)].confidence_label, "High")
        self.assertEqual(by[("secret", 13)].evidence["match"], "exact")
        self.assertEqual(by[("hidden", 23)].confidence_label, "High")
        self.assertEqual(data[23:29], b"hidden")

    def test_no_phrases_configured_reports_nothing(self):
        from imagehunter.analyzers.base import AnalyzerContext
        from imagehunter.analyzers.text.phrases import PhraseAnalyzer
        from imagehunter.config.settings import Settings
        from imagehunter.models.artifact import Artifact

        art = Artifact(id="A001", role="original", path="x", working_path="x", sha256="0" * 64, size=3)
        res = PhraseAnalyzer().run(AnalyzerContext(artifact=art, data=b"abc", settings=Settings(), shared={}))
        self.assertEqual(res.findings, [])
        self.assertIn("skipped", res.properties)

    def test_settings_reject_bad_phrases(self):
        from imagehunter.config.settings import ConfigError, Settings
        with self.assertRaises(ConfigError):
            Settings(expected_phrases=("",)).validate()


if __name__ == "__main__":
    unittest.main()


class LiveDeliveryTests(unittest.TestCase):
    """Events must reach the consumer while the scan is still running (the GUI depends on this)."""

    def test_events_arrive_while_scan_thread_is_still_running(self):
        import queue
        import threading
        import time

        from imagehunter.analyzers.base import Analyzer, AnalyzerResult

        class Slow(Analyzer):
            name = "test.slow"

            def run(self, ctx):
                time.sleep(0.6)
                return AnalyzerResult()

        q = queue.Queue()
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "clean.png"
            src.write_bytes(build_fixtures()[0].data)
            worker = threading.Thread(
                target=lambda: run_scan(src, workspace_base=Path(tmp) / "ws",
                                        analyzers=[Slow()] + default_analyzers(), on_event=q.put),
                daemon=True)
            worker.start()
            seen_while_running = False
            deadline = time.time() + 20
            while time.time() < deadline:
                try:
                    e = q.get(timeout=0.1)
                except queue.Empty:
                    continue
                if e.module == "test.slow" and e.operation == "Run analyzer" and e.status == "running":
                    seen_while_running = worker.is_alive()
                    break
            worker.join(timeout=30)
            self.assertTrue(seen_while_running, "the 'starting' event for the slow analyzer arrived only after the scan ended")
            self.assertFalse(worker.is_alive())
