"""Analyzer status accounting: a skipped, failed or cancelled analyzer is never an execution.

Regression for RC3, where every analyzer that returned normally was recorded as "ok",
including analyzers that had declared they did no work (e.g. LSB on a JPEG).
"""

import unittest

from imagehunter.core.status import (CANCELLED, EXECUTED, FINDINGS, PARTIAL, PASS, SKIPPED,
                                     ERROR, classify, count_by_status)
from imagehunter.services.report_data import build_view


class ClassifyTests(unittest.TestCase):
    def test_declared_skip_beats_everything(self):
        status, message = classify(skipped_reason="not applicable", findings=3, warnings=["x"])
        self.assertEqual((status, message), (SKIPPED, "not applicable"))

    def test_findings_outrank_limitations(self):
        self.assertEqual(classify(skipped_reason=None, findings=1, warnings=["limited"])[0], FINDINGS)

    def test_warnings_without_findings_are_partial(self):
        status, message = classify(skipped_reason=None, findings=0, warnings=["a", "b"])
        self.assertEqual((status, message), (PARTIAL, "a; b"))

    def test_clean_run_is_pass(self):
        self.assertEqual(classify(skipped_reason=None, findings=0, warnings=[]), (PASS, ""))

    def test_executed_set_excludes_non_runs(self):
        self.assertEqual(EXECUTED, frozenset({PASS, FINDINGS, PARTIAL}))
        for status in (SKIPPED, ERROR, CANCELLED):
            self.assertNotIn(status, EXECUTED)


class CountTests(unittest.TestCase):
    def test_counts_each_category_and_total(self):
        records = [{"status": s} for s in (PASS, FINDINGS, PARTIAL, SKIPPED, SKIPPED, ERROR, CANCELLED)]
        counts = count_by_status(records)
        self.assertEqual(counts["total"], 7)
        self.assertEqual(counts["executed"], 3)
        self.assertEqual(counts[SKIPPED], 2)
        self.assertEqual(counts[ERROR], 1)
        self.assertEqual(counts[CANCELLED], 1)
        self.assertEqual(counts[FINDINGS], 1)
        self.assertEqual(counts[PARTIAL], 1)


class ReportMetricsTests(unittest.TestCase):
    def _summary(self, analyzers):
        return {"scan_id": "t", "status": "completed_with_warnings", "started_at": None,
                "finished_at": None, "input": {"path": "/x/a.jpg"}, "properties": {},
                "findings": [], "warnings": [], "analyzers": analyzers, "execution_log": []}

    def test_modules_executed_excludes_skipped_and_cancelled(self):
        analyzers = [
            {"name": "image.identity", "status": PASS, "message": ""},
            {"name": "stego.lsb", "status": SKIPPED, "message": "needs PNG or BMP"},
            {"name": "image.ocr_qr", "status": SKIPPED, "message": "disabled"},
            {"name": "text.phrases", "status": CANCELLED, "message": "cancelled by user"},
            {"name": "carving.embedded", "status": ERROR, "message": "boom"},
        ]
        metrics = build_view(self._summary(analyzers))["metrics"]
        self.assertEqual(metrics["modules_total"], 5)
        self.assertEqual(metrics["modules_executed"], 1)
        self.assertEqual(metrics["modules_skipped"], 2)
        self.assertEqual(metrics["modules_cancelled"], 1)
        self.assertEqual(metrics["modules_failed"], 1)
        self.assertEqual(metrics["modules_with_findings"], 0)
        self.assertEqual(metrics["modules_partial"], 0)


class PipelineStatusTests(unittest.TestCase):
    """End to end: a JPEG cannot take the LSB path, so that analyzer must not report success."""

    def test_jpeg_scan_does_not_count_skipped_stego_as_executed(self):
        import tempfile
        from pathlib import Path
        from imagehunter.core.pipeline import run_scan
        from tests.fixtures.generate import make_exif_jpeg

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "sample.jpg"
            src.write_bytes(make_exif_jpeg())
            summary = run_scan(src, workspace_base=Path(tmp) / "work")
            by_name = {a["name"]: a for a in summary.analyzers}
            self.assertEqual(by_name["stego.lsb"]["status"], SKIPPED)
            self.assertNotEqual(by_name["stego.lsb"]["status"], PASS)
            self.assertIn(by_name["image.identity"]["status"], EXECUTED)
            self.assertLess(count_by_status(summary.analyzers)["executed"], len(summary.analyzers))


if __name__ == "__main__":
    unittest.main()
