"""Tests for bounded evidence-driven follow-up artifact analysis."""
import tempfile
import unittest
from pathlib import Path

from imagehunter.core.pipeline import run_scan
from tests.fixtures.generate import build_fixtures


class DynamicFollowupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        fixtures = {item.filename: item for item in build_fixtures()}
        cls.appended = cls.root / "appended_zip.png"
        cls.appended.write_bytes(fixtures["appended_zip.png"].data)
        cls.summary = run_scan(cls.appended, workspace_base=cls.root / "workspace")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_appended_zip_is_queued_and_member_is_analyzed(self):
        followup = self.summary.properties["investigation"]["followup"]
        self.assertGreaterEqual(followup["tasks_processed"], 2)
        origins = [item["origin"] for item in followup["artifacts"]]
        self.assertTrue(any("embedded signature" in origin for origin in origins))
        self.assertTrue(any("ZIP member flag.txt" in origin for origin in origins))

    def test_flag_from_archive_member_is_reported_with_provenance(self):
        flags = [f for f in self.summary.findings if f.kind == "derived_flag_candidate"]
        self.assertTrue(any(f.evidence["text"] == "CTF{fixture_appended_zip}" for f in flags))
        candidate = next(f for f in flags if f.evidence["text"] == "CTF{fixture_appended_zip}")
        self.assertTrue(candidate.source_artifact_id.startswith("D"))
        self.assertTrue(candidate.evidence["sha256"])

    def test_graph_links_derived_artifact_and_finding(self):
        graph = self.summary.evidence_graph
        derived = {n["id"] for n in graph["nodes"] if n["type"] == "derived_artifact"}
        self.assertTrue(derived)
        flag = next(f for f in self.summary.findings if f.kind == "derived_flag_candidate")
        self.assertIn(flag.source_artifact_id, derived)
        self.assertTrue(any(e["from"] == flag.source_artifact_id and e["to"] == flag.id
                            for e in graph["edges"]))

    def test_followup_limits_are_recorded(self):
        followup = self.summary.properties["investigation"]["followup"]
        self.assertLessEqual(followup["tasks_processed"], followup["limits"]["max_artifacts"])
        self.assertLessEqual(followup["bytes_processed"], followup["limits"]["max_total_bytes"])


if __name__ == "__main__":
    unittest.main()
