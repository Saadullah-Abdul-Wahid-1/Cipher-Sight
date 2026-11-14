"""Analyst review and stored-result statistics through the local HTTP API.

These tests inject finished scan summaries built with the same helpers as the report tests.
No flag value is special-cased: decisions apply to whatever the scan reported.
"""

import tempfile
import unittest
from pathlib import Path

from imagehunter.config.settings import Settings
from imagehunter.web.jobs import Job, JobManager
from imagehunter.web.server import ImageHunterServer, serve_forever_in_thread

from tests.integration.test_web_server import Client
from tests.unit.test_report_html import _flag, _summary

OK = {"X-ImageHunter": "1"}
REAL = "RHL{t3st_fl4g_lsb_42}"
DECOY = "CTF{n0t_th3_fl4g_keep_l00king}"


class ReviewApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name) / "workspace"
        cls.manager = JobManager(Settings(), base, runner=None)
        cls.job = Job("sample.png", base / "uploads" / "x" / "sample.png")
        cls.job.finish("completed", _summary(findings=[_flag("F001", REAL, offset=17760),
                                                       _flag("F002", DECOY, offset=900)]))
        cls.manager._jobs[cls.job.id] = cls.job
        cls.running = Job("late.png", base / "uploads" / "y" / "late.png")
        cls.manager._jobs[cls.running.id] = cls.running
        cls.server = ImageHunterServer(0, cls.manager)
        serve_forever_in_thread(cls.server)
        cls.client = Client(cls.server.server_address[1])

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def _decide(self, value, decision, job_id=None, headers=OK):
        import json
        body = json.dumps({"value": value, "decision": decision}).encode("utf-8")
        h = dict(headers or {})
        h["Content-Type"] = "application/json"
        h["Content-Length"] = str(len(body))
        return self.client.json("POST", f"/api/scans/{job_id or self.job.id}/verifications", body=body, headers=h)

    def _summary_view(self):
        return self.client.json("GET", f"/api/scans/{self.job.id}/summary")[1]

    def _reset(self):
        self.job.verifications.clear()

    def test_scan_starts_with_candidate_and_likely_decoy_and_no_auto_confirmation(self):
        self._reset()
        v = self._summary_view()
        self.assertEqual([f["value"] for f in v["flags"]["candidates"]], [REAL])
        self.assertEqual([f["value"] for f in v["flags"]["likely_decoys"]], [DECOY])
        self.assertEqual(v["flags"]["confirmed"], [])

    def test_confirm_then_clear_round_trip(self):
        self._reset()
        status, view = self._decide(REAL, "confirmed")
        self.assertEqual(status, 200)
        self.assertEqual([f["value"] for f in view["flags"]["confirmed"]], [REAL])
        status, view = self._decide(REAL, "clear")
        self.assertEqual(status, 200)
        self.assertEqual(view["flags"]["confirmed"], [])
        self.assertEqual([f["value"] for f in view["flags"]["candidates"]], [REAL])

    def test_analyst_can_override_a_likely_decoy_label(self):
        self._reset()
        status, view = self._decide(DECOY, "confirmed")
        self.assertEqual(status, 200)
        self.assertEqual([f["value"] for f in view["flags"]["confirmed"]], [DECOY])
        self.assertEqual(view["flags"]["likely_decoys"], [])

    def test_rejection_is_recorded_as_analyst_decision(self):
        self._reset()
        status, view = self._decide(DECOY, "rejected")
        self.assertEqual(status, 200)
        self.assertEqual([f["value"] for f in view["flags"]["rejected"]], [DECOY])

    def test_post_without_custom_header_is_refused(self):
        status, _ = self._decide(REAL, "confirmed", headers={})
        self.assertEqual(status, 403)
        self._reset()

    def test_unknown_value_is_refused(self):
        self._reset()
        status, body = self._decide("THM{not_in_this_scan}", "confirmed")
        self.assertEqual(status, 400)
        self.assertIn("not a flag", body["error"])

    def test_invalid_decision_is_refused(self):
        self._reset()
        status, body = self._decide(REAL, "probably")
        self.assertEqual(status, 400)

    def test_unknown_scan_is_404(self):
        status, _ = self._decide(REAL, "confirmed", job_id="0" * 32)
        self.assertEqual(status, 404)

    def test_unfinished_scan_is_refused(self):
        status, body = self._decide(REAL, "confirmed", job_id=self.running.id)
        self.assertEqual(status, 400)
        self.assertIn("not finished", body["error"])

    def test_malformed_json_is_refused(self):
        status, _, _ = self.client.req("POST", f"/api/scans/{self.job.id}/verifications", body=b"not json",
                                       headers={**OK, "Content-Type": "application/json",
                                                "Content-Length": "8"})
        self.assertEqual(status, 400)

    def test_stats_endpoint_reflects_stored_decisions(self):
        self._reset()
        self._decide(REAL, "confirmed")
        status, stats = self.client.json("GET", "/api/stats")
        self.assertEqual(status, 200)
        self.assertEqual(stats["confirmed_flags"], 1)
        self.assertEqual(stats["likely_decoy_flags"], 1)
        self.assertEqual(stats["flag_candidates"], 0)
        self.assertEqual(stats["total_scans"], 2)          # the injected scan and the running one
        self.assertEqual(stats["running_scans"], 1)
        self.assertEqual(stats["images_analyzed"], 1)
        self._reset()


if __name__ == "__main__":
    unittest.main()
