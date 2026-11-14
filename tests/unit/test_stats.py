"""Dashboard statistics are computed only from scans that produced a summary."""

import unittest

from imagehunter.services.stats import aggregate


def _view(sha="aa" * 32, confirmed=0, candidates=0, decoys=0, embedded=0, warnings=0, errors=0,
          duration=2.0):
    return {"sha256": sha, "metrics": {"confirmed_flags": confirmed, "flag_candidates": candidates,
                                       "likely_decoy_flags": decoys, "embedded_items": embedded,
                                       "warnings": warnings, "errors": errors,
                                       "duration_seconds": duration}}


class AggregateTests(unittest.TestCase):
    def test_empty_session_is_all_zero_and_no_average(self):
        s = aggregate([])
        self.assertEqual(s["total_scans"], 0)
        self.assertEqual(s["images_analyzed"], 0)
        self.assertIsNone(s["average_duration_seconds"])
        self.assertIsNone(s["last_duration_seconds"])

    def test_counts_come_from_completed_views_only(self):
        entries = [
            {"status": "completed", "view": _view(confirmed=1, candidates=2, decoys=1, embedded=1, duration=3.0)},
            {"status": "failed", "view": None},
            {"status": "running", "view": None},
        ]
        s = aggregate(entries)
        self.assertEqual(s["total_scans"], 3)
        self.assertEqual(s["completed_scans"], 1)
        self.assertEqual(s["failed_scans"], 1)
        self.assertEqual(s["running_scans"], 1)
        self.assertEqual((s["confirmed_flags"], s["flag_candidates"], s["likely_decoy_flags"]), (1, 2, 1))
        self.assertEqual(s["embedded_items"], 1)

    def test_images_analyzed_counts_distinct_hashes(self):
        entries = [{"status": "completed", "view": _view(sha="aa" * 32)},
                   {"status": "completed_with_warnings", "view": _view(sha="aa" * 32, warnings=2)},
                   {"status": "completed", "view": _view(sha="bb" * 32, errors=1)}]
        s = aggregate(entries)
        self.assertEqual(s["images_analyzed"], 2)
        self.assertEqual(s["completed_scans"], 3)
        self.assertEqual(s["warnings"], 2)
        self.assertEqual(s["errors"], 1)

    def test_average_and_last_duration(self):
        entries = [{"status": "completed", "view": _view(duration=2.0)},
                   {"status": "completed", "view": _view(duration=4.0)}]
        s = aggregate(entries)
        self.assertEqual(s["average_duration_seconds"], 3.0)
        self.assertEqual(s["last_duration_seconds"], 4.0)


if __name__ == "__main__":
    unittest.main()
