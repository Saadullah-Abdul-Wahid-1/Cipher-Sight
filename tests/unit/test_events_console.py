"""Event recorder and console model: ordering, filtering, search, export and pause-safe storage."""

import tempfile
import threading
import unittest
from pathlib import Path

from imagehunter.core.events import EventRecorder
from imagehunter.ui.console import ConsoleModel


class EventRecorderTests(unittest.TestCase):
    def test_events_recorded_in_order_and_forwarded(self):
        seen = []
        rec = EventRecorder(seen.append)
        rec.emit("INFO", "engine", "Start", "one", status="running", percent=0)
        rec.emit("SUCCESS", "engine", "Start", "two", status="ok", percent=50)
        self.assertEqual([e.message for e in seen], ["one", "two"])
        self.assertEqual([d["message"] for d in rec.as_dicts()], ["one", "two"])

    def test_invalid_level_and_status_rejected(self):
        rec = EventRecorder()
        with self.assertRaises(ValueError):
            rec.emit("CERTAIN", "m", "o", "x")
        with self.assertRaises(ValueError):
            rec.emit("INFO", "m", "o", "x", status="maybe")

    def test_broken_sink_does_not_stop_recording(self):
        def bad(_):
            raise RuntimeError("gui gone")
        rec = EventRecorder(bad)
        rec.emit("INFO", "m", "o", "still recorded")
        self.assertEqual(len(rec.as_dicts()), 1)

    def test_thread_safe_recording(self):
        rec = EventRecorder()

        def spam(n):
            for i in range(200):
                rec.emit("DEBUG", f"t{n}", "op", str(i))
        threads = [threading.Thread(target=spam, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(rec.as_dicts()), 800)


class ConsoleModelTests(unittest.TestCase):
    def setUp(self):
        self.m = ConsoleModel(max_entries=100)
        self.m.add({"ts": "2026-11-07T08:52:01.123+00:00", "level": "INFO", "module": "engine",
                    "operation": "Start", "message": "booting", "percent": 0})
        self.m.add({"ts": "2026-11-07T08:52:01.500+00:00", "level": "FINDING", "module": "stego.lsb",
                    "operation": "Detection", "message": "THM{x} found", "percent": None})
        self.m.add({"ts": "2026-11-07T08:52:02.000+00:00", "level": "ERROR", "module": "carving.embedded",
                    "operation": "Run analyzer", "message": "parser crashed", "percent": 80})

    def test_line_format_shows_time_level_module_and_percent(self):
        line = ConsoleModel.format_line(self.m.entries()[0])
        self.assertEqual(line, "[08:52:01.123] [INFO] [engine] Start: booting (0%)")

    def test_filter_by_level(self):
        only_errors = self.m.visible({"ERROR"})
        self.assertEqual([e["message"] for e in only_errors], ["parser crashed"])

    def test_search_is_case_insensitive_over_full_line(self):
        self.assertEqual(len(self.m.visible(None, "THM{X}")), 1)
        self.assertEqual(len(self.m.visible(None, "carving.embedded")), 1)
        self.assertEqual(self.m.visible(None, "nothing-like-this"), [])

    def test_export_txt_matches_visible_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "console.txt"
            n = self.m.export_txt(out, {"INFO", "FINDING"}, "")
            text = out.read_text(encoding="utf-8")
            self.assertEqual(n, 2)
            self.assertIn("THM{x} found", text)
            self.assertNotIn("parser crashed", text)

    def test_bounded_memory_counts_dropped(self):
        small = ConsoleModel(max_entries=3)
        for i in range(10):
            small.add({"ts": "", "level": "DEBUG", "module": "m", "operation": "o", "message": str(i)})
        self.assertEqual(len(small), 3)
        self.assertEqual(small.dropped, 7)
        self.assertEqual([e["message"] for e in small.entries()], ["7", "8", "9"])

    def test_clear_resets(self):
        self.m.clear()
        self.assertEqual(len(self.m), 0)


if __name__ == "__main__":
    unittest.main()
