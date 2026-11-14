"""CLI end-to-end through main.py, as a user would run it."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.fixtures.generate import build_fixtures

ROOT = Path(__file__).resolve().parents[2]
MAIN = ROOT / "main.py"


def _run(*args):
    return subprocess.run([sys.executable, str(MAIN), *args], cwd=ROOT,
                          capture_output=True, text=True, timeout=120)


class CliScanTests(unittest.TestCase):
    def test_scan_prints_json_summary(self):
        fx = {f.filename: f for f in build_fixtures()}["appended.bmp"]
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "appended.bmp"
            src.write_bytes(fx.data)
            proc = _run("scan", str(src), "--workdir", str(Path(tmp) / "ws"), "--log-level", "ERROR")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["schema_version"], "1.0")
            self.assertEqual(summary["input"]["sha256"], summary["input"]["sha256"])
            self.assertEqual([f["kind"] for f in summary["findings"]], ["appended_data"])
            self.assertEqual(summary["findings"][0]["confidence_label"], "High")
            self.assertIn("binary.structure", summary["properties"])

    def test_missing_file_exit_code_2(self):
        proc = _run("scan", "does_not_exist.png")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("error", proc.stderr.lower())

    def test_bad_settings_exit_code_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "bad.json"
            cfg.write_text('{"unknown_key": 1}')
            src = Path(tmp) / "x.png"
            src.write_bytes(b"\x89PNG\r\n\x1a\n")
            proc = _run("scan", str(src), "--settings", str(cfg))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("settings error", proc.stderr)

    def test_stdout_is_pure_json_logs_go_to_stderr(self):
        fx = {f.filename: f for f in build_fixtures()}["clean.png"]
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "clean.png"
            src.write_bytes(fx.data)
            proc = _run("scan", str(src), "--workdir", str(Path(tmp) / "ws"), "--log-level", "INFO")
            json.loads(proc.stdout)  # must parse cleanly
            self.assertIn("scan_started", proc.stderr)

    def test_check_deps_runs(self):
        proc = _run("check-deps")
        self.assertIn("Pillow", proc.stdout)
        self.assertIn(proc.returncode, (0, 1))

    def test_broken_pipe_exits_quietly(self):
        proc = subprocess.run(f"{sys.executable} {MAIN} check-deps | head -1",
                              shell=True, cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertNotIn("BrokenPipeError", proc.stderr)
        self.assertIn("CipherSight", proc.stdout)

    def test_check_tools_lists_all_tools(self):
        proc = _run("check-tools")
        for name in ("exiftool", "binwalk", "zsteg", "stegseek"):
            self.assertIn(name, proc.stdout)


if __name__ == "__main__":
    unittest.main()
