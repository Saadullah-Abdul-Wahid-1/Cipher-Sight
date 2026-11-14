"""Phase 1 foundation: validation, evidence copies, workspace, settings, logging, runner, registry."""

import io
import json
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from imagehunter.config.settings import ConfigError, Settings, load_settings
from imagehunter.core.logging_setup import setup_logging
from imagehunter.core.validation import ValidationError, validate_input
from imagehunter.core.workspace import SUBDIRS, Workspace
from imagehunter.integrations.registry import TOOLS, ExternalTool, check_tool
from imagehunter.integrations.runner import run_tool
from imagehunter.models.artifact import Artifact
from imagehunter.models.finding import Finding
from imagehunter.services.evidence_service import (
    EvidenceError, make_readonly_copy, sanitize_filename, verify_unchanged,
)
from imagehunter.services.hash_service import sha256_bytes, sha256_file


class _TmpCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()


class ValidationTests(_TmpCase):
    def test_valid_file_accepted(self):
        f = self.root / "ok.png"
        f.write_bytes(b"x" * 10)
        self.assertEqual(validate_input(f, 100), f.resolve())

    def test_missing_file_rejected(self):
        with self.assertRaises(ValidationError):
            validate_input(self.root / "nope.png", 100)

    def test_directory_rejected(self):
        with self.assertRaises(ValidationError):
            validate_input(self.root, 100)

    def test_empty_file_rejected(self):
        f = self.root / "empty.png"
        f.write_bytes(b"")
        with self.assertRaisesRegex(ValidationError, "empty"):
            validate_input(f, 100)

    def test_oversized_file_rejected(self):
        f = self.root / "big.png"
        f.write_bytes(b"x" * 50)
        with self.assertRaisesRegex(ValidationError, "limit"):
            validate_input(f, 10)


class EvidenceTests(_TmpCase):
    def setUp(self):
        super().setUp()
        self.src = self.root / "input.bin"
        self.src.write_bytes(b"original-bytes-\x00\x01\x02")

    def test_copy_matches_hash_and_original_untouched(self):
        before = sha256_file(self.src)
        dest = make_readonly_copy(self.src, self.root / "evidence")
        self.assertEqual(sha256_file(dest), before)
        self.assertEqual(sha256_file(self.src), before)

    def test_copy_is_marked_read_only(self):
        dest = make_readonly_copy(self.src, self.root / "evidence")
        if os.name != "nt" and os.getuid() != 0:
            self.assertFalse(os.access(dest, os.W_OK))

    def test_hostile_name_sanitised_into_evidence_dir(self):
        hostile = self.root / "a; echo PWNED.png"
        hostile.write_bytes(b"x")
        dest = make_readonly_copy(hostile, self.root / "evidence")
        self.assertEqual(dest.parent, self.root / "evidence")
        self.assertNotIn(";", dest.name)
        self.assertNotIn(" ", dest.name)

    def test_verify_unchanged_detects_modification(self):
        h = sha256_file(self.src)
        verify_unchanged(self.src, h)
        self.src.write_bytes(b"tampered")
        with self.assertRaises(EvidenceError):
            verify_unchanged(self.src, h)

    def test_sanitize_shell_and_traversal(self):
        out = sanitize_filename("evil; rm -rf ~ $(id).png")
        for ch in ";$() ~":
            self.assertNotIn(ch, out)
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("..\\..\\boot.ini"), "boot.ini")
        self.assertEqual(sanitize_filename("...."), "file")


class HashTests(_TmpCase):
    def test_hash_consistent_for_bytes_and_file(self):
        f = self.root / "h.bin"
        f.write_bytes(b"abc")
        self.assertEqual(sha256_file(f), sha256_bytes(b"abc"))
        self.assertEqual(sha256_bytes(b"abc"),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


class WorkspaceTests(_TmpCase):
    def test_creates_all_subdirectories(self):
        ws = Workspace.create(self.root)
        for sub in SUBDIRS:
            self.assertTrue((ws.root / sub).is_dir())

    def test_scan_ids_are_unique(self):
        ids = {Workspace.create(self.root).scan_id for _ in range(20)}
        self.assertEqual(len(ids), 20)


class SettingsTests(_TmpCase):
    def test_defaults_load(self):
        s = load_settings()
        self.assertEqual(s.min_string_length, 4)
        self.assertEqual(s.log_level, "WARNING")

    def test_user_override_applies(self):
        p = self.root / "s.json"
        p.write_text(json.dumps({"min_string_length": 8}))
        self.assertEqual(load_settings(p).min_string_length, 8)

    def test_unknown_key_rejected(self):
        p = self.root / "s.json"
        p.write_text(json.dumps({"min_strng_length": 8}))
        with self.assertRaisesRegex(ConfigError, "unknown"):
            load_settings(p)

    def test_invalid_value_rejected(self):
        for bad in ({"max_input_bytes": 0}, {"log_level": "LOUD"}, {"min_string_length": True},
                    {"tool_timeout_seconds": -1}, {"workspace_root": "  "}):
            p = self.root / "bad.json"
            p.write_text(json.dumps(bad))
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                load_settings(p)

    def test_malformed_json_rejected(self):
        p = self.root / "bad.json"
        p.write_text("{not json")
        with self.assertRaises(ConfigError):
            load_settings(p)


class LoggingTests(unittest.TestCase):
    def test_log_lines_are_json_with_event_and_fields(self):
        buf = io.StringIO()
        setup_logging("INFO", stream=buf)
        logging.getLogger("imagehunter.test").info("scan_started", extra={"fields": {"scan_id": "X1"}})
        line = json.loads(buf.getvalue().strip().splitlines()[-1])
        self.assertEqual(line["event"], "scan_started")
        self.assertEqual(line["scan_id"], "X1")
        self.assertEqual(line["level"], "INFO")
        setup_logging("WARNING", stream=io.StringIO())  # reset to quiet default


class RunnerTests(unittest.TestCase):
    def test_shell_syntax_passed_as_literal_argument(self):
        payload = "; echo PWNED"
        res = run_tool([sys.executable, "-c", "import sys; print(sys.argv[1])", payload])
        self.assertTrue(res.ok, res.error or res.stderr)
        self.assertEqual(res.stdout.strip(), payload)

    def test_timeout_enforced(self):
        res = run_tool([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
        self.assertTrue(res.timed_out)
        self.assertFalse(res.ok)

    def test_output_is_capped(self):
        res = run_tool([sys.executable, "-c", "print('a'*5000)"], output_cap=100)
        self.assertLessEqual(len(res.stdout), 101)

    def test_missing_executable_reported(self):
        res = run_tool(["definitely-not-a-real-binary-xyz"])
        self.assertIsNotNone(res.error)
        self.assertFalse(res.ok)

    def test_argv_validation(self):
        with self.assertRaises(ValueError):
            run_tool([])
        with self.assertRaises(ValueError):
            run_tool(["python", 3])


class RegistryTests(unittest.TestCase):
    def test_missing_tool_not_found_not_verified(self):
        status = check_tool(ExternalTool("zz-no-such-tool", ("--version",), "any", True, "t"))
        self.assertFalse(status.found)
        self.assertFalse(status.verified)

    def test_unvalidated_probe_never_verified(self):
        tool = ExternalTool("python", ("-c", "print('1.2.3')"), "any", False, "t")
        with mock.patch("imagehunter.integrations.registry.find_executable", return_value=sys.executable):
            status = check_tool(tool)
        self.assertTrue(status.found)
        self.assertFalse(status.verified)

    def test_validated_probe_marked_verified(self):
        tool = ExternalTool("python", ("-c", "print('9.9.9')"), "any", True, "t")
        with mock.patch("imagehunter.integrations.registry.find_executable", return_value=sys.executable):
            status = check_tool(tool)
        self.assertTrue(status.verified)
        self.assertEqual(status.version, "9.9.9")

    def test_registry_lists_requested_tools(self):
        names = {t.name for t in TOOLS}
        for expected in ("exiftool", "binwalk", "zsteg", "steghide", "stegseek", "foremost",
                         "outguess", "stegoveritas"):
            self.assertIn(expected, names)

    def test_no_tool_marked_probe_tested_yet(self):
        self.assertFalse(any(t.probe_tested for t in TOOLS))


class ModelTests(unittest.TestCase):
    def test_finding_rejects_invalid_label(self):
        with self.assertRaises(ValueError):
            Finding(kind="x", category="c", description="d", confidence_label="certain")

    def test_finding_title_defaults_from_kind(self):
        f = Finding(kind="appended_data", category="structure", description="d", confidence_label="High")
        self.assertEqual(f.title, "Appended data")

    def test_derived_artifact_requires_parent(self):
        with self.assertRaises(ValueError):
            Artifact(id="A2", role="derived", path="p", working_path="w", sha256="0" * 64, size=1)

    def test_invalid_artifact_role_rejected(self):
        with self.assertRaises(ValueError):
            Artifact(id="A1", role="copy", path="p", working_path="w", sha256="0" * 64, size=1)


if __name__ == "__main__":
    unittest.main()
