"""HTML report: escaping, consistency with the JSON model, empty and multi-flag states, failed scans."""

import copy
import json
import re
import tempfile
import unittest

from html.parser import HTMLParser
from pathlib import Path

from imagehunter.core.status import EXECUTED
from imagehunter.services.report_data import build_view, classify_flags
from imagehunter.services.report_html import build_report_html, esc


def _summary(findings=None, analyzers=None, warnings=None, props=None, log=None, path="/data/sample.png"):
    return {
        "scan_id": "20261107T000000Z-test0001",
        "started_at": "2026-11-07T10:00:00+00:00",
        "finished_at": "2026-11-07T10:00:04.250+00:00",
        "status": "completed",
        "input": {"id": "A001", "path": path, "sha256": "ab" * 32, "size": 1234, "role": "original"},
        "findings": findings or [],
        "properties": props or {"image.identity": {"signature_format": "png", "pillow_format": "PNG",
                                                   "width": 640, "height": 480, "mode": "RGB", "frames": 1,
                                                   "extension": ".png"}},
        "analyzers": analyzers or [{"name": "stego.lsb", "status": "pass", "message": ""}],
        "warnings": warnings or [],
        "workspace": "/work/ws/scan1",
        "limitations": ["Limitation one."],
        "execution_log": log or [],
        "app_version": "0.5.0",
    }


def _flag(fid, text, offset=17760, channel="B", key=0x37):
    return {"id": fid, "kind": "lsb_flag_candidate", "category": "stego", "method": "stego.lsb",
            "offset": offset, "confidence_label": "High", "description": "d",
            "evidence": {"text": text, "byte_offset": offset // 8, "first_pixel": [37, 0],
                         "experiments": [{"channel": channel, "bit": 0, "traversal": "column",
                                          "bit_order": "LSB-first", "xor_key": key}]}}


def _phrase(fid, phrase, offset, context="ctx"):
    return {"id": fid, "kind": "expected_phrase", "category": "phrase", "method": "text.phrases",
            "offset": offset, "confidence_label": "High", "description": "p",
            "evidence": {"phrase": phrase, "match": "exact", "encoding": "raw bytes",
                         "context": context}}


class _TagCounter(HTMLParser):
    """Collects tag names and whether any external resource is referenced."""

    def __init__(self):
        super().__init__()
        self.tags = []
        self.external = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for k, v in attrs:
            if k in ("src", "href") and v and (v.startswith("http") or v.startswith("//")):
                self.external.append((tag, k, v))


class EscapingTests(unittest.TestCase):
    def test_escape_helper(self):
        self.assertEqual(esc('<a href="x">&\'</a>'), "&lt;a href=&quot;x&quot;&gt;&amp;&#x27;&lt;/a&gt;")

    def test_hostile_strings_never_become_markup(self):
        evil_path = '/data/<script>alert(1)</script>"><img src=x onerror=alert(2)>.png'
        evil_flag = 'THM{<img src=x onerror=alert(3)>&"\'}'
        evil_phrase = '"><svg onload=alert(4)>'
        evil_context = "<iframe src=javascript:alert(5)></iframe>"
        s = _summary(
            findings=[_flag("F001", evil_flag), _phrase("F002", evil_phrase, 9, evil_context)],
            path=evil_path,
            warnings=["<b>bold warning</b>"],
            log=[{"ts": "2026-11-07T10:00:00.000+00:00", "level": "INFO", "module": "m<i>",
                  "operation": "o", "message": "<script>x</script>", "status": "ok", "percent": 5}],
        )
        page = build_report_html(s)
        for bad in ("<script>alert", "<img src=x", "<svg onload", "<iframe", "<b>bold", "<i>m"):
            self.assertNotIn(bad, page, bad)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("&lt;img src=x onerror=alert(3)&gt;", page)
        self.assertIn("&quot;&gt;&lt;svg onload=alert(4)&gt;", page)

    def test_copy_attribute_is_escaped(self):
        s = _summary(findings=[_flag("F001", 'THM{"quote"}')])
        page = build_report_html(s)
        self.assertIn('data-copy="THM{&quot;quote&quot;}"', page)


class ConsistencyTests(unittest.TestCase):
    def test_html_counts_match_json_model(self):
        s = _summary(findings=[_flag("F001", "THM{one}"), _flag("F002", "THM{two}", offset=8),
                               _phrase("F003", "flag", 40)])
        view = build_view(s)
        page = build_report_html(s)
        self.assertEqual(view["metrics"]["flag_candidates"], 2)
        self.assertEqual(view["metrics"]["phrase_matches"], 1)
        self.assertEqual(view["metrics"]["total_findings"], 3)
        self.assertIn(f'<div class="cv">{view["metrics"]["total_findings"]}</div>', page)
        self.assertIn(f'<div class="cv">{view["metrics"]["flag_candidates"]}</div>', page)
        for f in s["findings"]:
            self.assertIn(f"{f['id']}</td>", page, f["id"])
        self.assertIn("THM{one}", page)
        self.assertIn("THM{two}", page)

    def test_every_finding_reference_appears_in_report(self):
        s = _summary(findings=[_flag("F001", "THM{a}"), _phrase("F002", "flag", 5)])
        page = build_report_html(s)
        self.assertIn("F001", page)
        self.assertIn("F002", page)


class FlagStateTests(unittest.TestCase):
    def test_no_flags_states_no_confirmed(self):
        page = build_report_html(_summary())
        self.assertIn("No confirmed flags found.", page)
        self.assertIn("No unverified flag candidates.", page)
        self.assertIn("No expected phrase matches.", page)

    def test_regex_match_is_candidate_not_confirmed(self):
        s = _summary(findings=[_flag("F001", "THM{only_a_match}")])
        page = build_report_html(s)
        self.assertIn("No confirmed flags found.", page)
        self.assertIn("THM{only_a_match}", page)
        flags = classify_flags(s)
        self.assertEqual(flags["confirmed"], [])
        self.assertEqual(flags["candidates"][0]["status"], "Candidate")

    def test_analyst_confirmation_moves_flag_to_confirmed_section(self):
        s = _summary(findings=[_flag("F001", "THM{real}"), _flag("F002", "THM{decoy}", offset=8)])
        page = build_report_html(s, verifications={"THM{real}": "confirmed", "THM{decoy}": "rejected"})
        flags = classify_flags(s, {"THM{real}": "confirmed", "THM{decoy}": "rejected"})
        self.assertEqual([f["value"] for f in flags["confirmed"]], ["THM{real}"])
        self.assertEqual([f["value"] for f in flags["rejected"]], ["THM{decoy}"])
        self.assertNotIn("No confirmed flags found.", page)
        self.assertIn("Rejected flags (false positives)", page)

    def test_unknown_decision_rejected(self):
        with self.assertRaises(ValueError):
            classify_flags(_summary(), {"THM{x}": "probably"})

    def test_unknown_prefix_lsb_lead_is_visible_as_weak_candidate(self):
        finding = {"id": "F009", "kind": "lsb_unknown_prefix_lead", "category": "stego",
                   "confidence_label": "Low", "method": "stego.lsb", "offset": 0,
                   "evidence": {"text": "RHL{t3st_fl4g_lsb_42}", "experiments": [
                       {"channel": "R", "bit": 0, "traversal": "row", "bit_order": "MSB-first", "xor_key": 0}]}}
        flags = classify_flags(_summary(findings=[finding]))
        self.assertEqual(flags["weak_candidates"][0]["value"], "RHL{t3st_fl4g_lsb_42}")
        self.assertEqual(flags["candidates"][0]["confidence"], "Low")

    def test_multiple_flags_and_phrases_all_listed(self):
        s = _summary(findings=[_flag("F001", "THM{a}"), _flag("F002", "CTF{b}", channel="R"),
                               _flag("F003", "FLAG{c}", channel="G"), _phrase("F004", "secret", 9),
                               _phrase("F005", "hidden", 90)])
        page = build_report_html(s)
        for needle in ("THM{a}", "CTF{b}", "FLAG{c}", "secret", "hidden"):
            self.assertIn(needle, page)
        self.assertEqual(build_view(s)["metrics"]["flag_candidates"], 3)
        self.assertEqual(build_view(s)["metrics"]["phrase_matches"], 2)


class ModuleHonestyTests(unittest.TestCase):
    def test_unexecuted_modules_are_labelled_not_executed(self):
        page = build_report_html(_summary())
        self.assertIn("Modules not executed in this scan", page)
        self.assertIn("Metadata (EXIF, XMP, IPTC, GPS)", page)
        self.assertIn("Embedded data is detected but not extracted.", page)

    def test_failed_analyzer_shows_failed_badge_and_error(self):
        s = _summary(
            analyzers=[{"name": "stego.lsb", "status": "error", "message": "ValueError: bad pixels"}],
            warnings=["stego.lsb failed: ValueError: bad pixels"],
        )
        s["status"] = "completed_with_warnings"
        page = build_report_html(s)
        self.assertIn("FAILED", page)
        self.assertIn("ValueError: bad pixels", page)
        self.assertIn("WARNING", page)

    def test_report_is_standalone_no_external_resources(self):
        page = build_report_html(_summary(findings=[_flag("F001", "THM{a}")]))
        counter = _TagCounter()
        counter.feed(page)
        self.assertEqual(counter.external, [])
        self.assertNotIn("https://", page)
        self.assertNotIn("<link ", page)

    def test_report_timestamp_and_print_css_present(self):
        page = build_report_html(_summary())
        self.assertIn("Report generated", page)
        self.assertIn("@media print", page)

    def test_json_round_trip_and_html_from_same_dict(self):
        s = _summary(findings=[_flag("F001", "THM{a}")])
        restored = json.loads(json.dumps(s))
        self.assertEqual(build_report_html(s), build_report_html(restored))


if __name__ == "__main__":
    unittest.main()
