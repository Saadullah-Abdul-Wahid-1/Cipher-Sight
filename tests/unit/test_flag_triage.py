"""Decoy labelling and flag status rules.

These tests check general behaviour (keyword tables, leetspeak, context windows,
analyst overrides). No test names a specific flag as special.
"""

import unittest

from imagehunter.services.flag_triage import (
    assess_candidate,
    context_items_from_findings,
    decoy_phrases_in,
    normalise,
)
from imagehunter.services.report_data import classify_flags
from imagehunter.services.report_html import build_report_html


def _lsb_finding(fid, value, offset=0, label="Medium"):
    return {"id": fid, "kind": "lsb_flag_candidate", "category": "stego", "method": "stego.lsb",
            "confidence_label": label, "offset": offset,
            "evidence": {"text": value, "byte_offset": offset, "experiments": [
                {"channel": "R", "bit": 0, "traversal": "row", "bit_order": "MSB-first", "xor_key": 0}]}}


def _summary(findings):
    return {"input": {"path": "/tmp/sample.png"}, "findings": findings}


class NormaliseTests(unittest.TestCase):
    def test_leetspeak_and_separators_are_folded(self):
        self.assertEqual(normalise("n0t_th3_fl4g_keep_l00king"), "not the flag keep looking")

    def test_empty_and_punctuation_only(self):
        self.assertEqual(normalise("{}_-"), "")


class DecoyPhraseTests(unittest.TestCase):
    def test_decoy_wording_inside_flag_body_is_detected(self):
        self.assertIn("not the flag", decoy_phrases_in("CTF{n0t_th3_fl4g_keep_l00king}"))
        self.assertIn("keep looking", decoy_phrases_in("CTF{n0t_th3_fl4g_keep_l00king}"))

    def test_phrase_must_match_whole_words(self):
        # "notable" contains "not" but not the phrase "not it" as whole words.
        self.assertEqual(decoy_phrases_in("CTF{notable_items}"), [])

    def test_ordinary_flag_has_no_decoy_wording(self):
        self.assertEqual(decoy_phrases_in("RHL{t3st_fl4g_lsb_42}"), [])


class AssessCandidateTests(unittest.TestCase):
    def test_decoy_body_is_likely_decoy_with_reason(self):
        result = assess_candidate("CTF{n0t_th3_fl4g_keep_l00king}", 10, [])
        self.assertTrue(result.is_likely_decoy)
        self.assertEqual(result.label, "LIKELY DECOY")
        self.assertTrue(any("decoy wording" in r for r in result.reasons))

    def test_plain_candidate_stays_unverified(self):
        result = assess_candidate("RHL{t3st_fl4g_lsb_42}", 10, [])
        self.assertFalse(result.is_likely_decoy)
        self.assertEqual(result.label, "UNVERIFIED")
        self.assertEqual(result.reasons, [])

    def test_nearby_decoy_text_marks_candidate_with_source(self):
        context = [{"offset": 40, "text": "this is a fake flag, try again", "source": "F010"}]
        result = assess_candidate("THM{real_looking_value}", 44, context)
        self.assertTrue(result.is_likely_decoy)
        self.assertTrue(any("F010" in r for r in result.reasons))

    def test_distant_context_is_ignored(self):
        context = [{"offset": 5000, "text": "decoy", "source": "F011"}]
        result = assess_candidate("THM{real_looking_value}", 44, context)
        self.assertFalse(result.is_likely_decoy)

    def test_decoy_keyword_in_context_does_not_reject_candidate(self):
        # The result is a label; nothing is marked Rejected automatically.
        context = [{"offset": 0, "text": "decoy", "source": "F012"}]
        result = assess_candidate("THM{x}", 0, context)
        self.assertNotIn(result.label, ("REJECTED", "CONFIRMED"))


class ClassifyFlagsDecoyTests(unittest.TestCase):
    def test_decoy_and_genuine_are_both_kept_and_separated(self):
        s = _summary([_lsb_finding("F001", "CTF{n0t_th3_fl4g_keep_l00king}", 10),
                      _lsb_finding("F002", "RHL{t3st_fl4g_lsb_42}", 900)])
        flags = classify_flags(s)
        self.assertEqual([x["value"] for x in flags["likely_decoys"]], ["CTF{n0t_th3_fl4g_keep_l00king}"])
        self.assertEqual([x["value"] for x in flags["candidates"]], ["RHL{t3st_fl4g_lsb_42}"])
        self.assertEqual(flags["confirmed"], [])
        self.assertEqual(flags["rejected"], [])

    def test_decoy_keeps_its_reasons_and_evidence_ref(self):
        s = _summary([_lsb_finding("F001", "CTF{decoy_here}", 10)])
        item = classify_flags(s)["likely_decoys"][0]
        self.assertEqual(item["status"], "Likely Decoy")
        self.assertEqual(item["evidence_ref"], "F001")
        self.assertTrue(item["decoy_reasons"])

    def test_analyst_confirmation_overrides_decoy_label(self):
        s = _summary([_lsb_finding("F001", "CTF{decoy_here}", 10)])
        flags = classify_flags(s, {"CTF{decoy_here}": "confirmed"})
        self.assertEqual([x["value"] for x in flags["confirmed"]], ["CTF{decoy_here}"])
        self.assertEqual(flags["likely_decoys"], [])

    def test_analyst_rejection_overrides_decoy_label(self):
        s = _summary([_lsb_finding("F001", "CTF{decoy_here}", 10)])
        flags = classify_flags(s, {"CTF{decoy_here}": "rejected"})
        self.assertEqual([x["value"] for x in flags["rejected"]], ["CTF{decoy_here}"])
        self.assertEqual(flags["likely_decoys"], [])

    def test_automatic_pass_never_confirms_or_rejects(self):
        s = _summary([_lsb_finding("F001", "CTF{decoy_here}", 10),
                      _lsb_finding("F002", "THM{plain_value}", 300)])
        flags = classify_flags(s)
        self.assertEqual(flags["confirmed"], [])
        self.assertEqual(flags["rejected"], [])

    def test_phrase_context_from_same_image_marks_nearby_candidate(self):
        phrase = {"id": "F020", "kind": "expected_phrase", "category": "text", "offset": 100,
                  "evidence": {"phrase": "clue", "context": "not the flag, look elsewhere",
                               "context_offset": 98}}
        s = _summary([_lsb_finding("F001", "THM{abc_plain}", 110), phrase])
        flags = classify_flags(s)
        self.assertEqual([x["value"] for x in flags["likely_decoys"]], ["THM{abc_plain}"])

    def test_context_items_only_from_findings_with_context(self):
        findings = [{"id": "A", "evidence": {"text": "x"}}, {"id": "B", "evidence": {"context": "hi"}}]
        self.assertEqual([i["source"] for i in context_items_from_findings(findings)], ["B"])


class ReportDecoyRenderingTests(unittest.TestCase):
    def test_html_report_shows_decoy_section_with_reasons(self):
        s = _summary([_lsb_finding("F001", "CTF{n0t_th3_fl4g_keep_l00king}", 10)])
        s["metrics"] = {}
        page = build_report_html(s)
        self.assertIn("Likely decoy flags (not verified, not rejected)", page)
        self.assertIn("decoy wording", page)
        self.assertIn("No confirmed flags found.", page)


if __name__ == "__main__":
    unittest.main()
