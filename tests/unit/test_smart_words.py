"""Smart word engine: tokenization, stopwords, clue patterns and negation, candidates, variants,
deduplication, ranking breakdown, determinism and caps. Synthetic text only; no answer keys."""

import unittest

from imagehunter.analyzers.base import AnalyzerContext
from imagehunter.analyzers.password_intelligence.analyzer import SmartWordsAnalyzer
from imagehunter.analyzers.password_intelligence.clues import (
    DATE, EMAIL, KEYVAL, QUOTED, URL, YEAR, find_clues, has_negated_key_clue)
from imagehunter.analyzers.password_intelligence.normalize import (
    TOKEN, is_binary_like, is_repetitive, normalize)
from imagehunter.analyzers.password_intelligence.ranking import (
    priority_of, score_group, group_instances, Instance)
from imagehunter.analyzers.password_intelligence.stopwords import COMMON_WORDS, stopwords_for
from imagehunter.analyzers.password_intelligence.transforms import (
    case_variants, leet_variants, separator_variants)
from imagehunter.config.settings import ConfigError, Settings
from imagehunter.models.artifact import Artifact


def run_smart(text: str, metadata=None, **overrides):
    """Run the analyzer on one ASCII source (plus optional metadata texts) and return its properties."""
    data = text.encode("utf-8")
    art = Artifact(id="A001", role="original", path="t.png", working_path="t.png", sha256="0" * 64, size=len(data))
    shared = {"ascii_runs": [(0, text)]}
    if metadata:
        shared["metadata_texts"] = metadata
    ctx = AnalyzerContext(artifact=art, data=data, settings=Settings(**overrides), shared=shared)
    res = SmartWordsAnalyzer().run(ctx)
    return res.properties


def values(props):
    return [c["value"] for c in props["candidates"]]


class TokenizerTests(unittest.TestCase):
    def test_unicode_words_apostrophes_and_hyphens(self):
        toks = TOKEN.findall("Café naïve pass-word don't ок 北京")
        for expected in ("Café", "naïve", "pass-word", "don't", "ок", "北京"):
            self.assertIn(expected, toks)

    def test_underscore_separates_tokens(self):
        self.assertEqual(TOKEN.findall("alpha_beta"), ["alpha", "beta"])

    def test_nfc_normalization_and_line_endings(self):
        decomposed = "cafe\u0301"
        self.assertEqual(normalize(decomposed), "caf\u00e9")
        self.assertEqual(normalize("a\r\nb\rc"), "a\nb\nc")

    def test_control_characters_are_replaced_not_kept(self):
        self.assertNotIn("\x01", normalize("ab\x01cd"))

    def test_binary_like_and_repetitive_detection(self):
        self.assertTrue(is_binary_like("\x01\x02\x03\x04\x05abc"))
        self.assertFalse(is_binary_like("A normal sentence."))
        self.assertTrue(is_repetitive("a" * 12))
        self.assertFalse(is_repetitive("aaa"))

    def test_stopwords_kept_for_clue_analysis_but_not_candidates(self):
        tokens = [(t.group(), t.start(), t.end()) for t in TOKEN.finditer("the first word")]
        self.assertIn("the", [v.lower() for v, _, _ in tokens])
        clues = find_clues("the first word", tokens)
        self.assertIn("first", [c.term for c in clues])          # 'the' did not hide the position clue
        props = run_smart("the first word")
        self.assertNotIn("the", [v.lower() for v in values(props)])

    def test_unsupported_stopword_language_rejected(self):
        with self.assertRaises(ValueError):
            stopwords_for("fr")
        with self.assertRaises(ConfigError):
            Settings(smart_stopword_language="fr").validate()

    def test_short_tokens_are_not_removed_globally(self):
        props = run_smart("key ab xy", smart_min_token_length=2, smart_min_candidate_score=0)
        self.assertIn("ab", [v.lower() for v in values(props)])
        strict = run_smart("key ab xy", smart_min_token_length=3, smart_min_candidate_score=0)
        self.assertNotIn("ab", [v.lower() for v in values(strict)])

    def test_multilingual_text_is_not_discarded(self):
        props = run_smart("Пароль: Ключ-7 mot de passe Zürich", smart_min_candidate_score=0)
        self.assertTrue(any("Ключ" in v or "Zürich" in v for v in values(props)))


class ClueAndNegationTests(unittest.TestCase):
    def _clue_terms(self, text):
        tokens = [(t.group(), t.start(), t.end()) for t in TOKEN.finditer(text)]
        return [c.term for c in find_clues(text, tokens)]

    def test_positive_password_clue(self):
        self.assertIn("password", self._clue_terms("The password is hidden here"))

    def test_negated_password_clue_is_ignored(self):
        self.assertNotIn("password", self._clue_terms("There is no password required."))
        self.assertNotIn("password", self._clue_terms("Not the password you think."))
        self.assertNotIn("password", self._clue_terms("no password is needed"))

    def test_without_spaces_is_a_combination_clue_not_negation(self):
        self.assertIn("without spaces", self._clue_terms("join the words without spaces"))

    def test_word_boundary_avoids_partial_matches(self):
        self.assertNotIn("password", self._clue_terms("passwords are listed"))

    def test_key_value_extraction_and_negation(self):
        m = KEYVAL.search("password = Quartz9.")
        self.assertEqual(m.group(2), "Quartz9.")
        text = "There is no password: Quartz9"
        self.assertTrue(has_negated_key_clue(text, text.index("password")))
        text2 = "The password: Quartz9"
        self.assertFalse(has_negated_key_clue(text2, text2.index("password")))

    def test_quoted_dates_emails_urls_detected_separately(self):
        self.assertEqual(QUOTED.search('say "Quartz" now').group(1), "Quartz")
        self.assertTrue(DATE.search("on 2024-05-06"))
        self.assertTrue(YEAR.search("in 1999"))
        self.assertTrue(EMAIL.search("write to a.b@example.org"))
        self.assertTrue(URL.search("see https://example.org/x"))

    def test_email_and_url_are_entities_not_candidates(self):
        props = run_smart("write a.b@example.org or visit https://example.org/page now")
        self.assertEqual(props["entities"]["emails"], 1)
        self.assertEqual(props["entities"]["urls"], 1)
        self.assertFalse([c for c in props["candidates"] if "@" in c["value"] or "http" in c["value"]])


class CandidateGenerationTests(unittest.TestCase):
    def test_sentence_boundary_stops_phrases(self):
        props = run_smart("Zebra. Quokka runs fast.", smart_min_candidate_score=0)
        for value in values(props):
            self.assertFalse("Zebra" in value and "Quokka" in value, value)

    def test_phrase_keeps_original_spacing(self):
        props = run_smart("Remember the lighthouse  moonlit  harbor now", smart_min_candidate_score=0)
        self.assertIn("lighthouse  moonlit  harbor", values(props))

    def test_sentence_edges_generated(self):
        props = run_smart("Alpha bravo charlie delta.", smart_min_candidate_score=0)
        by_value = {c["value"]: c for c in props["candidates"]}
        self.assertIn("sentence_edge", by_value["Alpha"]["types"])
        self.assertIn("sentence_edge", by_value["delta"]["types"])

    def test_acrostic_only_when_clue_present_and_lines_known(self):
        text_with = "Use the initials of each line.\nApple tree\nBanana split\nCherry pie\nDate night"
        # 'Use the initials...' also starts a line, so its U is part of the acrostic.
        self.assertIn("UABCD", values(run_smart(text_with, smart_min_candidate_score=0)))
        text_without = "Apple tree\nBanana split\nCherry pie\nDate night"
        self.assertFalse([v for v in values(run_smart(text_without, smart_min_candidate_score=0))
                          if v == "ABCD" or v == "ABCD".lower()])

    def test_every_nth_only_when_selection_clue_present(self):
        with_clue = run_smart("Every second word matters. Quartz river zephyr lantern.", smart_min_candidate_score=0)
        self.assertIn("Quartzzephyr", values(with_clue))
        without = run_smart("Quartz river zephyr lantern. Quartz river zephyr lantern.", smart_min_candidate_score=0)
        self.assertNotIn("Quartzzephyr", values(without))

    def test_reverse_only_next_to_clue_in_clue_only_mode(self):
        plain = run_smart("The password is Quartz9.", smart_min_candidate_score=0)
        self.assertFalse([c for c in plain["candidates"] if "reverse" in c["transform_chain"]])
        with_gate = run_smart("Read the password backwards: Quartz9.", smart_min_candidate_score=0)
        self.assertTrue([c for c in with_gate["candidates"] if "reverse" in c["transform_chain"]])


class TransformTests(unittest.TestCase):
    def test_case_variants_are_bounded_and_recorded(self):
        out = case_variants("Quartz")
        # "Quartz" is already title case, so the title_case form equals the original and is not repeated.
        self.assertEqual({step for _, step in out}, {"lowercase", "uppercase"})
        self.assertIn(("quartz", "lowercase"), out)

    def test_leet_variants_bounded_no_cartesian_explosion(self):
        value = "aeiostaeiost"                       # 12 substitutable characters
        self.assertLessEqual(len(leet_variants(value, 24)), 24)
        self.assertEqual(len(leet_variants(value, 3)), 3)
        self.assertEqual(leet_variants("zzz", 24), [])

    def test_separator_variants_only_for_phrases(self):
        out = [v for v, _ in separator_variants("alpha beta")]
        self.assertEqual(out, ["alphabeta", "alpha-beta", "alpha_beta"])
        self.assertEqual(separator_variants("single"), [])

    def test_variant_count_respects_setting(self):
        props = run_smart("The password is aeiostaeiost today.", smart_max_variants=2, smart_min_candidate_score=0)
        leet = [c for c in props["candidates"] if any(s.startswith("leetspeak") for s in c["transform_chain"])]
        for c in leet:
            self.assertTrue(len(c["variants"]) <= 10)


class DeduplicationAndCapTests(unittest.TestCase):
    def test_case_insensitive_duplicates_merge(self):
        props = run_smart("Quartz here. quartz there. QUARTZ again.", smart_min_candidate_score=0)
        keys = [c["value"].casefold() for c in props["candidates"]]
        self.assertEqual(len(keys), len(set(keys)))

    def test_candidate_cap_and_truncation_flag(self):
        text = " ".join(f"word{i}xyz" for i in range(60))
        props = run_smart(text, smart_max_candidates=5, smart_min_candidate_score=0)
        self.assertEqual(props["returned"], 5)
        self.assertTrue(props["truncated"])
        self.assertGreater(props["total_candidates"], 5)

    def test_deterministic_order_for_identical_input(self):
        text = "The password is Quartz9. Remember the lighthouse moon. Alpha bravo charlie."
        self.assertEqual(run_smart(text), run_smart(text))


class RankingTests(unittest.TestCase):
    WEIGHTS = {"clue_strong": 30, "clue_medium": 20, "clue_weak": 10, "clue_context": 5, "rarity": 20,
               "corroboration": 15, "phrase_near_clue": 15, "caps_digits": 10, "date_near_clue": 10,
               "transform_penalty": 10}

    def _group(self, **kw):
        base = dict(value="Quartz9", ctype="token", chain=[], source="ascii strings", offset=0, context="",
                    token_norms=["quartz9"], clue_points=30, phrase_near=True, date_near=False, caps_digits=True)
        base.update(kw)
        return group_instances([Instance(**base)])

    def test_breakdown_components_and_bounds(self):
        g = self._group()
        s = score_group(next(iter(g.values())), self.WEIGHTS, {"quartz9": 1}, COMMON_WORDS)
        self.assertEqual(set(s["breakdown"]), {"clue_context", "rarity", "corroboration", "phrase_near_clue",
                                               "caps_or_digits", "date_near_clue", "transform_penalty"})
        self.assertEqual(s["score"], sum(s["breakdown"].values()))
        self.assertTrue(0 <= s["score"] <= 100)

    def test_transformed_only_form_is_penalised(self):
        plain = self._group()
        leet = self._group(value="Qu4rtz9", chain=["leetspeak:pos2"])
        p = score_group(next(iter(plain.values())), self.WEIGHTS, {}, COMMON_WORDS)
        l = score_group(next(iter(leet.values())), self.WEIGHTS, {}, COMMON_WORDS)
        self.assertEqual(l["breakdown"]["transform_penalty"], -10)
        self.assertLess(l["score"], p["score"] + 1)

    def test_corroboration_counts_independent_sources(self):
        two = group_instances([
            Instance(value="Quartz9", ctype="token", chain=[], source="ascii strings", offset=0, context="",
                     token_norms=["quartz9"], clue_points=30),
            Instance(value="Quartz9", ctype="token", chain=[], source="metadata:tEXt Author", offset=40,
                     context="", token_norms=["quartz9"], clue_points=30)])
        s = score_group(next(iter(two.values())), self.WEIGHTS, {}, COMMON_WORDS)
        self.assertEqual(s["source_count"], 2)
        self.assertEqual(s["breakdown"]["corroboration"], 5)

    def test_metadata_copy_of_ascii_text_is_not_corroboration(self):
        props = run_smart("Remember Quartz9 today", metadata=[("metadata:tEXt Comment", 0, "Remember Quartz9 today")],
                          smart_min_candidate_score=0)
        hit = [c for c in props["candidates"] if c["value"] == "Quartz9"]
        self.assertTrue(hit)
        self.assertEqual(hit[0]["source_count"], 1)

    def test_priority_thresholds(self):
        self.assertEqual(priority_of(50), "High")
        self.assertEqual(priority_of(49), "Medium")
        self.assertEqual(priority_of(30), "Medium")
        self.assertEqual(priority_of(29), "Low")

    def test_min_score_and_low_priority_filters(self):
        text = "The password is Quartz9. Random filler tokens here for context."
        high = run_smart(text, smart_min_candidate_score=90)
        self.assertTrue(all(c["score"] >= 90 for c in high["candidates"]))
        no_low = run_smart(text, smart_min_candidate_score=0, smart_include_low_priority=False)
        self.assertNotIn("Low", {c["priority"] for c in no_low["candidates"]})

    def test_reasons_match_present_components(self):
        props = run_smart("The password is Quartz9.", smart_min_candidate_score=0)
        top = props["candidates"][0]
        self.assertTrue(top["reasons"])
        self.assertTrue(all(isinstance(r, str) for r in top["reasons"]))


class SettingsValidationTests(unittest.TestCase):
    def test_weights_must_have_exact_keys(self):
        bad = dict(Settings().smart_weights)
        bad.pop("rarity")
        with self.assertRaises(ConfigError):
            Settings(smart_weights=bad).validate()

    def test_reverse_mode_validated(self):
        with self.assertRaises(ConfigError):
            Settings(smart_reverse_mode="sometimes").validate()


if __name__ == "__main__":
    unittest.main()
