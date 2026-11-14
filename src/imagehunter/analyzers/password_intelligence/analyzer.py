"""text.smart_words: explainable word and phrase candidates from text the other analyzers already found.

Text sources: printable ASCII runs and UTF-16 runs from the image bytes, and metadata text published
by the metadata analyzer. The analyzer never writes to evidence and never reports a candidate as a
verified password. Every candidate keeps its source, offset, transformation chain and score breakdown.
"""

from __future__ import annotations

import re
from collections import Counter

from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.analyzers.password_intelligence.clues import (
    CLUE_GROUPS, DATE, EMAIL, KEYVAL, QUOTED, URL, YEAR, find_clues, gate_present, has_negated_key_clue)
from imagehunter.analyzers.password_intelligence.normalize import (
    TOKEN, is_binary_like, is_repetitive, looks_like_text, normalize)
from imagehunter.analyzers.password_intelligence.ranking import (
    Instance, build_candidates, group_instances, has_caps_or_digits)
from imagehunter.analyzers.password_intelligence.segments import split_source
from imagehunter.analyzers.password_intelligence.stopwords import COMMON_WORDS, stopwords_for
from imagehunter.analyzers.password_intelligence.transforms import (
    case_variants, leet_variants, reverse_variant, separator_variants)

NOTE = ("Candidates are ranked for analyst review. They are not verified passwords or flags. "
        "Scores are review priorities, not probabilities.")
WINDOW = 160                      # characters on each side for "near clue"
MAX_NGRAMS_PER_SEGMENT = 300
MAX_TOKENS = 200_000
UTF16_LE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
UTF16_BE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")
MAX_CONTEXT = 80
CLUE_VOCAB = frozenset(w for _, terms in CLUE_GROUPS.values() for t in terms for w in t.split())


def _near(pos_start: int, pos_end: int, clues) -> tuple[int, bool]:
    best = 0
    for c in clues:
        if pos_start - WINDOW <= c.start <= pos_end + WINDOW:
            best = max(best, c.weight)
    return best, best > 0


class SmartWordsAnalyzer(Analyzer):
    name = "text.smart_words"

    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        res = AnalyzerResult()
        s = ctx.settings
        if not s.smart_words_enabled:
            res.properties.update(enabled=False)
            return res
        weights = dict(s.smart_weights)
        stop = stopwords_for(s.smart_stopword_language)
        common = COMMON_WORDS
        warnings: list[str] = []

        sources = self._sources(ctx, s.smart_max_source_chars, warnings)
        splits = []
        skipped_noise = 0
        for label, base, raw in sources:
            norm = normalize(raw)
            # A run with clue language is kept even if short: short passwords sit next to clue words.
            has_clue = any(w.lower() in CLUE_VOCAB for w in TOKEN.findall(norm))
            if is_repetitive(norm) or is_binary_like(norm) or not (looks_like_text(norm) or has_clue):
                skipped_noise += 1          # routine for binary files: counted, not a warning
                continue
            splits.append(split_source(label, base, norm))

        all_segments = [seg for sp in splits for seg in sp.segments]
        joined_lower = " \n".join(seg.text for seg in all_segments).lower()
        gates = {
            "acrostic_or_initials": gate_present(joined_lower, "acrostic_or_initials"),
            "every_nth": gate_present(joined_lower, "every_nth"),
            "reverse": gate_present(joined_lower, "reverse"),
        }
        freq: Counter = Counter()
        total_tokens = 0
        for seg in all_segments:
            for val, _, _ in seg.tokens:
                freq[val.lower()] += 1
                total_tokens += 1
        if total_tokens > MAX_TOKENS:
            warnings.append(f"token limit reached: {total_tokens} tokens, only the first {MAX_TOKENS} used")

        entities = Counter()
        instances: list[Instance] = []
        cap = s.smart_max_candidates * 20
        for sp in splits:
            for seg in sp.segments:
                if len(instances) >= cap:
                    break
                self._segment_instances(seg, s, stop, weights, gates, instances, entities, freq, common)
            if gates["acrostic_or_initials"] and 3 <= len(sp.line_first_letters) <= 64:
                instances.append(Instance(
                    value="".join(sp.line_first_letters), ctype="acrostic", chain=[], source=sp.segments[0].source
                    if sp.segments else "", offset=sp.segments[0].base if sp.segments else 0,
                    context="first letters of consecutive lines", token_norms=[]))
        if len(instances) >= cap:
            warnings.append(f"candidate generation stopped at {cap} instances")
        instances = self._transforms(instances, s, gates)

        groups = group_instances(instances)
        ranked = build_candidates(groups, weights, freq, common, s.smart_min_candidate_score,
                                  s.smart_include_low_priority)
        limited = ranked[: s.smart_max_candidates]
        for i, c in enumerate(limited, start=1):
            c["id"] = f"W{i:04d}"

        counts = Counter(c["priority"] for c in limited)
        res.properties.update(
            enabled=True,
            note=NOTE,
            language=s.smart_stopword_language,
            sources={"used": len(splits), "skipped_non_text": skipped_noise},
            tokens=min(total_tokens, MAX_TOKENS),
            entities={"emails": entities["email"], "urls": entities["url"],
                      "dates": entities["date"], "years": entities["year"]},
            gates=gates,
            candidates=limited,
            total_candidates=len(ranked),
            returned=len(limited),
            truncated=len(ranked) > len(limited),
            priority_counts={"High": counts.get("High", 0), "Medium": counts.get("Medium", 0),
                             "Low": counts.get("Low", 0)},
            limits={"max_candidates": s.smart_max_candidates, "max_variants": s.smart_max_variants,
                    "max_ngram_words": s.smart_max_ngram_words, "max_source_chars": s.smart_max_source_chars},
        )
        res.warnings.extend(warnings)
        return res

    # ---------------------------------------------------------------- sources
    @staticmethod
    def _sources(ctx, max_chars, warnings):
        out = []
        ascii_runs = ctx.shared.get("ascii_runs")
        if ascii_runs is None:
            ascii_runs = [(m.start(), m.group().decode("ascii"))
                          for m in re.finditer(rb"[\x20-\x7e]{%d,}" % ctx.settings.min_string_length, ctx.data)]
        for off, text in ascii_runs:
            out.append(("ascii strings", off, text))
        for m in UTF16_LE.finditer(ctx.data):
            out.append(("utf-16le strings", m.start(), m.group().decode("utf-16-le", errors="ignore")))
        for m in UTF16_BE.finditer(ctx.data):
            out.append(("utf-16be strings", m.start(), m.group().decode("utf-16-be", errors="ignore")))
        # Metadata values are read from the same bytes as the ASCII runs (for example a PNG tEXt chunk).
        # Such copies are not independent evidence, so they are dropped here.
        ascii_blob = "\n".join(t for _, t in ascii_runs)
        for label, off, text in ctx.shared.get("metadata_texts", []):
            if text and text in ascii_blob:
                continue
            out.append((label, off, text))
        budget, kept = max_chars, []
        for label, off, text in out:
            if budget <= 0:
                warnings.append(f"source character limit {max_chars} reached; later text skipped")
                break
            text = text[:budget]
            budget -= len(text)
            kept.append((label, off, text))
        return kept

    # -------------------------------------------------------------- instances
    def _segment_instances(self, seg, s, stop, weights, gates, instances, entities, freq, common):
        text = seg.text
        clues = find_clues(text, seg.tokens)
        clues_w = [type("C", (), {"start": c.start, "weight": weights[c.strength]}) for c in clues]
        dates = [m.start() for m in DATE.finditer(text)] + [m.start() for m in YEAR.finditer(text)]
        entities["date"] += len(DATE.findall(text))
        entities["year"] += len(YEAR.findall(text))
        entities["email"] += len(EMAIL.findall(text))
        entities["url"] += len(URL.findall(text))

        entity_spans = [m.span() for rx in (EMAIL, URL) for m in rx.finditer(text)]

        def add(value, ctype, start, end, norms, stopword_only=False):
            # Words inside an e-mail address or URL are entities, not candidates.
            if any(start < e and st < end for st, e in entity_spans):
                return
            cp, near = _near(start, end, clues_w)
            dnear = any(start - WINDOW <= d <= end + WINDOW and _near(d, d, clues_w)[1] for d in dates)
            ctx_text = text[max(0, start - MAX_CONTEXT):end + MAX_CONTEXT]
            instances.append(Instance(
                value=value, ctype=ctype, chain=[], source=seg.source, offset=seg.base + start,
                context=ctx_text, token_norms=norms, clue_points=cp,
                phrase_near=near, date_near=dnear, caps_digits=has_caps_or_digits(value),
                stopword_only=stopword_only))

        toks = seg.tokens[:MAX_TOKENS]
        for val, st, en in toks:
            if s.smart_min_token_length <= len(val) <= s.smart_max_token_length and val.lower() not in stop:
                add(val, "token", st, en, [val.lower()])

        n_max = min(s.smart_max_ngram_words, len(toks))
        made = 0
        for n in range(2, n_max + 1):
            for i in range(len(toks) - n + 1):
                if made >= MAX_NGRAMS_PER_SEGMENT:
                    break
                window = toks[i:i + n]
                norms = [v.lower() for v, _, _ in window if v.lower() not in stop]
                if not norms or window[0][0].lower() in stop or window[-1][0].lower() in stop:
                    continue                       # phrases start and end on a content word
                if all(t in CLUE_VOCAB for t in (v.lower() for v, _, _ in window)):
                    continue                       # a phrase made only of clue words is not a candidate
                rare = any(t not in common and freq.get(t, 1) <= 3 for t in norms)
                unusual = any(has_caps_or_digits(v) for v, _, _ in window)
                near_clue = _near(window[0][1], window[-1][2], clues_w)[1]
                if not (rare or unusual or near_clue):
                    continue
                value = text[window[0][1]:window[-1][2]]
                add(value, "phrase", window[0][1], window[-1][2], norms)
                made += 1

        if len(toks) >= 3:
            for v, st, en in (toks[0], toks[-1]):
                if v.lower() not in stop:
                    add(v, "sentence_edge", st, en, [v.lower()])

        if gates["every_nth"] and len(toks) >= 4:
            for picks in (toks[0::2], toks[1::2]):
                value = "".join(v for v, _, _ in picks)
                if 3 <= len(value) <= 64:
                    add(value, "every_nth", picks[0][1], picks[-1][2], [v.lower() for v, _, _ in picks])

        if gates["acrostic_or_initials"] and 3 <= len(toks) <= 32:
            value = "".join(v[0] for v, _, _ in toks)
            add(value, "first_letters", toks[0][1], toks[-1][2], [])

        for m in QUOTED.finditer(text):
            val = m.group(1).strip()
            if val:
                add(val, "quoted", m.start(1), m.end(1), [t.lower() for t in TOKEN.findall(val)][:8])

        for m in KEYVAL.finditer(text):
            if has_negated_key_clue(text, m.start()):
                continue
            val = m.group(2).rstrip(".,;:!?)]}")
            if not val:
                continue
            cp = weights["clue_strong"]
            instances.append(Instance(
                value=val, ctype="structured_value", chain=[], source=seg.source, offset=seg.base + m.start(2),
                context=text[max(0, m.start() - MAX_CONTEXT):m.end() + MAX_CONTEXT],
                token_norms=[t.lower() for t in TOKEN.findall(val)][:8] or [val.lower()],
                clue_points=cp, phrase_near=True, date_near=False,
                caps_digits=has_caps_or_digits(val)))

    # ---------------------------------------------------------- transformations
    @staticmethod
    def _transforms(instances, s, gates):
        out = list(instances)
        for inst in instances:
            if inst.ctype in ("token", "structured_value", "quoted") and (inst.clue_points > 0 or inst.ctype != "token"):
                for val, step in case_variants(inst.value):
                    out.append(_copy(inst, val, inst.chain + [step]))
            if s.smart_enable_leetspeak and inst.ctype in ("token", "structured_value"):
                for val, step in leet_variants(inst.value, s.smart_max_variants):
                    out.append(_copy(inst, val, inst.chain + [step]))
            if (s.smart_enable_separators and inst.ctype == "phrase" and inst.clue_points > 0
                    and len(inst.value.split()) <= 3):
                for val, step in separator_variants(inst.value):
                    out.append(_copy(inst, val, inst.chain + [step]))
            # Reversal only for clue-adjacent tokens. In clue_only mode it also needs a reversal clue.
            reverse_ok = s.smart_reverse_mode == "on" or (s.smart_reverse_mode == "clue_only" and gates["reverse"])
            if inst.ctype == "token" and inst.clue_points > 0 and reverse_ok:
                val, step = reverse_variant(inst.value)
                out.append(_copy(inst, val, inst.chain + [step]))
        return out


def _copy(inst: Instance, value: str, chain: list[str]) -> Instance:
    return Instance(value=value, ctype=inst.ctype, chain=chain, source=inst.source, offset=inst.offset,
                    context=inst.context, token_norms=inst.token_norms, clue_points=inst.clue_points,
                    phrase_near=inst.phrase_near, date_near=inst.date_near,
                    caps_digits=has_caps_or_digits(value), stopword_only=inst.stopword_only)
