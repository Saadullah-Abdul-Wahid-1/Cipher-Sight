# Smart word and phrase candidates (v0.8.0)

Analyzer name: `text.smart_words`. Runs last, after the strings, phrase and metadata analyzers, and reads
their text. Results are in `properties["text.smart_words"]` in the JSON report.

## What it does
- **Sources:** printable ASCII runs and UTF-16 runs from the image bytes, and metadata text (PNG tEXt/zTXt/iTXt,
  EXIF text fields). A metadata value that repeats bytes already read from the image is not counted again.
- **Filtering:** a run is used only if it looks like text (mostly letters, a 3+ letter word, English-like letter
  pairs) or contains clue language. Compressed-data noise is counted in `sources.skipped_non_text`.
- **Tokens:** Unicode words with internal apostrophes and hyphens. Stopwords are kept for clue analysis and are
  only left out of standalone token candidates.
- **Candidate types:** `token`, `phrase` (2 to N words, original spacing kept, starts and ends on a content word),
  `sentence_edge`, `quoted`, `structured_value` (from `password = ...`, `key is ...`), `every_nth` and
  `first_letters` (only when a selection clue is present), `acrostic` (only when line boundaries are known and a
  clue is present), and `reverse` (only next to a clue).
- **Transformations:** case variants, leetspeak (bounded by `smart_max_variants`), phrase separators, reversal.
  Each variant keeps its chain, e.g. `["leetspeak:pos2"]`. The original is always kept.
- **Scoring:** a transparent breakdown per candidate (see below). A transformed-only form gets a penalty.
- **Entities:** e-mail addresses, URLs, dates and years are counted separately. Words inside an e-mail or URL
  are never candidates.

## Score breakdown (default weights, configurable in `smart_weights`)
| Component | Points | Meaning |
|---|---|---|
| clue_context | up to 30 (strong), 20 (medium), 10 (weak), 5 (context) | strongest clue within 160 characters |
| rarity | up to 20 | token is rare in this artifact and not a common word |
| corroboration | up to 15 | same value in independent sources (5 per extra source) |
| phrase_near_clue | 15 | phrase-type candidate near a clue |
| caps_or_digits | 10 | mixed case or letters with digits |
| date_near_clue | 10 | date or year near a clue |
| transform_penalty | -10 | only a transformed form exists |

The score is a review priority from 0 to 100. It is not a probability and it does not mean "this is the password".
Priority: High at 50+, Medium at 30+, otherwise Low.

## Settings
Flat keys in the existing settings file: `smart_words_enabled`, `smart_min_token_length` (3),
`smart_max_token_length` (64), `smart_max_ngram_words` (5), `smart_min_candidate_score` (20),
`smart_max_candidates` (10000), `smart_max_variants` (24), `smart_enable_leetspeak`, `smart_enable_separators`,
`smart_reverse_mode` (off | clue_only | on), `smart_include_low_priority`, `smart_stopword_language` ("en" only),
`smart_max_source_chars`, `smart_weights`.

## CLI
    python main.py scan image.png --smart-words
    python main.py scan image.png --smart-words --min-score 35
    python main.py scan image.png --export-candidates candidates.txt
    python main.py scan image.png --export-candidates-json candidates.json

TXT is a plain list of values. JSON includes scores, breakdowns, provenance and a sensitivity warning.
Both are deterministic for identical input and settings.

## Limits
- Only English stopwords and English letter-pair checks are bundled. Other languages are kept as text but
  are not stopword-filtered.
- Printable text inside XMP or C2PA structures (for example `specVersion`, `contentauth`) passes the text filter and
  can appear as Medium candidates with no clue. Filter by source or raise `smart_min_candidate_score`.
- `every_nth` and `first_letters` candidates are generated when a clue asks for them, so they can be
  meaningless. They are review leads only.
- No OCR, no decoded-payload or carved-file sources yet (those analyzers are not built).
- GUI panel, web-interface panel and PDF output for candidates are not implemented in this version.
  Candidates are available in the CLI, JSON, TXT and the HTML report section.
- No archive password attempts. Nothing is sent to external services.

## Privacy and safety
Candidates are derived from evidence and can contain sensitive text. Exports carry a warning. The engine never
evaluates image text, never calls a network service, and bounds every stage (source characters, tokens,
n-gram words, candidates, variants).
