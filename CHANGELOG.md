## Unreleased (rc7 work)

- Web UI restructured into grouped navigation: Overview (Dashboard, New Investigation, Scan History), Findings (Findings and Evidence, Confirmed Flags, Unverified Candidates, Decoy Flags), Analysis (Steganography, Text and Clues, Metadata, Embedded Files, OCR and QR, Forensic Analysis), Records (Scan Logs, Reports, About). Settings is not shown because the UI does not edit settings.
- Front end moved to real files in `src/imagehunter/web/static/` (index.html, app.css, app.js, logo.jpg). `assets.py` loads them.
- Dashboard statistics come from `GET /api/stats`, computed from stored scan results for the current server session only. Results are kept in memory and clear when the server stops.
- Analyst review in the browser: `POST /api/scans/<id>/verifications` with `{"value", "decision": "confirmed" | "rejected" | "clear"}` and the X-ImageHunter header. Decisions change the on-screen views for that scan. Exported reports are written when the scan finishes and do not include later decisions.
- Flag vocabulary in the UI: CONFIRMED, UNVERIFIED (engine status Candidate), LIKELY DECOY, REJECTED.
- Browser check run with headless Chromium: all pages render, scan and review work, no console errors. Tests added: `tests/unit/test_stats.py`, `tests/integration/test_review_and_stats_api.py`.

- Added decoy triage for flag-format candidates. A candidate is labelled LIKELY DECOY when decoy wording (for example "not the flag", "keep looking", "fake flag") appears in the flag text after leetspeak normalisation, or in nearby text from the same image within 512 bytes. Each label records its reasons. Decoys are kept visible in a "Likely decoy flags" section, and analyst decisions override them. Nothing is automatically confirmed or rejected.
- Official logo integrated into the local web UI header (top right, before the CipherSight text) and the sidebar. The logo file is bundled unmodified and served from `/static/logo.jpg`. Its SHA-256 is checked by tests.
- Corrected two stale brand assertions that expected "ImageHunter" text in CLI output and the HTML report title. The product and report now say CipherSight.
- Test totals after this work: unit 244 pass, integration 88 pass.

# Changelog

## Unreleased (rc6: stego coverage for flags that are not plain LSB)
- LSB search now covers serpentine and diagonal pixel traversals, in addition to row and column (`lsb.traversal_prefix`).
- Bit-shift search: a payload need not start on a byte boundary of the traversal stream. All 8 shifts are tried. Hits report `bit_shift`.
- Repeating-key XOR (key length 2 to `lsb_repeating_key_max`, default 3, max 4): crib-based. A configured prefix plus `{` is used as known plaintext. Keys are accepted only when the body is plausible, and periodic bodies are rejected. Evidence contains the key bytes.
- Single-byte XOR search is vectorised (`single_byte_keys`). It is equivalent to brute force, checked on random streams, and about an order of magnitude faster than the previous 256 x n matrix.
- Decoy handling: when several flag-format texts are recovered, each finding is ranked (`rank`, `candidates_total`, `rank_score`, `rank_breakdown`). The description says the ranking is a review aid, not verification. Confidence labels are unchanged.
- Fixed a bug found during this work: a noise image produced false repeating-key matches from the crib method alone. The body check and window prefilter fix that.
- Not changed: unknown-prefix leads are still low confidence. Pure-hex bodies and periodic bodies are no longer reported as leads.
- Known failing tests in the uploaded build, not caused by these changes: `tests/integration/test_cli.py::test_broken_pipe_exits_quietly` and `tests/integration/test_web_server.py::test_html_report_served_with_csp_and_matches_content` expect the old product name "ImageHunter", but the build says "CipherSight".
- Not implemented: repeating keys longer than 4 bytes, statistical detection with no known prefix, length-prefixed payloads, and JPEG coefficient payloads.

## 1.0.0-rc4
- Enabled unknown-prefix LSB lead detection by default.
- Improved CTF-style leetspeak and underscore body filtering to recover custom-prefix patterns such as `RHL{t3st_fl4g_lsb_42}` as low-confidence candidates.
- Added unknown-prefix LSB leads to report/UI weak-candidate classification.
- Added regression tests for extraction and report visibility.
- Refreshed localhost UI with a 3D-inspired, glass/neon visual style using local CSS only.
- Retained the RC status pending Windows-native and manual real-world validation.


## Unreleased (rc3 follow-up: analyzer status accounting)
- Analyzer statuses are now PASS, FINDINGS, PARTIAL, SKIPPED, ERROR and CANCELLED (`imagehunter.core.status`).
- Fixed: analyzers that declared they did no work (for example LSB on a JPEG, or OCR when disabled) were recorded as successful and counted in "modules executed". They are now SKIPPED with their reason.
- Cancelled runs mark the analyzers that were not started as CANCELLED, not SKIPPED. Derived-artifact analyzers follow the same rules.
- Report metrics now split total, executed, with findings, partial, skipped, failed and cancelled modules.
- Web UI status badges and HTML report badges use the new vocabulary.
- Not changed in this release: the 1.0.0 feature set (web UI sections, JPEG payload recovery, Windows install test) is still open. Version remains 1.0.0rc3.

## 1.0.0-rc3
- Updated release-candidate version metadata to 1.0.0rc3.
- Improved Windows one-click setup: Python version gate, isolated virtual environment, editable project install, PDF dependency, dependency report, quoted paths, and readable failure handling.
- Updated PowerShell setup helper and Windows installation documentation.
- Added a branded desktop header and an About dialog with clickable developer profile links and the requested feedback message.
- Updated README installation, optional OCR/Tesseract notes, and social links.
- Official logo integration remains pending receipt of the separate logo image.
- Windows execution and full integration suite remain unverified in this Linux environment.

# Changelog

## 1.0.0rc2 — 2026-11-09

- Fixed ZIP extraction to stream members and enforce actual decompressed-byte budgets, including forged-size regression coverage.
- Added bounded TAR and GZIP artifact recovery.
- Added classic TIFF IFD and WebP RIFF chunk inspection.
- Added optional OCR, QR and barcode analysis (opt-in through `vision_analysis_enabled`).
- Added optional JPEG quantized-DCT coefficient statistics through `jpegio`; this is statistical triage, not a payload decoder.
- Added optional PDF report generation and PDF download/open actions in Web UI and desktop UI.
- Added verified, strong-candidate and weak-candidate flag triage; automatic matches remain unverified.
- Added cooperative cancellation checks to frame-based optional vision analysis.
- Unit validation: 203 passed, 7 subtests. Integration modules: 85 passed, 22 subtests when run individually. GUI/Windows manual checks remain pending.
- This remains a release candidate; license selection and stable publication are pending.

## 1.0.0rc1 — 2026-11-09

- Added bounded indexed-palette inventory and palette-index LSB candidate analysis.
- Added TIFF and WebP signature/extension recognition; Pillow identity is used when supported.
- Included palette analysis for derived image artifacts.
- Consolidated release documentation, limitations, manual validation, security guidance, and GitHub release steps.
- Added GitHub Actions test matrix for Python 3.10, 3.11, and 3.12.
- This is a release candidate. OCR/QR, JPEG DCT coefficients, PDF export, and dedicated TIFF/WebP structural parsers remain unimplemented.

## 0.12.0 — Evidence-driven follow-up investigation
- Added a bounded dynamic task queue that expands decoded file outputs and high-confidence appended payloads.
- Added safe ZIP member extraction and nested archive investigation with size, count, recursion, compression-ratio and path safety limits.
- Added content-based analyzer selection for derived artifacts, including image metadata and steganography checks.
- Added derived-artifact flag candidates with SHA-256 provenance and evidence-graph parent/child relationships.
- Added integration tests for appended ZIP extraction, nested member flag discovery, graph provenance and resource limits.
- Validation: compileall passed; targeted follow-up, pipeline, investigation, steganography and decoder tests: 59 passed.
- Full test suite not yet verified for this release. This remains an incremental development release, not v1.0.0.


## 0.11.1 — Advanced pixel-domain steganography (incremental release)
- Added `stego.advanced`: bounded sparse-pixel extraction using pixel strides 2 and 3, per-stride offsets,
  forward/reverse traversal, bit planes 0–1, LSB/MSB byte packing, and single-byte XOR 0–255.
- Added per-channel/per-bit-plane zero/one ratios and Shannon entropy statistics to analyzer properties.
- Capped advanced experiments at 48 and decoded output at 8 KiB per experiment to bound runtime and memory.
- Added synthetic known-answer coverage for a sparse pixel-stride payload and entropy statistics.
- Existing analyzers and interfaces remain in place. This release does not yet implement dynamic cross-artifact
  orchestration, GIF/JPEG-DCT steganography, OCR, Rust acceleration, React, or FastAPI.
- Validation in the development environment: `compileall` succeeded; all 187 unit tests passed, with 7 subtests;
  the targeted steganography suite passed 29 tests with 2 subtests. Full integration suite not yet verified.


## 0.11.0 — Autonomous investigation engine (first step of the master plan)
- Planner (`core/planner.py`): cheap evidence checks, recorded triggers, modes quick/standard/deep/auto.
- `--mode` on the CLI; `investigation_mode` and `investigation_time_budget_seconds` settings.
- Cancellation (`cancel_event`) and time budget, checked between analyzers. Skipped analyzers are reported.
- Evidence graph in the summary (`evidence_graph`): nodes and edges from recorded relations only.
- Decoder keeps binary archives reachable (ZIP/PDF/image signatures) and reports signatures inside decoded artifacts.
- Evidence classes: raw, deterministic, heuristic; ai_hypothesis and verified are reserved and never produced.
- `docs/investigation.md`, `IMPLEMENTATION_STATUS.md` (audit, completed, pending, risks).
- Fix found by repeated runs: known-prefix XOR and ROT leaf matches could accept symbol-heavy random text
  (a symbol-heavy string inside braces). Key-based matches now need a mostly word-like body. A fixed-seed regression test
  catches the old behaviour (verified by disabling the check).
- 263 tests. Mutation checks on cancellation and on the plausibility rule.
- Not in this release: v0.12 to v1.0 items (see IMPLEMENTATION_STATUS.md).

## 0.10.0 — Recursive decoder with provenance
- `decoding.recursive` analyzer: base64, base32, hex, binary digits, URL, HTML entities, zlib, gzip,
  bzip2, xz (output-capped), ROT/Caesar (all shifts, leaf check), known-prefix single-byte XOR (leaf check).
- Bounded search: depth, nodes, output size, seed count and XOR byte budget are settings. Duplicate artifacts
  are not expanded twice (sha256), which also stops cycles.
- Every decoded flag carries its chain (for example `base64 > zlib`) and seed source; classified as Candidate.
- Plain-text flags are not reported by this analyzer; existing results are unchanged.
- `docs/ASSESSMENT_v0.10.md`: honest status of every section of the master specification.
- 245 tests.

## 0.9.0 — Multi-channel LSB streams and unknown-prefix leads
- `lsb_max_channels` (1, 2 or 3): reads channels together as interleaved bit streams (R+G, G+R, R+G+B, ...).
  Default 1, so existing scans are unchanged and as fast as before.
- `lsb_unknown_prefix_leads` (default false): reports readable text with an unconfigured prefix as
  `lsb_unknown_prefix_lead` (Low). Leads are never candidates. A vectorised pre-filter keeps the cost low.
- Readability test for leads (letter pairs, repeat rules, leetspeak-aware).
- Bugs found while implementing: the first lead filter let through runs such as `yyyy{yyy}` and `lllfh9`
  (hundreds of false leads); tightened. Brute-force search was too slow with a per-brace Python loop; replaced
  with a numpy pre-filter.
- Limits: leads are heuristic; channel streams are only byte-aligned when the start pixel is a multiple of 8.
- 223 tests.

## 0.8.0 — Smart word and phrase candidates
- `text.smart_words` analyzer: Unicode tokens, English stopwords kept for clue analysis, n-grams with original
  spacing, sentence edges, quoted and key=value values, gated acrostic / every-Nth / first-letter candidates,
  bounded case, leetspeak, separator and reverse transformations.
- Clue language with negation ("there is no password" is not a positive hint). Positional, selection,
  combination and context clue groups.
- Transparent score breakdown with configurable weights and a transformation penalty. Priority High/Medium/Low.
  Candidates are never marked as verified.
- Text filter for printable runs from compressed data; metadata copies of image bytes are not double-counted.
- CLI: `--smart-words`, `--min-score`, `--export-candidates` (TXT), `--export-candidates-json` (JSON with warning).
- HTML report section "Smart word candidates" (escaped).
- Fixed a real GUI race: the window could report "scan finished" before the last console lines were shown.
- Not in this version: GUI and web panels for candidates, OCR, decoded/carved sources.
- 211 tests.

## 0.7.0 — Metadata forensics (roadmap Phase A, part)
- `metadata.extract` analyzer: PNG tEXt, zTXt and iTXt (with decompression capped by `metadata_max_bytes`),
  iCCP profile name and size, XMP key fields (without an XML parser), EXIF fields and timestamps via Pillow.
- Findings only for review items: flag-shaped text in metadata, oversized blocks, conflicting timestamps,
  GPS presence (with a local-only privacy note). Ordinary comments create no findings.
- HTML report shows real metadata results when the analyzer ran, and "not executed" otherwise.
- Test flags are now generated per run; no challenge flag or answer key is stored in the repository or docs.
- `docs/ROADMAP_STATUS.md` maps every roadmap item to what is done, partial, or not started.
- 164 tests.

## 0.6.0 — Local web interface
- `python main.py web`: browser interface on 127.0.0.1 with the design's layout (dashboard, analyze,
  results, export). It runs the same pipeline and reports as the CLI and the desktop window.
- Upload, live console with real events and progress, results with confirmed / candidate / phrase
  groups, and report download. Scan output is inserted as text, never as markup.
- Security: localhost-only, Host-header check, required custom header for POST, size limits,
  fixed report names, one scan at a time.
- Features shown in the design but not built (hex editor, pixel inspector, carving, metadata,
  decoders, PDF) are listed as not in this build, not shown as working.
- Windows launcher: `CipherSight_Windows.bat web`.

## 0.5.0 — HTML forensic report and live console
- `scan_report.html`: standalone, offline HTML report from the same summary as the JSON. Sections for
  executive summary, flags (Confirmed, Candidate, Rejected), expected phrases, metadata (honest "not executed"),
  steganography, embedded items, binary structure, decoded strings, execution log, evidence and integrity.
  All values are escaped. Search, copy, expand/collapse and print work without external scripts or CDNs.
- `scan_report.json` added. `scan_summary.json` kept for compatibility (identical content).
- Structured event stream (`core/events.py`): every step emits an event after it really finishes or fails.
  The pipeline accepts `on_event`. Events are stored in the report's execution log.
- Expected phrases analyzer (`text.phrases`) with a settings key `expected_phrases` (empty by default).
- Verification statuses: matches are Candidates by default. Confirmed and Rejected only via explicit analyst decisions.
- GUI: live LIVE FORENSIC SCAN CONSOLE with colours, level filters, search, pause/resume, clear, copy,
  export TXT, progress bar, and a results dashboard with buttons to open the HTML, export JSON,
  view flag groups, and open the evidence folder. Scans run in a worker thread; events reach the window through a queue.
- Tests: 129 tests including HTML escaping, JSON/HTML consistency, no-flag and multi-flag states,
  failed-analyzer reports, live event delivery during a running scan, and a headless wiring test of the window.
- Not done: PySide6 (the window stays on Tkinter); metadata, decoders, payload extraction and palette analysis
  (shown as not executed); a manual verification UI.

## 0.4.0 — Phase 4: LSB and bit planes
- `stego.lsb` analyzer: single-byte XOR LSB extraction across channels, bit planes 0-7, row and column
  order, LSB-first and MSB-first bits. Reports only flag-format matches for the configured prefixes.
- Channel views, alpha statistics, and bit-plane rendering helpers.
- New settings: `stego_max_bytes`, `max_pixels`, `flag_prefixes` (validated).
- New dependency: numpy (added to requirements.txt and pyproject.toml).
- Known-answer tests with an LSB encoder in fixtures, plus a rebuild of the signal_hunt layers.
  88 tests pass. Mutation checks confirm column and bit-order logic are tested.
- Real challenge image: the analyzer finds the embedded flag at (37, 0) and the decoy. Test flags are generated per run.

## 0.3.1 — Windows window
- Desktop window (`main.py gui`, Tkinter from the standard library, no extra install). Choose an image,
  press Scan, read the summary, open the reports folder. Scans run in a background thread through the same
  pipeline as the CLI.
- `CipherSight_Windows.bat` with no arguments opens the window. Arguments still give console scans and tests.
- Summary formatter (`imagehunter/ui/summary.py`) with headless tests.
- Challenge files are no longer shipped inside the tool package.
- Not yet run on Windows or with a display in the build sandbox. Tk is not installed there.
- Deviation: the blueprint's Phase 7 targets PySide6. This window uses Tkinter for now, to avoid extra
  dependencies. It can be replaced in Phase 7.

## 0.3.0 — 2026-11-07 (integration of Phases 1–2 into the blueprint structure)

Rebuilt the Phase 1–2 code from the blueprint's project layout. Earlier 0.2.0 code is superseded.

### Changed (breaking, from 0.2.0)
- Layout: src-layout (`src/imagehunter/`), `main.py` entry point, `pyproject.toml`.
- CLI: `analyze` is now `scan`. It prints a JSON scan summary to stdout. Logs go to stderr.
- Confidence labels are now `High` / `Medium` / `Low` (blueprint wording), not lowercase.
- Finding fields: `confidence` → `confidence_label`; `details` → `evidence`; added `id`,
  `category`, `title`, `source_artifact_id`, `method`, `warnings`, `created_at`.
- Analysis runs as an ordered pipeline of analyzers with a shared contract (`analyzers/base.py`).
- `tools/` is now `integrations/`. The dependency checker moved to `services/dependency_service.py`
  and `scripts/check_dependencies.py`.
- Settings defaults ship inside the package (`src/imagehunter/config/default_settings.json`)
  instead of a root `config/` folder, so they work after installation.

### Added
- Typed models: `Artifact` (original vs derived with parent link), `Finding`, `ScanSummary` (schema 1.0).
- Settings loader with validation; unknown keys are rejected.
- Per-scan workspace: `evidence/`, `extracted/`, `temporary/`, `reports/`, with unique scan IDs.
- Structured JSON-lines logging to stderr.
- Input validation (missing, not a file, empty, over size limit, unreadable).
- Pillow-based identity: real format, mode, width, height, frame count; decoder failures are warnings.
- Printable-string extraction with offsets (capped by `max_strings`).
- Pipeline isolation: an analyzer crash is recorded as `status: error` and the scan continues.
- Scan summary written to `workspace/<scan_id>/reports/scan_summary.json`.
- Installers for Linux and Windows; `editable install` via `pyproject.toml`.

### Tests
- 68 tests (unit and integration). Suite passes. Piping output into `head` exits quietly. Mutation check: breaking PNG end detection fails 3 tests.

## 0.2.0 — superseded
Standalone prototype: structure parsing, embedded scan, CLI `analyze`. Replaced by 0.3.0.

## 0.1.0 — superseded
Foundation: safety layer, safe runner, tool registry, dependency checker.

## 0.13.0 — Lightweight GIF frame intelligence
- Added bounded GIF frame-by-frame inspection without extracting frame files or adding dependencies.
- Records frame dimensions, duration, disposal metadata and changed-pixel ratios.
- Checks each frame's red-channel LSB stream for configured flag-shaped candidates; results remain Medium-confidence candidates, never verified flags.
- Enforces 100-frame and 20-million cumulative-pixel limits and respects the existing per-image pixel and decoded-byte settings.
- Adds the analyzer to original and GIF-derived artifact scans; non-GIF derived images do not pay the extra analyzer cost.
- Added synthetic known-answer tests. No OCR, DCT, new package dependency, or broad architecture change in this focused release.

## [1.0.0-rc2] - 2026-11-09

- Fixed ZIP extraction to read members incrementally and enforce output budgets against bytes actually produced, not only attacker-controlled ZIP header sizes.
- Added bounded TAR and GZIP artifact recovery with traversal and size protections.
- Added TIFF IFD and WebP RIFF chunk inspection.
- Added optional OCR, QR and barcode analysis (disabled by default; enable with `vision_analysis_enabled`).
- Added optional JPEG quantized-DCT coefficient statistics via `jpegio`; this reports statistics only and does not claim to decode arbitrary JPEG steganography.
- Added optional PDF report export; JSON and HTML remain available if PDF support is missing or fails.
- Added verified / strong-candidate / weak-candidate flag triage while preserving analyst confirmation and rejection decisions.
- Passed cancellation signals into analyzers and made the optional frame-based vision analyzer check cancellation between frames.
