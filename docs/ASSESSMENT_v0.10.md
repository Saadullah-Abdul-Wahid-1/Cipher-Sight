# Assessment and milestone status (v0.10.0)

Baseline: the uploaded `ImageHunter_v0_8_0.zip` (211 tests, all passing; no answer-key or flag text).
Current tree: v0.9.0 features (multi-channel LSB, unknown-prefix leads) plus the v0.10.0 recursive decoder.

## What the specification asks for vs what exists

Status: **Done** = implemented and tested here. **Partial** = some of it works, with stated gaps.
**Not started** = not built. Nothing below is marked Done without a test.

| Spec section | Status | Notes |
|---|---|---|
| 1 Inspect existing project | Done | This document. |
| 2 Python / Rust / TypeScript architecture | **Not started** (Rust, TS, FastAPI, PyO3) | Python only. A small web UI exists (stdlib server, v0.6). No Rust crates, no React app. |
| 3 Universal image input (PNG, JPEG, GIF, BMP, TIFF, WebP, ICO, HEIC, AVIF, SVG) | **Partial** | Signature detection for PNG, JPEG, GIF, BMP, ZIP, PDF etc. Structure parsers only for PNG, JPEG, BMP. Pillow reads the rest. No HEIC/AVIF, no SVG handling, no TIFF/WebP/ICO structure. |
| 4 Metadata forensics | **Partial** | PNG text chunks, EXIF fields, GPS (local only), timestamp conflicts, XMP key fields, ICC name. No IPTC, no TIFF tag inventory, no thumbnail extraction, no metadata diffing between embedded and primary image. |
| 5 Structure forensics | **Partial** | PNG chunk walk with CRC and after-IEND data; JPEG marker walk; BMP size. No GIF block parser, no PNG chunk-order checks, no duplicate-chunk checks, no WebP/TIFF parsers. |
| 6 Steganography | **Partial** | LSB and bit planes, row/column order, LSB/MSB-first, single-byte XOR, interleaved 1-3 channel streams, unknown-prefix leads, alpha stats, bit-plane rendering helper. Missing: palette analysis, GIF frame steganography, DCT research, per-channel entropy maps, pixel skipping/sampling, reverse traversal, channel permutation scoring. |
| 7 Decoders and data intelligence | **Partial (this release)** | Base64, base32, hex, binary digits, URL, HTML entities, ROT/Caesar (all shifts, leaf), zlib, gzip, bzip2, xz (output-capped), known-prefix single-byte XOR (leaf). Recursive, depth-limited, deduplicated, with provenance. Missing: Base58, UTF-16 decoding as a step, repeating-key XOR analysis, ZIP as a decode step, decoder scoring beyond printable ratio. |
| 8 Strings and hidden text | **Partial** | ASCII printable runs with offsets, UTF-16 LE/BE runs (smart words), redaction not implemented in views. No UTF-8 multi-byte scanning beyond decoding, no URL/email/path/command classifier output. |
| 9 OCR and visual forensics | **Not started** | No OCR engine, no QR or barcode decoder. |
| 10 Transformations | **Not started** | No CLAHE, sharpening, histogram equalization, difference images. Only channel isolation and bit planes exist. |
| 11 Carving and artifact recovery | **Partial** | Embedded signature detection and ZIP listing only. No extraction to a quarantine folder, no PDF/Office/audio carving, no nested archive inspection. |
| 12 Smart password intelligence | **Done (v0.8.0 scope)** | Tokens, n-grams, clue patterns with negation, transformations, score breakdown. Not yet fed by OCR or carved files. |
| 13 Flag hunter | **Partial** | Configurable prefixes; sources: raw LSB, metadata, decoded chains. Not searched: OCR, carved files, reconstructed images. Classification: Candidate by default; Confirmed/Rejected only by analyst input in code. Decoy and "unverified" classes not separate. |
| 14 Autonomous investigation and AI correlation | **Not started** | The pipeline runs a fixed analyzer list. No planner, no hypothesis engine, no evidence graph, no AI. No LLM use. |
| 15 Analyzer plugin system | **Partial** | `Analyzer` base class and a registry list. No dynamic loading, no per-analyzer version, no resource-limit declarations. |
| 16 Evidence management | **Partial** | Original hashed and re-verified; working copy in workspace; artifacts with parent/role; event log. No artifact store for extracted files, no SQLite history, no evidence bundle export. |
| 17 React dashboard | **Not started** | The existing web UI (v0.6) is a single-page JavaScript app with no build step. |
| 18 FastAPI backend | **Not started** | Existing stdlib HTTP server: scan upload, poll, summary, report download. No Pydantic schemas, no versioning, no WebSocket/SSE. |
| 19 Reports (PDF, HTML, JSON) | **Partial** | HTML and JSON exist. No PDF. |
| 20 Performance | **Partial** | Per-analyzer budgets for LSB, decoding, smart words, metadata; timings measured on the two challenge images (2-5 s default). No Rust acceleration, no streaming for large files, no parallel analyzers. |
| 21 Security | **Partial** | Localhost-only server, CSRF header, size limits, filename sanitising, decompression caps, no archive extraction (so no path-traversal surface yet). No dependency audit, no sandboxing. |
| 22 Testing | **Partial** | 245 unit and integration tests. No Rust tests, no frontend tests, no benchmark suite, no synthetic dataset with measured detection/false-positive rates. Mutation checks done on LSB, metadata and channel code. |
| 23 Directory structure | **Not started** | Current layout is `src/imagehunter/...`. Not the spec's backend/rust/frontend split. |
| 24 Milestones | See below | |
| 25 Acceptance (one-click Deep Investigation) | **Not started** | No Deep Investigation mode. Default scan runs all analyzers once, nothing is recursive except the decoder. |
| 26 First action (assessment) | **Done** | This document. |

## Milestone status
- M1 Inspect and baseline: **Done** (this document).
- M2 Stabilise Python core: **Partial**. Settings validated, analyzers isolated, tests green. Refactoring of the pipeline into an orchestrator is not done.
- M3 Autonomous orchestration: **Not started**.
- M4 Steganography and decoding: **Partial** (see tables). Decoder chains and channel streams are in.
- M5 Structure and carving: **Not started** beyond existing parsers.
- M6 OCR and image intelligence: **Not started**.
- M7 Evidence graph and correlation: **Not started**.
- M8 Rust acceleration: **Not started**.
- M9 React dashboard: **Not started**.
- M10 Reporting, security, performance: **Partial**.
- M11 Testing and regression: **Partial**.
- M12 Packaging: **Partial** (zip with installers and Windows launcher).

## Verified on the two challenge images (default settings)
- Scan time 2-5 s each. Decoder: 1000 seeds, about 1000 artifacts, no budget exhaustion, no decoded flag reported (expected: neither image contains an encoded flag in text).
- LSB flag with configured `RHL` prefix: found (see v0.9.0 notes).

## Known risks
- Leads and smart words produce Medium candidates from text inside XMP or C2PA structures without any clue.
- Decoder recall for encodings not in the table is zero by design.
- The rest of the specification needs new dependencies (OCR engine, Rust toolchain, Node build). None are installed in this environment, so they cannot be verified here.
