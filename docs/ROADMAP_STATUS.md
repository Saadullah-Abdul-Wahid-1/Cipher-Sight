> Historical development notes. For current, verified capabilities and limitations, see `IMPLEMENTATION_STATUS.md`.

# Roadmap status (v0.7.0)

Source: ImageHunter Advanced CTF & Image Forensics Implementation Roadmap. Each item is marked by what the
code actually does and what the tests cover. Nothing is marked done without a test.

| # | Roadmap item | Status | Notes |
|---|---|---|---|
| 1 | EXIF: make, model, timestamps, orientation, software, comments | **Done (partial)** | Pillow EXIF read; orientation is listed as a raw tag value. |
| 1 | GPS with privacy warning, no transmission | **Done** | Shown locally with a privacy note; no network code exists in the package. |
| 1 | PNG tEXt, iTXt, zTXt, with decompression | **Done** | Capped inflate; offsets recorded; oversized blocks reported, not read. |
| 1 | XMP / IPTC / ICC inventory, comments, thumbnails | **Partial** | XMP: key fields via a regex summary (no XML parser, so no entity expansion). ICC: iCCP name and size. IPTC and embedded thumbnails: not implemented. |
| 1 | Anomaly checks: conflicting timestamps, unusual software, missing/duplicated fields, large blocks | **Partial** | Timestamp conflicts and large blocks done. Unusual-software and duplicate-field checks not done. |
| 1 | Optional ExifTool with safe argv, timeouts, version checks | **Not done** | Registry knows ExifTool; no adapter has run, so it is not marked tested. |
| 2 | LSB: configurable start offsets, skipped pixels, channel masks, payload length | **Not done** | Start offset and bit-plane/traversal/bit-order variants exist. Skipped pixels, masks and length detection do not. |
| 2 | Multi-channel and split-payload reconstruction | **Not done** | |
| 2 | Alpha and palette analysis | **Partial** | Alpha statistics done. Palette ordering and unused entries not done. |
| 2 | Bit-plane export and comparison | **Partial** | `render_bitplane` helper exists; no export command or UI yet. |
| 2 | GIF frame analysis | **Not done** | Frame count only. |
| 2 | JPEG DCT inspection | **Not done** | |
| 2 | Statistical indicators (bit distribution, chi-square) | **Not done in the app** | Checked during review by script only. Not part of the analyzers. |
| 3 | Base64/Base32, hex, URL, ROT13 decoders | **Not done** | |
| 3 | XOR analysis with key limits and scoring | **Not done** | Single-byte XOR is only inside the LSB search. |
| 3 | zlib / gzip / raw-deflate with limits | **Partial** | zlib inside PNG text chunks only. |
| 3 | UTF-16 and printable extraction | **Partial** | ASCII strings only. |
| 3 | Recursive decoding chains and artifact lineage | **Not done** | |
| 4 | PNG chunk CRC, ordering, unknown chunks, data after IEND | **Partial** | CRC and after-IEND existed; unknown-chunk and ordering checks not done. |
| 4 | JPEG marker parser robustness | **Partial** | Basic; progressive JPEG untested. |
| 4 | Signature mismatch and broader magic database | **Partial** | Ten signatures. |
| 4 | Safe carving with length bounds; quarantine | **Not done** | Embedded ZIP is listed, not extracted. |
| 4 | Nested archive inspection with limits | **Not done** | |
| 5 | Configurable flag prefixes | **Done** | `flag_prefixes` setting. |
| 5 | Search raw bytes, decoded strings, metadata, extracted files | **Partial** | Raw LSB and metadata text. Decoded strings and extracted files not yet. |
| 5 | Dedup and ranking | **Partial** | Dedup by text. No ranking score (deliberately not added yet). |
| 5 | Candidate / Confirmed / Rejected with reason and timestamp | **Partial** | Statuses exist; reason and timestamp of analyst decisions are not stored. |
| 6 | JSON and HTML reports | **Done** | |
| 6 | PDF export | **Not done** | |
| 6 | Hex viewer, GIF frame selector, panels | **Not done** | |
| 7 | Size, pixel and decompression limits | **Partial** | File size, pixel count, text inflate cap. No frame-count limit (no GIF analysis yet). |
| 7 | Fuzz tests | **Partial** | Random bytes and truncation tests. No fuzzing run. |
| 7 | Regression fixtures; no answer key in release | **Done** | Test flags are generated per run. Release contains no answer key. |
| 7 | CI, SBOM, reproducible builds | **Not done** | |

## Known issues
- One headless GUI test (`test_gui_logic_headless`) failed once in about four full runs. It passed on re-run. Cause not yet identified.
- The uploaded v0.6.0 copy had a test calling `make_png()` with an array argument, which errors. That copy is replaced by the v0.7.0 tests.
