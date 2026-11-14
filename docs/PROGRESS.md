> Historical development notes. For current, verified capabilities and limitations, see `IMPLEMENTATION_STATUS.md`.

# Progress report

Version 0.6.0 · 2026-11-07 · Linux, Python 3.12.3, Pillow 13.0.0

## Phase status

| Phase | Blueprint scope | Status |
|---|---|---|
| 1 Foundation | Repo layout, settings, logging, workspace, validation, SHA-256, dependency checker, CLI JSON summary | **Complete**, tests pass |
| 2 Basic image analyzer | Format, dimensions, mode, frames, decoder warnings, printable strings, signatures | **Complete**, tests pass |
| 3 Metadata Explorer | Metadata interface, EXIF, optional ExifTool, thumbnails | Not started |
| 4 Stego core | Channels, alpha, bit planes, controlled LSB (adds numpy) | **Complete** for LSB, channels, alpha, bit planes. Palette analysis not yet done. |
| 5 Binary and carving | Hex utilities, safe extraction, optional Binwalk/Foremost | Not started |
| 6 Text and Flag Hunter | Decoders, regex patterns, dedup, verification state | Not started |
| 7 Desktop GUI | PySide6 | Not started |
| 8 Reports and evidence | JSON/HTML/PDF, history, lineage | Not started |
| 9 Hardening | Malformed corpus, CI matrix, performance | Not started |
| 10 Packaging | Installers, release checklist | Not started |

## Phase 4 results

Files: `analyzers/stego/lsb.py`, `channels.py`, `analyzer.py`, `tests/unit/test_lsb.py`, `docs/stego.md`.

What works: single-byte XOR LSB extraction across R/G/B/A/L, bit planes 0-7, row and column order,
LSB-first and MSB-first bits. Accepted only for the configured flag prefixes. Also channel views,
alpha stats, and bit-plane rendering.

Real challenge (`signal_hunt.png`): two findings, both correct.
- Embedded flag: blue channel bit 0, column order, LSB-first, XOR 0x37, first pixel (37, 0). Test flags are generated per run.
- Decoy: red channel bit 0, row order, MSB-first, no XOR, first pixel (0, 0).
Scan time: about 2 seconds.

Tests: 88 pass (`python -m unittest discover -s tests -t .`), about 4.5 s.
Mutation checks: ignoring column order fails 2 tests; ignoring bit order fails 3.

Known bug found and fixed during Phase 4: the first version used a generic prefix pattern
(`[A-Za-z]+\{...\}`), which produced about 500 false positives on random bytes. Fixed by matching
only configured prefixes.

## Phase 1 exit criteria (blueprint §12)

"A command can accept a test image, validate it, hash it, and return a structured scan summary."
- `python main.py scan FILE` validates, hashes, copies read-only, and prints a JSON summary. ✔
- Covered by unit tests (validation, evidence, workspace, settings, logging, runner, registry, models)
  and by `tests/integration/test_cli.py`.

## Phase 2 exit criteria (blueprint §12)

"Tests pass for valid JPEG/PNG/GIF/BMP and invalid/misnamed files."
- Valid JPEG, BMP and animated GIF: dimensions, mode and frame count asserted (Pillow-written samples). ✔
- Valid PNG: structure and mode asserted. ✔
- Misnamed file: High `extension_mismatch`. ✔
- Invalid/undecodable input: Low `unknown_format` or decoder warning; never a crash. ✔

## Test results

    python -m unittest discover -s tests -t .
    Ran 73 tests in ~1.3s — OK

Mutation check: breaking PNG end-of-image detection → 3 failures; restored → OK.

Manual scan of `appended_zip.png` (`main.py scan`): status `completed`; F001 High `appended_data` at
offset 102; F002 High `embedded_zip` at offset 102 with entry `flag.txt`; identity PNG, mode L,
1×1; 9 printable strings.

Editable install (`pip install -e . --no-build-isolation --no-deps` in a venv): works; `imagehunter --version` → 0.3.0.

## Known limitations
- Phase 4: single-byte XOR only. No Base64/ROT13 decoding yet (Phase 6). No palette analysis yet.
- Phase 4: multi-channel or split payloads are not reassembled.

- Whole file is read into memory. Streaming for large files is Phase 10.
- Strings are printable-ASCII only. Unicode/UTF-16 is not yet extracted.
- Adjacent strings can merge (e.g. `flag.txtCTF{...}`), as in the `strings` command. Flag Hunter (Phase 6) will split them.
- Synthetic JPEG fixtures are marker-only, not decodable; real JPEG tests use Pillow-written files.
- JPEG parser assumes standard structure; progressive JPEGs are untested.
- Embedded hits inside the image structure are Low because compressed data can contain any byte pattern.
- No real CTF samples have been tested (no internet in the build sandbox).
- No external tool is installed here; none is marked tested. See `docs/TOOL_FLAGS.md`.
- Windows: code is pure Python, but not run on Windows. `install_windows.ps1` is syntax-unverified (no PowerShell in the sandbox).
- `install_linux.sh` was checked for syntax only; its full run needs network for pip.
- Blueprint has no LICENSE file yet; add one before any public release.

## Next phase (Phase 3: Metadata Explorer, not yet started)

Prerequisites: Phase 2 exit criteria met (done). Plan:
1. Metadata provider interface in `analyzers/metadata/`, returning normalized findings.
2. Pillow EXIF reader: common tags, orientation, timestamps, software, comments.
3. Optional ExifTool adapter via `integrations/runner.py`. Marked tested only after a real ExifTool run with a known fixture.
4. Known-EXIF fixtures generated in tests; missing metadata reported as "absent", not as error.
