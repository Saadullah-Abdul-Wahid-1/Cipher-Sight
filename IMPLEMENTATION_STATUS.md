# Implementation status — ImageHunter 1.0.0rc4

This is a release candidate, not a claim that every forensic technique is implemented.

## Implemented and tested in this build

- Read-only working-copy workflow and original-file SHA-256 integrity check.
- Format identification and extension mismatch checks.
- PNG/JPEG/BMP structural checks and GIF frame-level analysis.
- Pillow image identity, dimensions, mode, frame count, EXIF/GPS and PNG text metadata.
- Printable strings, phrase clues, ranked smart-word leads, and bounded decoding.
- LSB, bit-plane, channel, advanced pixel-domain, GIF frame and indexed-palette analysis.
- Embedded-signature discovery and bounded follow-up of decoded files and appended payloads.
- ZIP extraction with incremental reads and actual-output byte limits; traversal, symlink, encryption, entry-count, ratio and recursion checks.
- Bounded TAR regular-file and GZIP payload recovery; archive members are never extracted by trusting their paths.
- TIFF classic IFD chain inspection with entry and traversal bounds.
- WebP RIFF chunk boundary and declared-size inspection.
- Optional OCR and QR/barcode analyzer using pytesseract and OpenCV; disabled by default (`vision_analysis_enabled=false`).
- Optional JPEG quantized-DCT coefficient statistics using `jpegio`; statistical analysis only, not an automatic payload decoder.
- JSON/HTML/PDF reporting; ReportLab is included in the standard dependency set.
- Flag triage exposes analyst-verified, strong-candidate and weak-candidate views; candidate strings are never auto-verified.
- CLI, desktop UI, local web UI, SHA-256 artifact deduplication and parent/child provenance.

## Optional dependencies

```bash
pip install -e ".[ocr,vision,jpeg-dct]"
```

OCR additionally requires the Tesseract executable. Enable optional vision analysis in the settings JSON with `"vision_analysis_enabled": true`.

## Known limitations

- JPEG DCT support reports quantized coefficient statistics only; it does not implement F5/JSteg/OutGuess or a universal JPEG payload decoder. The optional `jpegio` dependency was not installed in the validation environment.
- OCR/QR/barcode processing depends on optional packages; OCR also depends on a working Tesseract executable.
- TIFF parser covers classic TIFF IFD chains and bounded tag descriptors; it does not fully decode every tag value or BigTIFF.
- WebP parser inspects RIFF chunk boundaries and trailing data, not every WebP metadata subformat.
- TAR/GZIP extraction is bounded; links and special files are ignored.
- Cancellation is cooperative. Vision analysis checks between frames, but an individual OCR call and existing legacy analyzers are not interruptible mid-call.
- License selection remains pending; no LICENSE file was added.
- GUI/Web UI behavior on Windows and clean-venv install/build must still be manually checked on the target machine.

## Release decision

Keep this build at `1.0.0rc4`. Promote to stable `1.0.0` only after clean-environment installation, wheel/sdist checks, target-platform GUI/Web UI smoke tests, and real CTF manual validation are complete. Do not push or publish without owner approval.


## RC3 implementation notes (2026-11-09)

- Windows BAT now creates/reuses `.venv`, validates Python 3.10–3.13, installs the editable project, checks dependencies, and launches the GUI; PowerShell helper follows the same isolated setup.
- ReportLab is included in core dependencies so PDF report support is available after standard installation.
- Dependency report now lists OpenCV, pytesseract, jpegio, and the external Tesseract executable separately.
- Desktop GUI has a branded header and an About dialog with clickable developer links and the requested feedback text.
- Local web UI has an About page and retains loopback-only server binding.
- Official logo not yet integrated because the logo image was not included in the uploaded archive.
- Unit tests: 204 passed. Integration tests: 85 passed when run separately. Combined one-shot run exceeded the environment's 55-second execution window.
- GUI display, Windows BAT/PowerShell execution, Windows fresh-install scenarios, and logo rendering were not verified in this Linux environment.

## Analyzer status follow-up (after rc3 validation)

- Analyzer status is now one of PASS, FINDINGS, PARTIAL, SKIPPED, ERROR or CANCELLED. Only PASS, FINDINGS and PARTIAL count as executed.
- Reproduced before the fix: a JPEG scan recorded 15 of 15 analyzers as "ok", including 7 that skipped their work. After the fix those 7 are SKIPPED with their reasons.
- Covered by `tests/unit/test_analyzer_status.py` and by the updated integration cancellation test.
- Still open for a final 1.0.0 release: the 14-section web UI (the current UI has 5 pages), the flag-confidence vocabulary (Confirmed / High-confidence / Possible / Suspicious), JPEG coefficient-level payload recovery (not implemented), Windows launcher and browser testing, and a clean-venv install check.


## RC4 recovery and UI update

- Unknown-prefix LSB leads are enabled by default so custom prefixes are not silently missed.
- The lead filter now accepts constrained CTF-style leetspeak/underscore bodies while retaining low-confidence classification.
- Unknown-prefix leads are included in the report/UI weak-candidate list; they are never auto-confirmed.
- Local web UI styling now has a polished 3D-inspired/glass visual treatment using local CSS only.
- Regression coverage includes `RHL{t3st_fl4g_lsb_42}`.
- Windows-native testing and manual real-world CTF validation remain owner-side release checks.

## rc6 stego coverage update

- New in LSB search: serpentine and diagonal traversals, bit shifts 0 to 7, and repeating-key XOR (length 2 to 4, crib-based).
- Coverage now includes flags that start mid-byte, which RC4 missed. The uploaded challenge image was missed by RC4's analyzer and is found now.
- Verified by `tests/unit/test_stego_extensions.py` (12 tests): traversal permutations, known answers, round trips for each new traversal, repeating-key recovery with exact key bytes, no false positives on noise, bit-shift recovery, and decoy ranking.
- Full unit suite: 226 pass. Integration: 2 failures that already exist in the uploaded build (brand string mismatch), listed in CHANGELOG.
- Runtime: about 11 s for the 640x480 challenge image with leads enabled.

## rc7 work (decoy triage and logo)

- Implemented: LIKELY DECOY labelling with recorded reasons (`services/flag_triage.py`), a separate "Likely decoy flags" HTML section, and the official logo in the web header. Verified by `tests/unit/test_flag_triage.py` and `tests/integration/test_logo_branding.py`.
- Test status: unit 244 pass; integration 88 pass (previous 2 brand-string failures corrected to the CipherSight brand).
- Web UI: grouped pages for findings and analysis, scan history, live statistics, and analyst confirm/reject with per-scan decisions. Verified in headless Chromium.
- Still open: Settings page (not editable in the web UI), Windows launcher and browser testing on Windows, clean-venv install check, persistence of scan history across server restarts, and a transparent logo variant.
- Tests after this step: unit 249 pass; integration 99 pass.
