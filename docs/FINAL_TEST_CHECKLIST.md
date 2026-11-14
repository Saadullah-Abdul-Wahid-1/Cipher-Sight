# Final manual test checklist — ImageHunter 1.0.0rc3

Run these tests on a clean machine and keep the reports/logs for failures.

## A. Clean installation
- [ ] Double-click `ImageHunter_Windows.bat` from a fresh extracted folder, including a path containing spaces.
- [ ] Repeat launch and confirm the existing `.venv` is reused.
- [ ] Simulate missing Python, unsupported Python, offline pip, and missing Tesseract.
- [ ] Confirm no package is installed into global Python.
- [ ] Python 3.10+ installed.
- [ ] Create a fresh virtual environment.
- [ ] Install `requirements-dev.txt`.
- [ ] Install project with `pip install -e .`.
- [ ] `imagehunter --version` reports `1.0.0rc3`.
- [ ] `imagehunter check-deps` reports required packages available.
- [ ] Repeat on Windows and one Linux/WSL environment if possible.

## B. Automated tests
- [ ] `python -m pytest -q tests/unit`
- [ ] `python -m pytest -q tests/integration`
- [ ] `python -m compileall -q src tests`
- [ ] No unexpected test skips or failures.

## C. Core scan
- [ ] Scan a normal PNG, JPEG, BMP, GIF, TIFF, and WebP file.
- [ ] Scan an image with a misleading file extension.
- [ ] Scan a truncated/corrupted image.
- [ ] Scan random non-image bytes.
- [ ] Confirm the original file hash is unchanged.
- [ ] Confirm JSON and HTML reports are generated.
- [ ] Confirm PDF report is generated when ReportLab is installed.
- [ ] Confirm Web UI PDF download and desktop PDF open action.
- [ ] Confirm optional OCR/QR remains disabled by default; enable `vision_analysis_enabled=true` and test if Tesseract/OpenCV are installed.
- [ ] Confirm TIFF IFD and WebP RIFF chunk details are present.
- [ ] Test TAR and GZIP derived artifact recovery.
- [ ] Test JPEG DCT statistics with optional `jpegio` installed; do not expect universal payload decoding.

## D. CTF evidence recovery
- [ ] Test a PNG with known LSB payload.
- [ ] Test a GIF with a known frame-level LSB payload.
- [ ] Test an indexed PNG with a known palette-index LSB payload.
- [ ] Test an image with EXIF/PNG text clues.
- [ ] Test an image with appended ZIP and a nested ZIP member.
- [ ] Test encoded strings that should be decoded.
- [ ] Confirm each candidate identifies its source artifact and extraction method.
- [ ] Confirm candidates are not labeled as verified flags.

## E. Negative and adversarial tests
- [ ] Clean image with no embedded payload.
- [ ] Random image noise that resembles strings.
- [ ] Malformed metadata and invalid chunk lengths.
- [ ] ZIP forged uncompressed-size header (must enforce actual output limits).
- [ ] ZIP path traversal entry.
- [ ] ZIP symlink entry.
- [ ] Encrypted ZIP member.
- [ ] Oversized archive member / high compression ratio.
- [ ] Nested archives beyond configured depth.
- [ ] Large image beyond pixel limits.
- [ ] Cancel a long scan and confirm it exits safely.

## F. User interface
- [ ] Desktop GUI opens and completes a scan.
- [ ] Local web UI binds only to loopback by default.
- [ ] Progress and analyzer warnings are visible.
- [ ] Reports open correctly.
- [ ] UI remains responsive on a moderately large image.

## G. Release readiness
- [ ] Review `git diff` and remove temporary files, workspaces, generated samples, and secrets.
- [ ] Confirm no test ground-truth answer key is included.
- [ ] Confirm no user challenge images or reports are included.
- [ ] Confirm README and known limitations match actual behavior.
- [ ] Test the source ZIP from a fresh extraction.
- [ ] Only then tag and publish `v1.0.0`.

Record each failed case with: OS, Python version, command, input format/size (not private challenge data), expected result, actual result, traceback, and report excerpt.
