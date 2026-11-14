# Verification record — ImageHunter 1.0.0rc3

Validation in this sandbox used Python 3.13.5. This is not a substitute for Windows and user-side manual validation.

## Passed

- Unit suite: **204 passed, 7 subtests passed**.
- Integration suite: **85 passed, 22 subtests passed**, run by individual integration test modules to isolate the test-runner teardown behavior.
- `python -m compileall -q src tests`: passed.
- `python main.py --version`: `imagehunter 1.0.0rc3`.
- `python main.py --help`: passed.
- `python main.py check-deps`: required Pillow and NumPy detected.
- TIFF IFD parser, WebP RIFF parser, TAR/GZIP recovery, ZIP traversal, forged ZIP-size and normal ZIP member regression tests passed.
- PDF report smoke test generated a valid `%PDF` file using ReportLab 4.4.9.
- Web UI PDF endpoint test passed.
- Wheel built successfully with `pip wheel --no-build-isolation --no-deps .`.
- Source distribution built successfully through `setuptools.build_meta.build_sdist`.

## Environment limitations

- A wheel build with normal build isolation could not fetch `setuptools>=68` because network access is unavailable. The no-build-isolation wheel build succeeded using the installed setuptools.
- `jpegio` was not installed, so coefficient analysis was verified only for graceful optional-dependency handling; actual coefficient parsing requires validation on a machine with the optional dependency installed.
- OCR/QR dependencies were present in this environment, but full OCR/QR end-to-end challenge fixture coverage and the external Tesseract executable should be validated on the target machine.
- GUI and Windows checks were not performed.
- License remains unset by design; no LICENSE file was added.

Run the manual checklist and GitHub Actions on the target machine before promoting this RC to stable v1.0.0.


## RC3 validation update
- Python: 3.13.5 on Linux.
- `python -m compileall -q src tests`: passed.
- Unit suite: 204 passed.
- Integration suite: 85 passed in a separate run.
- GUI integration headless tests: passed; this environment lacks tkinter, so a real desktop window could not be opened.
- Dependency checker: Pillow, NumPy, ReportLab, OpenCV, pytesseract, and Tesseract detected; jpegio absent (optional).
- Windows BAT/PowerShell: not executed; requires Windows validation.
- Logo: pending separate upload.


## RC4 verification update

Environment: Linux sandbox, Python 3.13.5.

- Unit suite: 215 passed, 7 subtests passed.
- Integration suite: 85 passed, 22 subtests passed (executed in two groups).
- Compile check: passed.
- CLI version: `1.0.0rc4`.
- Localhost smoke test: server page, CSS asset and `/api/status` returned successfully.
- End-to-end web upload test: uploaded the supplied `stego_test.png`, completed a 15-analyzer scan, and returned `RHL{t3st_fl4g_lsb_42}` as a low-confidence unknown-prefix LSB lead.
- CLI scan of the same supplied image also recorded the same lead.
- Extracted evidence parameters: Red channel, bit plane 0, row traversal, MSB-first, XOR key 0, byte offset 0.
- Windows-native installation/launcher testing was not possible in this Linux sandbox and remains a manual owner check.
- Full suite in one combined pytest process previously hit the execution time limit; all unit and integration groups passed separately.
