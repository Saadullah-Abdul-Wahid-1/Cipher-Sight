# Installation

Requirements: Python 3.10+, pip. Optional external tools (see TOOL_FLAGS.md).

Linux / WSL: `bash scripts/install_linux.sh`
Windows: `powershell -ExecutionPolicy Bypass -File scripts\install_windows.ps1`

Manual: create `.venv`, activate it, `pip install -r requirements.txt`, then
`python -m unittest discover -s tests -t .` to verify.

Editable install: `pip install -e .` gives an `imagehunter` command.

## Optional analysis and reporting extras

The core install remains lightweight. Install only the extras you need:

```bash
pip install -e ".[ocr,vision]"       # OCR wrapper and OpenCV QR/barcode support
pip install -e ".[pdf]"              # PDF report export
pip install -e ".[jpeg-dct]"         # jpegio coefficient statistics
pip install -e ".[all]"              # all optional Python extras
```

OCR also requires the Tesseract executable to be installed and available on `PATH`.
OCR/QR analysis is disabled by default. In the user settings JSON, set:

```json
{"vision_analysis_enabled": true}
```

JPEG DCT support currently reports quantized coefficient statistics only; it is not a universal JPEG steganography payload decoder. BigTIFF and full decoding of every TIFF/WebP metadata subformat are not supported.
