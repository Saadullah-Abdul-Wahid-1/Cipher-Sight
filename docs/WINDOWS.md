# Running ImageHunter on Windows

## Easiest way
1. Install Python 3.10 through 3.13 from https://www.python.org/downloads/.
   During installation, tick **"Add python.exe to PATH"**.
2. Unzip the project folder anywhere (for example `C:\ImageHunter`).
3. Double-click `ImageHunter_Windows.bat`, or open Command Prompt in that folder.

## Using the window (easiest)
Double-click `ImageHunter_Windows.bat`. The launcher checks Python and pip, creates or reuses `.venv`, installs the project and PDF-reporting dependency, prints the dependency/optional-tool report, and opens the ImageHunter window.
1. Press **Choose image...** and pick your file from any folder.
2. Press **Scan**. The summary appears in the window. The file is never changed.
3. **Open reports folder** shows the saved JSON report.

## Commands (console)
    ImageHunter_Windows.bat                     open the window
    ImageHunter_Windows.bat help                show help
    ImageHunter_Windows.bat test                run the test suite
    ImageHunter_Windows.bat C:\path\image.png   scan in the console (JSON)

The first run creates `.venv` and installs the declared project dependencies (Pillow, NumPy, ReportLab). This needs internet once. Later runs reuse the environment and pip checks for missing/outdated requirements. Optional OpenCV/pytesseract and the external Tesseract OCR engine are not installed automatically; see `docs/installation.md`.

Output: the JSON summary prints on screen. The same JSON is saved to
`workspace\<scan_id>\reports\scan_summary.json`. The original image is never changed.

## Exit codes
- `0`: scan completed (findings may still exist).
- `1`: setup problem (Python missing or too old, or install failed).
- `2`: bad input (file not found, empty, too large) or bad settings.

## Troubleshooting
- **"Python was not found"**: reinstall Python with "Add python.exe to PATH", or use the `py` launcher.
- **Microsoft Store opens instead of Python**: turn off the App execution aliases for `python.exe`
  (Settings > Apps > Advanced app settings > App execution aliases), then install Python from python.org.
- **Package install fails behind a proxy or firewall**: install Pillow manually inside `.venv`:
  `.venv\Scripts\python.exe -m pip install Pillow`
- **Window does not open**: check `workspace\gui_error.log` for the error.
- **"Tcl/Tk" error**: reinstall Python from python.org with "tcl/tk and IDLE" ticked.
- **Paths with spaces**: the launcher quotes paths. Wrap the file path in quotes if needed.
- **Pure command-line alternative**: `py -3 -m venv .venv`, then
  `.venv\Scripts\activate`, `pip install -r requirements.txt`, `python main.py scan image.png`.

## Status
Windows BAT and PowerShell workflows are source-reviewed only in this Linux build environment; they have not been executed on Windows. Please complete the Windows checklist before calling this release validated.
