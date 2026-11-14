"""Writes the JSON and HTML reports for one scan into the scan's reports folder.

scan_report.json is the machine-readable report. scan_summary.json is the same content under
the name used since v0.3, kept so existing scripts keep working. scan_report.html is generated
from the same summary dict, so the two outputs cannot disagree.
"""

from __future__ import annotations

import json
from pathlib import Path

from imagehunter.services.report_html import build_report_html

JSON_NAME = "scan_report.json"
LEGACY_JSON_NAME = "scan_summary.json"
HTML_NAME = "scan_report.html"
PDF_NAME = "scan_report.pdf"


def write_reports(summary: dict, reports_dir: str | Path, verifications: dict[str, str] | None = None) -> dict:
    out = Path(reports_dir)
    out.mkdir(parents=True, exist_ok=True)
    text = json.dumps(summary, indent=2, ensure_ascii=False)
    json_path = out / JSON_NAME
    json_path.write_text(text, encoding="utf-8")
    (out / LEGACY_JSON_NAME).write_text(text, encoding="utf-8")
    html_path = out / HTML_NAME
    html_path.write_text(build_report_html(summary, verifications), encoding="utf-8")
    result = {"json": str(json_path), "html": str(html_path), "legacy_json": str(out / LEGACY_JSON_NAME)}
    try:
        from imagehunter.services.report_pdf import write_pdf
        result["pdf"] = write_pdf(summary, out / PDF_NAME)
    except Exception as exc:
        # Optional PDF support must never break the core JSON/HTML report.
        result["pdf_warning"] = f"PDF export unavailable: {type(exc).__name__}: {exc}"
    return result
