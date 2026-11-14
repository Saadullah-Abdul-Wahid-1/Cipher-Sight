"""Front-end assets for the local web interface.

The interface lives in static/ as ordinary files: index.html, app.css, app.js and the
official logo. This module reads the text files once so the server can serve them and the
tests can inspect them. Everything is local: no CDN, no remote fonts, no remote scripts.
"""

from pathlib import Path

_STATIC = Path(__file__).resolve().parent / "static"

PAGE_HTML = (_STATIC / "index.html").read_text(encoding="utf-8")
APP_CSS = (_STATIC / "app.css").read_text(encoding="utf-8")
APP_JS = (_STATIC / "app.js").read_text(encoding="utf-8")
