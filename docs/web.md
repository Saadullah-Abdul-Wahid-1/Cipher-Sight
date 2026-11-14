# Local web interface (v0.6.0)

Start it with `python main.py web` (or double-click `ImageHunter_Windows.bat` and type `web`).
It opens http://127.0.0.1:8765/ in your browser. Use `--port` to pick another port and
`--no-browser` to skip opening the browser.

## Security
- Listens on 127.0.0.1 only. Requests whose Host header is not localhost are refused.
- Every POST needs the header `X-ImageHunter: 1`, which blocks cross-site form posts.
- Uploads are size-limited (`max_input_bytes`) before the body is read, and stored in generated folders.
- Filenames are sanitised. Report downloads only serve the two known file names for a scan.
- Only one scan runs at a time (HTTP 409 otherwise).
- All pages send a Content-Security-Policy. The page loads no external scripts, fonts or CDNs.
- Scan output is inserted with textContent, never innerHTML.

## API (used by the page; also usable from scripts)
| Method and path | Purpose |
|---|---|
| GET `/api/status` | version, busy flag, recent scans, upload limit |
| POST `/api/scans` | body = raw file bytes, header `X-Filename` (URL-encoded) → 201 `{id}` |
| GET `/api/scans/<id>?after=N` | live status, progress and events after cursor N |
| GET `/api/scans/<id>/summary` | report view (metrics, flags, phrases, analyzers) once finished |
| GET `/api/scans/<id>/report/html` | standalone HTML report |
| GET `/api/scans/<id>/report/json` | JSON report |

Status codes: 201 accepted, 400 empty or incomplete, 403 security check failed, 404 unknown,
409 busy or not ready, 411 no Content-Length, 413 too large.

## What the page shows
- Dashboard: recent scans, and a list of design features that are NOT in this build.
- Analyze: drag-and-drop or file picker, live progress, LIVE FORENSIC SCAN CONSOLE with level
  colours, filters, search, auto-scroll, pause/resume, clear, copy, export TXT.
- Results: metric cards, CONFIRMED FLAGS (or "No confirmed flags found."), candidates, phrases,
  embedded items, analyzer status, warnings.
- Export: HTML report, JSON download, evidence hash.

## Not in this build
Hex editor, pixel inspector, brightness/contrast sliders, bit-plane viewer, metadata (Phase 3),
carving tools, payload extraction, decoders (UTF-16, Base64, hex) and PDF export. The mockup showed
these; they are listed as not implemented rather than shown as working.

## Testing
`tests/integration/test_web_server.py` covers the security rules, the upload-to-report flow, busy
state, size limits, filename sanitising and escaping of scan output. The page script is checked with
`node --check` when Node is installed. Layout and clicks in a real browser still need a manual check.


## Pages and API (rc7)

Pages are grouped in the sidebar. Analysis pages read the summary of the selected scan. Scan History and the dashboard use stored scans from the current server session.

API:

- `GET /api/status`: version, busy flag, recent scans.
- `GET /api/stats`: dashboard totals computed from stored scan results.
- `POST /api/scans`: upload a file (header `X-ImageHunter: 1`).
- `GET /api/scans/<id>`: live progress and console events.
- `GET /api/scans/<id>/summary`: the scan view, with analyst decisions applied.
- `POST /api/scans/<id>/verifications`: body `{"value": "...", "decision": "confirmed" | "rejected" | "clear"}`. Only flags found by that scan are accepted.
- `GET /api/scans/<id>/report/{html,json,pdf}`: reports written when the scan finished.

Limits:

- Results are held in memory for the server session. Restarting the server clears history and statistics.
- Analyst decisions are held in memory with the scan. Reports do not change after they are written.
- Settings are not editable in the web UI.
