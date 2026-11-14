"""Local web interface. Listens on 127.0.0.1 only and serves the scanner as a small JSON API.

Security rules enforced here:
  * Host header must be 127.0.0.1 or localhost (blocks DNS-rebinding from other websites).
  * Every POST must carry X-ImageHunter: 1. A cross-site form cannot add a custom header
    without a permission check that browsers do not grant to plain forms.
  * Job ids must be 32 hex characters; reports are served only from the known file names
    inside the job's own reports folder. Users never supply a file path.
  * Uploads are size-limited before the body is read, and stored under generated folders.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote

from imagehunter import __version__
from imagehunter.services.report_data import build_view
from imagehunter.services.stats import aggregate
from imagehunter.web.assets import APP_CSS, APP_JS, PAGE_HTML
from imagehunter.web.jobs import BusyError, JobManager, UploadError

JOB_ID = re.compile(r"^[0-9a-f]{32}$")
REPORTS = {"html": ("scan_report.html", "text/html; charset=utf-8"),
           "json": ("scan_report.json", "application/json; charset=utf-8"),
           "pdf": ("scan_report.pdf", "application/pdf")}
REPORT_CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
              "img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
PAGE_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


_LOGO_PATH = Path(__file__).resolve().parent / "static" / "ciphersight-logo.jpg"


def _logo_bytes() -> bytes:
    """The official logo, served unmodified."""
    return _LOGO_PATH.read_bytes()


class ImageHunterServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port: int, manager: JobManager, host: str = "127.0.0.1"):
        super().__init__((host, port), Handler)
        self.manager = manager
        self.allowed_hosts = {f"127.0.0.1:{self.server_address[1]}", f"localhost:{self.server_address[1]}"}


class Handler(BaseHTTPRequestHandler):
    server_version = "ImageHunter"
    sys_version = ""

    def log_message(self, fmt, *args):  # keep the terminal quiet; the scan console is the log
        return

    # ------------------------------------------------------------ helpers
    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.server.allowed_hosts

    def _send(self, status: int, body: bytes, ctype: str, csp: str | None = None,
              extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        if csp:
            self.send_header("Content-Security-Policy", csp)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _forbidden_host(self) -> bool:
        if not self._host_ok():
            self._error(403, "request host is not allowed")
            return True
        return False

    # ------------------------------------------------------------ routes
    def do_GET(self):
        if self._forbidden_host():
            return
        path, _, query = self.path.partition("?")
        params = parse_qs(query)
        if path == "/":
            return self._send(200, PAGE_HTML.encode("utf-8"), "text/html; charset=utf-8", csp=PAGE_CSP)
        if path == "/static/app.css":
            return self._send(200, APP_CSS.encode("utf-8"), "text/css; charset=utf-8", csp=PAGE_CSP)
        if path == "/static/logo.jpg":
            return self._send(200, _logo_bytes(), "image/jpeg", csp=PAGE_CSP)
        if path == "/static/app.js":
            return self._send(200, APP_JS.encode("utf-8"), "application/javascript; charset=utf-8", csp=PAGE_CSP)
        if path == "/api/stats":
            return self._json(200, self._stats())
        if path == "/api/status":
            return self._json(200, {"version": __version__, "busy": self.server.manager.busy(),
                                    "jobs": self.server.manager.recent(),
                                    "max_upload_bytes": self.server.manager.settings.max_input_bytes})
        if path.startswith("/api/scans/"):
            return self._get_scan(path, params)
        return self._error(404, "not found")

    def _get_scan(self, path: str, params: dict) -> None:
        parts = path.split("/")            # ["", "api", "scans", id, ...]
        if len(parts) < 4 or not JOB_ID.match(parts[3]):
            return self._error(404, "unknown scan")
        job = self.server.manager.get(parts[3])
        if job is None:
            return self._error(404, "unknown scan")
        if len(parts) == 4:
            try:
                after = int(params.get("after", ["0"])[0])
            except ValueError:
                return self._error(400, "after must be an integer")
            return self._json(200, job.snapshot(after))
        if len(parts) == 5 and parts[4] == "summary":
            if not job.done:
                return self._error(409, "scan is still running")
            if job.summary is None:
                return self._error(409, "scan failed; no summary")
            return self._json(200, job.view())
        if len(parts) == 6 and parts[4] == "report" and parts[5] in REPORTS:
            if not job.done or job.summary is None:
                return self._error(409, "report not ready")
            name, ctype = REPORTS[parts[5]]
            report = Path(job.summary["workspace"]) / "reports" / name
            if not report.is_file():
                return self._error(404, "report file missing")
            body = report.read_bytes()
            csp = REPORT_CSP if parts[5] == "html" else None
            return self._send(200, body, ctype, csp=csp)
        return self._error(404, "not found")

    def _stats(self) -> dict:
        entries = []
        for job in self.server.manager.all_jobs():
            view = job.view() if job.done else None
            entries.append({"status": job.status, "view": view})
        return aggregate(entries)

    def _post_verification(self, job_id: str) -> None:
        if not JOB_ID.match(job_id):
            return self._error(404, "unknown scan")
        body = _read_json_body(self)
        if body is None or not isinstance(body.get("value"), str) or not isinstance(body.get("decision"), str):
            return self._error(400, "send JSON with a string 'value' and 'decision'")
        if len(body["value"]) > 1000:
            return self._error(400, "value is too long")
        try:
            view = self.server.manager.set_verification(job_id, body["value"], body["decision"])
        except KeyError:
            return self._error(404, "unknown scan")
        except ValueError as exc:
            return self._error(400, str(exc))
        return self._json(200, view)

    def do_POST(self):
        if self._forbidden_host():
            return
        if self.headers.get("X-ImageHunter", "") != "1":
            return self._error(403, "missing X-ImageHunter header")
        path = self.path.partition("?")[0]
        parts = path.split("/")                     # ["", "api", "scans", id, "verifications"]
        if len(parts) == 5 and parts[1:3] == ["api", "scans"] and parts[4] == "verifications":
            return self._post_verification(parts[3])
        if path != "/api/scans":
            return self._error(404, "not found")
        raw_len = self.headers.get("Content-Length")
        try:
            length = int(raw_len) if raw_len is not None else None
        except ValueError:
            length = None
        name = unquote(self.headers.get("X-Filename", "upload.bin"))
        try:
            job = self.server.manager.submit(name, self.rfile, length)
        except BusyError as exc:
            return self._error(409, str(exc))
        except UploadError as exc:
            # Do not read the rest of an oversized body; close the connection after the answer.
            self.close_connection = True
            return self._error(exc.status, str(exc))
        return self._json(201, {"id": job.id, "filename": job.filename})


def _read_json_body(handler, limit: int = 4096) -> dict | None:
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        return None
    if length <= 0 or length > limit:
        return None
    try:
        data = json.loads(handler.rfile.read(length).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def serve_forever_in_thread(server: ImageHunterServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def serve(port: int, open_browser: bool, base_dir: str | Path, settings) -> int:
    import webbrowser
    manager = JobManager(settings, base_dir)
    try:
        server = ImageHunterServer(port, manager)
    except OSError as exc:
        print(f"Cannot listen on 127.0.0.1:{port}: {exc}. Try another port with --port.")
        return 2
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"CipherSight web interface: {url}")
    print("Listening on this computer only. Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
