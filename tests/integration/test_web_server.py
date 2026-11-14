"""Local web interface: security rules, the upload-to-report flow, and the API shapes the page uses."""

import http.client
import json
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from imagehunter.config.settings import Settings
from imagehunter.services.report_data import build_view
from imagehunter.web.assets import APP_CSS, APP_JS, PAGE_HTML
from imagehunter.web.jobs import JobManager
from imagehunter.web.server import ImageHunterServer, serve_forever_in_thread
from tests.fixtures.generate import build_fixtures, make_signal_hunt_like, REAL_FLAG

OK_HEADERS = {"X-ImageHunter": "1"}


class Client:
    def __init__(self, port: int, host: str | None = None):
        self.port = port
        self.host = host or f"127.0.0.1:{port}"

    def req(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Host": self.host}
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        status, hdrs = r.status, {k.lower(): v for k, v in r.getheaders()}
        conn.close()
        return status, hdrs, data

    def json(self, method, path, body=None, headers=None):
        status, hdrs, data = self.req(method, path, body, headers)
        return status, json.loads(data.decode("utf-8"))

    def upload(self, name: str, data: bytes, extra=None):
        h = {"Content-Type": "application/octet-stream", "Content-Length": str(len(data)),
             "X-Filename": name.replace(" ", "%20")}
        h.update(OK_HEADERS)
        h.update(extra or {})
        return self.json("POST", "/api/scans", body=data, headers=h)

    def wait_done(self, job_id: str, timeout: float = 120):
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, d = self.json("GET", f"/api/scans/{job_id}?after=0")
            if d["done"]:
                return d
            time.sleep(0.05)
        raise AssertionError("scan did not finish")


class _Base(unittest.TestCase):
    settings_kwargs: dict = {}
    runner = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.tmp.name) / "workspace"
        cls.settings = Settings(**cls.settings_kwargs)
        cls.manager = JobManager(cls.settings, cls.base, runner=cls.runner)
        cls.server = ImageHunterServer(0, cls.manager)
        serve_forever_in_thread(cls.server)
        cls.client = Client(cls.server.server_address[1])

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()


class PageAndSecurityTests(_Base):
    def test_page_is_served_with_security_headers(self):
        status, hdrs, body = self.client.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", hdrs["content-type"])
        self.assertIn("default-src 'none'", hdrs["content-security-policy"])
        self.assertEqual(hdrs["x-frame-options"], "DENY")
        self.assertIn(b"LIVE FORENSIC SCAN CONSOLE", body)

    def test_page_and_assets_have_no_external_references(self):
        for text in (PAGE_HTML, APP_CSS, APP_JS):
            self.assertNotIn("https://", text)
            self.assertNotIn("http://", text)
        status, _, _ = self.client.req("GET", "/static/app.js")
        self.assertEqual(status, 200)
        status, _, _ = self.client.req("GET", "/static/app.css")
        self.assertEqual(status, 200)

    def test_foreign_host_header_is_refused(self):
        c = Client(self.client.port, host="evil.example.com")
        status, d = c.json("GET", "/api/status")
        self.assertEqual(status, 403)

    def test_post_without_custom_header_is_refused(self):
        status, d = self.client.json("POST", "/api/scans", body=b"x",
                                     headers={"Content-Length": "1", "X-Filename": "a.png"})
        self.assertEqual(status, 403)

    def test_unknown_routes_and_bad_ids_return_404(self):
        self.assertEqual(self.client.req("GET", "/nope")[0], 404)
        self.assertEqual(self.client.req("GET", "/api/scans/../../etc")[0], 404)
        self.assertEqual(self.client.req("GET", "/api/scans/not-hex")[0], 404)
        self.assertEqual(self.client.req("GET", "/api/scans/" + "0" * 32)[0], 404)

    def test_report_name_is_fixed_not_user_supplied(self):
        status, d = self.client.json("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(self.client.req("GET", "/api/scans/" + "a" * 32 + "/report/../../x")[0], 404)
        self.assertEqual(self.client.req("GET", "/api/scans/" + "a" * 32 + "/report/exe")[0], 404)

    def test_empty_upload_refused(self):
        status, d = self.client.upload("empty.png", b"")
        self.assertIn(status, (400, 411))

    def test_status_endpoint_shape(self):
        status, d = self.client.json("GET", "/api/status")
        self.assertEqual(status, 200)
        for key in ("version", "busy", "jobs", "max_upload_bytes"):
            self.assertIn(key, d)


class UploadFlowTests(_Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        fx = {f.filename: f for f in build_fixtures()}["appended_zip.png"]
        status, d = cls.client.upload("appended_zip.png", fx.data)
        assert status == 201, d
        cls.job_id = d["id"]
        cls.final = cls.client.wait_done(cls.job_id)

    def test_upload_accepted_and_completes(self):
        self.assertEqual(self.final["status"], "completed")
        self.assertIsNone(self.final["error"])
        self.assertEqual(self.final["percent"], 100)

    def test_live_events_have_real_structure(self):
        events = self.final["events"]
        self.assertTrue(events)
        for e in events:
            self.assertIn(e["level"], ("DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "FINDING"))
            self.assertTrue(e["module"])
        hash_ok = [e for e in events if e["operation"] == "SHA-256" and e["level"] == "SUCCESS"]
        self.assertEqual(len(hash_ok), 1)

    def test_cursor_returns_only_new_events(self):
        _, first = self.client.json("GET", f"/api/scans/{self.job_id}?after=0")
        _, rest = self.client.json("GET", f"/api/scans/{self.job_id}?after={first['total_events'] - 2}")
        self.assertEqual(len(rest["events"]), 2)
        self.assertEqual(rest["total_events"], first["total_events"])

    def test_summary_matches_the_saved_json_report(self):
        status, view = self.client.json("GET", f"/api/scans/{self.job_id}/summary")
        self.assertEqual(status, 200)
        status, _, raw = self.client.req("GET", f"/api/scans/{self.job_id}/report/json")
        saved = json.loads(raw.decode("utf-8"))
        expected = build_view(saved)
        self.assertEqual(view["metrics"]["total_findings"], len(saved["findings"]))
        self.assertEqual(view["metrics"]["flag_candidates"], expected["metrics"]["flag_candidates"])
        self.assertEqual([f["kind"] for f in view["findings"]], [f["kind"] for f in saved["findings"]])
        self.assertEqual(view["sha256"], saved["input"]["sha256"])

    def test_html_report_served_with_csp_and_matches_content(self):
        status, hdrs, body = self.client.req("GET", f"/api/scans/{self.job_id}/report/html")
        self.assertEqual(status, 200)
        self.assertIn("text/html", hdrs["content-type"])
        self.assertIn("frame-ancestors 'none'", hdrs["content-security-policy"])
        self.assertIn(b"No confirmed flags found.", body)
        self.assertIn(b"CipherSight Forensic Report", body)

    def test_pdf_report_endpoint_is_available_when_optional_export_succeeded(self):
        status, headers, body = self.client.req("GET", f"/api/scans/{self.job_id}/report/pdf")
        if status == 200:
            self.assertEqual(headers["content-type"], "application/pdf")
            self.assertTrue(body.startswith(b"%PDF"))
        else:
            self.assertEqual(status, 404)  # ReportLab is optional.

    def test_summary_while_running_is_refused(self):
        status, d = self.client.json("GET", "/api/scans/" + "b" * 32 + "/summary")
        self.assertEqual(status, 404)


class BusyAndLimitTests(unittest.TestCase):
    def _server(self, runner, **settings_kwargs):
        tmp = tempfile.TemporaryDirectory()
        mgr = JobManager(Settings(**settings_kwargs), Path(tmp.name) / "ws", runner=runner)
        srv = ImageHunterServer(0, mgr)
        serve_forever_in_thread(srv)
        return tmp, srv, Client(srv.server_address[1])

    def test_second_scan_refused_while_first_runs(self):
        release = threading.Event()

        def blocking_runner(path, settings, workspace_base, on_event):
            release.wait(30)
            raise RuntimeError("stopped by test")

        tmp, srv, c = self._server(blocking_runner)
        try:
            fx = {f.filename: f for f in build_fixtures()}["clean.png"]
            status, d = c.upload("one.png", fx.data)
            self.assertEqual(status, 201)
            status2, d2 = c.upload("two.png", fx.data)
            self.assertEqual(status2, 409)
            self.assertEqual(c.json("GET", "/api/status")[1]["busy"], True)
            status3, _ = c.json("GET", f"/api/scans/{d['id']}/summary")
            self.assertEqual(status3, 409)
            release.set()
            final = c.wait_done(d["id"])
            self.assertEqual(final["status"], "failed")
            self.assertIn("stopped by test", final["error"])
            self.assertTrue(any(e["level"] == "ERROR" for e in final["events"]))
        finally:
            release.set()
            srv.shutdown()
            srv.server_close()
            tmp.cleanup()

    def test_oversized_upload_refused_with_413(self):
        tmp, srv, c = self._server(None, max_input_bytes=100)
        try:
            status, d = c.upload("big.png", b"x" * 500)     # larger than the 100-byte limit
            self.assertEqual(status, 413)
            self.assertIn("limit", d["error"])
        finally:
            srv.shutdown()
            srv.server_close()
            tmp.cleanup()

    def test_hostile_filename_is_sanitised_and_stored_inside_uploads(self):
        tmp, srv, c = self._server(lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no scan")))
        try:
            fx = {f.filename: f for f in build_fixtures()}["clean.png"]
            status, d = c.upload("../../evil; rm -rf ~.png", fx.data)
            self.assertEqual(status, 201)
            self.assertNotIn("/", d["filename"])
            self.assertNotIn(";", d["filename"])
            self.assertNotIn(" ", d["filename"])
            job = srv.manager.get(d["id"])
            self.assertTrue(str(job.path.resolve()).startswith(str((Path(tmp.name) / "ws" / "uploads").resolve())))
            c.wait_done(d["id"])
        finally:
            srv.shutdown()
            srv.server_close()
            tmp.cleanup()


class HostileContentTests(_Base):
    """Scan results containing markup must come back escaped in the served report."""

    def test_hostile_flag_text_is_escaped_in_served_html(self):
        data = make_signal_hunt_like()
        status, d = self.client.upload('<img src=x onerror=alert(1)>.png', data)
        self.assertEqual(status, 201)
        final = self.client.wait_done(d["id"])
        self.assertEqual(final["status"], "completed")
        _, _, body = self.client.req("GET", f"/api/scans/{d['id']}/report/html")
        text = body.decode("utf-8")
        # The filename is sanitised before it is stored, so no markup reaches the report at all.
        self.assertNotIn("<img", text)
        self.assertNotIn("onerror=alert", text)
        self.assertIn("img_src_x_onerror_alert_1__.png", text)
        self.assertIn(REAL_FLAG, text)


@unittest.skipUnless(shutil.which("node"), "node is not installed; syntax check skipped")
class ScriptSyntaxTests(unittest.TestCase):
    def test_page_script_parses(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "app.js"
            f.write_text(APP_JS, encoding="utf-8")
            proc = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
