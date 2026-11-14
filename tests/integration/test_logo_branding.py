"""Official logo: served unmodified, referenced in the header, and kept out of production code paths.

The expected SHA-256 is the hash of the logo supplied by the owner. If the logo is
intentionally replaced, update the constant with the new file's hash.
"""

import hashlib
import tempfile
import unittest
from pathlib import Path

from imagehunter.config.settings import Settings
from imagehunter.web.assets import PAGE_HTML
from imagehunter.web.jobs import JobManager
from imagehunter.web.server import ImageHunterServer, serve_forever_in_thread

from tests.integration.test_web_server import Client

OFFICIAL_LOGO_SHA256 = "0cd747feedfb43358525d4ca3c3fb45cfd4d0884e270e4848fb654f0e0c3e336"
LOGO_FILE = Path(__file__).resolve().parents[2] / "src" / "imagehunter" / "web" / "static" / "ciphersight-logo.jpg"


class LogoAssetTests(unittest.TestCase):
    def test_bundled_logo_matches_official_hash(self):
        self.assertEqual(hashlib.sha256(LOGO_FILE.read_bytes()).hexdigest(), OFFICIAL_LOGO_SHA256)

    def test_header_places_logo_before_brand_text(self):
        top = PAGE_HTML.index('class="top-brand"')
        img = PAGE_HTML.index('class="top-logo"', top)
        text = PAGE_HTML.index('class="top-brand-text">CipherSight', top)
        self.assertLess(img, text)
        self.assertIn('src="/static/logo.jpg"', PAGE_HTML)

    def test_logo_served_unmodified_with_image_type(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            manager = JobManager(Settings(), Path(tmp.name) / "workspace", runner=None)
            server = ImageHunterServer(0, manager)
            serve_forever_in_thread(server)
            try:
                status, headers, body = Client(server.server_address[1]).req("GET", "/static/logo.jpg")
                self.assertEqual(status, 200)
                self.assertEqual(headers["content-type"], "image/jpeg")
                self.assertEqual(hashlib.sha256(body).hexdigest(), OFFICIAL_LOGO_SHA256)
            finally:
                server.shutdown()
                server.server_close()
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
