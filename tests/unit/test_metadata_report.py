"""The HTML report shows metadata results only when the metadata analyzer really ran."""

import unittest


from imagehunter.core.status import EXECUTED
from imagehunter.services.report_html import build_report_html
from tests.unit.test_report_html import _summary


class MetadataReportTests(unittest.TestCase):
    def test_not_executed_when_analyzer_absent(self):
        page = build_report_html(_summary())
        self.assertIn("Metadata (EXIF, XMP, IPTC, GPS)", page)
        self.assertNotIn("PNG text chunks", page)

    def test_shows_real_values_when_analyzer_ran(self):
        s = _summary(
            analyzers=[{"name": "metadata.extract", "status": "pass", "message": ""}],
            props={"image.identity": {"signature_format": "png"},
                   "metadata.extract": {
                       "png_text": [{"chunk": "tEXt", "offset": 33, "keyword": "Author",
                                     "text": "<b>alice</b>", "text_truncated": False,
                                     "compressed": False, "length": 13}],
                       "xmp": None, "icc_profile": None,
                       "exif": {"present": True, "fields": {"Software": "Tool"},
                                "timestamps": {}, "gps": {"GPSLatitude": "33.6"},
                                "privacy_note": "local only"}}},
        )
        page = build_report_html(s)
        self.assertIn("PNG text chunks", page)
        self.assertIn("&lt;b&gt;alice&lt;/b&gt;", page)          # escaped
        self.assertNotIn("<b>alice</b>", page)
        self.assertIn("Privacy: local only", page)
        self.assertNotIn("Metadata (EXIF, XMP, IPTC, GPS)", page)


if __name__ == "__main__":
    unittest.main()
