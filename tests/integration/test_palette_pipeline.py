"""End-to-end indexed palette candidate detection."""
import io
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from imagehunter.core.pipeline import run_scan


class PalettePipelineTests(unittest.TestCase):
    def test_palette_index_candidate_is_reported_with_original_provenance(self):
        payload = b"CTF{palette_pipeline}"
        bits = [(byte >> shift) & 1 for byte in payload for shift in range(7, -1, -1)]
        image = Image.new("P", (len(bits), 1))
        image.putpalette([0, 0, 0, 255, 255, 255] + [0, 0, 0] * 254)
        image.putdata(bits)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "palette.png"
            target.write_bytes(buffer.getvalue())
            summary = run_scan(target, workspace_base=Path(tmp) / "workspace")
        findings = [f for f in summary.findings if f.kind == "palette_index_lsb_flag_candidate"]
        self.assertTrue(any(f.evidence["text"] == "CTF{palette_pipeline}" for f in findings))
        self.assertTrue(all(f.source_artifact_id == "A001" for f in findings))
        self.assertIn("image.palette", [item["name"] for item in summary.analyzers])


if __name__ == "__main__":
    unittest.main()
