"""End-to-end GIF frame analyzer registration and report provenance."""
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from imagehunter.core.pipeline import run_scan


class GifPipelineTests(unittest.TestCase):
    def test_gif_frame_candidate_is_reported_in_scan(self):
        payload = b"CTF{gif_pipeline_test}"
        bits = [(byte >> shift) & 1 for byte in payload for shift in range(7, -1, -1)]
        image = Image.new("P", (len(bits), 1))
        image.putpalette([0, 0, 0, 1, 0, 0] + [0, 0, 0] * 254)
        image.putdata(bits)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "frame_payload.gif"
            image.save(target, format="GIF")
            summary = run_scan(target, workspace_base=Path(tmp) / "workspace")
        matches = [f for f in summary.findings if f.kind == "gif_frame_lsb_flag_candidate"]
        self.assertTrue(any(f.evidence["text"] == "CTF{gif_pipeline_test}" for f in matches))
        self.assertTrue(all(f.source_artifact_id == "A001" for f in matches))
        self.assertIn("image.animation", [item["name"] for item in summary.analyzers])


if __name__ == "__main__":
    unittest.main()
