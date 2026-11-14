import io
import unittest

import numpy as np
from PIL import Image

from imagehunter.analyzers.base import AnalyzerContext
from imagehunter.analyzers.stego.advanced import AdvancedStegoAnalyzer, bitplane_statistics
from imagehunter.config.settings import Settings
from imagehunter.models.artifact import Artifact


class AdvancedStegoTests(unittest.TestCase):
    def _png(self, arr):
        buf = io.BytesIO()
        Image.fromarray(arr, mode="RGB").save(buf, format="PNG")
        return buf.getvalue()

    def test_bitplane_statistics_are_bounded_and_reproducible(self):
        arr = np.zeros((8, 8, 3), dtype=np.uint8)
        arr[:, :, 0] = 255
        stats = bitplane_statistics(arr, ["R", "G", "B"])
        self.assertEqual(stats["R"]["0"]["ones_ratio"], 1.0)
        self.assertEqual(stats["R"]["0"]["entropy_bits"], 0.0)
        self.assertEqual(stats["G"]["0"]["ones_ratio"], 0.0)

    def test_detects_sparse_pixel_stride_payload(self):
        rng = np.random.default_rng(20261109)
        arr = rng.integers(0, 256, size=(96, 96, 3), dtype=np.uint8)
        payload = b"CTF{sparse_pixel_stride_test}"
        key = 0x5A
        bits = np.unpackbits(np.frombuffer(bytes(b ^ key for b in payload), dtype=np.uint8), bitorder="little")
        positions = np.arange(0, arr.shape[0] * arr.shape[1], 2)[:len(bits)]
        flat = arr[:, :, 0].reshape(-1)
        flat[positions] = (flat[positions] & 0xFE) | bits
        data = self._png(arr)
        artifact = Artifact(id="A001", role="original", path="memory.png", working_path="memory.png",
                            sha256="0" * 64, size=len(data))
        ctx = AnalyzerContext(artifact=artifact, data=data, settings=Settings(stego_max_bytes=4096),
                              shared={"detected_format": "png"})
        result = AdvancedStegoAnalyzer().run(ctx)
        texts = [f.evidence.get("text") for f in result.findings]
        self.assertIn(payload.decode(), texts)
        finding = next(f for f in result.findings if f.evidence.get("text") == payload.decode())
        self.assertTrue(any(x["pixel_stride"] == 2 and x["xor_key"] == "0x5A"
                            for x in finding.evidence["experiments"]))


if __name__ == "__main__":
    unittest.main()
