"""Serpentine/diagonal traversal, repeating-key XOR (crib method) and decoy ranking.

Payloads are embedded by the test itself, from the known answer. The analyzer is never used to build its own expected output.
"""

import unittest

import numpy as np

from imagehunter.analyzers.stego.analyzer import LsbFlagAnalyzer
from imagehunter.analyzers.stego.lsb import scan_sequences, traversal_prefix, TRAVERSALS
from imagehunter.config.settings import Settings
from tests.fixtures.generate import make_noise_rgb, make_signal_hunt_like
from tests.unit.test_lsb import _ctx

PREFIXES = Settings().flag_prefixes


def embed(arr, channel, bit, traversal, payload: bytes, start_byte: int = 0, key: bytes = b""):
    """Write payload (MSB-first bits) into one bit plane along a traversal, starting at a byte offset.

    If key is given, the payload is XORed with the repeating key first, using the absolute byte
    position modulo the key length (the convention the scanner assumes)."""
    H, W, _ = arr.shape
    data = bytearray(payload)
    if key:
        for k in range(len(data)):
            data[k] ^= key[(start_byte + k) % len(key)]
    bits = np.unpackbits(np.frombuffer(bytes(data), dtype=np.uint8))
    total = start_byte * 8 + bits.size
    pos = traversal_prefix(H, W, traversal, total)[start_byte * 8:total]
    rows, cols = pos // W, pos % W
    values = arr[rows, cols, channel]
    mask = np.uint8(0xFF ^ (1 << bit))
    arr[rows, cols, channel] = (values & mask) | (bits.astype(np.uint8) << np.uint8(bit))


def texts(flags):
    return {f.text for f in flags}


class TraversalOrderTests(unittest.TestCase):
    def test_every_traversal_is_a_permutation(self):
        for traversal in TRAVERSALS:
            for H, W in ((7, 5), (4, 9), (1, 6), (6, 1)):
                order = traversal_prefix(H, W, traversal, H * W).tolist()
                self.assertEqual(sorted(order), list(range(H * W)), (traversal, H, W))

    def test_known_answer_3x3(self):
        self.assertEqual(traversal_prefix(3, 3, "row", 9).tolist(), list(range(9)))
        self.assertEqual(traversal_prefix(3, 3, "column", 9).tolist(), [0, 3, 6, 1, 4, 7, 2, 5, 8])
        self.assertEqual(traversal_prefix(3, 3, "serpentine", 9).tolist(), [0, 1, 2, 5, 4, 3, 6, 7, 8])
        self.assertEqual(traversal_prefix(3, 3, "diagonal", 9).tolist(), [0, 1, 3, 2, 4, 6, 5, 7, 8])

    def test_prefix_matches_full_order(self):
        for traversal in TRAVERSALS:
            full = traversal_prefix(6, 8, traversal, 48).tolist()
            self.assertEqual(traversal_prefix(6, 8, traversal, 20).tolist(), full[:20], traversal)


class NewTraversalRoundTripTests(unittest.TestCase):
    def _scan(self, arr, traversal, bit):
        flags, _ = scan_sequences(arr, ["R", "G", "B"], 4096, PREFIXES, max_channels=1, leads=False)
        return [f for f in flags if f.traversal == traversal and f.bit == bit]

    def test_serpentine_green_bit1_round_trip(self):
        flag = b"CTF{zig_zag_rows_42}"
        arr = make_noise_rgb(160, 120, 7)
        embed(arr, 1, 1, "serpentine", flag, start_byte=20)
        found = self._scan(arr, "serpentine", 1)
        self.assertIn(flag.decode(), texts(found))

    def test_diagonal_blue_bit0_round_trip(self):
        flag = b"THM{corner_to_corner}"
        arr = make_noise_rgb(160, 120, 11)
        embed(arr, 2, 0, "diagonal", flag, start_byte=8)
        found = self._scan(arr, "diagonal", 0)
        self.assertIn(flag.decode(), texts(found))


class BitAlignmentTests(unittest.TestCase):
    def test_flag_not_byte_aligned_to_stream_start_is_found_with_shift(self):
        """A payload that starts 3 bits into the traversal stream is missed by byte-aligned scans."""
        flag = b"CTF{bit_shift_three}"
        arr = make_noise_rgb(160, 120, 13)
        H, W, _ = arr.shape
        lead_bits = 3
        bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
        total = lead_bits + bits.size
        pos = traversal_prefix(H, W, "row", total)[lead_bits:total]
        rows, cols = pos // W, pos % W
        arr[rows, cols, 2] = (arr[rows, cols, 2] & np.uint8(0xFE)) | bits.astype(np.uint8)
        flags, _ = scan_sequences(arr, ["R", "G", "B"], 4096, PREFIXES, max_channels=1, leads=False)
        hits = [f for f in flags if f.text == flag.decode() and f.channel == "B" and f.traversal == "row"]
        self.assertTrue(hits, "flag at bit offset 3 not recovered")
        self.assertIn(3, {h.bit_shift for h in hits})


class RepeatingKeyTests(unittest.TestCase):
    def _scan_with_keys(self, arr, max_key_len=3):
        flags, _ = scan_sequences(arr, ["R", "G", "B"], 4096, PREFIXES, max_channels=1, leads=False,
                                  repeating_key_max=max_key_len)
        return flags

    def test_two_byte_key_recovered_with_exact_key_bytes(self):
        key = b"\x13\x7a"
        flag = b"CTF{rep3at_k3y_w0rks}"
        arr = make_noise_rgb(160, 120, 3)
        embed(arr, 0, 0, "row", flag, start_byte=40, key=key)
        flags = self._scan_with_keys(arr, 2)
        match = [f for f in flags if f.text == flag.decode() and f.key]
        self.assertTrue(match, "repeating-key flag not recovered")
        self.assertEqual(match[0].key, key)

    def test_three_byte_key_recovered(self):
        key = b"\x5a\x11\xc3"
        flag = b"FLAG{three_byte_key_ok}"
        arr = make_noise_rgb(160, 120, 5)
        embed(arr, 1, 0, "row", flag, start_byte=33, key=key)
        flags = self._scan_with_keys(arr, 3)
        self.assertTrue(any(f.text == flag.decode() and f.key == key for f in flags))

    def test_pure_noise_has_no_repeating_key_flags(self):
        arr = make_noise_rgb(160, 120, 21)
        self.assertEqual(self._scan_with_keys(arr, 3), [])

    def test_disabled_by_default_in_scan_api(self):
        key = b"\x13\x7a"
        arr = make_noise_rgb(160, 120, 3)
        embed(arr, 0, 0, "row", b"CTF{rep3at_k3y_w0rks}", start_byte=40, key=key)
        flags, _ = scan_sequences(arr, ["R", "G", "B"], 4096, PREFIXES, max_channels=1, leads=False)
        self.assertFalse(any(f.key for f in flags))


class DecoyRankingTests(unittest.TestCase):
    def test_two_flags_are_ranked_and_marked_for_review(self):
        res = LsbFlagAnalyzer().run(_ctx(make_signal_hunt_like()))
        flags = [f for f in res.findings if f.kind == "lsb_flag_candidate"]
        self.assertEqual(len(flags), 2)
        for f in flags:
            self.assertEqual(f.evidence["candidates_total"], 2)
            self.assertIn(f.evidence["rank"], (1, 2))
            self.assertIn("rank", f.description)
            self.assertIn("not verification", f.description)
            self.assertIn("rank_breakdown", f.evidence)
        self.assertEqual(sorted(f.evidence["rank"] for f in flags), [1, 2])

    def test_single_flag_has_no_ambiguity_note(self):
        arr = make_noise_rgb(160, 120, 9)
        embed(arr, 2, 0, "row", b"CTF{only_one_here}", start_byte=0)
        from PIL import Image
        import io
        buf = io.BytesIO()
        Image.fromarray(arr, "RGB").save(buf, format="PNG")
        res = LsbFlagAnalyzer().run(_ctx(buf.getvalue()))
        flags = [f for f in res.findings if f.kind == "lsb_flag_candidate"]
        self.assertEqual(len(flags), 1)
        self.assertNotIn("rank 1 of", flags[0].description)


if __name__ == "__main__":
    unittest.main()
