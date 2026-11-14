"""Multi-channel interleaved LSB streams and unknown-prefix leads.

Flags and bodies are generated fresh on each run. Nothing here stores an answer."""

import secrets
import unittest

import numpy as np

from imagehunter.analyzers.stego.lsb import (
    channel_sequences, readable_body, scan_sequences)
from imagehunter.config.settings import ConfigError, Settings
from tests.fixtures.generate import embed_lsb, embed_lsb_interleaved, make_noise_rgb

PREFIXES = ("THM", "CTF", "FLAG", "flag", "HTB", "picoCTF")


def _random_token(n=6):
    return "".join(secrets.choice("0123456789") for _ in range(n))


class SequenceTests(unittest.TestCase):
    def test_counts_by_max_channels(self):
        names = ["R", "G", "B"]
        self.assertEqual(len(channel_sequences(names, 1)), 3)
        self.assertEqual(len(channel_sequences(names, 2)), 3 + 6)
        self.assertEqual(len(channel_sequences(names, 3)), 3 + 6 + 6)

    def test_order_is_significant(self):
        seqs = channel_sequences(["R", "G", "B"], 2)
        self.assertIn((0, 1), seqs)
        self.assertIn((1, 0), seqs)


class InterleavedRoundTripTests(unittest.TestCase):
    def test_two_channel_interleaved_flag_found_only_with_two_channels(self):
        flag = ("CTF{" + _random_token() + "}").encode()
        arr = make_noise_rgb(64, 48, 11)
        embed_lsb_interleaved(arr, (0, 1), 0, "row", "LSB-first", flag, xor_key=0x21, start_index=0)
        one, _ = scan_sequences(arr, ["R", "G", "B"], 65536, PREFIXES, max_channels=1)
        self.assertNotIn(flag.decode(), [h.text for h in one])
        two, _ = scan_sequences(arr, ["R", "G", "B"], 65536, PREFIXES, max_channels=2)
        hits = [h for h in two if h.text == flag.decode()]
        self.assertTrue(hits)
        self.assertEqual(hits[0].channel, "R+G")
        self.assertEqual(hits[0].xor_key, 0x21)

    def test_column_order_interleaved_three_channels(self):
        flag = ("THM{" + _random_token() + "}").encode()
        arr = make_noise_rgb(64, 48, 12)
        embed_lsb_interleaved(arr, (2, 0, 1), 1, "column", "MSB-first", flag, xor_key=0, start_index=0)
        flags, _ = scan_sequences(arr, ["R", "G", "B"], 65536, PREFIXES, max_channels=3)
        hit = [h for h in flags if h.text == flag.decode()]
        self.assertTrue(hit)
        self.assertEqual(hit[0].channel, "B+R+G")
        self.assertEqual(hit[0].bit, 1)
        self.assertEqual(hit[0].traversal, "column")

    def test_single_channel_behaviour_unchanged(self):
        flag = ("CTF{" + _random_token() + "}").encode()
        arr = make_noise_rgb(64, 48, 13)
        embed_lsb(arr, 1, 0, "row", "LSB-first", flag, 0, 0)
        flags, leads = scan_sequences(arr, ["R", "G", "B"], 65536, PREFIXES, max_channels=1, leads=False)
        self.assertIn(flag.decode(), [h.text for h in flags])
        self.assertEqual(leads, [])


class LeadTests(unittest.TestCase):
    def _stego_like(self, body: str):
        """Blue channel, bit plane 1, column order, MSB-first, XOR 0x5A: the layout of the challenge that
        exposed this feature. The prefix RHL is not in the default list."""
        arr = make_noise_rgb(640, 480, 2026)
        embed_lsb(arr, 2, 1, "column", "MSB-first", body.encode(), 0x5A, 37 * 480 // 1)
        return arr

    def test_unconfigured_prefix_is_a_lead_only_when_enabled(self):
        body = "RHL{stone_" + _random_token() + "_xor}"
        arr = self._stego_like(body)
        flags, leads = scan_sequences(arr, ["R", "G", "B"], 65536, PREFIXES, max_channels=1, leads=False)
        self.assertEqual(flags, [])
        self.assertEqual(leads, [])
        flags, leads = scan_sequences(arr, ["R", "G", "B"], 65536, PREFIXES, max_channels=1, leads=True)
        self.assertEqual(flags, [])
        self.assertIn(body, [h.text for h in leads])
        self.assertEqual([h.kind for h in leads if h.text == body], ["lead"])

    def test_configured_prefix_is_a_flag_not_a_lead(self):
        body = "RHL{stone_" + _random_token() + "_xor}"
        arr = self._stego_like(body)
        flags, leads = scan_sequences(arr, ["R", "G", "B"], 65536, PREFIXES + ("RHL",),
                                      max_channels=1, leads=True)
        self.assertIn(body, [h.text for h in flags])
        self.assertNotIn(body, [h.text for h in leads])

    def test_noise_produces_no_leads(self):
        arr = make_noise_rgb(128, 96, 77)
        _, leads = scan_sequences(arr, ["R", "G", "B"], 65536, PREFIXES, max_channels=1, leads=True)
        self.assertEqual(leads, [])

    def test_unknown_prefix_leetspeak_flag_body_is_detected(self):
        body = "RHL{t3st_fl4g_lsb_42}"
        arr = make_noise_rgb(96, 64, 4242)
        embed_lsb(arr, 0, 0, "row", "MSB-first", body.encode(), xor_key=0, start_index=0)
        flags, leads = scan_sequences(arr, ["R", "G", "B"], 65536, PREFIXES,
                                      max_channels=1, leads=True)
        self.assertNotIn(body, [h.text for h in flags])
        self.assertIn(body, [h.text for h in leads])


class ReadableBodyTests(unittest.TestCase):
    def test_readable_text_and_leetspeak_pass(self):
        for body in (b"stone_w0rd_xor", b"readme_notes", b"stone_123456_xor"):
            self.assertTrue(readable_body(body), body)

    def test_noise_and_repeats_fail(self):
        for body in (b"yyyy", b"LLL", b"lllfh9", b"zz1zzz", b"UQSEX", b"xyzzy", b"Hyd", b"kkkkkkkkkkkicika"):
            self.assertFalse(readable_body(body), body)


class SettingsForChannelsTests(unittest.TestCase):
    def test_max_channels_validated(self):
        for bad in (0, 4):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                Settings(lsb_max_channels=bad).validate()

    def test_leads_flag_must_be_boolean(self):
        with self.assertRaises(ConfigError):
            Settings(lsb_unknown_prefix_leads="yes").validate()


if __name__ == "__main__":
    unittest.main()
