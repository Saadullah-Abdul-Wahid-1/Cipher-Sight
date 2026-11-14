"""Recursive decoding: known-answer chains, limits, provenance, and the analyzer in the real pipeline.
Flags are generated per run. Nothing here stores an answer."""

import base64
import binascii
import codecs
import gzip
import html
import re
import secrets
import tempfile
import unittest
import zlib
from pathlib import Path
from urllib.parse import quote

from imagehunter.analyzers.decoding.recursive import search
from imagehunter.analyzers.stego.lsb import flag_pattern
from imagehunter.config.settings import ConfigError, Settings
from imagehunter.core.pipeline import run_scan
from imagehunter.services.report_data import classify_flags
from tests.fixtures.generate import make_png_with_chunks

PREFIXES = ("THM", "CTF", "FLAG", "flag", "HTB", "picoCTF")
PAT = flag_pattern(PREFIXES)


def _flag() -> str:
    return "CTF{" + secrets.token_hex(5) + "}"


def _run(seeds, **kw):
    return search(seeds, PREFIXES, PAT, **kw)


class ChainTests(unittest.TestCase):
    def test_base64(self):
        f = _flag()
        flags, _ = _run([("s", 0, base64.b64encode(f.encode()).decode())])
        self.assertEqual(flags[f]["chain_text"], "base64")

    def test_hex(self):
        f = _flag()
        flags, _ = _run([("s", 0, f.encode().hex())])
        self.assertEqual(flags[f]["chain_text"], "hex")

    def test_base32(self):
        f = _flag()
        flags, _ = _run([("s", 0, base64.b32encode(f.encode()).decode().rstrip("="))])
        self.assertIn("base32", flags[f]["chain_text"])

    def test_nested_base64_then_zlib(self):
        f = _flag()
        blob = base64.b64encode(zlib.compress(f"note {f} end".encode())).decode()
        flags, _ = _run([("s", 0, blob)])
        self.assertEqual(flags[f]["chain_text"], "base64 > zlib(max_output=65536)")

    def test_hex_wrapping_base64_wrapping_gzip(self):
        f = _flag()
        inner = base64.b64encode(gzip.compress(f.encode())).decode()
        flags, _ = _run([("s", 0, inner.encode().hex())])
        self.assertEqual(flags[f]["depth"], 3)
        self.assertTrue(flags[f]["chain_text"].startswith("hex > base64 > "))

    def test_url_encoding(self):
        f = _flag()
        flags, _ = _run([("s", 0, quote(f"x {f}"))])
        self.assertEqual(flags[f]["chain_text"], "url")

    def test_html_entities(self):
        f = _flag()
        flags, _ = _run([("s", 0, html.escape(f, quote=True).replace("{", "&#123;").replace("}", "&#125;"))])
        self.assertIn(f, flags)

    def test_binary_digits(self):
        f = _flag()
        flags, _ = _run([("s", 0, "".join(format(b, "08b") for b in f.encode()))])
        self.assertEqual(flags[f]["chain_text"], "binary")

    def test_rot13_is_a_leaf_with_shift_recorded(self):
        f = _flag()
        flags, _ = _run([("s", 0, codecs.encode(f, "rot_13"))])
        self.assertEqual(flags[f]["chain_text"], "rot(shift=13)")

    def test_caesar_other_shift(self):
        f = _flag()
        from imagehunter.analyzers.decoding.decoders import rot_shift
        shifted = rot_shift(f, 5)                      # encoded with shift 5
        flags, _ = _run([("s", 0, shifted)])
        self.assertEqual(flags[f]["chain_text"], "rot(shift=21)")   # decoding needs 26 - 5 = 21

    def test_single_byte_xor_known_prefix_recovers_key(self):
        f = "THM{" + secrets.token_hex(4) + "}"
        key = secrets.randbelow(254) + 1
        cipher = bytes(b ^ key for b in f.encode())
        flags, _ = _run([("s", 0, cipher.decode("latin-1"))])
        self.assertEqual(flags[f]["chain"][-1]["method"], "xor_known_prefix")
        self.assertEqual(flags[f]["chain"][-1]["params"]["key"], f"0x{key:02X}")


class LimitTests(unittest.TestCase):
    def test_depth_limit_stops_deep_chains(self):
        f = _flag()
        blob = f.encode()
        for _ in range(4):
            blob = binascii.hexlify(blob)
        flags, _ = _run([("s", 0, blob.decode())], max_depth=3)
        self.assertNotIn(f, flags)
        flags, _ = _run([("s", 0, blob.decode())], max_depth=4)
        self.assertIn(f, flags)

    def test_node_budget_is_reported(self):
        seeds = [("s", i, base64.b64encode(secrets.token_bytes(30)).decode()) for i in range(40)]
        _, stats = _run(seeds, max_nodes=10)
        self.assertTrue(stats.budget_exhausted)
        self.assertLessEqual(stats.nodes_created, 10)

    def test_zlib_bomb_is_capped_not_expanded(self):
        bomb = zlib.compress(b"\x00" * 5_000_000)
        flags, stats = _run([("s", 0, base64.b64encode(bomb).decode())], max_output=65536)
        self.assertTrue(any("exceeds" in w for w in stats.warnings))
        self.assertEqual(flags, {})

    def test_duplicate_artifacts_expanded_once(self):
        f = _flag()
        blob = base64.b64encode(f.encode()).decode()
        _, stats = _run([("a", 0, blob), ("b", 9, blob)])
        self.assertEqual(stats.nodes_created, 2)          # the seed and its one decoded child

    def test_xor_budget_respected(self):
        seeds = [("s", i, "A" * 200) for i in range(50)]
        _, stats = _run(seeds, xor_budget=500)
        self.assertLessEqual(stats.xor_bytes_tested, 500)
        self.assertTrue(stats.budget_exhausted)


class DecoyTests(unittest.TestCase):
    def test_random_base64_and_junk_give_no_flags(self):
        seeds = [("s", i, base64.b64encode(secrets.token_bytes(48)).decode()) for i in range(30)]
        flags, _ = _run(seeds)
        self.assertEqual(flags, {})

    def test_plain_flag_is_not_reported_by_this_search(self):
        f = _flag()
        flags, _ = _run([("s", 0, f"plain text {f} here")])
        self.assertNotIn(f, flags)                          # no decode step, so not this analyzer's result


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _scan(self, text, name="d.png", **settings):
        path = self.root / name
        path.write_bytes(make_png_with_chunks([(b"tEXt", b"Comment\x00" + text.encode())]))
        return run_scan(path, settings=Settings(**settings), workspace_base=self.root / "ws")

    def test_encoded_flag_in_metadata_becomes_candidate_with_chain(self):
        f = _flag()
        s = self._scan("data: " + base64.b64encode(zlib.compress(f.encode())).decode(), name="a.png")
        hits = [x for x in s.findings if x.kind == "decoded_flag_candidate"]
        self.assertEqual([h.evidence["text"] for h in hits], [f])
        self.assertEqual(hits[0].evidence["chain_text"], "base64 > zlib(max_output=65536)")
        self.assertEqual(hits[0].method, "decoding.recursive")
        view = classify_flags(s.to_dict())
        self.assertEqual([c["value"] for c in view["candidates"]], [f])
        self.assertEqual(view["confirmed"], [])            # never confirmed automatically

    def test_clean_image_has_no_decoded_candidates(self):
        s = self._scan("just a plain comment", name="b.png")
        self.assertFalse([x for x in s.findings if x.kind == "decoded_flag_candidate"])

    def test_disabled_setting_reports_disabled(self):
        s = self._scan("x", name="c.png", decoding_enabled=False)
        self.assertEqual(s.properties["decoding.recursive"], {"enabled": False})

    def test_settings_validation(self):
        with self.assertRaises(ConfigError):
            Settings(decoding_max_depth=9).validate()
        with self.assertRaises(ConfigError):
            Settings(decoding_enabled="yes").validate()


if __name__ == "__main__":
    unittest.main()


class KeyLeafPlausibilityTests(unittest.TestCase):
    """Regression: random bytes once produced a symbol-heavy 'CTF{...}' through known-prefix XOR (found by
    repeated runs). The fixed seed below reproduces that case when the plausibility check is disabled."""

    def test_symbol_heavy_bodies_are_rejected(self):
        from imagehunter.analyzers.decoding.recursive import plausible_body
        symbol_heavy = "CTF{" + "`=d&bb" + "Doh_XB}"          # built at runtime; no literal decoy in source
        self.assertFalse(plausible_body(symbol_heavy))
        self.assertTrue(plausible_body("CTF{" + "a1B_2c3" + "}"))
        self.assertTrue(plausible_body("THM{" + secrets.token_hex(4) + "}"))

    def test_random_junk_never_yields_a_key_leaf_flag(self):
        import random
        rng = random.Random(20261108)                     # fixed seed: reproducible, and it covers the old failure
        for trial in range(300):
            seeds = [("s", i, base64.b64encode(bytes(rng.randrange(256) for _ in range(48))).decode())
                     for i in range(30)]
            flags, _ = _run(seeds)
            key_flags = [v for v in flags.values() if "xor" in v["chain_text"] or "rot" in v["chain_text"]]
            self.assertEqual(key_flags, [], f"trial {trial}")
