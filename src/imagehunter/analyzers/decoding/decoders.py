"""Single-step decoders. Each returns a list of (method, parameters, output_bytes). Empty list = not applicable.

Rules:
  * Text decoders accept only strings that match their alphabet exactly, then validate the decode.
  * Byte decoders (compression) use output caps; a stream that expands past the cap is refused, never
    truncated and presented as complete.
  * Key-based attacks (XOR, ROT) are leaf checks: they look for flag text and never expand further,
    which keeps the search bounded.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import gzip
import html
import lzma
import re
import zlib
from urllib.parse import unquote

B64 = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
B32 = re.compile(r"[A-Z2-7]{8,}={0,6}")
HEX = re.compile(r"(?:[0-9a-fA-F]{2}){4,}")
BIN = re.compile(r"(?:[01]{8})+")


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (9, 10, 13))
    return ok / len(data)


FILE_MAGICS = (b"PK\x03\x04", b"%PDF-", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a",
               b"BM", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07")


def useful(data: bytes) -> bool:
    """Keep a decoded output if it is text-like, starts like a compressed stream, or starts with a known
    file signature (so archives and images inside a payload can be inspected)."""
    if any(data.startswith(m) for m in FILE_MAGICS) or data[:1] == b"x":
        return True
    return printable_ratio(data) >= 0.7


def decode_base64(text: str):
    if not B64.fullmatch(text) or len(text.rstrip("=")) % 4 == 1:
        return []
    padded = text + "=" * (-len(text) % 4)
    try:
        out = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return []
    return [("base64", {}, out)] if useful(out) else []


def decode_base32(text: str):
    if not B32.fullmatch(text):
        return []
    padded = text + "=" * (-len(text) % 8)
    try:
        out = base64.b32decode(padded)
    except (binascii.Error, ValueError):
        return []
    return [("base32", {}, out)] if useful(out) else []


def decode_hex(text: str):
    if not HEX.fullmatch(text):
        return []
    out = bytes.fromhex(text)
    return [("hex", {}, out)] if useful(out) else []


def decode_binary(text: str):
    if not BIN.fullmatch(text):
        return []
    out = bytes(int(text[i:i + 8], 2) for i in range(0, len(text), 8))
    return [("binary", {}, out)] if useful(out) else []


def decode_url(text: str):
    if "%" not in text:
        return []
    out = unquote(text).encode("utf-8", errors="replace")
    return [("url", {}, out)] if out != text.encode("utf-8", errors="replace") else []


def decode_html_entities(text: str):
    if "&" not in text or ";" not in text:
        return []
    out = html.unescape(text).encode("utf-8", errors="replace")
    return [("html_entities", {}, out)] if out != text.encode("utf-8", errors="replace") else []


def _bounded(decompressor_call, cap: int):
    try:
        out = decompressor_call(cap + 1)
    except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError):
        return None
    if len(out) > cap:
        return "too_large"
    return out


def decode_compression(data: bytes, cap: int):
    """zlib, gzip, bzip2, xz/lzma. Output capped; oversize is reported as a warning by the caller."""
    results, warnings = [], []
    if data[:2] == b"\x1f\x8b":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = _bounded(lambda n: d.decompress(data, n), cap)
        name = "gzip"
    elif data[:1] == b"x" and len(data) > 2 and (data[0] * 256 + data[1]) % 31 == 0:
        d = zlib.decompressobj()
        out = _bounded(lambda n: d.decompress(data, n), cap)
        name = "zlib"
    elif data[:3] == b"BZh":
        d = bz2.BZ2Decompressor()
        out = _bounded(lambda n: d.decompress(data, n), cap)
        name = "bzip2"
    elif data[:6] == b"\xfd7zXZ\x00":
        d = lzma.LZMADecompressor()
        out = _bounded(lambda n: d.decompress(data, n), cap)
        name = "xz"
    else:
        return results, warnings
    if out == "too_large":
        warnings.append(f"{name} output exceeds the {cap}-byte cap; not expanded")
    elif out is not None and useful(out):
        results.append((name, {"max_output": cap}, out))
    return results, warnings


def rot_shift(text: str, k: int) -> str:
    def shift(ch):
        if "a" <= ch <= "z":
            return chr((ord(ch) - 97 + k) % 26 + 97)
        if "A" <= ch <= "Z":
            return chr((ord(ch) - 65 + k) % 26 + 65)
        return ch
    return "".join(shift(c) for c in text)


def rot_variants(text: str):
    """All Caesar shifts 1..25 (ROT13 is shift 13). Yields (shift, decoded_text)."""
    for k in range(1, 26):
        yield k, rot_shift(text, k)


def xor_known_prefix(data: bytes, prefixes, max_len: int = 4096):
    """Known-plaintext single-byte XOR: find keys for which a configured prefix appears in the data.

    For each position i and prefix P, key = data[i] ^ P[0]; the key is accepted only when every prefix byte
    matches. This is a leaf check: it returns (prefix, key, decoded_bytes) and never expands further.
    """
    if len(data) > max_len:
        return []
    found = []
    n = len(data)
    seen = set()
    for p in prefixes:
        pb = p.encode("ascii")
        L = len(pb)
        for i in range(0, n - L + 1):
            key = data[i] ^ pb[0]
            if key == 0 or (p, key) in seen:
                continue
            if all((data[i + j] ^ key) == pb[j] for j in range(L)):
                seen.add((p, key))
                found.append((p, key, bytes(b ^ key for b in data)))
    return found
