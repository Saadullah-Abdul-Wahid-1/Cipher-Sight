"""Synthetic test fixtures with answers decided in advance.

Each sample records where its hidden data was placed when it was built. Tests
compare analyzer output with those recorded facts, never with analyzer output.

    python tests/fixtures/generate.py OUT_DIR   # write samples + ground_truth.json
"""

from __future__ import annotations

import io
import json
import struct
import sys
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Fixture:
    filename: str
    data: bytes
    expect_kinds: set[str]
    expect_offsets: dict[str, int] = field(default_factory=dict)
    extra: dict = field(default_factory=dict)


def _chunk(ctype: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF)


def make_png(pad_comment_to: int | None = None) -> bytes:
    """Valid 1x1 grayscale PNG, optionally padded to an exact length with a tEXt chunk."""
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00")
    parts = [b"\x89PNG\r\n\x1a\n", _chunk(b"IHDR", ihdr)]
    if pad_comment_to is not None:
        base = len(b"".join(parts)) + len(_chunk(b"IDAT", idat)) + len(_chunk(b"IEND", b""))
        keyword = b"Comment"
        text_len = pad_comment_to - base - (12 + len(keyword) + 1)
        if text_len < 0:
            raise ValueError("pad_comment_to too small")
        parts.append(_chunk(b"tEXt", keyword + b"\x00" + b"x" * text_len))
    parts += [_chunk(b"IDAT", idat), _chunk(b"IEND", b"")]
    return b"".join(parts)


def make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def make_jpeg_structure() -> bytes:
    """Marker-only JPEG (SOI, APP0, SOF0, SOS, scan, EOI). Synthetic: not decodable."""
    soi = b"\xff\xd8"
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    sof0 = b"\xff\xc0" + struct.pack(">H", 11) + b"\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    sos = b"\xff\xda" + struct.pack(">H", 8) + b"\x01\x01\x00\x00\x3f\x00"
    return soi + app0 + sof0 + sos + b"\x12\x34\x56" + b"\xff\xd9"


def make_bmp_structure() -> bytes:
    """1x1 24-bit BMP with a correct declared file size."""
    pixel_row = b"\x00\x00\x00\x00"
    dib = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, len(pixel_row), 0, 0, 0, 0)
    total = 14 + len(dib) + len(pixel_row)
    header = b"BM" + struct.pack("<IHHI", total, 0, 0, 14 + len(dib))
    data = header + dib + pixel_row
    assert len(data) == total
    return data


def make_real_samples() -> dict[str, bytes]:
    """Real files written by Pillow, for identity checks (dimensions, mode, frames)."""
    from PIL import Image

    out = {}
    rgb = Image.new("RGB", (8, 6), (200, 40, 90))
    buf = io.BytesIO(); rgb.save(buf, format="JPEG", quality=90); out["real.jpg"] = buf.getvalue()
    buf = io.BytesIO(); rgb.save(buf, format="BMP"); out["real.bmp"] = buf.getvalue()
    frames = [Image.new("L", (4, 4), v) for v in (0, 255)]
    buf = io.BytesIO(); frames[0].save(buf, format="GIF", save_all=True, append_images=frames[1:]); out["anim.gif"] = buf.getvalue()
    return out


def build_fixtures() -> list[Fixture]:
    fixtures: list[Fixture] = []

    fixtures.append(Fixture("clean.png", make_png(), expect_kinds=set()))

    png_102 = make_png(pad_comment_to=102)
    assert len(png_102) == 102, len(png_102)
    hidden_zip = make_zip({"flag.txt": b"CTF{fixture_appended_zip}\n"})
    fixtures.append(Fixture(
        "appended_zip.png", png_102 + hidden_zip,
        expect_kinds={"appended_data", "embedded_zip", "derived_flag_candidate"},
        expect_offsets={"appended_data": 102, "embedded_zip": 102},
        extra={"zip_entries": ["flag.txt"]},
    ))

    fixtures.append(Fixture(
        "renamed_as.jpg", make_png(),
        expect_kinds={"extension_mismatch"},
        expect_offsets={"extension_mismatch": 0},
        extra={"detected_format": "png"},
    ))

    jpeg_base = make_jpeg_structure()
    appended_text = b"hidden: flag{after_eoi_jpeg}\n"
    assert len(appended_text) == 29, len(appended_text)
    fixtures.append(Fixture(
        "appended_text.jpg", jpeg_base + appended_text,
        expect_kinds={"appended_data"},
        expect_offsets={"appended_data": len(jpeg_base)},
        extra={"appended_length": 29},
    ))

    idat_start = 8 + 25                     # signature + IHDR chunk (12 + 13)
    fixtures.append(Fixture(
        "truncated.png", make_png()[: idat_start + 8 + 4],
        expect_kinds={"png_truncated"},
        expect_offsets={"png_truncated": idat_start},
    ))

    bad = bytearray(make_png())
    bad[idat_start + 8] ^= 0xFF
    fixtures.append(Fixture(
        "bad_crc.png", bytes(bad),
        expect_kinds={"png_crc_mismatch"},
        expect_offsets={"png_crc_mismatch": idat_start},
    ))

    bmp = make_bmp_structure()
    bmp_tail = b"tail-secret!!"
    assert len(bmp_tail) == 13
    fixtures.append(Fixture(
        "appended.bmp", bmp + bmp_tail,
        expect_kinds={"appended_data"},
        expect_offsets={"appended_data": len(bmp)},
        extra={"appended_length": 13},
    ))
    return fixtures


def write_fixtures(out_dir: str | Path) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths, manifest = [], {}
    for fx in build_fixtures():
        p = out / fx.filename
        p.write_bytes(fx.data)
        paths.append(p)
        manifest[fx.filename] = {"expect_kinds": sorted(fx.expect_kinds),
                                 "expect_offsets": fx.expect_offsets, "extra": fx.extra}
    (out / "ground_truth.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return paths


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "samples"
    for p in write_fixtures(target):
        print(p)


# ---------------------------------------------------------------- LSB encoder (test fixtures only)
def embed_lsb(arr, channel_index: int, bit: int, traversal: str, bit_order: str,
              payload: bytes, xor_key: int = 0, start_index: int = 0):
    """Write payload into bit plane `bit` of one channel. Mirrors the analyzer's decoder exactly.

    traversal: "row" (left-to-right, top-to-bottom) or "column" (top-to-bottom, left-to-right)
    bit_order: "LSB-first" or "MSB-first" (within each byte)
    start_index: traversal index of the first written bit (must be a multiple of 8 to be decodable)
    """
    import numpy as np

    H, W = arr.shape[0], arr.shape[1]
    data = bytes(b ^ xor_key for b in payload)
    if bit_order == "LSB-first":
        bits = [(b >> j) & 1 for b in data for j in range(8)]
    else:
        bits = [(b >> (7 - j)) & 1 for b in data for j in range(8)]
    idx = np.arange(start_index, start_index + len(bits))
    if traversal == "row":
        ys, xs = np.divmod(idx, W)
    else:
        xs, ys = np.divmod(idx, H)
    mask = np.uint8(255 ^ (1 << bit))
    values = np.array(bits, dtype=np.uint8) << np.uint8(bit)
    arr[ys, xs, channel_index] = (arr[ys, xs, channel_index] & mask) | values
    return arr


def make_noise_rgb(w: int, h: int, seed: int):
    import numpy as np
    return np.random.default_rng(seed).integers(0, 256, size=(h, w, 3), dtype=np.uint8)


import secrets as _secrets

# Test-only flags, generated fresh on every run. No flag value is stored in the repository,
# so release packages contain no hard-coded expected answer.
REAL_FLAG = "THM{" + _secrets.token_hex(6) + "}"
DECOY_FLAG = "THM{" + _secrets.token_hex(6) + "}"


def make_signal_hunt_like(seed: int = 1337, real_flag: str | None = None, decoy_flag: str | None = None) -> bytes:
    """Rebuilds the challenge image layers from the answer key, on a noise base, so tests need no external file.

    Layer A: flag in BLUE LSB, column order, starting at x=37 (index 37*480), LSB-first, XOR 0x37.
    Layer B: decoy in RED LSB, row order, MSB-first, no XOR.
    """
    import numpy as np
    from PIL import Image

    arr = make_noise_rgb(640, 480, seed)
    real = (real_flag or REAL_FLAG).encode("ascii")
    decoy = (decoy_flag or DECOY_FLAG).encode("ascii")
    embed_lsb(arr, 2, 0, "column", "LSB-first", real, xor_key=0x37, start_index=37 * 480)
    embed_lsb(arr, 0, 0, "row", "MSB-first", decoy, xor_key=0, start_index=0)
    buf = io.BytesIO()
    Image.fromarray(arr, "RGB").save(buf, format="PNG")
    return buf.getvalue()


def make_png_with_chunks(extra: list[tuple[bytes, bytes]]) -> bytes:
    """1x1 PNG with extra chunks inserted before IDAT. Used to test metadata parsing."""
    base = make_png()
    ihdr_end = 8 + 12 + 13
    head, tail = base[:ihdr_end], base[ihdr_end:]
    body = b"".join(_chunk(t, d) for t, d in extra)
    return head + body + tail


def make_exif_jpeg(timestamps: dict | None = None, gps: bool = False, software: str | None = None) -> bytes:
    """Real JPEG written by Pillow with EXIF tags, for metadata tests."""
    from PIL import Image

    exif = Image.Exif()
    if timestamps:
        if "DateTime" in timestamps:
            exif[306] = timestamps["DateTime"]
        if "DateTimeOriginal" in timestamps:
            exif[36867] = timestamps["DateTimeOriginal"]
    if software:
        exif[305] = software
    if gps:
        ifd = exif.get_ifd(0x8825)
        ifd[1] = "N"
        ifd[2] = (33.0, 41.0, 0.0)
        ifd[3] = "E"
        ifd[4] = (73.0, 3.0, 0.0)
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), (90, 120, 150)).save(buf, format="JPEG", exif=exif.tobytes())
    return buf.getvalue()


def embed_lsb_interleaved(arr, seq, bit: int, traversal: str, bit_order: str, payload: bytes,
                          xor_key: int = 0, start_index: int = 0):
    """Write payload into interleaved channel streams: for each pixel in traversal order, one bit from each
    channel in `seq`. Mirror of extract_interleaved() + pack_bits(). start_index is a pixel index."""
    import numpy as np

    H, W, _ = arr.shape
    k = len(seq)
    data = bytes(b ^ xor_key for b in payload)
    if bit_order == "LSB-first":
        bits = [(b >> j) & 1 for b in data for j in range(8)]
    else:
        bits = [(b >> (7 - j)) & 1 for b in data for j in range(8)]
    n = len(bits)
    i = np.arange(n)
    pixel = start_index + i // k
    chan = np.asarray(seq)[i % k]
    if traversal == "row":
        ys, xs = np.divmod(pixel, W)
    else:
        xs, ys = np.divmod(pixel, H)
    mask = np.uint8(255 ^ (1 << bit))
    values = np.array(bits, dtype=np.uint8) << np.uint8(bit)
    arr[ys, xs, chan] = (arr[ys, xs, chan] & mask) | values
    return arr
