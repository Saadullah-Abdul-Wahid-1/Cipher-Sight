"""Structural parsers for PNG, JPEG and BMP. Walk the structure; never decode pixels.

Each parser returns (findings, end_offset). end_offset is where the format's own
data ends, or None if the structure is incomplete.
"""

from __future__ import annotations

import struct
import zlib

from imagehunter.models.finding import Finding

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _f(kind, label, description, offset=None, length=None, **evidence) -> Finding:
    return Finding(kind=kind, category="structure", description=description,
                   confidence_label=label, offset=offset, length=length, evidence=evidence)


def _be32(b: bytes) -> int:
    return struct.unpack(">I", b)[0]


def _be16(b: bytes) -> int:
    return struct.unpack(">H", b)[0]


def parse_png(data: bytes) -> tuple[list[Finding], int | None]:
    findings: list[Finding] = []
    n = len(data)
    pos = len(PNG_SIGNATURE)
    while True:
        if pos + 8 > n:
            findings.append(_f("png_truncated", "Medium",
                               "PNG ends before IEND: chunk header is incomplete", pos, n - pos))
            return findings, None
        length = _be32(data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        name = ctype.decode("latin-1")
        data_end = pos + 8 + length
        crc_end = data_end + 4
        if crc_end > n:
            findings.append(_f("png_truncated", "Medium",
                               f"PNG chunk {name} declares {length} bytes but the file ends early",
                               pos, n - pos, chunk=name, declared_length=length))
            return findings, None
        stored = _be32(data[data_end:crc_end])
        actual = zlib.crc32(ctype + data[pos + 8:data_end]) & 0xFFFFFFFF
        if stored != actual:
            findings.append(_f("png_crc_mismatch", "Medium", f"CRC mismatch in PNG chunk {name}",
                               pos, crc_end - pos, chunk=name,
                               stored_crc=f"{stored:08x}", actual_crc=f"{actual:08x}"))
        if ctype == b"IEND":
            return findings, crc_end
        pos = crc_end


def parse_jpeg(data: bytes) -> tuple[list[Finding], int | None]:
    findings: list[Finding] = []
    n = len(data)
    pos = 2  # skip SOI
    while True:
        if pos + 2 > n:
            findings.append(_f("jpeg_truncated", "Medium", "JPEG ends before EOI marker", pos, n - pos))
            return findings, None
        if data[pos] != 0xFF:
            findings.append(_f("jpeg_malformed", "Medium", "expected a JPEG marker here", pos))
            return findings, None
        marker = data[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker == 0xD9:
            return findings, pos + 2
        if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if pos + 4 > n:
            findings.append(_f("jpeg_truncated", "Medium", "JPEG segment header cut off", pos, n - pos))
            return findings, None
        seg_len = _be16(data[pos + 2:pos + 4])
        seg_end = pos + 2 + seg_len
        if seg_len < 2 or seg_end > n:
            findings.append(_f("jpeg_truncated", "Medium",
                               f"JPEG segment 0x{marker:02X} has an invalid length or runs past end of file",
                               pos, n - pos))
            return findings, None
        if marker == 0xDA:
            pos = _skip_scan(data, seg_end)
            if pos is None:
                findings.append(_f("jpeg_truncated", "Medium",
                                   "JPEG scan data runs to end of file without EOI", seg_end, n - seg_end))
                return findings, None
        else:
            pos = seg_end


def _skip_scan(data: bytes, start: int) -> int | None:
    i = start
    n = len(data)
    while True:
        j = data.find(b"\xff", i)
        if j < 0 or j + 1 >= n:
            return None
        nxt = data[j + 1]
        if nxt == 0x00 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
            i = j + 1
            continue
        return j


def parse_bmp(data: bytes) -> tuple[list[Finding], int | None]:
    findings: list[Finding] = []
    if len(data) < 6:
        findings.append(_f("bmp_truncated", "Medium", "BMP header is incomplete"))
        return findings, None
    declared = struct.unpack("<I", data[2:6])[0]
    if declared < 14 or declared > 2**31:
        findings.append(_f("bmp_malformed", "Medium", f"BMP declares an implausible file size ({declared})", 2, 4))
        return findings, None
    if len(data) < declared:
        findings.append(_f("bmp_truncated", "Medium",
                           f"BMP declares {declared} bytes but the file has {len(data)}",
                           len(data), declared - len(data), declared_size=declared))
        return findings, None
    return findings, declared
