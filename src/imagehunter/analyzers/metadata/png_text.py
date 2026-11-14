"""PNG textual and profile chunks: tEXt, zTXt, iTXt, iCCP.

Every record keeps the chunk offset, so each value can be traced to its exact location.
Compressed data is inflated with an output cap, so a decompression bomb cannot exhaust memory.
Parsing never trusts declared lengths beyond the file size.
"""

from __future__ import annotations

import re
import struct
import zlib
from dataclasses import dataclass

PNG_SIG = b"\x89PNG\r\n\x1a\n"
XMP_KEYWORD = b"XML:com.adobe.xmp"


@dataclass
class TextRecord:
    chunk: str
    offset: int
    keyword: str
    text: str
    compressed: bool
    raw_bytes: bytes         # the value as bytes, for flag searching
    length: int


class InflateError(ValueError):
    def __init__(self, message: str, too_large: bool = False):
        super().__init__(message)
        self.too_large = too_large


def inflate_capped(blob: bytes, cap: int) -> bytes:
    d = zlib.decompressobj()
    try:
        out = d.decompress(blob, cap + 1)
    except zlib.error as exc:
        raise InflateError(f"zlib data is invalid: {exc}") from exc
    if len(out) > cap:
        raise InflateError(f"decompressed data exceeds the {cap}-byte cap", too_large=True)
    return out


def _latin(b: bytes) -> str:
    return b.decode("latin-1")


def walk_png_chunks(data: bytes):
    """Yield (type, offset, body) for each chunk, stopping at IEND or at a malformed length."""
    if not data.startswith(PNG_SIG):
        return
    pos = len(PNG_SIG)
    n = len(data)
    while pos + 8 <= n:
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        end = pos + 8 + length
        if end + 4 > n:
            return
        yield ctype.decode("latin-1"), pos, data[pos + 8:end]
        if ctype == b"IEND":
            return
        pos = end + 4


def parse_png_text(data: bytes, cap: int):
    """Return (records, info, warnings, oversized). oversized lists chunks whose data exceeds the cap."""
    records: list[TextRecord] = []
    info: dict = {"icc_profile": None}
    warnings: list[str] = []
    oversized: list[dict] = []
    for ctype, off, body in walk_png_chunks(data):
        if ctype == "tEXt":
            k, _, v = body.partition(b"\x00")
            if len(v) > cap:
                oversized.append({"chunk": "tEXt", "offset": off, "keyword": _latin(k), "size": len(v)})
                continue
            records.append(TextRecord("tEXt", off, _latin(k), _latin(v), False, v, len(v)))
        elif ctype == "zTXt":
            k, _, rest = body.partition(b"\x00")
            try:
                v = inflate_capped(rest[1:], cap)          # rest[0] is the compression method
            except InflateError as exc:
                if exc.too_large:
                    oversized.append({"chunk": "zTXt", "offset": off, "keyword": _latin(k)})
                else:
                    warnings.append(f"zTXt at offset {off}: {exc}")
                continue
            records.append(TextRecord("zTXt", off, _latin(k), v.decode("latin-1"), True, v, len(v)))
        elif ctype == "iTXt":
            k, _, rest = body.partition(b"\x00")
            if len(rest) < 2:
                warnings.append(f"iTXt at offset {off}: header incomplete")
                continue
            compressed = rest[0] == 1
            rest = rest[2:]
            _, _, rest = rest.partition(b"\x00")         # language tag
            _, _, rest = rest.partition(b"\x00")         # translated keyword
            if not compressed and len(rest) > cap:
                oversized.append({"chunk": "iTXt", "offset": off, "keyword": _latin(k), "size": len(rest)})
                continue
            try:
                v = inflate_capped(rest, cap) if compressed else rest
            except InflateError as exc:
                if exc.too_large:
                    oversized.append({"chunk": "iTXt", "offset": off, "keyword": _latin(k)})
                else:
                    warnings.append(f"iTXt at offset {off}: {exc}")
                continue
            records.append(TextRecord("iTXt", off, _latin(k), v.decode("utf-8", errors="replace"),
                                      compressed, v, len(v)))
        elif ctype == "iCCP":
            name, _, rest = body.partition(b"\x00")
            try:
                profile = inflate_capped(rest[1:], cap)
                info["icc_profile"] = {"name": _latin(name), "offset": off, "size": len(profile)}
            except InflateError as exc:
                warnings.append(f"iCCP at offset {off}: {exc}")
    return records, info, warnings, oversized


_XMP_FIELDS = {
    "creator_tool": re.compile(rb"CreatorTool[^>]*>([^<]{1,200})<"),
    "create_date": re.compile(rb"CreateDate[^>]*>([^<]{1,64})<"),
    "modify_date": re.compile(rb"ModifyDate[^>]*>([^<]{1,64})<"),
}


def xmp_summary(record: TextRecord) -> dict:
    """Pull a few known fields out of an XMP packet without an XML parser (no entity expansion risk)."""
    out = {"packet_bytes": record.length, "offset": record.offset}
    for name, rx in _XMP_FIELDS.items():
        m = rx.search(record.raw_bytes)
        if m:
            out[name] = m.group(1).decode("utf-8", errors="replace")
    out["contains_doctype"] = b"<!DOCTYPE" in record.raw_bytes or b"<!ENTITY" in record.raw_bytes
    return out
