"""File signatures (magic bytes) and extension rules."""

from __future__ import annotations

HEADER_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("gif", b"GIF87a"),
    ("gif", b"GIF89a"),
    ("bmp", b"BM"),
    ("tiff", b"II*\x00"),
    ("tiff", b"MM\x00*"),
    ("zip", b"PK\x03\x04"),
    ("gzip", b"\x1f\x8b\x08"),
    ("pdf", b"%PDF-"),
    ("rar", b"Rar!\x1a\x07"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
)

EMBEDDED_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("zip", b"PK\x03\x04"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("gif", b"GIF89a"),
    ("gif", b"GIF87a"),
    ("gzip", b"\x1f\x8b\x08"),
    ("pdf", b"%PDF-"),
    ("rar", b"Rar!\x1a\x07"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
)

IMAGE_EXTENSIONS: dict[str, str] = {
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".bmp": "bmp",
    ".gif": "gif",
    ".tif": "tiff",
    ".tiff": "tiff",
    ".webp": "webp",
}


def detect_format(head: bytes) -> str | None:
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    if len(head) >= 3 and head[:3] == b"\x1f\x8b\x08":
        return "gzip"
    # RIFF/WEBP is a compound signature, not a prefix-only signature.
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    for name, sig in HEADER_SIGNATURES:
        if head.startswith(sig):
            return name
    return None
