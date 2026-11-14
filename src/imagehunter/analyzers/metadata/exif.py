"""EXIF and GPS through Pillow. Returns plain values with the tag names, nothing is transmitted."""

from __future__ import annotations

import io

TIMESTAMP_TAGS = {306: "DateTime", 36867: "DateTimeOriginal", 36868: "DateTimeDigitized"}
TEXT_TAGS = {270: "ImageDescription", 271: "Make", 272: "Model", 305: "Software", 37510: "UserComment",
             315: "Artist", 33432: "Copyright"}
GPS_IFD = 0x8825


def _text(v):
    if isinstance(v, bytes):
        return v[:300].decode("utf-8", errors="replace")
    return str(v)[:300]


def read_exif(data: bytes) -> dict:
    from PIL import ExifTags, Image

    out = {"present": False, "fields": {}, "timestamps": {}, "gps": None, "warnings": []}
    try:
        with Image.open(io.BytesIO(data)) as img:
            exif = img.getexif()
            if not exif:
                return out
            out["present"] = True
            names = ExifTags.TAGS
            for tag, value in exif.items():
                if tag in TIMESTAMP_TAGS:
                    out["timestamps"][TIMESTAMP_TAGS[tag]] = _text(value)
                elif tag in TEXT_TAGS:
                    out["fields"][TEXT_TAGS[tag]] = _text(value)
                elif tag not in (GPS_IFD,):
                    out["fields"][names.get(tag, f"tag_{tag}")] = _text(value)[:120]
            gps = exif.get_ifd(GPS_IFD) if GPS_IFD in exif else None
            if gps:
                out["gps"] = {names.get(k, f"gps_{k}"): _text(v) for k, v in gps.items()}
    except Exception as exc:  # unreadable EXIF is a warning, never a crash
        out["warnings"].append(f"EXIF could not be read: {type(exc).__name__}: {exc}")
    return out


def timestamp_conflicts(timestamps: dict) -> list[tuple[str, str, str, str]]:
    """Return pairs of timestamp fields that disagree. Equal strings are not conflicts."""
    names = list(timestamps)
    conflicts = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            if timestamps[a] != timestamps[b]:
                conflicts.append((a, timestamps[a], b, timestamps[b]))
    return conflicts
