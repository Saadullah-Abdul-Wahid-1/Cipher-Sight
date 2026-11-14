"""Input validation before any analysis happens."""

from __future__ import annotations

import os
from pathlib import Path


class ValidationError(ValueError):
    """The input cannot be analysed (missing, not a file, empty, too large, unreadable)."""


def validate_input(path: str | os.PathLike, max_bytes: int) -> Path:
    p = Path(path)
    if not p.exists():
        raise ValidationError(f"file not found: {p}")
    if not p.is_file():
        raise ValidationError(f"not a regular file: {p}")
    size = p.stat().st_size
    if size == 0:
        raise ValidationError("file is empty")
    if size > max_bytes:
        raise ValidationError(f"file is {size} bytes; the limit is {max_bytes} bytes")
    if not os.access(p, os.R_OK):
        raise ValidationError(f"file is not readable: {p}")
    return p.resolve()
