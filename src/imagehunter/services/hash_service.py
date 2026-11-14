"""SHA-256 helpers. Files are only ever opened read-only here."""

from __future__ import annotations

import hashlib
import os

_CHUNK = 1024 * 1024


def sha256_file(path: str | os.PathLike) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
