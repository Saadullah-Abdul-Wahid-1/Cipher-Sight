"""Evidence handling: the original input is never modified.

Analysis runs on a read-only working copy in the scan's evidence folder. The
copy's hash must match the original, and the original is re-checked at the end
of the scan.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from pathlib import Path

from imagehunter.services.hash_service import sha256_file

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


class EvidenceError(RuntimeError):
    """The evidence copy or the original cannot be trusted."""


def sanitize_filename(name: str, max_len: int = 120) -> str:
    base = os.path.basename(name.replace("\\", "/"))
    cleaned = _UNSAFE.sub("_", base).strip("._") or "file"
    return cleaned[:max_len]


def make_readonly_copy(source: str | os.PathLike, dest_dir: str | os.PathLike) -> Path:
    source = Path(source)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / sanitize_filename(source.name)

    original_hash = sha256_file(source)
    shutil.copyfile(source, dest)
    if sha256_file(dest) != original_hash:
        dest.unlink(missing_ok=True)
        raise EvidenceError("hash mismatch between original and working copy")
    dest.chmod(stat.S_IREAD)  # best effort; Windows honours only the read-only flag
    return dest


def verify_unchanged(original: str | os.PathLike, expected_hash: str) -> None:
    if sha256_file(original) != expected_hash:
        raise EvidenceError("original file changed during analysis")
