"""Per-scan workspace. Every scan gets its own directory; outputs never mix."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SUBDIRS = ("evidence", "extracted", "temporary", "reports")


@dataclass(frozen=True)
class Workspace:
    scan_id: str
    root: Path

    @property
    def evidence(self) -> Path:
        return self.root / "evidence"

    @property
    def extracted(self) -> Path:
        return self.root / "extracted"

    @property
    def temporary(self) -> Path:
        return self.root / "temporary"

    @property
    def reports(self) -> Path:
        return self.root / "reports"

    @classmethod
    def create(cls, base: str | Path) -> "Workspace":
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        scan_id = f"{stamp}-{uuid.uuid4().hex[:8]}"
        root = Path(base) / scan_id
        for sub in SUBDIRS:
            (root / sub).mkdir(parents=True, exist_ok=False)
        return cls(scan_id=scan_id, root=root.resolve())
