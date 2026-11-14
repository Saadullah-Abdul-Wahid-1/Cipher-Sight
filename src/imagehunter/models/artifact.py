"""An artifact is the original input or a file derived from it (parent link required)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

ROLES = ("original", "derived")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Artifact:
    id: str
    role: str
    path: str                 # where the user supplied it (or the derived file's location)
    working_path: str         # read-only copy used for analysis
    sha256: str
    size: int
    parent_id: str | None = None
    origin: str = "input file"
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self):
        if self.role not in ROLES:
            raise ValueError(f"invalid artifact role: {self.role}")
        if self.role == "derived" and not self.parent_id:
            raise ValueError("derived artifacts must reference a parent_id")

    def to_dict(self) -> dict:
        return asdict(self)
