"""A Finding is one observation with its location and an explainable confidence label.

confidence_label is a triage hint, not proof. High means the structure is objectively
present. It never means a flag is valid.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from imagehunter.models.artifact import utc_now

CONFIDENCE_LABELS = ("High", "Medium", "Low")


@dataclass
class Finding:
    kind: str                       # stable machine code, e.g. "appended_data"
    category: str                   # identity | structure | embedded | ...
    description: str
    confidence_label: str
    title: str = ""
    offset: int | None = None
    length: int | None = None
    evidence: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    id: str = ""                    # assigned by the pipeline
    source_artifact_id: str = ""    # assigned by the pipeline
    method: str = ""                # analyzer name, assigned by the pipeline
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self):
        if self.confidence_label not in CONFIDENCE_LABELS:
            raise ValueError(f"invalid confidence_label: {self.confidence_label!r}")
        if not self.title:
            self.title = self.kind.replace("_", " ").capitalize()

    def to_dict(self) -> dict:
        return asdict(self)
