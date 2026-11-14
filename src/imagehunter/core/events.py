"""Structured scan events. The pipeline emits them; the console and the report consume them.

An event is recorded only after the operation it describes has finished (for success
messages) or has failed (for error messages). Nothing here is timer-driven or simulated.
"""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable

LEVELS = ("DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "FINDING")
STATUSES = ("running", "ok", "warning", "error", "skipped", "info")


@dataclass(frozen=True)
class ScanEvent:
    ts: str
    level: str
    module: str
    operation: str
    message: str
    status: str = "info"
    percent: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def utc_ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class EventRecorder:
    """Keeps every event in order and forwards it to an optional sink (for example a GUI queue).

    Thread-safe: the pipeline runs in a worker thread and the sink may be read from another.
    """

    def __init__(self, sink: Callable[[ScanEvent], None] | None = None):
        self._sink = sink
        self._events: list[ScanEvent] = []
        self._lock = threading.Lock()

    def emit(self, level: str, module: str, operation: str, message: str,
             status: str = "info", percent: int | None = None) -> ScanEvent:
        if level not in LEVELS:
            raise ValueError(f"unknown level {level!r}")
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}")
        event = ScanEvent(utc_ts(), level, module, operation, message, status, percent)
        with self._lock:
            self._events.append(event)
        if self._sink is not None:
            try:
                self._sink(event)
            except Exception:  # a broken GUI sink must never stop the scan
                pass
        return event

    def as_dicts(self) -> list[dict]:
        with self._lock:
            return [e.to_dict() for e in self._events]
