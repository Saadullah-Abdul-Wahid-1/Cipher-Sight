"""Console data model for the live scan panel. No GUI toolkit imports, so it is unit-tested directly.

Keeps every event (up to max_entries) even while the display is paused, so nothing is lost
when the display resumes. Filtering and search apply to the displayed view and to exports.
"""

from __future__ import annotations

from collections import deque

from imagehunter.core.events import LEVELS


class ConsoleModel:
    def __init__(self, max_entries: int = 5000):
        self._entries: deque[dict] = deque(maxlen=max_entries)
        self.dropped = 0
        self._max = max_entries

    def add(self, event: dict) -> None:
        if len(self._entries) == self._max:
            self.dropped += 1
        self._entries.append(dict(event))

    def __len__(self) -> int:
        return len(self._entries)

    def entries(self) -> list[dict]:
        return list(self._entries)

    def clear(self) -> None:
        self._entries.clear()
        self.dropped = 0

    @staticmethod
    def format_line(e: dict) -> str:
        ts = str(e.get("ts", ""))
        clock = ts[11:23] if len(ts) >= 23 else ts      # HH:MM:SS.mmm
        pct = f" ({e['percent']}%)" if e.get("percent") is not None else ""
        return (f"[{clock}] [{e.get('level', '?')}] [{e.get('module', '?')}] "
                f"{e.get('operation', '')}: {e.get('message', '')}{pct}")

    def visible(self, levels: set[str] | None = None, query: str = "") -> list[dict]:
        allowed = set(LEVELS) if levels is None else set(levels)
        q = (query or "").strip().lower()
        out = []
        for e in self._entries:
            if e.get("level") not in allowed:
                continue
            if q and q not in self.format_line(e).lower():
                continue
            out.append(e)
        return out

    def export_text(self, levels: set[str] | None = None, query: str = "") -> str:
        lines = [self.format_line(e) for e in self.visible(levels, query)]
        return "\n".join(lines) + ("\n" if lines else "")

    def export_txt(self, path, levels: set[str] | None = None, query: str = "") -> int:
        text = self.export_text(levels, query)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return text.count("\n")
