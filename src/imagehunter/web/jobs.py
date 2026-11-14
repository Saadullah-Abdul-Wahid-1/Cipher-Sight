"""Scan jobs for the web interface.

A job is one uploaded file scanned in a background thread through run_scan(), the same pipeline
the CLI and the desktop window use. Events are stored as they happen, and the browser reads them
with a cursor. Only one scan runs at a time, so the engine is never overloaded by a single machine.
"""

from __future__ import annotations

import secrets
import threading
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from imagehunter.core.events import ScanEvent, utc_ts
from imagehunter.services.evidence_service import sanitize_filename
from imagehunter.services.report_data import build_view

VERIFICATION_DECISIONS = ("confirmed", "rejected", "clear")

MAX_JOB_EVENTS = 5000
MAX_JOBS_KEPT = 50
CHUNK = 256 * 1024


class BusyError(RuntimeError):
    """Another scan is still running."""


class UploadError(ValueError):
    """The upload is empty, incomplete, or larger than the configured limit."""

    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status


class Job:
    def __init__(self, filename: str, path: Path):
        self.id = secrets.token_hex(16)
        self.filename = filename
        self.path = path
        self.created = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.status = "running"            # running | completed | completed_with_warnings | failed
        self.percent = 0
        self.error: str | None = None
        self.summary: dict | None = None
        self.verifications: dict[str, str] = {}   # flag value -> "confirmed" | "rejected"
        self._events: list[dict] = []
        self._truncated = False
        self._lock = threading.Lock()

    @property
    def done(self) -> bool:
        return self.status != "running"

    def add_event(self, event: ScanEvent) -> None:
        with self._lock:
            if len(self._events) >= MAX_JOB_EVENTS:
                self._truncated = True
                return
            self._events.append(event.to_dict())
            if event.percent is not None:
                self.percent = event.percent

    def finish(self, status: str, summary: dict | None = None, error: str | None = None) -> None:
        with self._lock:
            self.status = status
            self.summary = summary
            self.error = error
            if status == "completed":
                self.percent = 100

    def snapshot(self, after: int = 0) -> dict:
        after = max(0, int(after))
        with self._lock:
            total = len(self._events)
            return {
                "id": self.id,
                "filename": self.filename,
                "status": self.status,
                "done": self.done,
                "percent": self.percent,
                "error": self.error,
                "total_events": total,
                "truncated": self._truncated,
                "events": self._events[after:],
            }

    def view(self) -> dict | None:
        """Summary view with this scan's analyst decisions applied. None if there is no summary."""
        with self._lock:
            summary, decisions = self.summary, dict(self.verifications)
        return build_view(summary, decisions) if summary is not None else None

    def brief(self) -> dict:
        with self._lock:
            findings = len(self.summary.get("findings", [])) if self.summary else None
            return {"id": self.id, "filename": self.filename, "status": self.status,
                    "created": self.created, "findings": findings, "error": self.error}


class JobManager:
    def __init__(self, settings, base_dir: str | Path, runner=None):
        from imagehunter.core.pipeline import run_scan
        self.settings = settings
        self.base = Path(base_dir)
        self.uploads = self.base / "uploads"
        self.scans = self.base / "scans"
        self._runner = runner or run_scan
        self._jobs: "OrderedDict[str, Job]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def recent(self, limit: int = 20) -> list[dict]:
        with self._lock:
            jobs = list(self._jobs.values())[::-1][:limit]
        return [j.brief() for j in jobs]

    def all_jobs(self) -> list[Job]:
        """Stored jobs, oldest first."""
        with self._lock:
            return list(self._jobs.values())

    def set_verification(self, job_id: str, value: str, decision: str) -> dict:
        """Record an analyst decision on one flag candidate and return the updated view.

        Raises KeyError for an unknown scan, ValueError for an invalid decision, a value that
        is not a flag of that scan, or a scan that has not finished.
        """
        job = self.get(job_id)
        if job is None:
            raise KeyError("unknown scan")
        if decision not in VERIFICATION_DECISIONS:
            raise ValueError("decision must be confirmed, rejected or clear")
        if not job.done or job.summary is None:
            raise ValueError("scan has not finished")
        flags = build_view(job.summary)["flags"]
        known = {f["value"] for group in ("candidates", "likely_decoys", "confirmed", "rejected")
                 for f in flags[group]}
        if value not in known:
            raise ValueError("that value is not a flag found in this scan")
        with job._lock:
            if decision == "clear":
                job.verifications.pop(value, None)
            else:
                job.verifications[value] = decision
        return job.view()

    def busy(self) -> bool:
        with self._lock:
            return any(not j.done for j in self._jobs.values())

    def submit(self, raw_name: str, stream, declared_length: int | None) -> Job:
        """Store the upload and start a scan. Raises UploadError or BusyError before anything runs."""
        if declared_length is None:
            raise UploadError("Content-Length is required", 411)
        if declared_length <= 0:
            raise UploadError("the uploaded file is empty", 400)
        if declared_length > self.settings.max_input_bytes:
            raise UploadError(f"file is {declared_length} bytes; the limit is "
                              f"{self.settings.max_input_bytes} bytes", 413)

        safe = sanitize_filename(raw_name or "upload.bin")
        with self._lock:
            if any(not j.done for j in self._jobs.values()):
                raise BusyError("another scan is running")
            job_dir = self.uploads / secrets.token_hex(16)
            job_dir.mkdir(parents=True, exist_ok=False)
            dest = job_dir / safe
            job = Job(safe, dest)
            self._jobs[job.id] = job                     # reserved: blocks other submissions
            while len(self._jobs) > MAX_JOBS_KEPT:
                self._jobs.popitem(last=False)

        received = 0
        try:
            with open(dest, "wb") as fh:
                remaining = declared_length
                while remaining > 0:
                    chunk = stream.read(min(CHUNK, remaining))
                    if not chunk:
                        break
                    fh.write(chunk)
                    received += len(chunk)
                    remaining -= len(chunk)
        except OSError:
            self._drop(job)
            raise
        if received != declared_length:
            self._drop(job)
            raise UploadError("upload ended before the declared length", 400)

        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def _drop(self, job: Job) -> None:
        with self._lock:
            self._jobs.pop(job.id, None)
        try:
            for p in sorted(job.path.parent.glob("*"), reverse=True):
                p.unlink(missing_ok=True)
            job.path.parent.rmdir()
        except OSError:
            pass

    def _run(self, job: Job) -> None:
        try:
            summary = self._runner(job.path, settings=self.settings,
                                   workspace_base=self.scans, on_event=job.add_event)
            data = summary.to_dict()
            job.finish(data["status"], summary=data)
        except Exception as exc:  # a failed scan is reported to the browser, never swallowed
            message = f"{type(exc).__name__}: {exc}"
            job.add_event(ScanEvent(utc_ts(), "ERROR", "web", "Scan failed", message, "error", None))
            job.finish("failed", error=message)

