"""Scan pipeline: validate -> workspace -> hash -> read-only copy -> analyzers -> verify -> reports.

Every step emits a structured event after it finishes, or when it fails. Events go to the
optional on_event callback (for the GUI console) and are stored in the report's execution log.

An analyzer crash is recorded and the scan continues. The original file is re-hashed at the
end, and a mismatch aborts the scan.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from imagehunter.core.status import CANCELLED, ERROR, SKIPPED, classify
from imagehunter import __version__
from imagehunter.analyzers import default_analyzers
from imagehunter.analyzers.base import AnalyzerContext
from imagehunter.config.settings import Settings, load_settings
from imagehunter.core.events import EventRecorder
from imagehunter.core.validation import validate_input
from imagehunter.core.workspace import Workspace
from imagehunter.models.artifact import Artifact
from imagehunter.models.scan import ScanSummary
from imagehunter.services.evidence_service import make_readonly_copy, verify_unchanged
from imagehunter.services.hash_service import sha256_file
from imagehunter.core.planner import plan_investigation
from imagehunter.core.investigation import run_followup_investigation
from imagehunter.services.evidence_graph import build_graph
from imagehunter.services.report_service import write_reports

log = logging.getLogger("imagehunter.pipeline")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_scan(input_path, settings: Settings | None = None, workspace_base=None, analyzers=None,
             on_event=None, verifications: dict[str, str] | None = None, cancel_event=None) -> ScanSummary:
    settings = settings or load_settings()
    analyzers = analyzers if analyzers is not None else default_analyzers()
    rec = EventRecorder(on_event)
    started = _now()
    total = len(analyzers) + 4          # hash, copy, integrity, reports
    done = 0

    def pct() -> int:
        return min(100, int(100 * done / total))

    rec.emit("INFO", "engine", "Initialize", f"Initializing CipherSight forensic engine v{__version__}",
             status="running", percent=0)
    name = str(input_path).replace("\\", "/").rsplit("/", 1)[-1]
    rec.emit("INFO", "input", "Validate", f"Loading target: {name}", status="running", percent=0)
    try:
        src = validate_input(input_path, settings.max_input_bytes)
    except Exception as exc:
        rec.emit("ERROR", "input", "Validate", f"Validation failed: {exc}", status="error", percent=0)
        raise
    rec.emit("SUCCESS", "input", "Validate", "Target accepted", status="ok", percent=0)

    ws = Workspace.create(workspace_base or settings.workspace_root)
    rec.emit("INFO", "workspace", "Create workspace", f"Scan folder {ws.scan_id}", status="ok", percent=0)
    log.info("scan_started", extra={"fields": {"scan_id": ws.scan_id, "input": str(src)}})

    rec.emit("INFO", "hash", "SHA-256", "Calculating SHA-256 hash...", status="running", percent=0)
    original_hash = sha256_file(src)
    done += 1
    rec.emit("SUCCESS", "hash", "SHA-256", f"SHA-256 calculation completed: {original_hash}",
             status="ok", percent=pct())

    rec.emit("INFO", "evidence", "Read-only copy", "Creating read-only working copy...",
             status="running", percent=pct())
    working = make_readonly_copy(src, ws.evidence)
    data = working.read_bytes()
    done += 1
    rec.emit("SUCCESS", "evidence", "Read-only copy", "Working copy created and hash-verified",
             status="ok", percent=pct())

    artifact = Artifact(id="A001", role="original", path=str(src), working_path=str(working),
                        sha256=original_hash, size=len(data))
    plan = plan_investigation(data, str(src), settings)
    settings = plan.settings
    rec.emit("INFO", "planner", "Investigation plan",
             f"mode {plan.mode_requested} -> {plan.mode_applied}; " + "; ".join(plan.decisions),
             status="ok", percent=pct())
    ctx = AnalyzerContext(artifact=artifact, data=data, settings=settings, shared={}, cancel_event=cancel_event)
    started_at_monotonic = time.monotonic()
    stop_reason = None
    analyzers_run = 0

    findings, warnings, statuses, properties = [], [], [], {}
    for analyzer in analyzers:
        if stop_reason is None and cancel_event is not None and cancel_event.is_set():
            stop_reason = "cancelled by user"
        if stop_reason is None and settings.investigation_time_budget_seconds > 0 and \
                time.monotonic() - started_at_monotonic > settings.investigation_time_budget_seconds:
            stop_reason = (f"time budget of {settings.investigation_time_budget_seconds:g} s exhausted")
        if stop_reason is not None:
            not_run = CANCELLED if stop_reason == "cancelled by user" else SKIPPED
            statuses.append({"name": analyzer.name, "status": not_run, "message": stop_reason})
            rec.emit("WARNING", analyzer.name, "Skipped" if not_run == SKIPPED else "Cancelled",
                     f"Not started: {stop_reason}", status="skipped")
            done += 1
            continue
        analyzers_run += 1
        rec.emit("INFO", analyzer.name, "Run analyzer", "Starting analysis...", status="running", percent=pct())
        try:
            result = analyzer.run(ctx)
        except Exception as exc:  # a parser crash must not lose the scan record
            message = f"{type(exc).__name__}: {exc}"
            log.error("analyzer_failed", extra={"fields": {"scan_id": ws.scan_id,
                                                           "analyzer": analyzer.name, "error": message}})
            statuses.append({"name": analyzer.name, "status": ERROR, "message": message})
            warnings.append(f"{analyzer.name} failed: {message}")
            done += 1
            rec.emit("ERROR", analyzer.name, "Run analyzer", f"Analyzer failed: {message}",
                     status="error", percent=pct())
            continue
        status, status_message = classify(skipped_reason=result.properties.get("skipped"),
                                          findings=len(result.findings), warnings=list(result.warnings))
        statuses.append({"name": analyzer.name, "status": status, "message": status_message})
        properties[analyzer.name] = result.properties
        warnings.extend(result.warnings)
        for f in result.findings:
            f.method = analyzer.name
            f.source_artifact_id = artifact.id
            findings.append(f)
            rec.emit("FINDING", analyzer.name, "Detection",
                     f"{f.kind} [{f.confidence_label}]: {f.description}", status="ok")
        for w in result.warnings:
            rec.emit("WARNING", analyzer.name, "Warning", w, status="warning")
        skipped = result.properties.get("skipped")
        if skipped:
            rec.emit("INFO", analyzer.name, "Skipped", str(skipped), status="skipped")
        done += 1
        if status != SKIPPED:
            count = len(result.findings)
            rec.emit("SUCCESS", analyzer.name, "Run analyzer",
                     f"Completed: {count} finding(s)" if count else "Completed: no findings",
                     status="ok", percent=pct())

    # Evidence-driven follow-up: decoded file signatures and high-confidence appended
    # payloads enqueue bounded derived-artifact tasks. The original artifact remains read-only.
    followup = {"artifacts": [], "analyzers": [], "warnings": [], "tasks_processed": 0,
                "bytes_processed": 0, "tasks_pending": 0}
    if stop_reason is None:
        def remaining_budget():
            if settings.investigation_time_budget_seconds <= 0:
                return float("inf")
            return settings.investigation_time_budget_seconds - (time.monotonic() - started_at_monotonic)
        try:
            findings_before_followup = len(findings)
            followup = run_followup_investigation(
                root_artifact=artifact, root_data=data, shared=ctx.shared, settings=settings,
                extracted_dir=ws.extracted, existing_findings=findings,
                cancel_event=cancel_event, time_remaining=remaining_budget)
            for finding in findings[findings_before_followup:]:
                rec.emit("FINDING", finding.method or "derived", "Detection",
                         f"{finding.kind} [{finding.confidence_label}]: {finding.description}", status="ok")
            warnings.extend(followup.get("warnings", []))
            for item in followup.get("analyzers", []):
                rec.emit("SUCCESS" if item.get("status") == "ok" else "ERROR",
                         item.get("name", "derived"), "Derived artifact analysis",
                         f"{item.get('artifact_id')}: {item.get('status')}",
                         status="ok" if item.get("status") == "ok" else "error")
        except Exception as exc:
            message = f"follow-up investigation failed: {type(exc).__name__}: {exc}"
            warnings.append(message)
            log.exception("followup_investigation_failed", extra={"fields": {"scan_id": ws.scan_id}})
    else:
        followup["warnings"].append(f"follow-up investigation not started: {stop_reason}")

    for i, f in enumerate(findings, start=1):
        f.id = f"F{i:03d}"

    verify_unchanged(src, original_hash)
    rec.emit("SUCCESS", "integrity", "Verify original", "Original file re-hashed; unchanged",
             status="ok", percent=pct())

    any_error = any(s["status"] == ERROR for s in statuses)
    properties["investigation"] = dict(
        plan.to_dict(), analyzers_run=analyzers_run, stop_reason=stop_reason,
        elapsed_seconds=round(time.monotonic() - started_at_monotonic, 3),
        followup=followup)
    summary = ScanSummary(
        scan_id=ws.scan_id,
        started_at=started,
        finished_at=_now(),
        status=("cancelled" if stop_reason == "cancelled by user"
                else "completed_with_warnings" if (warnings or any_error or stop_reason) else "completed"),
        input=artifact.to_dict(),
        findings=findings,
        properties=properties,
        analyzers=statuses,
        warnings=warnings,
        workspace=str(ws.root),
    )

    rec.emit("INFO", "report", "Generate reports", "Writing JSON and HTML reports...",
             status="running", percent=pct())
    summary.evidence_graph = build_graph(summary.to_dict())
    summary.execution_log = rec.as_dicts()     # the log stored in the reports, up to this step
    try:
        paths = write_reports(summary.to_dict(), ws.reports, verifications)
    except OSError as exc:
        summary.warnings.append(f"report writing failed: {exc}")
        summary.status = "completed_with_warnings"
        rec.emit("ERROR", "report", "Generate reports", f"Report writing failed: {exc}", status="error")
    else:
        done += 1
        rec.emit("SUCCESS", "report", "JSON report", f"JSON report written: {paths['json']}",
                 status="ok", percent=pct())
        rec.emit("SUCCESS", "report", "HTML report", f"HTML report written: {paths['html']}",
                 status="ok", percent=100)
    rec.emit("SUCCESS" if summary.status == "completed" else "WARNING", "scan", "Complete",
             f"Forensic scan finished with status {summary.status}",
             status="ok" if summary.status == "completed" else "warning", percent=100)
    log.info("scan_completed", extra={"fields": {"scan_id": ws.scan_id, "findings": len(findings),
                                                 "status": summary.status}})
    return summary
