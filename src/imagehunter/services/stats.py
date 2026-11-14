"""Dashboard statistics computed from stored scan results.

Every number comes from build_view() output for scans that actually ran. Nothing is
estimated, cached across restarts, or invented for display.
"""

from __future__ import annotations

COMPLETED = ("completed", "completed_with_warnings")


def aggregate(entries: list[dict]) -> dict:
    """entries: [{"status": str, "view": dict | None}] one per stored scan.

    status is the job status ("running", "completed", "completed_with_warnings", "failed"...).
    view is build_view() output, or None when the scan produced no summary.
    """
    total = len(entries)
    completed = [e for e in entries if e["status"] in COMPLETED and e.get("view")]
    views = [e["view"] for e in completed]
    hashes = {v["sha256"] for v in views if v.get("sha256")}
    durations = [v["metrics"]["duration_seconds"] for v in views
                 if v["metrics"].get("duration_seconds") is not None]

    def total_of(key: str) -> int:
        return sum(v["metrics"].get(key, 0) or 0 for v in views)

    return {
        "total_scans": total,
        "completed_scans": len(completed),
        "failed_scans": sum(1 for e in entries if e["status"] == "failed"),
        "running_scans": sum(1 for e in entries if e["status"] == "running"),
        "images_analyzed": len(hashes),
        "confirmed_flags": total_of("confirmed_flags"),
        "flag_candidates": total_of("flag_candidates"),
        "likely_decoy_flags": total_of("likely_decoy_flags"),
        "embedded_items": total_of("embedded_items"),
        "warnings": total_of("warnings"),
        "errors": total_of("errors"),
        "average_duration_seconds": round(sum(durations) / len(durations), 3) if durations else None,
        "last_duration_seconds": durations[-1] if durations else None,
    }
