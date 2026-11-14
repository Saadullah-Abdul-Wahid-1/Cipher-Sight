"""Analyzer status vocabulary and classification.

Every analyzer run ends in exactly one of these states. Only the first three count
as "executed"; a skipped, failed or cancelled analyzer never counts as a success.

    PASS       completed, no evidence found
    FINDINGS   completed and produced at least one finding
    PARTIAL    completed, but with stated limitations (warnings)
    SKIPPED    not performed; the reason is recorded in the message
    ERROR      raised an exception
    CANCELLED  stopped by the user before or during its run
"""

from __future__ import annotations

PASS = "pass"
FINDINGS = "findings"
PARTIAL = "partial"
SKIPPED = "skipped"
ERROR = "error"
CANCELLED = "cancelled"

ALL = (PASS, FINDINGS, PARTIAL, SKIPPED, ERROR, CANCELLED)

# Statuses for analyzers that actually ran to completion.
EXECUTED = frozenset({PASS, FINDINGS, PARTIAL})

LABELS = {
    PASS: "PASS",
    FINDINGS: "FINDINGS",
    PARTIAL: "PARTIAL",
    SKIPPED: "SKIPPED",
    ERROR: "FAILED",
    CANCELLED: "CANCELLED",
}


def classify(*, skipped_reason: str | None, findings: int, warnings: list[str]) -> tuple[str, str]:
    """Return (status, message) for an analyzer that returned normally.

    Precedence: a declared skip wins over everything (the analyzer did no work), then
    evidence (FINDINGS), then stated limitations (PARTIAL), then PASS.
    """
    if skipped_reason:
        return SKIPPED, str(skipped_reason)
    if findings:
        return FINDINGS, ""
    if warnings:
        return PARTIAL, "; ".join(str(w) for w in warnings[:3])
    return PASS, ""


def count_by_status(analyzers: list[dict]) -> dict[str, int]:
    """Count analyzer records per status, plus the derived report totals."""
    counts = {s: 0 for s in ALL}
    for record in analyzers:
        status = record.get("status")
        if status in counts:
            counts[status] += 1
    counts["total"] = len(analyzers)
    counts["executed"] = sum(1 for a in analyzers if a.get("status") in EXECUTED)
    return counts
