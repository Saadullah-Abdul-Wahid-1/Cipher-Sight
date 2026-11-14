"""Plain-text summary of a scan, for people reading results in a window or a terminal.

Takes the dict produced by ScanSummary.to_dict(), so it has no dependency on the GUI toolkit.
"""

from __future__ import annotations


def _get(d, *path, default=None):
    cur = d
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def format_summary(d: dict) -> str:
    inp = d.get("input", {})
    identity = _get(d, "properties", "image.identity", default={})
    lines = [
        f"Status:    {d.get('status', '?')}",
        f"Scan ID:   {d.get('scan_id', '?')}",
        f"File:      {inp.get('path', '?')}",
        f"SHA-256:   {inp.get('sha256', '?')}",
        f"Size:      {inp.get('size', '?')} bytes",
    ]

    fmt = identity.get("signature_format") or "unknown"
    lines.append(f"Format:    {fmt} (extension {identity.get('extension') or 'none'})")
    if identity.get("pillow_format"):
        lines.append(
            f"Image:     {identity['pillow_format']} {identity.get('width')}x{identity.get('height')}, "
            f"mode {identity.get('mode')}, frames {identity.get('frames')}"
        )

    findings = d.get("findings", [])
    lines += ["", f"Findings: {len(findings)}"]
    if not findings:
        lines.append("  none. No structural anomalies found.")
    for f in findings:
        where = f"offset {f['offset']}" if f.get("offset") is not None else "whole file"
        length = f", {f['length']} bytes" if f.get("length") is not None else ""
        lines.append(f"  {f.get('id', '')} [{f.get('confidence_label', '?')}] {f.get('kind', '?')}: "
                     f"{f.get('description', '')} ({where}{length})")
        zip_entries = (f.get("evidence") or {}).get("zip_entries")
        if zip_entries:
            lines.append(f"      zip contents: {', '.join(zip_entries)}")

    strings = _get(d, "properties", "text.strings", default={})
    if strings:
        lines += ["", f"Printable strings: {strings.get('string_count', 0)} found"]
        for s in strings.get("strings", [])[:15]:
            lines.append(f"  @{s['offset']}: {s['text'][:100]}")
        if strings.get("list_truncated"):
            lines.append("  ... list truncated; see the JSON report for all entries")

    warnings = d.get("warnings", [])
    if warnings:
        lines += ["", "Warnings:"] + [f"  - {w}" for w in warnings]

    lines += ["", "Analyzers:"]
    for a in d.get("analyzers", []):
        extra = f" ({a['message']})" if a.get("message") else ""
        lines.append(f"  {a.get('name')}: {a.get('status')}{extra}")

    lines += ["", "Limitations:"] + [f"  - {x}" for x in d.get("limitations", [])]
    lines += ["", f"Full JSON report: {d.get('workspace', '?')}\\reports\\scan_summary.json"]
    return "\n".join(lines)
