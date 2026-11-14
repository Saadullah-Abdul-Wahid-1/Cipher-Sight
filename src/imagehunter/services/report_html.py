"""Standalone HTML forensic report. No external resources: works offline and when printed.

Every value from the scan (file names, flags, phrases, log text, metadata) passes through
esc() before it is placed in the page. The only raw HTML is the template and the markup
written by this module.
"""

from __future__ import annotations

import html
import json

from imagehunter.core.status import ERROR, EXECUTED
from imagehunter.services.report_data import VERIFICATION_STATUSES, build_view


def esc(value) -> str:
    if value is None:
        return "&mdash;"
    return html.escape(str(value), quote=True)


def _badge(text: str, kind: str) -> str:
    return f'<span class="badge {esc(kind)}">{esc(text)}</span>'


def _status_badge(status: str) -> str:
    mapping = {"pass": ("PASS", "pass"), "findings": ("FINDINGS", "pass"), "partial": ("PARTIAL", "warn"),
               "skipped": ("SKIPPED", "muted"), "error": ("FAILED", "fail"), "cancelled": ("CANCELLED", "muted"),
               "completed": ("PASS", "pass"), "warning": ("WARNING", "warn"),
               "completed_with_warnings": ("WARNING", "warn"), "cancelled_scan": ("CANCELLED", "muted")}
    label, kind = mapping.get(status, (str(status or "unknown").upper(), "muted"))
    return _badge(label, kind)


def _copy_button(value) -> str:
    # data-copy is an escaped attribute; the browser decodes it, so the value is never executed.
    return f'<button class="copy" type="button" data-copy="{esc(value)}">Copy</button>'


def _table(headers: list[str], rows: list[list[str]], searchable: bool = True) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    if not rows:
        body = f'<tr><td colspan="{len(headers)}" class="empty">No entries.</td></tr>'
    cls = "searchable" if searchable else ""
    return (f'<div class="tablewrap"><table class="{cls}"><thead><tr>{head}</tr></thead>'
            f"<tbody>{body}</tbody></table></div>")


def _section(sec_id: str, title: str, body: str, open_: bool = True) -> str:
    state = " open" if open_ else ""
    return (f'<details class="section" id="{esc(sec_id)}"{state}>'
            f"<summary><h2>{esc(title)}</h2></summary><div class=\"sbody\">{body}</div></details>")


def _kv(pairs: list[tuple[str, str]]) -> str:
    """Key/value table. Keys are escaped here; values must already be HTML-safe (built with esc())."""
    rows = "".join(f"<tr><th>{esc(k)}</th><td>{v}</td></tr>" for k, v in pairs)
    return f'<div class="tablewrap"><table class="kv"><tbody>{rows}</tbody></table></div>'


def _not_executed(keys: list[str], view: dict) -> str:
    items = []
    for key in keys:
        label, reason = view["planned_modules"][key]
        items.append(f"<li><strong>{esc(label)}</strong> &mdash; not executed. {esc(reason)}</li>")
    return f'<div class="notexec"><p class="muted">Modules not executed in this scan:</p><ul>{"".join(items)}</ul></div>'


def _executed_note(names: list[str], view: dict) -> str:
    ran = {a.get("name"): a.get("status") for a in view["analyzers"]}
    items = [f"<li>{esc(n)} &mdash; {_status_badge(ran.get(n, 'not run'))}</li>" for n in names]
    return f'<p class="muted">Analyzers that ran for this section:</p><ul class="inline">{"".join(items)}</ul>'


# ---------------------------------------------------------------- sections

def _sec_analyzers(v: dict) -> str:
    rows = []
    for a in v["analyzers"]:
        rows.append([esc(a.get("name")), _status_badge(a.get("status")), esc(a.get("message") or "")])
    return ("<h3>Analyzer status</h3>"
            + _table(["Analyzer", "Result", "Message"], rows, searchable=False))


def _sec_summary(v: dict) -> str:
    dur = f"{v['duration_seconds']} s" if v["duration_seconds"] is not None else None
    size = f"{v['size']:,} bytes" if isinstance(v["size"], int) else None
    rows = [
        ("Image filename", esc(v["file_name"])),
        ("Scan started", esc(v["started_at"])),
        ("Scan finished", esc(v["finished_at"])),
        ("Scan duration", esc(dur)),
        ("File format", esc(v["format"])),
        ("File size", esc(size)),
        ("Image dimensions", esc(v["dimensions"])),
        ("Colour mode", esc(v["mode"])),
        ("Frame count", esc(v["frames"])),
        ("SHA-256", f'<code>{esc(v["sha256"])}</code> {_copy_button(v["sha256"])}'),
        ("Scan profile", esc("Default analyzer set (no named profile in this build)")),
        ("Overall scan status", _status_badge(v["status"])),
        ("Scan ID", esc(v["scan_id"])),
        ("Report generated", esc(v["generated_at"])),
    ]
    m = v["metrics"]
    cards = "".join(
        f'<div class="card"><div class="cv">{esc(val)}</div><div class="cl">{esc(lbl)}</div></div>'
        for lbl, val in [
            ("Modules executed", m["modules_executed"]), ("Total findings", m["total_findings"]),
            ("Confirmed flags", m["confirmed_flags"]), ("Flag candidates", m["flag_candidates"]),
            ("Likely decoys", m.get("likely_decoy_flags", 0)),
            ("Expected phrase matches", m["phrase_matches"]), ("Embedded items", m["embedded_items"]),
            ("Warnings", m["warnings"]), ("Errors", m["errors"]),
        ])
    return f'<div class="cards">{cards}</div>' + _kv(rows) + _sec_analyzers(v)


def _flag_row(f: dict, with_verify: bool) -> list[str]:
    cells = [f"<code>{esc(f['value'])}</code> {_copy_button(f['value'])}",
             esc(f["source_file"]), esc(f["method"]), esc(f["technique"] or None),
             esc(f["byte_offset"]), esc(f["evidence_ref"]), _badge(f["status"], f["status"].lower())]
    return cells


def _sec_flags(v: dict) -> str:
    f = v["flags"]
    headers = ["Flag value", "Source file", "Detection method", "Encoding / technique",
               "Byte offset", "Evidence ref", "Verification"]
    if f["confirmed"]:
        confirmed = _table(headers, [_flag_row(x, True) for x in f["confirmed"]])
    else:
        confirmed = '<p class="nofound">No confirmed flags found.</p>'
    note = ('<p class="muted">A pattern match is a candidate until verified. Confirmed requires an '
            'explicit verification method or an analyst decision.</p>')
    cand = (_table(headers, [_flag_row(x, True) for x in f["candidates"]]) if f["candidates"]
            else '<p class="muted">No unverified flag candidates.</p>')
    rej = (_table(headers, [_flag_row(x, True) for x in f["rejected"]]) if f["rejected"] else "")
    rej_block = _section("rejected", "Rejected flags (false positives)", rej, open_=False) if rej else ""
    decoy_block = ""
    if f.get("likely_decoys"):
        decoy_rows = [[f"<code>{esc(x['value'])}</code> {_copy_button(x['value'])}", esc(x["source_file"]),
                       esc(x["method"]), esc(x["byte_offset"]), esc(x["evidence_ref"]),
                       "<ul>" + "".join(f"<li>{esc(r)}</li>" for r in x.get("decoy_reasons", [])) + "</ul>"]
                      for x in f["likely_decoys"]]
        decoy_block = _section(
            "likely-decoys", "Likely decoy flags (not verified, not rejected)",
            "<p class=\"muted\">These match the flag format but contain or sit beside decoy wording. "
            "They are kept visible so an analyst can overrule the label.</p>"
            + _table(["Flag value", "Source file", "Detection method", "Byte offset", "Evidence ref", "Why"],
                     decoy_rows),
            open_=False)
    tier_headers = ["Flag value", "Detection method", "Confidence", "Evidence ref"]
    def tier_rows(items):
        return _table(tier_headers, [[f"<code>{esc(x.get('value'))}</code> {_copy_button(x.get('value'))}",
                                     esc(x.get("method")), esc(x.get("confidence")), esc(x.get("evidence_ref"))]
                                    for x in items])
    strong_block = _section("strong-candidates", "Strong candidates", tier_rows(f.get("strong_candidates", [])), open_=False) if f.get("strong_candidates") else ""
    weak_block = _section("weak-candidates", "Weak candidates", tier_rows(f.get("weak_candidates", [])), open_=False) if f.get("weak_candidates") else ""
    return (
        '<div class="callout"><h3>CONFIRMED FLAGS FOUND</h3>' + confirmed + "</div>"
        + note
        + _section("candidates", "Unverified flag candidates", cand, open_=bool(f["candidates"]))
        + strong_block + weak_block
        + decoy_block
        + rej_block
        + _section("experiments", "Experiment details for each candidate",
                   _experiment_table(f), open_=False)
    )


def _experiment_table(f: dict) -> str:
    rows = []
    for x in f["candidates"] + f["confirmed"]:
        for e in x["experiments"]:
            rows.append([esc(x["value"]), esc(e.get("channel")), esc(e.get("bit")),
                         esc(e.get("traversal")), esc(e.get("bit_order")),
                         esc(f"0x{e.get('xor_key', 0):02X}")])
    return _table(["Flag value", "Channel", "Bit plane", "Order", "Bit order", "XOR key"], rows)


def _sec_phrases(v: dict) -> str:
    rows = []
    for p in v["phrases"]:
        ctx = f"<pre class=\"ctx\">{esc(p['context'])}</pre>"
        rows.append([esc(p["phrase"]), esc(p["source_file"]), esc(p["method"]), esc(p["encoding"]),
                     esc(p["offset"]), esc(p["match"]), ctx, _badge(p["confidence"] or "?", "conf"),
                     esc(p["evidence_ref"])])
    headers = ["Matched phrase", "Source", "Method", "Encoding", "Offset", "Match", "Context",
               "Confidence", "Evidence ref"]
    body = _table(headers, rows) if rows else '<p class="muted">No expected phrase matches.</p>'
    if not v["properties"].get("text.phrases", {}).get("configured_phrases"):
        body = ('<p class="muted">No expected phrases configured. Add phrases under '
                '<code>expected_phrases</code> in the settings file to search for them.</p>' + body)
    return body + '<p class="muted">Phrase matches are not flags. They are clues to review.</p>'


def _sec_metadata(v: dict) -> str:
    ran = any(a.get("name") == "metadata.extract" and a.get("status") in EXECUTED for a in v["analyzers"])
    if not ran:
        return _not_executed(["metadata"], v)
    md = v["properties"].get("metadata.extract", {})
    exif = md.get("exif", {}) or {}
    parts = [_executed_note(["metadata.extract"], v)]

    png_rows = [[esc(r.get("chunk")), esc(r.get("offset")), esc(r.get("keyword")),
                 esc(r.get("text")) + (" (truncated)" if r.get("text_truncated") else ""),
                 esc("yes" if r.get("compressed") else "no"), esc(r.get("length"))]
                for r in md.get("png_text", [])]
    parts.append("<h3>PNG text chunks</h3>" + (
        _table(["Chunk", "Offset", "Keyword", "Text", "Compressed", "Length"], png_rows)
        if png_rows else '<p class="muted">No tEXt, zTXt or iTXt chunks.</p>'))

    xmp = md.get("xmp")
    if xmp:
        xrows = [(k, esc(xmp.get(k))) for k in ("creator_tool", "create_date", "modify_date",
                                                 "packet_bytes", "offset", "contains_doctype") if k in xmp]
        parts.append("<h3>XMP packet</h3>" + _kv(xrows))
    icc = md.get("icc_profile")
    parts.append("<h3>ICC profile</h3>" + _kv([("Profile", esc(icc.get("name") if icc else None)),
                                               ("Size (bytes)", esc(icc.get("size") if icc else None))]))

    if exif.get("present"):
        erows = [(esc(k), esc(val)) for k, val in exif.get("fields", {}).items()]
        erows += [(esc("Timestamp: " + k), esc(val)) for k, val in exif.get("timestamps", {}).items()]
        parts.append("<h3>EXIF</h3>" + _kv(erows))
        if exif.get("gps"):
            grows = [(esc(k), esc(val)) for k, val in exif["gps"].items()]
            parts.append('<div class="notexec"><p class="muted">Privacy: ' + esc(exif.get("privacy_note"))
                         + '</p></div><h3>GPS</h3>' + _kv(grows))
    else:
        parts.append('<p class="muted">No EXIF block found.</p>')

    anomalies = [f for f in v["findings"] if f.get("category") == "metadata"]
    arows = [[esc(f.get("id")), _badge(f.get("confidence_label", "?"), "conf"), esc(f.get("kind")),
              esc(f.get("description"))] for f in anomalies]
    parts.append("<h3>Metadata findings</h3>" + (
        _table(["Ref", "Confidence", "Kind", "Description"], arows)
        if arows else '<p class="muted">No metadata anomalies.</p>'))
    return "".join(parts)


def _sec_stego(v: dict) -> str:
    props = v["properties"].get("stego.lsb", {})
    ran = [a for a in v["analyzers"] if a.get("name") == "stego.lsb"]
    parts = [_executed_note(["stego.lsb"], v) if ran else '<p class="muted">LSB analyzer did not run.</p>']
    if props:
        if props.get("skipped"):
            parts.append(f'<p class="muted">LSB analysis skipped: {esc(props["skipped"])}</p>')
        else:
            parts.append(_kv([
                ("Channels analysed", esc(", ".join(props.get("channels", [])) or None)),
                ("Colour mode", esc(props.get("mode"))),
                ("Alpha channel", esc("present" if props.get("alpha", {}).get("present") else "not present")),
                ("Alpha distinct values", esc(props.get("alpha", {}).get("distinct_values"))),
                ("Candidate patterns", esc(props.get("candidate_count"))),
                ("Experiments run", esc(props.get("experiments"))),
            ]))
    parts.append(_not_executed(["palette", "jpeg_stego"], v))
    png = v["properties"].get("binary.structure", {})
    parts.append(_kv([("Structure parser used", esc(png.get("structure_parser") or "none"))]))
    return "".join(parts)


def _sec_embedded(v: dict) -> str:
    rows = []
    for f in v["embedded"]:
        ev = f.get("evidence", {})
        zips = ", ".join(ev.get("zip_entries", []) or []) or None
        rows.append([esc(ev.get("signature", f.get("kind"))), esc(zips), esc(f.get("offset")),
                     esc(f.get("length")), esc("Signature detection"), esc("Detected, not extracted"),
                     esc("not computed (not extracted)"), esc(f.get("evidence", {}).get("hit_count")),
                     esc(f.get("id"))])
    headers = ["Detected type", "Contents (ZIP)", "Offset", "Length", "Method", "Extraction status",
               "SHA-256 of extract", "Hit count", "Evidence ref"]
    body = _table(headers, rows) if rows else '<p class="muted">No embedded signatures found.</p>'
    return _executed_note(["carving.embedded"], v) + body + _not_executed(["extraction"], v)


def _sec_binary(v: dict) -> str:
    ident = v["properties"].get("image.identity", {})
    struct = v["properties"].get("binary.structure", {})
    rows = [
        ("Signature format (magic bytes)", esc(ident.get("signature_format") or "unknown")),
        ("File extension", esc(ident.get("extension") or "none")),
        ("Structure parser", esc(struct.get("structure_parser") or "none")),
        ("Structure end offset", esc(struct.get("structure_end"))),
    ]
    structural = [f for f in v["findings"] if f.get("category") in ("structure", "identity")]
    srows = [[esc(f.get("id")), _badge(f.get("confidence_label", "?"), "conf"), esc(f.get("kind")),
              esc(f.get("offset")), esc(f.get("length")), esc(f.get("description"))] for f in structural]
    return (_executed_note(["image.identity", "binary.structure"], v) + _kv(rows)
            + "<h3>Structural findings</h3>"
            + _table(["Ref", "Confidence", "Kind", "Offset", "Length", "Description"], srows))


def _sec_decoded(v: dict) -> str:
    strings = v["properties"].get("text.strings", {})
    rows = [[esc(s.get("offset")), esc(s.get("text"))] for s in strings.get("strings", [])]
    head = (f'<p class="muted">Printable ASCII strings: {esc(strings.get("string_count", 0))} found'
            + (" (list truncated)" if strings.get("list_truncated") else "") + ".</p>")
    not_done = ('<div class="notexec"><p class="muted">Not executed in this build:</p><ul>'
                "<li>UTF-8 and UTF-16 decoding</li><li>Base64 decoding</li><li>Hexadecimal decoding</li>"
                "</ul></div>")
    return (_executed_note(["text.strings"], v) + head
            + _table(["Offset", "ASCII string"], rows) + not_done)


def _sec_smart(v: dict) -> str:
    block = v["properties"].get("text.smart_words", {}) or {}
    if not block.get("enabled"):
        return '<p class="muted">Smart word candidates are disabled for this scan.</p>'
    cands = block.get("candidates", [])
    note = (f'<p class="muted">{esc(block.get("note"))}</p>'
            f'<p class="muted">Returned {esc(block.get("returned"))} of {esc(block.get("total_candidates"))} '
            f'candidates. Priority counts: High {esc(block.get("priority_counts", {}).get("High"))}, '
            f'Medium {esc(block.get("priority_counts", {}).get("Medium"))}, '
            f'Low {esc(block.get("priority_counts", {}).get("Low"))}.</p>')
    rows = []
    for c in cands[:200]:
        chain = " > ".join(c.get("transform_chain", [])) or "original"
        why = "; ".join(c.get("reasons", [])) or "-"
        ctx = c["occurrences"][0]["context"] if c.get("occurrences") else ""
        rows.append([esc(c.get("id")), esc(c.get("value")), _badge(c.get("priority", "?"), "conf"),
                     esc(c.get("score")), esc(c.get("type")), esc(chain), esc(c.get("source_count")),
                     esc(why), f'<pre class="ctx">{esc(ctx)}</pre>'])
    table = _table(["ID", "Candidate", "Priority", "Score", "Type", "Transform", "Sources", "Why flagged",
                    "Context"], rows)
    return note + table + ('<p class="muted">Candidates are for review only. They are not verified passwords.</p>')


def _sec_log(v: dict) -> str:
    rows = []
    for e in v["execution_log"]:
        rows.append([esc(e.get("ts")), esc(e.get("module")), esc(e.get("operation")),
                     esc(e.get("message")),
                     _badge(e.get("status", ""), "fail" if e.get("level") == "ERROR" else
                            "warn" if e.get("level") == "WARNING" else "pass" if e.get("level") == "SUCCESS" else "muted"),
                     esc(e.get("level")), esc(e.get("percent"))])
    note = ('<p class="muted">Entries are in the order they happened. Messages about writing the reports '
            "appear in the live console, not in this log.</p>")
    return note + _table(["Timestamp", "Module", "Operation", "Result / message", "Status", "Level", "%"], rows)


def _sec_evidence(v: dict) -> str:
    art = [[esc("A001 (original)"), esc(v["file_path"]), f"<code>{esc(v['sha256'])}</code>", esc(v["size"])]]
    tv = "".join(f"<li>{esc(k)}: {esc(val)}</li>" for k, val in v["tool_versions"].items())
    lim = "".join(f"<li>{esc(x)}</li>" for x in v["limitations"])
    return (_table(["Artifact", "Path", "SHA-256", "Size (bytes)"], art)
            + _kv([("Workspace (evidence folder)", esc(v["workspace"])),
                   ("Analysis started", esc(v["started_at"])),
                   ("Analysis finished", esc(v["finished_at"])),
                   ("Extracted artifact hashes", esc("none (no extraction performed)"))])
            + f'<h3>Tool versions</h3><ul class="inline">{tv}</ul>'
            + f'<h3>Limitations</h3><ul>{lim}</ul>')


def _sec_warnings(v: dict) -> str:
    items = "".join(f"<li>{esc(w)}</li>" for w in v["warnings"])
    errs = [a for a in v["analyzers"] if a.get("status") == ERROR]
    err_items = "".join(f"<li>{esc(a.get('name'))}: {esc(a.get('message'))}</li>" for a in errs)
    return (f"<h3>Warnings</h3><ul>{items or '<li class=\"muted\">No warnings.</li>'}</ul>"
            f"<h3>Errors</h3><ul>{err_items or '<li class=\"muted\">No errors.</li>'}</ul>")


CSS = """
:root{--bg:#07090e;--panel:#0d111a;--card:#111726;--line:#22314d;--text:#e0e6ed;--muted:#8b9bb4;
--green:#00ff66;--cyan:#00e5ff;--red:#ff2a55;--amber:#ffaa00}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 Inter,system-ui,Segoe UI,Arial,sans-serif}
header{padding:24px 32px;border-bottom:1px solid var(--line);background:var(--panel)}
header h1{margin:0;font-size:22px;color:var(--green);letter-spacing:.5px}
header p{margin:4px 0 0;color:var(--muted)}
main{max-width:1200px;margin:0 auto;padding:20px 24px 60px}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:16px 0}
input[type=search]{flex:1;min-width:220px;background:var(--card);color:var(--text);border:1px solid var(--line);
border-radius:6px;padding:8px 10px;font:inherit}
details.section{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin:14px 0;padding:0 16px}
details.section>summary{cursor:pointer;list-style:none;padding:12px 0}
details.section>summary::-webkit-details-marker{display:none}
details.section>summary h2{display:inline;font-size:17px;color:var(--cyan);margin:0}
.sbody{padding:0 0 16px}
h3{font-size:14px;color:var(--cyan);margin:18px 0 8px}
.callout{border:1px solid var(--green);background:rgba(0,255,102,.05);border-radius:8px;padding:12px 16px;margin:12px 0}
.callout h3{color:var(--green);margin-top:0;font-size:16px;letter-spacing:1px}
.nofound{color:var(--amber);font-weight:600;margin:6px 0}
.muted{color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:8px 0 14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}
.card .cv{font-size:22px;color:var(--green);font-weight:700}
.card .cl{color:var(--muted);font-size:12px}
.tablewrap{overflow-x:auto;margin:8px 0}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
thead th{color:var(--cyan);font-weight:600;background:var(--card)}
table.kv th{width:32%;color:var(--muted);font-weight:500}
code,pre{font-family:"JetBrains Mono",Consolas,monospace;font-size:12.5px}
code{color:var(--green)}
pre.ctx{margin:0;white-space:pre-wrap;color:var(--text);background:#0a0e16;padding:6px;border-radius:4px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.4px;border:1px solid}
.badge.pass{color:var(--green);border-color:var(--green)}
.badge.warn{color:var(--amber);border-color:var(--amber)}
.badge.fail{color:var(--red);border-color:var(--red)}
.badge.candidate{color:var(--cyan);border-color:var(--cyan)}
.badge.confirmed{color:var(--green);border-color:var(--green)}
.badge.rejected{color:var(--muted);border-color:var(--muted)}
.badge.conf{color:var(--cyan);border-color:var(--cyan)}
.badge.muted{color:var(--muted);border-color:var(--line)}
button.copy{background:transparent;color:var(--cyan);border:1px solid var(--cyan);border-radius:4px;padding:1px 7px;
font:inherit;font-size:11px;cursor:pointer;margin-left:4px}
button.copy:hover{background:rgba(0,229,255,.1)}
.notexec{border-left:3px solid var(--amber);padding:6px 12px;margin:10px 0;background:rgba(255,170,0,.05)}
ul.inline,div.inline{list-style:none;padding:0;display:flex;gap:14px;flex-wrap:wrap}
nav a{color:var(--cyan);text-decoration:none}
footer{color:var(--muted);text-align:center;padding:20px;font-size:12px}
@media print{body{background:#fff;color:#000}header{background:#fff;border-color:#999}
header h1{color:#000}details.section{border-color:#999;background:#fff;break-inside:avoid}
details.section>summary h2{color:#000}.card,thead th{background:#fff}.card .cv{color:#000}
.no-print,input[type=search],button.copy{display:none!important}
th,td{border-color:#999}code{color:#000}.badge{color:#000!important;border-color:#000!important}
details{display:block}details>.sbody{display:block}a{color:#000}}
@media (max-width:700px){main{padding:12px}header{padding:16px}}
"""

JS = """
(function(){
  var search=document.getElementById('search');
  function filter(){
    var q=(search.value||'').toLowerCase();
    document.querySelectorAll('table.searchable tbody tr').forEach(function(tr){
      tr.style.display = (!q || tr.textContent.toLowerCase().indexOf(q)>=0) ? '' : 'none';
    });
  }
  search.addEventListener('input', filter);
  document.querySelectorAll('button.copy').forEach(function(btn){
    btn.addEventListener('click', function(){
      var text = btn.getAttribute('data-copy') || '';
      var done = function(){ var old=btn.textContent; btn.textContent='Copied'; setTimeout(function(){btn.textContent=old;},1200); };
      if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(text).then(done, function(){}); }
    });
  });
  document.getElementById('expand').addEventListener('click', function(){
    document.querySelectorAll('details.section').forEach(function(d){ d.open = true; });
  });
  document.getElementById('collapse').addEventListener('click', function(){
    document.querySelectorAll('details.section').forEach(function(d){ d.open = false; });
  });
})();
"""


def build_report_html(summary: dict, verifications: dict[str, str] | None = None) -> str:
    v = build_view(summary, verifications)
    nav = "".join(f'<a href="#{i}">{esc(t)}</a>' for i, t in [
        ("summary", "Summary"), ("flags", "Flags"), ("phrases", "Phrases"), ("metadata", "Metadata"),
        ("stego", "Steganography"), ("embedded", "Embedded"), ("binary", "Binary"),
        ("smart", "Smart words"), ("decoded", "Decoded"), ("log", "Log"), ("evidence", "Evidence"), ("warnings", "Warnings")])
    body = "".join([
        _section("summary", "1. Executive Summary", _sec_summary(v)),
        _section("flags", "2. Correct Flags Found", _sec_flags(v)),
        _section("phrases", "3. Expected Phrases & Clue Matches", _sec_phrases(v)),
        _section("metadata", "4. Metadata Findings", _sec_metadata(v), open_=False),
        _section("stego", "5. Steganography Findings", _sec_stego(v)),
        _section("embedded", "6. Embedded Files and Payloads", _sec_embedded(v)),
        _section("binary", "7. Binary Analysis", _sec_binary(v), open_=False),
        _section("smart", "Smart word candidates (for analyst review)", _sec_smart(v), open_=False),
        _section("decoded", "8. Decoded Data", _sec_decoded(v), open_=False),
        _section("log", "9. Analysis Execution Log", _sec_log(v), open_=False),
        _section("evidence", "10. Evidence and Integrity", _sec_evidence(v)),
        _section("warnings", "Warnings and Errors", _sec_warnings(v), open_=False),
    ])
    # Show the whole report model once as data for auditing. Escaped, so it cannot break the page.
    raw = esc(json.dumps({"scan_id": v["scan_id"], "status": v["status"], "metrics": v["metrics"]},
                         indent=2, ensure_ascii=False))
    title = f"CipherSight report: {esc(v['file_name'])}"
    status_badge = _status_badge(v["status"])
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="ImageHunter {esc(v['tool_versions']['ImageHunter'])}">
<title>{title}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>CipherSight Forensic Report</h1>
  <p>{esc(v['file_name'])} &middot; Scan {esc(v['scan_id'])} &middot; {status_badge}</p>
  <p>Generated {esc(v['generated_at'])}</p>
</header>
<main>
  <div class="toolbar no-print">
    <input type="search" id="search" placeholder="Search findings, flags, phrases and log...">
    <button class="copy" id="expand" type="button">Expand all</button>
    <button class="copy" id="collapse" type="button">Collapse all</button>
    <button class="copy" type="button" onclick="window.print()">Print</button>
  </div>
  <nav class="no-print"><div class="inline">{nav}</div></nav>
  {body}
  <details class="section"><summary><h2>Raw summary (audit)</h2></summary>
    <pre class="ctx">{raw}</pre></details>
</main>
<footer>Findings are rule-based. A pattern match is a candidate, not a verified flag.
Generated offline by CipherSight {esc(v['tool_versions']['ImageHunter'])}.</footer>
<script>{JS}</script>
</body>
</html>
"""
