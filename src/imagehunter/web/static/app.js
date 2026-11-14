(function () {
  "use strict";
  // Every value from a scan is written with textContent, never innerHTML.
  var LEVELS = ["INFO", "SUCCESS", "WARNING", "ERROR", "FINDING", "DEBUG"];
  var HDR = {"X-ImageHunter": "1"};
  var TITLES = {
    dashboard: "Dashboard", analyze: "New Investigation", history: "Scan History",
    results: "Findings and Evidence", confirmed: "Confirmed Flags", candidates: "Unverified Candidates",
    decoys: "Decoy Flags", stego: "Steganography", clues: "Text and Clues", metadata: "Metadata",
    embedded: "Embedded Files", ocr: "OCR and QR", forensic: "Forensic Analysis", logs: "Scan Logs",
    export: "Reports", about: "About CipherSight"
  };
  var VIEW_PAGES = ["results", "confirmed", "candidates", "decoys", "stego", "clues", "metadata",
                    "embedded", "ocr", "forensic", "logs"];
  // Internal status values from the engine, shown with the spec's vocabulary.
  var FLAG_LABEL = {"Confirmed": "CONFIRMED", "Candidate": "UNVERIFIED", "Likely Decoy": "LIKELY DECOY",
                    "Rejected": "REJECTED"};
  var FLAG_CLASS = {"Confirmed": "b-conf", "Candidate": "b-warn", "Likely Decoy": "b-decoy",
                    "Rejected": "b-rej"};
  var STATUS_CLASS = {"pass": "b-pass", "findings": "b-pass", "partial": "b-warn", "skipped": "b-muted",
                      "error": "b-fail", "cancelled": "b-muted"};

  var state = {jobId: null, cursor: 0, timer: null, lines: [], paused: false, pendingWhilePaused: 0,
               view: null, file: null, page: "dashboard"};
  var $ = function (id) { return document.getElementById(id); };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = String(text); }
    return e;
  }

  function setPill(kind, text) {
    var p = $("statusPill");
    p.className = "pill " + kind;
    p.textContent = text;
  }

  function badge(text, cls) { return el("span", "badge " + cls, text); }

  function toast(text) {
    var t = $("flash");
    t.textContent = text;
    t.classList.remove("hidden");
    clearTimeout(toast.timer);
    toast.timer = setTimeout(function () { t.classList.add("hidden"); }, 4000);
  }

  function copyButton(value) {
    var b = el("button", "btn small", "Copy");
    b.type = "button";
    b.addEventListener("click", function () {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(String(value)).then(function () {
          b.textContent = "Copied";
          setTimeout(function () { b.textContent = "Copy"; }, 1200);
        }, function () {});
      }
    });
    return b;
  }

  // Cells: plain text, {copy: value}, {badge: text, cls}, or {node: element}.
  function table(headers, rows) {
    var wrap = el("div", "tablewrap");
    var t = el("table");
    var thead = el("thead"), htr = el("tr");
    headers.forEach(function (h) { htr.appendChild(el("th", null, h)); });
    thead.appendChild(htr);
    t.appendChild(thead);
    var tb = el("tbody");
    if (!rows.length) {
      var tr0 = el("tr"), td0 = el("td", "empty", "None.");
      td0.colSpan = headers.length;
      tr0.appendChild(td0);
      tb.appendChild(tr0);
    }
    rows.forEach(function (cells) {
      var tr = el("tr");
      cells.forEach(function (c) {
        var td = el("td");
        if (c && c.node) { td.appendChild(c.node); }
        else if (c && c.badge !== undefined) { td.appendChild(badge(c.badge, c.cls || "b-muted")); }
        else if (c && c.copy !== undefined) {
          td.appendChild(el("code", null, c.copy));
          td.appendChild(document.createTextNode(" "));
          td.appendChild(copyButton(c.copy));
        } else {
          td.textContent = (c === null || c === undefined || c === "") ? "-" : String(c);
        }
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    wrap.appendChild(t);
    return wrap;
  }

  function kvTable(pairs) {
    return table(["Field", "Value"], pairs.map(function (p) {
      var v = p[1];
      if (v !== null && typeof v === "object") { v = JSON.stringify(v); }
      return [p[0], v];
    }));
  }

  function panel(title, note) {
    var p = el("div", "panel");
    if (title) { p.appendChild(el("h2", null, title)); }
    if (note) { p.appendChild(el("p", "muted", note)); }
    return p;
  }

  function statusCell(status) {
    var label = String(status || "unknown").toUpperCase();
    return {badge: label, cls: STATUS_CLASS[String(status).toLowerCase()] || "b-muted"};
  }

  var JOB_STATUS = {
    "running": {badge: "RUNNING", cls: "b-warn"},
    "completed": {badge: "COMPLETED", cls: "b-pass"},
    "completed_with_warnings": {badge: "WARNINGS", cls: "b-warn"},
    "failed": {badge: "FAILED", cls: "b-fail"},
    "cancelled": {badge: "CANCELLED", cls: "b-muted"}
  };

  function jobStatusCell(status) {
    return JOB_STATUS[status] || {badge: String(status).toUpperCase(), cls: "b-muted"};
  }

  function flagStatusCell(status) {
    return {badge: FLAG_LABEL[status] || String(status).toUpperCase(), cls: FLAG_CLASS[status] || "b-muted"};
  }

  function metricCard(label, value) {
    var c = el("div", "card");
    c.appendChild(el("div", "cv", value === null || value === undefined ? "-" : value));
    c.appendChild(el("div", "cl", label));
    return c;
  }

  function cardRow(pairs) {
    var row = el("div", "cards");
    pairs.forEach(function (p) { row.appendChild(metricCard(p[0], p[1])); });
    return row;
  }

  function formatLine(e) {
    var ts = String(e.ts || "");
    var clock = ts.length >= 23 ? ts.slice(11, 23) : ts;
    var pct = (e.percent !== null && e.percent !== undefined) ? " (" + e.percent + "%)" : "";
    return "[" + clock + "] [" + e.level + "] [" + e.module + "] " + e.operation + ": " + e.message + pct;
  }

  // ------------------------------------------------------------- live console
  function levelChecked(level) {
    var box = document.querySelector('input[data-level="' + level + '"]');
    return box ? box.checked : true;
  }

  function visibleLines() {
    var q = $("consoleSearch").value.trim().toLowerCase();
    return state.lines.filter(function (e) {
      if (!levelChecked(e.level)) { return false; }
      return !q || formatLine(e).toLowerCase().indexOf(q) >= 0;
    });
  }

  function rebuildConsole() {
    var box = $("console");
    while (box.firstChild) { box.removeChild(box.firstChild); }
    visibleLines().forEach(function (e) { box.appendChild(lineNode(e)); });
    if ($("autoscroll").checked) { box.scrollTop = box.scrollHeight; }
  }

  function lineNode(e) { return el("div", "ln lv-" + e.level, formatLine(e)); }

  function appendLine(e) {
    state.lines.push(e);
    if (state.paused) { state.pendingWhilePaused += 1; updatePausedNote(); return; }
    if (!levelChecked(e.level)) { return; }
    var q = $("consoleSearch").value.trim().toLowerCase();
    if (q && formatLine(e).toLowerCase().indexOf(q) < 0) { return; }
    var box = $("console");
    box.appendChild(lineNode(e));
    if ($("autoscroll").checked) { box.scrollTop = box.scrollHeight; }
  }

  function updatePausedNote() {
    $("pausedNote").textContent = state.paused
      ? "Display paused. " + state.pendingWhilePaused + " new event(s) recorded." : "";
  }

  function consoleText() { return visibleLines().map(formatLine).join("\n"); }

  // ------------------------------------------------------------- navigation
  function showPage(name) {
    state.page = name;
    document.querySelectorAll(".page").forEach(function (p) { p.classList.add("hidden"); });
    $("page-" + name).classList.remove("hidden");
    document.querySelectorAll(".navbtn").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-page") === name);
    });
    $("pageTitle").textContent = TITLES[name] || name;
    if (name === "dashboard") { refreshDashboard(); }
    if (name === "history") { refreshHistory(); }
    if (name === "export") { renderExport(); }
    if (VIEW_PAGES.indexOf(name) >= 0) { renderViewPage(name); }
  }

  // ------------------------------------------------------------- dashboard and history
  var STAT_CARDS = [
    ["Total scans", "total_scans"], ["Images analyzed", "images_analyzed"],
    ["Confirmed flags", "confirmed_flags"], ["Unverified candidates", "flag_candidates"],
    ["Likely decoys", "likely_decoy_flags"], ["Embedded files", "embedded_items"],
    ["Warnings", "warnings"], ["Errors", "errors"], ["Failed scans", "failed_scans"],
    ["Average scan duration (s)", "average_duration_seconds"]
  ];

  function refreshDashboard() {
    fetch("/api/stats").then(function (r) { return r.json(); }).then(function (s) {
      var row = el("div", "cards");
      STAT_CARDS.forEach(function (c) { row.appendChild(metricCard(c[0], s[c[1]])); });
      var holder = $("statsCards");
      while (holder.firstChild) { holder.removeChild(holder.firstChild); }
      holder.appendChild(row);
    }).catch(function () { setPill("fail", "SERVER ERROR"); });
    fetch("/api/status").then(function (r) { return r.json(); }).then(function (s) {
      var holder = $("dashRecent");
      while (holder.firstChild) { holder.removeChild(holder.firstChild); }
      holder.appendChild(historyTable(s.jobs.slice(0, 5)));
      setPill(s.busy ? "busy" : "idle", s.busy ? "SCANNING" : "IDLE");
    });
  }

  function refreshHistory() {
    fetch("/api/status").then(function (r) { return r.json(); }).then(function (s) {
      var holder = $("historyBody");
      while (holder.firstChild) { holder.removeChild(holder.firstChild); }
      holder.appendChild(historyTable(s.jobs));
    });
  }

  function historyTable(jobs) {
    return table(["File", "Status", "Findings", "Started", "Scan"], jobs.map(function (j) {
      var open = el("button", "btn small", "Open");
      open.type = "button";
      open.addEventListener("click", function () { loadView(j.id, "results"); });
      return [j.filename, jobStatusCell(j.status),
              j.findings === null ? "-" : j.findings, j.created, {node: open}];
    }));
  }

  // ------------------------------------------------------------- analysis: upload and run
  function onFileChosen(file) {
    state.file = file || null;
    $("fileName").textContent = file ? (file.name + " (" + file.size + " bytes)") : "No file selected.";
    $("btnStart").disabled = !file;
    $("analyzeError").textContent = "";
  }

  function startScan() {
    if (!state.file) { return; }
    $("btnStart").disabled = true;
    $("analyzeError").textContent = "";
    state.lines = []; state.pendingWhilePaused = 0;
    $("console").textContent = "";
    fetch("/api/scans", {
      method: "POST",
      headers: Object.assign({"Content-Type": "application/octet-stream",
                              "X-Filename": encodeURIComponent(state.file.name)}, HDR),
      body: state.file
    }).then(function (r) {
      return r.json().then(function (data) { return {ok: r.ok, data: data}; });
    }).then(function (res) {
      if (!res.ok) {
        $("analyzeError").textContent = (res.data && res.data.error) ? res.data.error : "Upload failed.";
        $("btnStart").disabled = false;
        return;
      }
      state.jobId = res.data.id;
      state.cursor = 0;
      setPill("busy", "SCANNING");
      $("progText").textContent = "Scan started.";
      state.timer = setInterval(poll, 350);
    }).catch(function () {
      $("analyzeError").textContent = "Could not reach the CipherSight server.";
      $("btnStart").disabled = false;
    });
  }

  function poll() {
    if (!state.jobId) { return; }
    fetch("/api/scans/" + state.jobId + "?after=" + state.cursor).then(function (r) {
      return r.json();
    }).then(function (d) {
      state.cursor = d.total_events;
      d.events.forEach(appendLine);
      $("progBar").style.width = d.percent + "%";
      $("progPct").textContent = d.percent + "%";
      var last = d.events.length ? d.events[d.events.length - 1] : null;
      if (last) {
        $("progText").textContent = last.operation + ": " + last.message;
        $("progMeta").textContent = "Module: " + last.module + "   Status: " + last.status +
                                    "   Progress: " + d.percent + "%";
      }
      if (d.done) {
        clearInterval(state.timer);
        state.timer = null;
        $("btnStart").disabled = !state.file;
        if (d.status === "failed") {
          setPill("fail", "FAILED");
          $("analyzeError").textContent = d.error || "The scan failed.";
        } else {
          setPill(d.status === "completed" ? "ok" : "busy", d.status === "completed" ? "COMPLETED" : "WARNINGS");
          loadView(state.jobId, null);
        }
      }
    }).catch(function () {
      clearInterval(state.timer);
      state.timer = null;
      setPill("fail", "CONNECTION LOST");
      $("btnStart").disabled = !state.file;
    });
  }

  // ------------------------------------------------------------- loading a scan
  function loadView(jobId, thenPage) {
    fetch("/api/scans/" + jobId + "/summary").then(function (r) {
      return r.json().then(function (v) { return {ok: r.ok, v: v}; });
    }).then(function (res) {
      if (!res.ok) { toast(res.v.error || "No results for that scan."); return; }
      state.jobId = jobId;
      state.view = res.v;
      if (thenPage) { showPage(thenPage); } else { renderAll(); }
    }).catch(function () { toast("Could not load the scan."); });
  }

  function renderAll() {
    renderExport();
    if (VIEW_PAGES.indexOf(state.page) >= 0) { renderViewPage(state.page); }
  }

  // ------------------------------------------------------------- analyst review
  function submitDecision(value, decision) {
    if (!state.jobId) { return; }
    fetch("/api/scans/" + state.jobId + "/verifications", {
      method: "POST",
      headers: Object.assign({"Content-Type": "application/json"}, HDR),
      body: JSON.stringify({value: value, decision: decision})
    }).then(function (r) {
      return r.json().then(function (d) { return {ok: r.ok, d: d}; });
    }).then(function (res) {
      if (!res.ok) { toast(res.d.error || "The decision was not saved."); return; }
      state.view = res.d;
      renderAll();
      toast("Decision saved for this scan's on-screen views.");
    }).catch(function () { toast("Could not reach the CipherSight server."); });
  }

  function reviewCell(value, status) {
    var wrap = el("span", "review");
    function act(decision, label) {
      var b = el("button", "btn small", label);
      b.type = "button";
      b.addEventListener("click", function () { submitDecision(value, decision); });
      wrap.appendChild(b);
    }
    if (status === "Candidate" || status === "Likely Decoy") {
      act("confirmed", "Confirm");
      act("rejected", "Reject");
    } else {
      act("clear", "Clear decision");
    }
    return {node: wrap};
  }

  // ------------------------------------------------------------- page renderers
  function requireScan(name) {
    var gate = document.querySelector("#page-" + name + " .gate");
    var body = document.querySelector("#page-" + name + " .pagebody");
    while (body.firstChild) { body.removeChild(body.firstChild); }
    if (!state.view) {
      gate.textContent = "No scan selected. Start a new investigation or open one from Scan History.";
      gate.classList.remove("hidden");
      return null;
    }
    gate.textContent = "";
    gate.classList.add("hidden");
    return body;
  }

  function renderViewPage(name) {
    var body = requireScan(name);
    if (!body) { return; }
    var v = state.view;
    var nodes = RENDERERS[name](v);
    nodes.forEach(function (n) { body.appendChild(n); });
  }

  function flagPanel(title, note, rows, showReasons) {
    var headers = ["Flag value", "Status", "Evidence", "Source file", "Detection method", "Technique",
                   "Byte offset", "Evidence ref"];
    if (showReasons) { headers.push("Why"); }
    headers.push("Review");
    var body = table(headers, rows.map(function (f) {
      var cells = [{copy: f.value}, flagStatusCell(f.status), f.evidence_tier || "-", f.source_file,
                   f.method, f.technique || "-", f.byte_offset, f.evidence_ref];
      if (showReasons) {
        var list = el("ul", "reasons");
        (f.decoy_reasons || []).forEach(function (r) { list.appendChild(el("li", null, r)); });
        cells.push({node: list});
      }
      cells.push(reviewCell(f.value, f.status));
      return cells;
    }));
    var p = panel(title, note);
    p.appendChild(body);
    return p;
  }

  function analyzerRows(v, prefixes) {
    return v.analyzers.filter(function (a) {
      return prefixes.some(function (p) { return String(a.name).indexOf(p) === 0; });
    });
  }

  function analyzerPanel(v, prefixes, title) {
    var rows = analyzerRows(v, prefixes);
    var p = panel(title || "Analyzer status");
    p.appendChild(table(["Analyzer", "Result", "Message"], rows.map(function (a) {
      return [a.name, statusCell(a.status), a.message || ""];
    })));
    return p;
  }

  function findingsPanel(v, categories, title, note) {
    var rows = v.findings.filter(function (f) { return categories.indexOf(f.category) >= 0; });
    var p = panel(title, note);
    p.appendChild(table(["Ref", "Kind", "Confidence", "Offset", "Description"], rows.map(function (f) {
      return [f.id, f.kind, f.confidence_label || "-", f.offset, f.description];
    })));
    return p;
  }

  var RENDERERS = {
    results: function (v) {
      var m = v.metrics;
      var out = [cardRow([
        ["Modules executed", m.modules_executed], ["Total findings", m.total_findings],
        ["Confirmed flags", m.confirmed_flags], ["Unverified candidates", m.flag_candidates],
        ["Likely decoys", m.likely_decoy_flags], ["Rejected", m.rejected_flags],
        ["Phrase matches", m.phrase_matches], ["Embedded items", m.embedded_items],
        ["Warnings", m.warnings], ["Errors", m.errors], ["Duration (s)", m.duration_seconds]
      ])];
      out.push(kvTable([["File", v.file_name], ["SHA-256", v.sha256], ["Overall status", v.status],
                        ["Scan ID", v.scan_id], ["Format", v.format], ["Dimensions", v.dimensions]]));
      var warn = panel("Warnings and errors");
      if (!v.warnings.length) { warn.appendChild(el("p", "muted", "No warnings.")); }
      v.warnings.forEach(function (w) { warn.appendChild(el("div", null, "- " + w)); });
      out.push(warn);
      out.push(analyzerPanel(v, [""], "All analyzers"));
      return out;
    },
    confirmed: function (v) {
      var rows = v.flags.confirmed;
      return [panel("CONFIRMED FLAGS",
        "A pattern match is never confirmed automatically. A flag is confirmed only when an analyst records it here."),
        rows.length ? flagPanel("", "", rows, false)
                    : el("p", "nofound", "No confirmed flags found.")];
    },
    candidates: function (v) {
      return [flagPanel("UNVERIFIED flag candidates",
        "Pattern matches that have not been verified and are not labelled as decoys. Evidence tier shows how strong the recovery evidence is.",
        v.flags.candidates, false)];
    },
    decoys: function (v) {
      var out = [flagPanel("LIKELY DECOY flags",
        "These match the flag format but contain or sit beside decoy wording. They are kept visible; confirm one to override the label.",
        v.flags.likely_decoys, true)];
      if (v.flags.rejected.length) {
        out.push(flagPanel("REJECTED by analyst", "Rejected through review in this session.",
                           v.flags.rejected, false));
      }
      return out;
    },
    stego: function (v) {
      var out = [analyzerPanel(v, ["stego.", "image.palette", "image.animation"], "Steganography analyzers")];
      out.push(findingsPanel(v, ["stego"], "Steganography findings",
        "Each finding carries its extraction configuration in the evidence report."));
      var notRun = panel("Not executed in this build",
        "Palette analysis runs only on indexed images. JPEG payload tools are not implemented.");
      out.push(notRun);
      return out;
    },
    clues: function (v) {
      var phrases = panel("Expected phrases and clue matches", "Clues to review. These are not flags.");
      phrases.appendChild(table(["Phrase", "Method", "Encoding", "Offset", "Context", "Confidence", "Ref"],
        v.phrases.map(function (p) {
          return [p.phrase, p.method, p.encoding, p.offset, p.context, p.confidence, p.evidence_ref];
        })));
      return [phrases,
              findingsPanel(v, ["text", "decoding"], "Text and decoded data findings"),
              analyzerPanel(v, ["text.", "decoding."], "Text analyzers")];
    },
    metadata: function (v) {
      return [findingsPanel(v, ["metadata"], "Metadata findings",
                            "Metadata is reported as found. Its presence does not prove hidden data."),
              analyzerPanel(v, ["metadata."], "Metadata analyzers")];
    },
    embedded: function (v) {
      var p = panel("Embedded files and payloads", "Detected signatures and appended data. Nothing is executed.");
      p.appendChild(table(["Type", "Contents", "Offset", "Length", "Status", "Ref"], v.embedded.map(function (f) {
        var ev = f.evidence || {};
        var zips = (ev.zip_entries && ev.zip_entries.length) ? ev.zip_entries.join(", ") : "-";
        return [ev.signature || f.kind, zips, f.offset, f.length, "Detected, not extracted", f.id];
      })));
      return [p, analyzerPanel(v, ["carving."], "Carving analyzers")];
    },
    ocr: function (v) {
      var rows = analyzerRows(v, ["image.ocr_qr"]);
      var notice = panel("OCR and QR analysis",
        "Optional. Needs the vision extra and Tesseract, and is enabled with vision_analysis_enabled.");
      if (rows.length && rows[0].status === "skipped") {
        notice.appendChild(el("p", "notexec", rows[0].message || "Not executed."));
      }
      var ocrFindings = v.findings.filter(function (f) { return String(f.kind).indexOf("ocr_") === 0; });
      var p = panel("OCR and QR findings");
      p.appendChild(table(["Ref", "Kind", "Confidence", "Offset", "Description"], ocrFindings.map(function (f) {
        return [f.id, f.kind, f.confidence_label || "-", f.offset, f.description];
      })));
      return [notice, p, analyzerPanel(v, ["image.ocr_qr"], "OCR and QR analyzer")];
    },
    forensic: function (v) {
      var out = [];
      var identity = v.properties["image.identity"] || {};
      out.push(kvTable([["SHA-256", v.sha256], ["File size (bytes)", v.size], ["Format", v.format],
                        ["Signature format", v.signature_format], ["Dimensions", v.dimensions],
                        ["Colour mode", v.mode], ["Frame count", v.frames]]));
      if (Object.keys(identity).length) {
        out.push(kvTable(Object.keys(identity).map(function (k) { return [k, identity[k]]; })));
      }
      out.push(findingsPanel(v, ["structure", "identity"], "Structure findings",
        "Structure is parsed for PNG, JPEG and BMP. Other formats are identified by signature."));
      out.push(analyzerPanel(v, ["image.", "binary."], "Image and binary analyzers"));
      var lim = panel("Limitations");
      v.limitations.forEach(function (l) { lim.appendChild(el("div", null, "- " + l)); });
      out.push(lim);
      return out;
    },
    logs: function (v) {
      var select = el("select", "logfilter");
      ["ALL"].concat(LEVELS).forEach(function (l) {
        var o = el("option", null, l); o.value = l; select.appendChild(o);
      });
      var holder = el("div");
      function draw() {
        while (holder.firstChild) { holder.removeChild(holder.firstChild); }
        var want = select.value;
        var rows = v.execution_log.filter(function (e) { return want === "ALL" || e.level === want; });
        holder.appendChild(table(["Timestamp", "Level", "Module", "Operation", "Message", "Status"],
          rows.map(function (e) {
            return [e.ts, e.level, e.module, e.operation, e.message, e.status];
          })));
      }
      select.addEventListener("change", draw);
      draw();
      var p = panel("Scan execution log", "Entries in the order they happened.");
      p.appendChild(select);
      p.appendChild(holder);
      return [p];
    }
  };

  // ------------------------------------------------------------- reports and about
  function renderExport() {
    var has = !!state.view;
    $("exportEmpty").classList.toggle("hidden", has);
    $("exportBody").classList.toggle("hidden", !has);
    if (!has) { return; }
    var id = state.jobId;
    $("linkHtml").href = "/api/scans/" + id + "/report/html";
    $("linkJson").href = "/api/scans/" + id + "/report/json";
    $("linkPdf").href = "/api/scans/" + id + "/report/pdf";
    $("evFile").textContent = state.view.file_name;
    $("evHash").textContent = state.view.sha256 || "-";
  }

  // ------------------------------------------------------------- wiring
  function wire() {
    document.querySelectorAll(".navbtn").forEach(function (b) {
      b.addEventListener("click", function () { showPage(b.getAttribute("data-page")); });
    });
    document.querySelectorAll("[data-profile]").forEach(function (a) {
      a.addEventListener("click", function (event) {
        event.preventDefault();
        var profile = a.getAttribute("data-profile");
        var parts = profile === "linkedin"
          ? ["https:", "", "www.linkedin.com", "in", "saadullah-abdul-wahid-142643393"]
          : ["https:", "", "x.com", "saadullahabd"];
        window.open(parts.join("/"), "_blank", "noopener,noreferrer");
      });
    });

    var drop = $("dropzone");
    ["dragenter", "dragover"].forEach(function (ev) {
      drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add("over"); });
    });
    ["dragleave", "drop"].forEach(function (ev) {
      drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove("over"); });
    });
    drop.addEventListener("drop", function (e) {
      if (e.dataTransfer && e.dataTransfer.files.length) { onFileChosen(e.dataTransfer.files[0]); }
    });
    $("fileInput").addEventListener("change", function (e) { onFileChosen(e.target.files[0] || null); });
    $("btnStart").addEventListener("click", startScan);

    $("btnPause").addEventListener("click", function () {
      state.paused = !state.paused;
      $("btnPause").textContent = state.paused ? "Resume display" : "Pause display";
      if (!state.paused) { state.pendingWhilePaused = 0; rebuildConsole(); }
      updatePausedNote();
    });
    $("btnClear").addEventListener("click", function () {
      state.lines = []; state.pendingWhilePaused = 0; $("console").textContent = "";
      updatePausedNote();
    });
    $("btnCopyLog").addEventListener("click", function () {
      if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(consoleText()); }
    });
    $("btnExportLog").addEventListener("click", function () {
      var blob = new Blob([consoleText() + "\n"], {type: "text/plain"});
      var a = el("a");
      a.href = URL.createObjectURL(blob);
      a.download = "ciphersight_console.txt";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    });
    $("consoleSearch").addEventListener("input", rebuildConsole);
    $("autoscroll").addEventListener("change", rebuildConsole);
    document.querySelectorAll('input[data-level]').forEach(function (box) {
      box.addEventListener("change", rebuildConsole);
    });
    $("btnCopyHash").addEventListener("click", function () {
      if (state.view && navigator.clipboard) { navigator.clipboard.writeText(state.view.sha256 || ""); }
    });
  }

  wire();
  showPage("dashboard");
})();
