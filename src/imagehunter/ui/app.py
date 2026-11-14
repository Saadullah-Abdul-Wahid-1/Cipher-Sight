"""Desktop window (Tkinter, standard library).

The window handles interaction only. Scans run in a worker thread through run_scan(), the same
code path as the CLI. Events cross from the worker to the window through a thread-safe queue,
and the window drains that queue on a timer. The GUI thread never runs analysis.

tkinter is imported inside run_gui(), so the package works where Tk is missing.
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

from imagehunter import __version__

from imagehunter.services.report_data import build_view
from imagehunter.ui.console import ConsoleModel

LEVEL_COLOURS = {
    "INFO": "#00e5ff", "SUCCESS": "#00ff66", "WARNING": "#ffaa00",
    "ERROR": "#ff2a55", "FINDING": "#d580ff", "DEBUG": "#5c6b82",
}
BG = "#07090e"
PANEL = "#0d111a"
CARD = "#111726"
TEXT = "#e0e6ed"
MUTED = "#8b9bb4"


def scan_file(path: str, workspace_base: str | None = None, on_event=None, verifications=None) -> dict:
    """Run a scan and return the summary dict. Used by the window and by tests."""
    from imagehunter.config.settings import load_settings
    from imagehunter.core.pipeline import run_scan

    settings = load_settings()
    base = workspace_base or str(Path.cwd() / settings.workspace_root)
    return run_scan(path, settings=settings, workspace_base=base, on_event=on_event,
                    verifications=verifications).to_dict()


def open_path(path: Path) -> None:
    if os.name == "nt":
        os.startfile(str(path))  # noqa: S606 - opens a folder or report the user chose to open
    else:
        subprocess.Popen(["xdg-open", str(path)])


def run_gui() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, scrolledtext, ttk
    except ImportError:
        print("tkinter is not available. Reinstall Python from python.org with the Tcl/Tk option ticked.",
              file=sys.stderr)
        return 1

    console = ConsoleModel()
    events_q: "queue.Queue" = queue.Queue()
    results_q: "queue.Queue" = queue.Queue()
    state = {"file": None, "summary": None, "running": False, "paused": False}

    root = tk.Tk()
    root.title(f"CipherSight {__version__}")
    root.geometry("1240x900")
    root.minsize(820, 620)
    root.configure(bg=BG)

    # ------------------------------------------------------------ product identity
    brand = tk.Frame(root, bg="#0b121b", padx=18, pady=12,
                     highlightbackground="#1b3440", highlightthickness=1)
    brand.pack(fill="x", padx=12, pady=(12, 4))
    brand_mark = tk.Frame(brand, bg="#00ff66", width=4, height=38)
    brand_mark.pack(side="left", padx=(0, 12))
    brand_mark.pack_propagate(False)
    brand_text = tk.Frame(brand, bg="#0b121b")
    brand_text.pack(side="left", fill="x", expand=True)
    tk.Label(brand_text, text="CIPHERSIGHT", bg="#0b121b", fg="#e8fff2",
             font=("Segoe UI", 17, "bold")).pack(anchor="w")
    tk.Label(brand_text, text="IMAGE FORENSICS  /  CTF INVESTIGATION",
             bg="#0b121b", fg="#58c9d8", font=("Segoe UI", 8, "bold")).pack(anchor="w")
    tk.Label(brand, text=f"v{__version__}", bg="#0b121b", fg=MUTED,
             font=("Segoe UI", 9)).pack(side="right", padx=(8, 12))
    tk.Button(brand, text="About", command=lambda: show_about(), bg="#14232b", fg="#9debd0",
              activebackground="#1b3540", activeforeground="#ffffff", relief="flat",
              padx=14, pady=7, cursor="hand2").pack(side="right")

    # ------------------------------------------------------------ top: target and progress
    top = tk.Frame(root, bg=BG, padx=12, pady=10)
    top.pack(fill="x")
    path_var = tk.StringVar(value="No image selected.")
    status_var = tk.StringVar(value="Choose an image to begin.")
    progress_var = tk.StringVar(value="")
    scan_btn = tk.Button(top, text="Scan", width=12, state="disabled")
    tk.Button(top, text="Choose image...", width=16,
              command=lambda: choose()).pack(side="left")
    scan_btn.pack(side="left", padx=8)
    tk.Label(top, textvariable=path_var, bg=BG, fg=TEXT, anchor="w").pack(side="left", fill="x", expand=True)

    prog = tk.Frame(root, bg=BG, padx=12)
    prog.pack(fill="x")
    bar = ttk.Progressbar(prog, mode="determinate", maximum=100)
    bar.pack(fill="x", pady=(0, 2))
    tk.Label(prog, textvariable=progress_var, bg=BG, fg=MUTED, anchor="w").pack(fill="x")

    # ------------------------------------------------------------ console panel
    cframe = tk.LabelFrame(root, text="LIVE FORENSIC SCAN CONSOLE", bg=PANEL, fg="#00ff66",
                           padx=8, pady=6, font=("Consolas", 10, "bold"))
    cframe.pack(fill="both", expand=True, padx=12, pady=(6, 4))

    tools = tk.Frame(cframe, bg=PANEL)
    tools.pack(fill="x", pady=(0, 6))
    level_vars = {}
    for lvl in ("INFO", "SUCCESS", "WARNING", "ERROR", "FINDING", "DEBUG"):
        var = tk.BooleanVar(value=lvl != "DEBUG")
        level_vars[lvl] = var
        tk.Checkbutton(tools, text=lvl, variable=var, bg=PANEL, fg=LEVEL_COLOURS[lvl],
                       selectcolor=CARD, activebackground=PANEL, activeforeground=LEVEL_COLOURS[lvl],
                       command=lambda: render_all()).pack(side="left", padx=2)
    search_var = tk.StringVar()
    search_entry = tk.Entry(tools, textvariable=search_var, bg=CARD, fg=TEXT, insertbackground=TEXT,
                            relief="flat", width=24)
    search_entry.pack(side="left", padx=(12, 4))
    tk.Label(tools, text="search", bg=PANEL, fg=MUTED).pack(side="left")
    autoscroll = tk.BooleanVar(value=True)
    tk.Checkbutton(tools, text="Auto-scroll", variable=autoscroll, bg=PANEL, fg=MUTED,
                   selectcolor=CARD, activebackground=PANEL).pack(side="right", padx=4)
    pause_btn = tk.Button(tools, text="Pause", width=8, command=lambda: toggle_pause())
    pause_btn.pack(side="right", padx=2)

    text = scrolledtext.ScrolledText(cframe, wrap="word", font=("Consolas", 10), bg=BG, fg=TEXT,
                                     insertbackground=TEXT, relief="flat", height=18, state="disabled")
    text.pack(fill="both", expand=True)
    for lvl, colour in LEVEL_COLOURS.items():
        text.tag_configure(lvl, foreground=colour)

    ctools = tk.Frame(cframe, bg=PANEL)
    ctools.pack(fill="x", pady=(6, 0))
    for label, cmd in [("Clear console", lambda: clear_console()),
                       ("Copy logs", lambda: copy_logs()),
                       ("Export logs as TXT", lambda: export_logs())]:
        tk.Button(ctools, text=label, command=cmd).pack(side="left", padx=2)
    tk.Label(ctools, textvariable=status_var, bg=PANEL, fg=MUTED, anchor="e").pack(side="right")

    # ------------------------------------------------------------ results dashboard
    dash = tk.LabelFrame(root, text="SCAN RESULTS", bg=PANEL, fg="#00e5ff", padx=8, pady=6,
                         font=("Consolas", 10, "bold"))
    dash.pack(fill="x", padx=12, pady=(4, 12))
    metric_vars = {}
    for i, (key, label) in enumerate([
            ("modules_executed", "Modules executed"), ("total_findings", "Total findings"),
            ("confirmed_flags", "Confirmed flags"), ("flag_candidates", "Unverified candidates"),
            ("phrase_matches", "Expected phrase matches"), ("embedded_items", "Embedded items"),
            ("warnings", "Warnings"), ("errors", "Errors"), ("duration_seconds", "Scan duration (s)")]):
        var = tk.StringVar(value="-")
        metric_vars[key] = var
        cell = tk.Frame(dash, bg=CARD, padx=8, pady=4)
        cell.grid(row=i // 5, column=i % 5, sticky="nsew", padx=3, pady=3)
        tk.Label(cell, textvariable=var, bg=CARD, fg="#00ff66", font=("Consolas", 13, "bold")).pack()
        tk.Label(cell, text=label, bg=CARD, fg=MUTED, font=("Consolas", 8)).pack()
    for c in range(5):
        dash.grid_columnconfigure(c, weight=1)
    actions = tk.Frame(dash, bg=PANEL)
    actions.grid(row=3, column=0, columnspan=5, sticky="ew", pady=(6, 0))
    btn_state = {}
    for label, cmd in [("Open HTML Report", lambda: open_html()),
                       ("Open PDF Report", lambda: open_pdf()),
                       ("Export JSON Report", lambda: export_json()),
                       ("View Confirmed Flags", lambda: show_view("Confirmed flags", "confirmed")),
                       ("View Flag Candidates", lambda: show_view("Flag candidates", "candidates")),
                       ("View Expected Phrases", lambda: show_view("Expected phrase matches", "phrases")),
                       ("Open Evidence Folder", lambda: open_evidence())]:
        b = tk.Button(actions, text=label, command=cmd, state="disabled")
        b.pack(side="left", padx=3)
        btn_state[label] = b

    # ------------------------------------------------------------ behaviour
    def show_about():
        win = tk.Toplevel(root)
        win.title("About CipherSight")
        win.geometry("520x390")
        win.resizable(False, False)
        win.configure(bg=BG)
        tk.Label(win, text="CIPHERSIGHT", bg=BG, fg="#00ff66",
                 font=("Segoe UI", 22, "bold")).pack(pady=(24, 4))
        tk.Label(win, text=f"Version {__version__}  |  Offline image forensics & CTF investigation",
                 bg=BG, fg=TEXT, font=("Segoe UI", 9)).pack(pady=(0, 18))
        tk.Label(win, text="Developer", bg=BG, fg=MUTED, font=("Segoe UI", 9, "bold")).pack()
        tk.Label(win, text="Saadullah Abdul Wahid", bg=BG, fg=TEXT,
                 font=("Segoe UI", 12, "bold")).pack(pady=(2, 12))
        for label, url in (("LinkedIn", "https://www.linkedin.com/in/saadullah-abdul-wahid-142643393"),
                           ("X (Twitter)", "https://x.com/saadullahabd")):
            link = tk.Label(win, text=label, bg=BG, fg="#58c9d8", cursor="hand2",
                            font=("Segoe UI", 10, "underline"))
            link.pack(pady=2)
            link.bind("<Button-1>", lambda _event, target=url: webbrowser.open(target))
        feedback = ("If you like CipherSight, please share your feedback, suggestions, bug reports, "
                    "and ideas for improvement. Your feedback helps us make CipherSight better.")
        tk.Label(win, text=feedback, bg=PANEL, fg=TEXT, wraplength=440, justify="center",
                 padx=16, pady=14, font=("Segoe UI", 9)).pack(fill="x", padx=22, pady=22)
        tk.Button(win, text="Close", command=win.destroy, bg="#15352a", fg="#dffff0",
                  activebackground="#1b4938", relief="flat", padx=20, pady=7).pack()

    def choose():
        chosen = filedialog.askopenfilename(
            title="Choose an image",
            filetypes=[("Images and files", "*.*"), ("PNG", "*.png"), ("JPEG", "*.jpg *.jpeg"),
                       ("BMP", "*.bmp"), ("GIF", "*.gif")])
        if chosen:
            state["file"] = chosen
            path_var.set(chosen)
            scan_btn.config(state="normal")
            status_var.set("Ready. Press Scan.")

    def set_buttons(enabled: bool):
        """Result buttons are usable only after a scan produced a summary."""
        on = enabled and state["summary"] is not None
        for b in btn_state.values():
            b.config(state="normal" if on else "disabled")

    def start_scan():
        if not state["file"] or state["running"]:
            return
        state["running"] = True
        state["summary"] = None
        scan_btn.config(state="disabled")
        set_buttons(False)
        for var in metric_vars.values():
            var.set("-")
        status_var.set("Scanning. The file is never modified.")
        bar["value"] = 0
        progress_var.set("Starting...")

        def on_event(event):
            events_q.put(event.to_dict())

        def worker():
            try:
                results_q.put(("ok", scan_file(state["file"], on_event=on_event)))
            except Exception as exc:  # shown in the console and status line, never a silent crash
                results_q.put(("error", f"{type(exc).__name__}: {exc}"))

        threading.Thread(target=worker, daemon=True).start()

    def render_line(e):
        text.insert("end", ConsoleModel.format_line(e) + "\n", (e.get("level"),))

    def render_all():
        text.config(state="normal")
        text.delete("1.0", "end")
        for e in console.visible(selected_levels(), search_var.get()):
            render_line(e)
        text.config(state="disabled")
        if autoscroll.get():
            text.see("end")

    def selected_levels():
        return {lvl for lvl, var in level_vars.items() if var.get()}

    def append_visible(e):
        if state["paused"]:
            return
        if e.get("level") not in selected_levels():
            return
        q = search_var.get().strip().lower()
        if q and q not in ConsoleModel.format_line(e).lower():
            return
        text.config(state="normal")
        render_line(e)
        text.config(state="disabled")
        if autoscroll.get():
            text.see("end")

    def toggle_pause():
        state["paused"] = not state["paused"]
        pause_btn.config(text="Resume" if state["paused"] else "Pause")
        if not state["paused"]:
            render_all()
        status_var.set("Display paused. Events are still recorded." if state["paused"] else "Display resumed.")

    def clear_console():
        console.clear()
        render_all()

    def copy_logs():
        data = console.export_text(selected_levels(), search_var.get())
        root.clipboard_clear()
        root.clipboard_append(data)
        status_var.set("Copied visible console lines to the clipboard.")

    def export_logs():
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="imagehunter_console.txt",
                                            filetypes=[("Text", "*.txt")])
        if path:
            n = console.export_txt(path, selected_levels(), search_var.get())
            status_var.set(f"Exported {n} line(s) to {path}")

    def take_events(limit=None):
        """Move queued events into the console. limit=None drains everything."""
        taken = 0
        while limit is None or taken < limit:
            try:
                e = events_q.get_nowait()
            except queue.Empty:
                break
            taken += 1
            console.add(e)
            append_visible(e)
            if e.get("percent") is not None:
                bar["value"] = e["percent"]
            progress_var.set(f"Module: {e.get('module')}   Operation: {e.get('operation')}   "
                             f"Status: {e.get('status')}   Progress: {e.get('percent', '-')}%")

    def drain():
        # Events are always queued before the result, so the console must receive every event
        # before the result is handled. Otherwise the window can report "finished" while the
        # last lines (for example "HTML report written") are still in the queue.
        take_events(limit=200)
        try:
            kind, payload = results_q.get_nowait()
        except queue.Empty:
            pass
        else:
            take_events()                      # everything the worker emitted, before the result
            state["running"] = False
            scan_btn.config(state="normal")
            if kind == "ok":
                state["summary"] = payload
                v = build_view(payload)
                for key, var in metric_vars.items():
                    value = v["metrics"][key]
                    var.set("-" if value is None else str(value))
                status_var.set(f"Scan finished: {payload['status']}")
            else:
                status_var.set("Scan failed. See the console for details.")
                messagebox.showerror("ImageHunter", f"The scan could not complete.\n\n{payload}")
            set_buttons(True)
        root.after(50, drain)

    def summary_or_warn():
        if not state["summary"]:
            messagebox.showinfo("ImageHunter", "Run a scan first.")
            return None
        return state["summary"]

    def open_html():
        s = summary_or_warn()
        if s:
            p = Path(s["workspace"]) / "reports" / "scan_report.html"
            if p.is_file():
                open_path(p)
            else:
                messagebox.showwarning("ImageHunter", f"HTML report not found:\n{p}")

    def open_pdf():
        s = summary_or_warn()
        if s:
            p = Path(s["workspace"]) / "reports" / "scan_report.pdf"
            if p.is_file():
                open_path(p)
            else:
                messagebox.showwarning("ImageHunter", f"PDF report not available. Install the optional ReportLab dependency:\n{p}")

    def export_json():
        s = summary_or_warn()
        if not s:
            return
        src = Path(s["workspace"]) / "reports" / "scan_report.json"
        dest = filedialog.asksaveasfilename(defaultextension=".json", initialfile="scan_report.json",
                                            filetypes=[("JSON", "*.json")])
        if dest and src.is_file():
            Path(dest).write_bytes(src.read_bytes())
            status_var.set(f"JSON report exported to {dest}")

    def open_evidence():
        s = summary_or_warn() if state["summary"] else None
        folder = Path(s["workspace"]) / "evidence" if s else Path.cwd() / "workspace"
        folder.mkdir(parents=True, exist_ok=True)
        open_path(folder)

    def show_view(title: str, which: str):
        s = summary_or_warn()
        if not s:
            return
        v = build_view(s)
        if which == "confirmed":
            rows = v["flags"]["confirmed"]
            body = "\n\n".join(f"{r['value']}  [{r['status']}]  {r['technique']}  ref {r['evidence_ref']}"
                               for r in rows) or "No confirmed flags found."
        elif which == "candidates":
            rows = v["flags"]["candidates"]
            body = "\n\n".join(f"{r['value']}  [{r['status']}]  {r['technique']}  ref {r['evidence_ref']}"
                               for r in rows) or "No unverified flag candidates."
        else:
            rows = v["phrases"]
            body = "\n\n".join(f"{r['phrase']}  [{r['match']}, {r['confidence']}]  offset {r['offset']}  "
                               f"ref {r['evidence_ref']}\n  context: {r['context']}" for r in rows) \
                or "No expected phrase matches."
        win = tk.Toplevel(root)
        win.title(f"ImageHunter: {title}")
        win.geometry("820x480")
        win.configure(bg=BG)
        box = scrolledtext.ScrolledText(win, wrap="word", bg=BG, fg=TEXT, font=("Consolas", 10))
        box.pack(fill="both", expand=True, padx=8, pady=8)
        box.insert("1.0", body)
        box.config(state="disabled")

    scan_btn.config(command=start_scan)
    search_var.trace_add("write", lambda *_: render_all())
    set_buttons(False)
    root.after(50, drain)
    root.mainloop()
    return 0
