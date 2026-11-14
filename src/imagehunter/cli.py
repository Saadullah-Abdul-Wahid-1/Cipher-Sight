"""Command-line interface.

  imagehunter scan FILE       run a scan and print the JSON summary (stdout)
  imagehunter gui             open the desktop window
  imagehunter web             start the local web interface (127.0.0.1 only)
  imagehunter check-deps      Python packages and optional tool status
  imagehunter check-tools     optional tool status table

Exit codes: 0 success, 1 environment problem (check-deps), 2 input or settings error.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys

from imagehunter import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="imagehunter",
                                     description="Offline image forensics and CTF steganography toolkit.")
    parser.add_argument("--version", action="version", version=f"imagehunter {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan an image and print a JSON summary")
    scan.add_argument("path", help="image file to scan (never modified)")
    scan.add_argument("--workdir", default=None, help="workspace base directory (default from settings)")
    scan.add_argument("--settings", default=None, help="JSON settings file overriding defaults")
    scan.add_argument("--log-level", default=None, choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    scan.add_argument("--mode", choices=["quick", "standard", "deep", "auto"], default=None,
                      help="investigation depth (default from settings: standard)")
    scan.add_argument("--smart-words", action="store_true",
                      help="enable word and phrase candidates (on by default in settings)")
    scan.add_argument("--min-score", type=int, default=None, metavar="0-100",
                      help="show only smart candidates with at least this review score")
    scan.add_argument("--export-candidates", metavar="FILE",
                      help="write candidate values as a TXT wordlist (contains sensitive text)")
    scan.add_argument("--export-candidates-json", metavar="FILE",
                      help="write full candidate records with provenance as JSON (contains sensitive text)")

    sub.add_parser("gui", help="open the desktop window")
    web = sub.add_parser("web", help="start the local web interface on 127.0.0.1")
    web.add_argument("--port", type=int, default=8765, help="port to listen on (default 8765)")
    web.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    sub.add_parser("check-deps", help="show Python packages and external tool status")
    sub.add_parser("check-tools", help="show external tool status only")
    return parser


def cmd_scan(args) -> int:
    from imagehunter.config.settings import ConfigError, load_settings
    from imagehunter.core.logging_setup import setup_logging
    from imagehunter.core.pipeline import run_scan
    from imagehunter.core.validation import ValidationError
    from imagehunter.services.evidence_service import EvidenceError

    try:
        settings = load_settings(args.settings)
        if args.mode is not None:
            settings = dataclasses.replace(settings, investigation_mode=args.mode)
        if args.min_score is not None:
            if not 0 <= args.min_score <= 100:
                raise ConfigError("--min-score must be between 0 and 100")
            settings = dataclasses.replace(settings, smart_min_candidate_score=args.min_score)
        exporting = bool(args.export_candidates or args.export_candidates_json)
        if args.smart_words or exporting or args.min_score is not None:
            settings = dataclasses.replace(settings, smart_words_enabled=True)
        settings.validate()
    except ConfigError as exc:
        print(f"settings error: {exc}", file=sys.stderr)
        return 2
    setup_logging(args.log_level or settings.log_level)
    try:
        summary = run_scan(args.path, settings=settings, workspace_base=args.workdir)
    except (ValidationError, EvidenceError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    data = summary.to_dict()
    try:
        from imagehunter.analyzers.password_intelligence.exporter import write_json, write_txt
        if args.export_candidates:
            n = write_txt(args.export_candidates, data)
            print(f"exported {n} candidate value(s) to {args.export_candidates}", file=sys.stderr)
        if args.export_candidates_json:
            n = write_json(args.export_candidates_json, data)
            print(f"exported {n} candidate record(s) to {args.export_candidates_json}", file=sys.stderr)
    except OSError as exc:
        print(f"export failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0


def cmd_gui(_args) -> int:
    import traceback
    from pathlib import Path
    from imagehunter.ui.app import run_gui
    try:
        return run_gui()
    except Exception:  # windowed launch has no console, so record the error in a file
        log = Path.cwd() / "workspace" / "gui_error.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(traceback.format_exc(), encoding="utf-8")
        return 1


def cmd_web(args) -> int:
    from pathlib import Path
    from imagehunter.config.settings import ConfigError, load_settings
    from imagehunter.core.logging_setup import setup_logging
    from imagehunter.web.server import serve
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"settings error: {exc}", file=sys.stderr)
        return 2
    setup_logging(settings.log_level)
    base = Path.cwd() / settings.workspace_root
    return serve(args.port, open_browser=not args.no_browser, base_dir=base, settings=settings)


def cmd_check_deps(_args) -> int:
    from imagehunter.services.dependency_service import all_required_ok, report_lines
    print("\n".join(report_lines()))
    return 0 if all_required_ok() else 1


def cmd_check_tools(_args) -> int:
    from imagehunter.integrations.registry import check_all
    for s in check_all():
        state = "found" if s.found else "not found"
        print(f"{s.name:<13} {state:<10} {s.note}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"scan": cmd_scan, "gui": cmd_gui, "web": cmd_web, "check-deps": cmd_check_deps,
                "check-tools": cmd_check_tools}
    try:
        return handlers[args.command](args)
    except BrokenPipeError:
        # Output was piped into a command that stopped reading (e.g. `| head`). Exit quietly.
        import os
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0
