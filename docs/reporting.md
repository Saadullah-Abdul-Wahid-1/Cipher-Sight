# Reports and live console (v0.5.0)

## Outputs per scan
Written to `workspace/<scan_id>/reports/` after every completed scan:

| File | Content |
|---|---|
| `scan_report.json` | Full machine-readable summary, including the execution log. |
| `scan_summary.json` | Same content as `scan_report.json`, kept under its v0.3 name for existing scripts. |
| `scan_report.html` | Standalone HTML forensic report, generated from the same summary dict. No external resources. |

## How the report decides what is a flag
Every regex or pattern match starts as a **Candidate**. Nothing automatic sets a flag to **Confirmed**.
- **Confirmed**: an analyst decision (passed as `verifications={"THM{...}": "confirmed"}`) or a
  future explicit verification method.
- **Rejected**: an analyst decision marking it a false positive.
- If no flag is confirmed, the report says `No confirmed flags found.`

## Expected phrases
Set your own clue phrases in a settings file:

    {"expected_phrases": ["flag", "secret", "signal"]}

Rules: exact-case match is High confidence, case-insensitive match is Medium. Phrase matches are clues,
not flags, and they are listed in their own section. With no phrases configured, the report says so.

## Modules that did not run
The report never claims a module ran unless it did. Modules not yet built (metadata, decoders,
payload extraction, palette, JPEG tools) appear under "Modules not executed in this scan" with the reason.

## Live console (GUI)
- Every event comes from a real pipeline step: validation, hash, copy, each analyzer, each finding,
  each warning or error, integrity re-hash, report writing.
- Success is only reported after the operation completed. A failed analyzer gets an ERROR line, not a success.
- The worker thread puts events on a queue; the window drains it about every 50 ms. The GUI thread never runs analysis.
- Controls: level filters, search, auto-scroll, pause and resume (events keep being recorded while paused),
  clear, copy visible lines, export visible lines as TXT.
- Progress bar and status line show current module, operation, status and percent.

## Consistency rule
HTML, the GUI dashboard and the tests all read counts from `services/report_data.build_view()`.
Tests check that HTML counts equal the JSON model's counts.

## Known limits
- The execution log in the saved report stops at the "Generate reports" step. Messages about writing
  the reports are visible in the live console, not in the saved log.
- The GUI is Tkinter, not PySide6. Layout and mouse behaviour are only checked by a headless wiring test
  (`tests/integration/test_gui_logic_headless.py`) and still need a manual run on Windows.
- No manual verification UI yet. Confirming a flag currently needs the `verifications` argument in code.
