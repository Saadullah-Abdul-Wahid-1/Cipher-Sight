# Autonomous investigation (v0.11.0)

## What runs
`python main.py scan image.png --mode <quick|standard|deep|auto>` (default from settings: `standard`).

1. Identify the file and check its size and hash (existing behaviour).
2. **Planner** (`core/planner.py`): inspects structure and signatures only (no pixel decoding). It records
   triggers with evidence: appended data, embedded signatures after the image structure, extension mismatch,
   unknown format, parser findings. It returns the settings the analyzers will use.
3. Analyzers run in a fixed order (unchanged). Each analyzer uses the planner's settings.
4. Recursive decoding inspects decoded artifacts: their decode chains are recorded, and file signatures found
   inside them (for example ZIP) are reported as `decoded_file_signature`.
5. **Evidence graph** (`summary.evidence_graph`): artifact, decoded artifact and finding nodes; edges only from
   recorded relations (parent artifact to decoded artifact by the decode step; artifact to finding by the
   analyzer that produced it).
6. Report and summary, as before.

## Modes
| Mode | Behaviour |
|---|---|
| quick | smart words off, decoding off, single-channel LSB, no leads |
| standard | current defaults (identical results to v0.10) |
| deep | 3-channel LSB streams, unknown-prefix leads, decoding depth 4, 6000 nodes, 20 MB XOR budget |
| auto | standard; escalated to deep when a trigger fires |

Deep mode on a 640x480 image takes about 50 seconds (3-channel streams and leads). Standard takes about 3 seconds.

## Controls
- `investigation_time_budget_seconds` (default 0 = none). When elapsed time exceeds it, remaining analyzers are
  marked `skipped` with the reason. The scan finishes with status `completed_with_warnings`.
- Cancellation: the pipeline accepts a `threading.Event` (`run_scan(..., cancel_event=...)`). When set, remaining
  analyzers are marked `skipped` ("cancelled by user") and the scan status is `cancelled`. Cancellation is checked
  between analyzers only; a running analyzer is not interrupted.

## Evidence classes (in the graph and in `services/evidence_graph.py`)
- raw evidence: the input and decoded bytes.
- deterministic: structure checks, embedded signatures, decoded file signatures, metadata structure.
- heuristic: pattern matches (flag candidates, leads, expected phrases).
- ai_hypothesis: reserved. No AI component exists in this build, so none are produced.
- verified: reserved for analyst confirmation. Never set automatically.

## Limitations
- The analyzer order is fixed. Mode and triggers change settings, not the set of analyzers.
- Cancellation and time budgets act between analyzers, not inside them.
- The evidence graph has no edges for findings whose source artifact is not in the decoded list (they point to A001).
- Decoded artifacts are listed up to 50 in the graph; `artifacts_truncated` says when more exist.
- No OCR, no image transformations, no carving to disk, no Rust, no web dashboard changes, no API versioning in this release.
