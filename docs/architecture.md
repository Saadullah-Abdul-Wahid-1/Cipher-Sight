# Architecture (v0.3.0)

Pipeline: validate → workspace → hash → read-only copy → analyzers (in order) → verify original → summary.

- **Analyzer contract** (`analyzers/base.py`): `run(ctx) -> AnalyzerResult`. Input is an
  `AnalyzerContext` (artifact, bytes, settings, shared dict). Analyzers must not raise for malformed
  input and must not write to disk.
- **Order** (`analyzers/__init__.py`): identity → binary structure → embedded carving → strings.
  The binary analyzer publishes `structure_end` in `ctx.shared`, and carving uses it to tell hits
  inside the image structure (Low) from hits after it (High).
- **Pipeline isolation** (`core/pipeline.py`): an analyzer exception is recorded as `status: error`
  and the scan continues. The original is re-hashed at the end; a change aborts the scan.
- **Models**: `Finding` (confidence labels High/Medium/Low), `Artifact` (role original|derived,
  parent link required for derived), `ScanSummary` (schema 1.0).
- **Extension points**: add an analyzer class and register it in `default_analyzers()`. Derived
  artifacts (Phase 5 carving) will set `parent_id` to the source artifact.

Deviation from the blueprint: defaults live under `src/imagehunter/config/` (not a root `config/`),
so they ship inside the installed package.
