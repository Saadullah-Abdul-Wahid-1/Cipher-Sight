# Evidence-driven follow-up investigation (v0.12.0)

ImageHunter retains its established first-pass analyzer order for compatibility. After
those analyzers finish, the follow-up engine creates a bounded task queue from decoded
file outputs and high-confidence signatures located beyond a parsed image structure.

## What is queued

- Decoded outputs whose magic bytes identify a supported file/archive format.
- Decoded text outputs containing a configured CTF flag-shaped token.
- High-confidence appended embedded files (for example, a ZIP appended after PNG IEND).
- Safe regular files extracted from supported ZIP archives, including nested ZIPs.

## Follow-up analyzer selection

Every derived artifact receives strings, binary-structure and embedded-signature checks.
Recognized image artifacts additionally receive image identity, metadata, standard LSB
and bounded advanced pixel-domain analysis. A direct flag-shaped match in a derived
artifact is recorded as a **Medium-confidence candidate**, never as a verified flag.

## Safety limits

- At most 50 derived artifacts per scan.
- At most 16 MiB per derived artifact.
- At most 32 MiB total derived bytes.
- At most 50 entries per ZIP archive.
- At most 3 nested archive levels.
- ZIP path traversal, absolute paths, symlinks, encrypted members, oversized members and
  suspicious compression ratios are rejected.
- Extracted content is written as data only and is never executed.
- Duplicate content is suppressed by SHA-256.
- Existing investigation cancellation and time-budget checks are applied between tasks
  and analyzers; a currently executing analyzer cannot be forcibly interrupted.

## Provenance

Each derived artifact has a stable per-scan ID, SHA-256, parent artifact ID, extraction
origin and stored path. Findings produced from it reference that artifact ID. The evidence
graph includes `derived_artifact` nodes and `extracted_from` edges.

## Scope and limitations

This is a bounded follow-up engine, not a claim of universal autonomous discovery. It
currently expands decoded outputs and appended embedded signatures, and safely enumerates
ZIP members. It does not decrypt encrypted archives, execute payloads, fetch URLs, parse
all archive formats, or guarantee recovery of data that is absent or irreversibly lost.
