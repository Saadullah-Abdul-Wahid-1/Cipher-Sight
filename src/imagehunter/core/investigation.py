"""Evidence-driven follow-up investigation of decoded and carved artifacts.

The primary analyzers still run in their established order. Their discoveries enqueue
bounded follow-up tasks. Derived files are never executed; archive members are read only
under strict size, count, path and recursion limits.
"""
from __future__ import annotations

import hashlib
import io
import re
import stat
import zipfile
import tarfile
import gzip
from collections import deque
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from imagehunter.core.status import CANCELLED, ERROR, SKIPPED, classify
from imagehunter.analyzers.base import AnalyzerContext
from imagehunter.analyzers.binary.analyzer import BinaryStructureAnalyzer
from imagehunter.analyzers.binary.signatures import detect_format
from imagehunter.analyzers.carving.analyzer import EmbeddedSignatureAnalyzer
from imagehunter.analyzers.image.identity import ImageIdentityAnalyzer
from imagehunter.analyzers.image.animation import AnimatedImageAnalyzer
from imagehunter.analyzers.image.palette import PaletteAnalyzer
from imagehunter.analyzers.image.format_extras import ImageContainerAnalyzer
from imagehunter.analyzers.image.vision_optional import VisionOptionalAnalyzer
from imagehunter.analyzers.image.jpeg_dct import JPEGDCTAnalyzer
from imagehunter.analyzers.metadata.analyzer import MetadataAnalyzer
from imagehunter.analyzers.stego.advanced import AdvancedStegoAnalyzer
from imagehunter.analyzers.stego.analyzer import LsbFlagAnalyzer
from imagehunter.analyzers.text.strings import StringsAnalyzer
from imagehunter.models.artifact import Artifact
from imagehunter.models.finding import Finding
from imagehunter.services.hash_service import sha256_file

MAX_DERIVED_ARTIFACTS = 50
MAX_DERIVED_BYTES = 16 * 1024 * 1024
MAX_TOTAL_DERIVED_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 50
MAX_ARCHIVE_DEPTH = 3
MAX_COMPRESSION_RATIO = 200
TEXT_SAMPLE_LIMIT = 2 * 1024 * 1024
FLAG_RE = re.compile(rb"(?:THM|CTF|FLAG|flag|HTB|picoCTF)\{[^\r\n{}]{1,200}\}")
IMAGE_FORMATS = {"png", "jpeg", "gif", "bmp", "tiff", "webp"}


@dataclass
class Task:
    label: str
    data: bytes
    parent_id: str
    origin: str
    depth: int = 0


def _safe_name(label: str, digest: str, suffix: str = ".bin") -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(label).name).strip("._")[:48]
    return f"{digest[:12]}_{clean or 'artifact'}{suffix}"


def _is_text_candidate(data: bytes) -> bool:
    if not data or len(data) > TEXT_SAMPLE_LIMIT:
        return False
    sample = data[: min(len(data), 8192)]
    printable = sum(b in (9, 10, 13) or 32 <= b <= 126 for b in sample) / max(1, len(sample))
    return printable >= 0.88 and bool(FLAG_RE.search(data))


def _archive_members(blob: bytes, depth: int):
    """Read ZIP members incrementally; enforce limits on actual decompressed bytes."""
    if depth >= MAX_ARCHIVE_DEPTH:
        return [], ["archive recursion depth limit reached"]
    members, warnings, total = [], [], 0
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                warnings.append(f"archive entry count capped at {MAX_ARCHIVE_ENTRIES}")
            for info in infos[:MAX_ARCHIVE_ENTRIES]:
                name = info.filename
                path = PurePosixPath(name.replace("\\", "/"))
                mode = (info.external_attr >> 16) & 0xFFFF
                if path.is_absolute() or ".." in path.parts or not path.parts or ":" in path.parts[0]:
                    warnings.append(f"rejected unsafe archive path: {name!r}")
                    continue
                if stat.S_ISLNK(mode) or info.is_dir() or info.flag_bits & 0x1:
                    continue
                # Header values are attacker-controlled. They are only early-rejection hints.
                if info.file_size > MAX_DERIVED_BYTES or info.compress_size > MAX_TOTAL_DERIVED_BYTES:
                    warnings.append(f"rejected oversized archive member: {name!r}")
                    continue
                if info.file_size / max(1, info.compress_size) > MAX_COMPRESSION_RATIO:
                    warnings.append(f"rejected high-ratio archive member: {name!r}")
                    continue
                remaining = min(MAX_DERIVED_BYTES, MAX_TOTAL_DERIVED_BYTES - total)
                if remaining <= 0:
                    warnings.append("archive extraction byte budget reached")
                    break
                try:
                    chunks, produced = [], 0
                    with archive.open(info, "r") as member:
                        while True:
                            chunk = member.read(min(65536, remaining - produced + 1))
                            if not chunk:
                                break
                            produced += len(chunk)
                            if produced > remaining:
                                raise ValueError("actual decompressed size exceeds extraction budget")
                            chunks.append(chunk)
                    content = b"".join(chunks)
                except (RuntimeError, zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
                    warnings.append(f"could not safely read archive member {name!r}: {exc}")
                    continue
                if len(content) != info.file_size:
                    warnings.append(f"size mismatch for archive member {name!r} (declared {info.file_size}, actual {len(content)})")
                    continue
                if len(content) / max(1, info.compress_size) > MAX_COMPRESSION_RATIO:
                    warnings.append(f"rejected actual high-ratio archive member: {name!r}")
                    continue
                total += len(content)
                members.append((name, content))
    except (zipfile.BadZipFile, ValueError, OSError):
        return [], ["recognized ZIP signature but archive directory is invalid"]
    return members, warnings


def _other_archive_members(blob: bytes, fmt: str, depth: int):
    """Safely recover bounded TAR/GZIP payloads without writing archive paths."""
    if depth >= MAX_ARCHIVE_DEPTH:
        return [], ["archive recursion depth limit reached"]
    members, warnings, total = [], [], 0
    try:
        if fmt == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(blob)) as stream:
                chunks=[]; produced=0
                while True:
                    chunk=stream.read(min(65536, MAX_DERIVED_BYTES-produced+1))
                    if not chunk: break
                    produced += len(chunk)
                    if produced > MAX_DERIVED_BYTES:
                        raise ValueError("GZIP output exceeds per-artifact limit")
                    chunks.append(chunk)
                return [("gzip_payload", b"".join(chunks))], warnings
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as archive:
            for index, member in enumerate(archive):
                if index >= MAX_ARCHIVE_ENTRIES:
                    warnings.append("TAR entry count limit reached"); break
                path = PurePosixPath(member.name.replace("\\", "/"))
                if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
                    warnings.append(f"rejected unsafe TAR path: {member.name!r}"); continue
                if not member.isfile() or member.issym() or member.islnk() or member.size > MAX_DERIVED_BYTES:
                    continue
                remaining = min(MAX_DERIVED_BYTES, MAX_TOTAL_DERIVED_BYTES-total)
                if remaining <= 0: warnings.append("TAR extraction byte budget reached"); break
                stream=archive.extractfile(member)
                if stream is None: continue
                content=stream.read(remaining+1)
                if len(content)>remaining:
                    warnings.append(f"rejected oversized TAR member: {member.name!r}"); continue
                if len(content)!=member.size:
                    warnings.append(f"TAR size mismatch: {member.name!r}"); continue
                total += len(content); members.append((member.name,content))
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        warnings.append(f"archive could not be safely read: {type(exc).__name__}: {exc}")
    return members, warnings


def run_followup_investigation(*, root_artifact: Artifact, root_data: bytes, shared: dict,
                               settings, extracted_dir: Path, existing_findings: list[Finding],
                               cancel_event=None, time_remaining=None):
    """Process decoded outputs and nested archive members with a bounded dynamic queue."""
    queue: deque[Task] = deque()
    seen: set[str] = {root_artifact.sha256}
    artifacts: list[dict] = []
    statuses: list[dict] = []
    warnings: list[str] = []
    next_id = 1
    total_bytes = 0

    for chain, digest, payload in shared.get("decoded_outputs", [])[:100]:
        if not payload or len(payload) > MAX_DERIVED_BYTES:
            continue
        fmt = detect_format(payload[:512])
        if fmt in {"zip", "gzip", "tar", "pdf", "png", "jpeg", "gif", "bmp", "tiff", "webp", "rar", "7z"} or _is_text_candidate(payload):
            queue.append(Task(f"decoded_{chain.replace(' > ', '_')}", payload, root_artifact.id,
                              f"recursive decoding: {chain}", depth=0))

    # Carve only high-confidence signatures located beyond the parsed image structure.
    structure_end = shared.get("structure_end")
    try:
        from imagehunter.analyzers.carving.embedded import scan_embedded
        for finding in scan_embedded(root_data, structure_end):
            if finding.confidence_label == "High" and finding.offset is not None:
                payload = root_data[finding.offset:]
                fmt = detect_format(payload[:512])
                if fmt in {"zip", "gzip", "tar", "pdf", "png", "jpeg", "gif", "bmp", "tiff", "webp", "rar", "7z"}:
                    queue.append(Task(f"carved_{fmt}_{finding.offset}", payload, root_artifact.id,
                                      f"embedded signature at byte offset {finding.offset}", depth=0))
    except Exception as exc:
        warnings.append(f"carving follow-up unavailable: {type(exc).__name__}: {exc}")

    while queue and len(artifacts) < MAX_DERIVED_ARTIFACTS:
        if cancel_event is not None and cancel_event.is_set():
            warnings.append("follow-up investigation cancelled by user")
            break
        if time_remaining is not None and time_remaining() <= 0:
            warnings.append("follow-up investigation stopped: time budget exhausted")
            break
        task = queue.popleft()
        digest = hashlib.sha256(task.data).hexdigest()
        if digest in seen:
            continue
        if total_bytes + len(task.data) > MAX_TOTAL_DERIVED_BYTES:
            warnings.append("follow-up derived-byte budget reached")
            break
        seen.add(digest)
        total_bytes += len(task.data)
        artifact_id = f"D{next_id:03d}"
        next_id += 1
        fmt = detect_format(task.data[:512])
        if fmt is None and len(task.data) >= 262 and task.data[257:262] == b"ustar":
            fmt = "tar"
        suffix = {"png": ".png", "jpeg": ".jpg", "gif": ".gif", "bmp": ".bmp",
                  "zip": ".zip", "gzip": ".gz", "tar": ".tar", "pdf": ".pdf", "rar": ".rar", "7z": ".7z", "tiff": ".tiff", "webp": ".webp"}.get(fmt, ".txt")
        out_path = extracted_dir / _safe_name(task.label, digest, suffix)
        out_path.write_bytes(task.data)
        try:
            out_path.chmod(0o400)
        except OSError:
            pass
        artifact = Artifact(id=artifact_id, role="derived", path=task.label,
                            working_path=str(out_path), sha256=digest, size=len(task.data),
                            parent_id=task.parent_id, origin=task.origin)
        artifacts.append(artifact.to_dict())

        # Analyzer selection is driven by the artifact's detected content, not its filename.
        selected = [StringsAnalyzer(), BinaryStructureAnalyzer(), EmbeddedSignatureAnalyzer()]
        if fmt in IMAGE_FORMATS:
            selected.extend([ImageIdentityAnalyzer(), MetadataAnalyzer(), ImageContainerAnalyzer(), VisionOptionalAnalyzer()])
        child_shared = {"detected_format": fmt}
        if fmt in IMAGE_FORMATS:
            selected.extend([LsbFlagAnalyzer(), AdvancedStegoAnalyzer(), PaletteAnalyzer(), JPEGDCTAnalyzer()])
            if fmt == "gif":
                selected.append(AnimatedImageAnalyzer())
        for position, analyzer in enumerate(selected):
            stop_status, stop_message = None, ""
            if cancel_event is not None and cancel_event.is_set():
                stop_status, stop_message = CANCELLED, "cancelled by user"
            elif time_remaining is not None and time_remaining() <= 0:
                stop_status, stop_message = SKIPPED, "time budget exhausted"
            if stop_status is not None:
                # Record every analyzer that will not run, so the report never implies it ran.
                for remaining in selected[position:]:
                    statuses.append({"artifact_id": artifact_id, "name": remaining.name,
                                     "status": stop_status, "message": stop_message})
                break
            try:
                result = analyzer.run(AnalyzerContext(artifact, task.data, settings, child_shared, cancel_event))
                status, message = classify(skipped_reason=result.properties.get("skipped"),
                                           findings=len(result.findings), warnings=list(result.warnings))
                statuses.append({"artifact_id": artifact_id, "name": analyzer.name,
                                 "status": status, "message": message})
                warnings.extend(result.warnings)
                for finding in result.findings:
                    finding.id = ""  # globally assigned by the parent pipeline
                    finding.source_artifact_id = artifact_id
                    finding.method = f"derived.{analyzer.name}"
                    existing_findings.append(finding)
            except Exception as exc:
                statuses.append({"artifact_id": artifact_id, "name": analyzer.name,
                                 "status": ERROR, "message": f"{type(exc).__name__}: {exc}"})
                warnings.append(f"{artifact_id}/{analyzer.name} failed: {type(exc).__name__}: {exc}")

        # Direct text flags in non-container artifacts are evidence-backed candidates,
        # not verified flags. ZIP bytes are not scanned as text: their members are.
        if fmt != "zip":
            for match in FLAG_RE.finditer(task.data):
                existing_findings.append(Finding(
                    kind="derived_flag_candidate", category="ctf",
                    description=f"Flag-shaped text recovered in derived artifact {artifact_id}",
                    confidence_label="Medium", offset=match.start(), length=len(match.group()),
                    evidence={"text": match.group().decode("latin-1"), "sha256": digest,
                              "artifact_id": artifact_id, "origin": task.origin},
                    source_artifact_id=artifact_id, method="derived.flag_scan"))

        if fmt in {"zip", "tar", "gzip"}:
            if fmt == "zip":
                members, member_warnings = _archive_members(task.data, task.depth)
            else:
                members, member_warnings = _other_archive_members(task.data, fmt, task.depth)
            warnings.extend(member_warnings)
            for name, content in members:
                if content and len(content) <= MAX_DERIVED_BYTES:
                    queue.append(Task(name, content, artifact_id,
                                      f"{fmt.upper()} member {name} extracted from {artifact_id}", task.depth + 1))

    if queue:
        warnings.append(f"follow-up queue truncated with {len(queue)} task(s) pending")
    return {"artifacts": artifacts, "analyzers": statuses, "warnings": list(dict.fromkeys(warnings)),
            "tasks_processed": len(artifacts), "bytes_processed": total_bytes,
            "tasks_pending": len(queue), "limits": {"max_artifacts": MAX_DERIVED_ARTIFACTS,
            "max_artifact_bytes": MAX_DERIVED_BYTES, "max_total_bytes": MAX_TOTAL_DERIVED_BYTES,
            "max_archive_entries": MAX_ARCHIVE_ENTRIES, "max_archive_depth": MAX_ARCHIVE_DEPTH}}
