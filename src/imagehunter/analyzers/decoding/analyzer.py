"""decoding.recursive: decode encoded text found in the image and look for flags in the results.

Seeds come from text the other analyzers already produced (printable runs and metadata text).
Only flags found AFTER at least one decode step are reported here. Plain-text flags stay with the
existing analyzers, so their results do not change.
"""

from __future__ import annotations

import re

from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.analyzers.decoding.recursive import search
from imagehunter.analyzers.stego.lsb import flag_pattern
from imagehunter.models.finding import Finding

TOKEN = re.compile(r"[^\s]{8,256}")
ENCODED_CHARS = re.compile(r"[A-Za-z0-9+/=%&;]")


def _encodedness(token: str) -> float:
    return len(ENCODED_CHARS.findall(token)) / len(token)


class RecursiveDecodingAnalyzer(Analyzer):
    name = "decoding.recursive"

    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        res = AnalyzerResult()
        s = ctx.settings
        if not s.decoding_enabled:
            res.properties["enabled"] = False
            return res

        sources = []
        for off, text in ctx.shared.get("ascii_runs", []):
            sources.append(("ascii strings", off, text))
        for label, off, text in ctx.shared.get("metadata_texts", []):
            sources.append((label, off, text))

        candidates = []
        for label, base, text in sources:
            if len(text) <= 256:
                candidates.append((1.0, label, base, text))       # whole short run (ROT, XOR, plain)
            for m in TOKEN.finditer(text):
                tok = m.group()
                score = _encodedness(tok)
                if score >= 0.9:
                    candidates.append((score, label, base + m.start(), tok))
        candidates.sort(key=lambda c: (-c[0], c[1], c[2]))
        seeds, seen = [], set()
        for _, label, off, text in candidates:
            if text in seen:
                continue
            seen.add(text)
            seeds.append((label, off, text))
            if len(seeds) >= s.decoding_max_seeds:
                break

        flag_re = flag_pattern(s.flag_prefixes)
        flags, stats = search(
            seeds, s.flag_prefixes, flag_re,
            max_depth=s.decoding_max_depth, max_nodes=s.decoding_max_nodes,
            max_output=s.decoding_max_output, xor_budget=s.decoding_xor_budget, rot=True)

        for text, rec in sorted(flags.items()):
            res.findings.append(Finding(
                kind="decoded_flag_candidate", category="decoding",
                description=f"flag-format text {text!r} found after decoding ({rec['chain_text']}) "
                            f"in {rec['seed']}",
                confidence_label="High", offset=rec["offset"],
                evidence={"text": text, "chain": rec["chain"], "chain_text": rec["chain_text"],
                          "seed": rec["seed"], "depth": rec["depth"], "sha256": rec["sha256"]},
            ))

        from imagehunter.analyzers.binary.signatures import detect_format
        for chain, sha, data in stats.outputs:
            fmt = detect_format(data[:16])
            if fmt is None or fmt in ("gzip",):
                continue
            res.findings.append(Finding(
                kind="decoded_file_signature", category="carving",
                description=f"{fmt.upper()} file signature in decoded artifact ({chain})",
                confidence_label="High", offset=None,
                evidence={"format": fmt, "chain_text": chain, "sha256": sha, "size": len(data)},
            ))

        # Keep bounded decoded bytes in memory for the evidence-driven follow-up queue.
        # This is an internal hand-off only; bytes are never executed or written here.
        ctx.shared["decoded_outputs"] = list(stats.outputs)

        res.properties.update(
            enabled=True,
            artifacts_truncated=stats.artifacts_truncated,
            seeds=len(seeds),
            nodes_created=stats.nodes_created,
            nodes_expanded=stats.nodes_expanded,
            max_depth_reached=stats.max_depth_reached,
            budget_exhausted=stats.budget_exhausted,
            xor_bytes_tested=stats.xor_bytes_tested,
            rot_checks=stats.rot_checks,
            flags=len(flags),
            artifacts=stats.artifacts,
            limits={"max_depth": s.decoding_max_depth, "max_nodes": s.decoding_max_nodes,
                    "max_output": s.decoding_max_output, "max_seeds": s.decoding_max_seeds,
                    "xor_budget": s.decoding_xor_budget},
        )
        res.warnings.extend(stats.warnings)
        return res
