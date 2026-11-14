"""Bounded recursive decoding with full provenance.

Breadth-first over decode steps. Limits: max_depth, max_nodes (created artifacts), max_output (bytes per
artifact), xor_budget (total bytes tested by known-prefix XOR). Duplicate artifacts (same sha256) are not
expanded twice, which also stops cycles. Every flag keeps the chain of steps that produced it.
"""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass, field

from imagehunter.analyzers.decoding.decoders import (
    decode_base32, decode_base64, decode_binary, decode_compression, decode_hex,
    decode_html_entities, decode_url, rot_variants, xor_known_prefix)


@dataclass
class Node:
    data: bytes
    chain: tuple                  # tuple of {"method": str, "params": dict}
    seed: str
    seed_offset: int | None


@dataclass
class Stats:
    seeds: int = 0
    nodes_created: int = 0
    nodes_expanded: int = 0
    max_depth_reached: int = 0
    budget_exhausted: bool = False
    xor_bytes_tested: int = 0
    rot_checks: int = 0
    warnings: list = field(default_factory=list)
    artifacts: list = field(default_factory=list)      # first 50: chain text, sha256, size, depth
    outputs: list = field(default_factory=list)        # first 100 decoded artifacts: (chain_text, sha256, bytes)
    artifacts_truncated: bool = False


def plausible_body(text: str) -> bool:
    """Key-based leaf matches (XOR, ROT) are accepted only when the text inside braces is mostly word-like.
    Random bytes match a short prefix by chance and then show symbols; real flag bodies do not."""
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start + 1:
        return False
    body = text[start + 1:end]
    if len(body) < 3:
        return False
    word = sum(1 for c in body if c.isalnum() or c in "_- ")
    return word / len(body) >= 0.8


def chain_text(chain) -> str:
    parts = []
    for step in chain:
        p = step.get("params", {})
        extra = ",".join(f"{k}={v}" for k, v in p.items())
        parts.append(step["method"] + (f"({extra})" if extra else ""))
    return " > ".join(parts)


def search(seeds, prefixes, flag_re, max_depth=3, max_nodes=2000, max_output=65536,
           xor_budget=5_000_000, rot=True):
    """seeds: list of (label, offset, text). Returns (flags, stats).

    flags: dict flag_text -> record with chain, seed, offset, depth, sha256. Only flags found after at
    least one decode step are returned; plain-text flags are left to the existing analyzers.
    """
    stats = Stats()
    flags: dict[str, dict] = {}
    seen: set[str] = set()
    queue: deque[Node] = deque()

    def add(node: Node) -> bool:
        if stats.nodes_created >= max_nodes:
            stats.budget_exhausted = True
            return False
        digest = hashlib.sha256(node.data).hexdigest()
        if digest in seen:
            return False
        seen.add(digest)
        stats.nodes_created += 1
        if node.chain:
            if len(stats.artifacts) < 50:
                stats.artifacts.append({"chain": chain_text(node.chain), "sha256": digest,
                                        "size": len(node.data), "depth": len(node.chain)})
            else:
                stats.artifacts_truncated = True
            if len(stats.outputs) < 100:
                stats.outputs.append((chain_text(node.chain), digest, node.data))
        queue.append(node)
        return True

    def record(text: str, chain: tuple, node: Node):
        if not chain:
            return
        if text not in flags or len(chain) < flags[text]["depth"]:
            flags[text] = {"text": text, "chain": list(chain), "chain_text": chain_text(chain),
                           "seed": node.seed, "offset": node.seed_offset,
                           "depth": len(chain),
                           "sha256": hashlib.sha256(node.data).hexdigest()}

    for label, offset, text in seeds:
        data = text.encode("latin-1", errors="replace")
        if data and add(Node(data, (), label, offset)):
            stats.seeds += 1

    while queue:
        node = queue.popleft()
        stats.nodes_expanded += 1
        stats.max_depth_reached = max(stats.max_depth_reached, len(node.chain))
        text = node.data.decode("latin-1")

        # Leaf checks (never expanded): ROT and known-prefix XOR.
        if rot:
            for k, rtext in rot_variants(text):
                stats.rot_checks += 1
                for m in flag_re.finditer(rtext.encode("latin-1", errors="replace")):
                    value = m.group().decode("latin-1")
                    if plausible_body(value):
                        record(value, node.chain + ({"method": "rot", "params": {"shift": k}},), node)
        if xor_budget > 0 and len(node.data) <= 4096:
            if stats.xor_bytes_tested + len(node.data) * len(prefixes) <= xor_budget:
                stats.xor_bytes_tested += len(node.data) * len(prefixes)
                for p, key, out in xor_known_prefix(node.data, prefixes):
                    for m in flag_re.finditer(out):
                        value = m.group().decode("latin-1")
                        if plausible_body(value):
                            record(value, node.chain + ({"method": "xor_known_prefix",
                                                         "params": {"prefix": p, "key": f"0x{key:02X}"}},), node)
            else:
                stats.budget_exhausted = True
                stats.warnings.append("xor budget exhausted; later nodes were not XOR-tested")

        if len(node.chain) >= max_depth:
            continue

        steps = []
        for fn in (decode_base64, decode_base32, decode_hex, decode_binary, decode_url, decode_html_entities):
            steps.extend(fn(text))
        comp, warns = decode_compression(node.data, max_output)
        steps.extend(comp)
        stats.warnings.extend(warns)

        for method, params, out in steps:
            if len(out) > max_output:
                stats.warnings.append(f"{method} output exceeds {max_output} bytes; not expanded")
                continue
            child = Node(out, node.chain + ({"method": method, "params": params},), node.seed, node.seed_offset)
            if add(child):
                # A decoded artifact can contain a flag directly; check it right away.
                for m in flag_re.finditer(out):
                    record(m.group().decode("latin-1"), child.chain, child)

    stats.warnings = list(dict.fromkeys(stats.warnings))[:50]
    return flags, stats
