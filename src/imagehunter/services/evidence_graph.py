"""Evidence graph built from the scan summary. Every edge comes from a recorded relation.

Nodes: the original artifact, decoded artifacts (with their decode chain), and findings.
Edges: artifact -> finding (the analyzer that produced it), parent artifact -> decoded artifact
(the last decode step). Nothing is inferred beyond what the analyzers recorded.

Evidence classes (applied to every node):
  raw evidence              the input file and the bytes produced by decoding
  deterministic             structural checks and file signatures (same input, same result)
  heuristic                 pattern matches and leads that need analyst review
  ai_hypothesis             reserved; no AI component exists in this build, so none are produced
  verified                  reserved for analyst confirmation; never set automatically
"""

from __future__ import annotations

DETERMINISTIC_KINDS = {
    "appended_data", "extension_mismatch", "unknown_format", "metadata_timestamp_conflict",
    "metadata_gps_present", "metadata_large_block", "decoded_file_signature",
}
DETERMINISTIC_PREFIXES = ("embedded_", "png_", "jpeg_", "bmp_")
HEURISTIC_KINDS = {"lsb_flag_candidate", "metadata_flag_candidate", "decoded_flag_candidate",
                   "lsb_unknown_prefix_lead", "expected_phrase"}


def evidence_class(kind: str) -> str:
    if kind in HEURISTIC_KINDS:
        return "heuristic"
    if kind in DETERMINISTIC_KINDS or kind.startswith(DETERMINISTIC_PREFIXES):
        return "deterministic"
    return "heuristic"


def _step_name(chain_text: str) -> str:
    last = chain_text.split(" > ")[-1]
    return last.split("(", 1)[0]


def build_graph(summary: dict) -> dict:
    inp = summary.get("input", {})
    root_id = inp.get("id", "A001")
    nodes = [{"id": root_id, "type": "artifact", "label": inp.get("path", "input"),
              "sha256": inp.get("sha256"), "evidence_class": "raw evidence"}]
    edges = []

    decoding = summary.get("properties", {}).get("decoding.recursive", {}) or {}
    artifacts = decoding.get("artifacts", []) or []
    by_chain = {}
    by_sha = {}
    for i, art in enumerate(artifacts, start=1):
        node_id = f"D{i:03d}"
        chain = art["chain"]
        parent_chain = " > ".join(chain.split(" > ")[:-1])
        parent_id = by_chain.get(parent_chain, root_id) if parent_chain else root_id
        nodes.append({"id": node_id, "type": "decoded_artifact", "label": chain, "sha256": art["sha256"],
                      "size": art["size"], "depth": art["depth"], "evidence_class": "raw evidence"})
        edges.append({"from": parent_id, "to": node_id, "relation": "decoded_by",
                      "method": _step_name(chain)})
        by_chain[chain] = node_id
        by_sha[art["sha256"]] = node_id

    # Derived artifacts produced by the evidence-driven follow-up queue.
    investigation = summary.get("properties", {}).get("investigation", {}) or {}
    followup = investigation.get("followup", {}) or {}
    derived_by_id = {}
    for art in followup.get("artifacts", []) or []:
        aid = art.get("id")
        if not aid:
            continue
        derived_by_id[aid] = art
        nodes.append({"id": aid, "type": "derived_artifact", "label": art.get("path", aid),
                      "sha256": art.get("sha256"), "size": art.get("size"),
                      "origin": art.get("origin"), "evidence_class": "raw evidence"})
        edges.append({"from": art.get("parent_id", root_id), "to": aid,
                      "relation": "extracted_from", "method": art.get("origin", "follow-up analysis")})

    for f in summary.get("findings", []):
        fid = f.get("id", "")
        nodes.append({"id": fid, "type": "finding", "label": f.get("kind"), "analyzer": f.get("method"),
                      "offset": f.get("offset"), "confidence": f.get("confidence_label"),
                      "evidence_class": evidence_class(f.get("kind", ""))})
        ev = f.get("evidence", {}) or {}
        source = f.get("source_artifact_id") or root_id
        decoded_source = by_sha.get(ev.get("sha256"))
        if decoded_source and source == root_id:
            source = decoded_source
        if source not in derived_by_id and source != root_id and source not in by_sha.values():
            source = decoded_source or root_id
        edges.append({"from": source, "to": fid, "relation": "detected_by", "method": f.get("method")})

    truncated = bool(decoding.get("artifacts_truncated"))
    return {"nodes": nodes, "edges": edges, "artifacts_truncated": truncated,
            "classes": ["raw evidence", "deterministic", "heuristic", "ai_hypothesis", "verified"]}
