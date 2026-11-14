"""Optional external tools. A tool is 'verified' only after its version probe runs cleanly here.

probe_tested=False means the probe arguments come from documentation and have not
been run on a real install. Such tools can be found and probed, but never claimed
as tested integrations.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from imagehunter.integrations.runner import find_executable, run_tool


@dataclass(frozen=True)
class ExternalTool:
    name: str
    probe: tuple[str, ...]
    platforms: str
    probe_tested: bool
    purpose: str


@dataclass
class ToolStatus:
    name: str
    found: bool
    path: str | None = None
    version: str | None = None
    verified: bool = False
    note: str = ""


TOOLS: tuple[ExternalTool, ...] = (
    ExternalTool("exiftool", ("-ver",), "Windows, Linux, macOS", False, "EXIF/XMP metadata (Phase 3)"),
    ExternalTool("binwalk", ("--version",), "Linux, WSL (v3 is Rust)", False, "embedded file carving (Phase 5)"),
    ExternalTool("foremost", ("-V",), "Linux, WSL", False, "file carving (Phase 5)"),
    ExternalTool("steghide", ("--version",), "Linux; Windows builds exist", False, "steghide extraction (Phase 5)"),
    ExternalTool("stegseek", ("--version",), "Linux or WSL only", False, "steghide cracking (Phase 5)"),
    ExternalTool("zsteg", ("--version",), "Ruby gem, Linux or Windows", False, "PNG/BMP LSB scan (Phase 4)"),
    ExternalTool("outguess", ("-h",), "Linux, WSL", False, "outguess extraction (Phase 5)"),
    ExternalTool("stegoveritas", ("--help",), "Python tool, Linux", False, "multi-check stego (Phase 5)"),
)


def check_tool(tool: ExternalTool) -> ToolStatus:
    path = find_executable(tool.name)
    if path is None:
        return ToolStatus(tool.name, found=False, note="not installed (optional)")
    result = run_tool([tool.name, *tool.probe], timeout=15)
    lines = (result.stdout or result.stderr).strip().splitlines()
    version = lines[0][:120] if lines else None
    if result.ok and version:
        if tool.probe_tested:
            return ToolStatus(tool.name, True, path, version, verified=True, note="probe ok")
        return ToolStatus(tool.name, True, path, version, verified=False,
                          note="installed; probe ran but flags are not yet validated on this platform")
    reason = result.error or f"probe exited with code {result.returncode}"
    return ToolStatus(tool.name, True, path, None, verified=False, note=f"installed but probe failed: {reason}")


def check_all() -> list[ToolStatus]:
    return [check_tool(t) for t in TOOLS]
