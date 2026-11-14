"""Safe external-process runner: shell=False, timeouts, capped output."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

DEFAULT_OUTPUT_CAP = 1024 * 1024


@dataclass
class ToolResult:
    argv: list[str]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and not self.timed_out and self.returncode == 0


def find_executable(name: str) -> str | None:
    return shutil.which(name)


def run_tool(argv: list[str], timeout: float = 30.0, cwd: str | None = None,
             output_cap: int = DEFAULT_OUTPUT_CAP) -> ToolResult:
    if not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("argv must be a non-empty list of strings")

    def _decode(data: bytes | None) -> str:
        return (data or b"")[:output_cap].decode("utf-8", errors="replace")

    try:
        proc = subprocess.run(argv, shell=False, cwd=cwd, capture_output=True,
                              timeout=timeout, check=False)
    except FileNotFoundError:
        return ToolResult(argv, None, error=f"executable not found: {argv[0]}")
    except subprocess.TimeoutExpired as exc:
        return ToolResult(argv, None, stdout=_decode(exc.stdout), stderr=_decode(exc.stderr),
                          timed_out=True, error=f"timed out after {timeout}s")
    except OSError as exc:
        return ToolResult(argv, None, error=str(exc))
    return ToolResult(argv, proc.returncode, stdout=_decode(proc.stdout), stderr=_decode(proc.stderr))
