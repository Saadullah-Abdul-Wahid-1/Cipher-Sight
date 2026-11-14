"""Reports Python version, required packages and optional external tools."""

from __future__ import annotations

import importlib
import platform
import shutil
import sys
from dataclasses import dataclass

from imagehunter import __version__
from imagehunter.integrations.registry import check_all

MIN_PYTHON = (3, 10)
REQUIRED_PACKAGES = {"PIL": "Pillow", "numpy": "numpy", "reportlab": "ReportLab"}
OPTIONAL_PACKAGES = {"cv2": "OpenCV (QR/barcode)", "pytesseract": "pytesseract (OCR bridge)", "jpegio": "jpegio (JPEG DCT)"}


@dataclass
class PackageStatus:
    name: str
    installed: bool
    version: str | None


def python_ok() -> bool:
    return sys.version_info[:2] >= MIN_PYTHON


def check_packages() -> list[PackageStatus]:
    out = []
    for module, dist in REQUIRED_PACKAGES.items():
        try:
            mod = importlib.import_module(module)
            out.append(PackageStatus(dist, True, getattr(mod, "__version__", "unknown")))
        except ImportError:
            out.append(PackageStatus(dist, False, None))
    return out


def check_optional_packages() -> list[PackageStatus]:
    out = []
    for module, label in OPTIONAL_PACKAGES.items():
        try:
            mod = importlib.import_module(module)
            out.append(PackageStatus(label, True, getattr(mod, "__version__", "unknown")))
        except ImportError:
            out.append(PackageStatus(label, False, None))
    return out


def all_required_ok() -> bool:
    return python_ok() and all(p.installed for p in check_packages())


def report_lines() -> list[str]:
    lines = [
        f"CipherSight {__version__}",
        f"Platform: {platform.system()} {platform.release()} ({platform.machine()})",
        f"Python {platform.python_version()} " + ("OK" if python_ok()
                                                  else f"TOO OLD (need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})"),
        "",
        "Required Python packages:",
    ]
    for p in check_packages():
        state = f"OK {p.version}" if p.installed else "MISSING (pip install -r requirements.txt)"
        lines.append(f"  {p.name:<10} {state}")
    lines += ["", "Optional Python capabilities:"]
    for p in check_optional_packages():
        state = f"available {p.version}" if p.installed else "not installed (optional)"
        lines.append(f"  {p.name:<28} {state}")
    tesseract = shutil.which("tesseract")
    lines.append(f"  {'Tesseract OCR engine':<28} {tesseract or 'not installed (OCR unavailable)'}")
    lines += ["", "Optional external tools ('verified' = probe ran successfully on this machine):"]
    for s in check_all():
        if not s.found:
            status = "not found"
        elif s.verified:
            status = f"verified  {s.version}"
        else:
            status = f"found     {s.version or ''}".rstrip()
        lines.append(f"  {s.name:<13} {status}")
        lines.append(f"  {'':<13} -> {s.note}")
    return lines
