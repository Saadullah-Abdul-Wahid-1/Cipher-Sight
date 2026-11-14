"""Dependency checker. Run from the project root: python scripts/check_dependencies.py"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from imagehunter.services.dependency_service import all_required_ok, report_lines  # noqa: E402

if __name__ == "__main__":
    print("\n".join(report_lines()))
    sys.exit(0 if all_required_ok() else 1)
