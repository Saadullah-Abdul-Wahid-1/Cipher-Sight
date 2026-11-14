"""Run CipherSight from a source checkout without installing: python main.py scan FILE"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))

from imagehunter.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
