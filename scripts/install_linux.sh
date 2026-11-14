#!/usr/bin/env bash
# ImageHunter installer for Linux (and WSL). Creates .venv, installs Python packages, runs tests.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-python3}"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || { echo "Python 3.10+ required" >&2; exit 1; }
[ -d "$ROOT/.venv" ] || "$PY" -m venv "$ROOT/.venv"
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"
python -m pip install --upgrade pip
python -m pip install -r "$ROOT/requirements.txt"
cd "$ROOT"
python -m unittest discover -s tests -t .
python scripts/check_dependencies.py || true
echo "Done. Activate with: source .venv/bin/activate   Then: python main.py scan path/to/image.png"
