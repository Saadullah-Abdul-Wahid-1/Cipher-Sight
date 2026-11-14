#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null 2>&1; then echo "Python 3.10+ is required" >&2; exit 1; fi
python3 - <<'PY'
import sys
if not ((3,10) <= sys.version_info[:2] < (3,14)):
    raise SystemExit("CipherSight requires Python 3.10 through 3.13")
PY
if [[ ! -x .venv/bin/python ]]; then python3 -m venv .venv; fi
.venv/bin/python -m pip install --disable-pip-version-check -e .
echo "Starting CipherSight at http://127.0.0.1:8000/ (Ctrl+C to stop)"
exec .venv/bin/python main.py web --port 8000
