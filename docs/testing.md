# Testing

    python -m unittest discover -s tests -t .

- `tests/unit/` — parsers, validation, settings, logging, runner, registry, models.
- `tests/integration/` — end-to-end scans on synthetic fixtures with recorded ground truth; CLI through `main.py`.
- `tests/fixtures/generate.py` — builds fixtures and `ground_truth.json`. Fixtures must not be
  "fixed" to match analyzer output. If a test fails, fix the analyzer or the recorded truth, with a reason.

Coverage of malformed-input robustness, crash isolation, and read-only original are part of the suite.
