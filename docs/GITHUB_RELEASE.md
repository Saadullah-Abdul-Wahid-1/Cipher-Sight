# GitHub release procedure

Do not publish this release candidate as stable until `docs/FINAL_TEST_CHECKLIST.md` is complete.

## 1. Inspect the source

```bash
git status --short
git diff --check
git diff
```

Do not commit workspaces, real challenge images, reports, API keys, local settings, or generated fixture answer keys.

## 2. Run tests in a clean environment

```bash
python -m pip install -r requirements-dev.txt
python -m pip install -e .
python -m pytest -q tests/unit
python -m pytest -q tests/integration
python -m compileall -q src tests
imagehunter --version
imagehunter check-deps
```

## 3. Create the repository commit

```bash
git add .
git commit -m "Prepare ImageHunter 1.0.0"
```

## 4. Promote release candidate to stable

Only after manual testing and accepted limitations:
- Change `version` in `pyproject.toml` to `1.0.0`.
- Change `__version__` in `src/imagehunter/__init__.py` to `1.0.0`.
- Update README and CHANGELOG release notes.
- Re-run tests and smoke checks.
- Commit the stable release changes.

## 5. Tag and push

```bash
git tag -a v1.0.0 -m "ImageHunter 1.0.0"
git push origin main
git push origin v1.0.0
```

Create a GitHub Release from tag `v1.0.0` and attach the source ZIP if desired.

Never use `git push --force` for a normal release. Review the remote repository and branch name before pushing.
