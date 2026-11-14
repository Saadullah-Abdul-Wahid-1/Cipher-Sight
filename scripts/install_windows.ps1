# ImageHunter Windows setup helper (PowerShell 5.1+).
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root
if (-not (Test-Path -LiteralPath (Join-Path $Root 'pyproject.toml'))) { throw 'Invalid ImageHunter project directory.' }

$Python = Get-Command py -ErrorAction SilentlyContinue
if ($Python) { $PyArgs = @('-3') } else {
    $Python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $Python) { throw 'Python 3.10+ not found. Install from https://www.python.org/downloads/windows/.' }
    $PyArgs = @()
}
& $Python.Source @PyArgs -c "import sys; print(sys.version); sys.exit(0 if (3,10) <= sys.version_info[:2] < (3,14) else 1)"
if ($LASTEXITCODE -ne 0) { throw 'Python 3.10 through 3.13 is required.' }
$VenvPython = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $VenvPython)) { & $Python.Source @PyArgs -m venv (Join-Path $Root '.venv') }
if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
& $VenvPython -m ensurepip --upgrade
& $VenvPython -m pip install --disable-pip-version-check -e .
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. Check internet access and pip output.' }
& $VenvPython scripts\check_dependencies.py
if ($LASTEXITCODE -ne 0) { Write-Warning 'A required dependency check did not pass.' }
Write-Host 'Setup complete. Launch with ImageHunter_Windows.bat.' -ForegroundColor Green
